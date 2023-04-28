// SPDX-License-Identifier: GPL-2.0
/*
 * PCI Endpoint function driver to impliment virtio-net device.
 */

#include <linux/module.h>
#include <linux/pci-epf.h>
#include <linux/virtio_config.h>
#include <linux/virtio_net.h>
#include <linux/virtio_pci.h>
#include <linux/virtio_ring.h>
#include <linux/dmaengine.h>
#include <rdma/ib_verbs.h>
#include <rdma/virtio_rdma_abi.h>

#include "pci-epf-virtio.h"

static int virtio_queue_size = 0x400;
module_param(virtio_queue_size, int, 0444);
MODULE_PARM_DESC(virtio_queue_size, "A length of virtqueue");

struct epf_vnet_rdma_pd;
struct epf_vnet_rdma_mr;

struct epf_vnet {
	/* virtio feature and configurations for virtio-net. It is commonly used
	 * local and remote. */
	struct virtio_net_config vnet_cfg;
	struct virtio_net_config vdev_vnet_cfg;
	u64 features;

	struct dma_chan *tx_dma_chan, *rx_dma_chan;

	/* To access virtqueues on remote host */
	struct epf_virtio evio;
	struct vringh_kiov *rdev_iovs;

	/* To register a local virtio bus */
	struct virtio_device vdev;

	/* To access virtqueus of local host driver */
	struct vringh *vdev_vrhs;
	struct vringh_kiov *vdev_iovs;
	struct virtqueue **vdev_vqs;

	struct workqueue_struct *task_wq;
	struct work_struct raise_irq_work, rx_work, tx_work;
	struct work_struct vdev_ctrl_work, ep_ctrl_work;
	/* for RDMA */
	struct work_struct roce_rx_work, roce_tx_work;

#define EPF_VNET_INIT_COMPLETE_VDEV BIT(0)
#define EPF_VNET_INIT_COMPLETE_EP_FUNC BIT(1)
	u8 initialized;
	bool enable_edma;

#define EPF_VNET_ROCE_GID_TBL_LEN 512
	union ib_gid vdev_roce_gid_tbl[EPF_VNET_ROCE_GID_TBL_LEN];
	union ib_gid ep_roce_gid_tbl[EPF_VNET_ROCE_GID_TBL_LEN];
	unsigned ncq, nqp, nah;
	unsigned ep_ncq, ep_nqp, ep_nmr, ep_npd, ep_nah;

	struct kmem_cache *pd_slab, *mr_slab;

#define EPF_VNET_RDMA_MAX_AH 32
#define EPF_VNET_RDMA_MAX_MR 32
#define EPF_VNET_RDMA_MAX_PD 32
	struct virtio_rdma_ack_query_device rdma_attr;
	struct epf_vnet_rdma_pd *pds[EPF_VNET_RDMA_MAX_PD];
	struct epf_vnet_rdma_mr *mrs[EPF_VNET_RDMA_MAX_MR];
};

struct epf_vnet_rdma_mr {
	int mrn;
	u64 virt_addr;
	u64 length;
	u32 npages;
	u64 *pages;
};

struct epf_vnet_rdma_pd {
	int pdn;
};

static inline struct epf_vnet *vdev_to_vnet(struct virtio_device *vdev)
{
	return container_of(vdev, struct epf_vnet, vdev);
}

/* TODO This nvq is fixed value so I can use cache */
static u16 epf_vnet_get_nvq(struct epf_vnet *vnet)
{
	u16 nvq;

	nvq = vnet->vnet_cfg.max_virtqueue_pairs * 2;

	if (vnet->features & BIT(VIRTIO_NET_F_CTRL_VQ))
		nvq++;

	if (vnet->features & BIT(VIRTIO_NET_F_ROCE)) {
		nvq += vnet->vnet_cfg.max_rdma_cqs;
		nvq += vnet->vnet_cfg.max_rdma_qps * 2;
	}

	return nvq;
}

static void epf_vnet_qnotify_callback(void *param)
{
	struct epf_vnet *vnet = param;

	queue_work(vnet->task_wq, &vnet->rx_work);
	queue_work(vnet->task_wq, &vnet->ep_ctrl_work);
}

static void epf_vnet_vdev_announce_linkup(struct epf_vnet *vnet);

static void epf_vnet_ep_announce_linkup(struct epf_vnet *vnet)
{
	struct epf_virtio *evio = &vnet->evio;

	epf_virtio_cfg_set16(evio,
			     VIRTIO_PCI_CONFIG_OFF(false) +
				     offsetof(struct virtio_net_config, status),
			     VIRTIO_NET_S_LINK_UP | VIRTIO_NET_S_ANNOUNCE);
	epf_virtio_cfg_set16(evio, VIRTIO_PCI_ISR, VIRTIO_PCI_ISR_CONFIG);

	queue_work(vnet->task_wq, &vnet->raise_irq_work);
}

static void epf_vnet_init_complete(struct epf_vnet *vnet, u8 from)
{
	vnet->initialized |= from;

	if (!(vnet->initialized & EPF_VNET_INIT_COMPLETE_VDEV))
		return;

	if (!(vnet->initialized & EPF_VNET_INIT_COMPLETE_EP_FUNC))
		return;

	epf_vnet_vdev_announce_linkup(vnet);
	epf_vnet_ep_announce_linkup(vnet);
}

static void epf_vnet_ep_init_complete(void *param)
{
	struct epf_vnet *vnet = param;
	epf_vnet_init_complete(vnet, EPF_VNET_INIT_COMPLETE_EP_FUNC);
}

static struct pci_epf_header epf_vnet_pci_header = {
	.vendorid = PCI_VENDOR_ID_REDHAT_QUMRANET,
	.deviceid = VIRTIO_TRANS_ID_NET,
	.subsys_vendor_id = PCI_VENDOR_ID_REDHAT_QUMRANET,
	.subsys_id = VIRTIO_ID_NET,
	.revid = 0,
	.baseclass_code = PCI_BASE_CLASS_NETWORK,
	.interrupt_pin = PCI_INTERRUPT_PIN,
};

static void epf_vnet_setup_pci_cfgs(struct epf_vnet *vnet,
				    struct epf_virtio *evio)
{
	epf_virtio_cfg_memcpy_toio(evio, VIRTIO_PCI_CONFIG_OFF(false),
				   &vnet->vnet_cfg, sizeof(vnet->vnet_cfg));
}

static int epf_vnet_setup_ep_func(struct epf_vnet *vnet, struct pci_epf *epf)
{
	struct epf_virtio *evio = &vnet->evio;
	u16 nvq = epf_vnet_get_nvq(vnet);
	int err;

	vnet->rdev_iovs =
		kmalloc_array(sizeof(vnet->rdev_iovs[0]), nvq, GFP_KERNEL);
	if (!vnet->rdev_iovs)
		return -ENOMEM;

	for (int i = 0; i < nvq; i++)
		vringh_kiov_init(&vnet->rdev_iovs[i], NULL, 0);

	evio->epf = epf;
	evio->features = vnet->features;
	evio->nvq = nvq;
	evio->vqlen = virtio_queue_size;

	evio->qn_callback = epf_vnet_qnotify_callback;
	evio->qn_param = vnet;

	evio->ic_callback = epf_vnet_ep_init_complete;
	evio->ic_param = vnet;

	err = epf_virtio_init(evio, &epf_vnet_pci_header,
			      sizeof(vnet->vnet_cfg));
	if (err)
		goto err_cleanup_kiov;

	epf_vnet_setup_pci_cfgs(vnet, evio);

	err = epf_virtio_launch_bgtask(evio);
	if (err)
		goto err_virtio_final;

	return 0;

err_cleanup_kiov:
err_virtio_final:

	return err;
}

static void epf_vnet_cleanup_ep_func(struct epf_vnet *vnet)
{
}

enum {
	VNET_VIRTQUEUE_RX,
	VNET_VIRTQUEUE_TX,
	VNET_VIRTQUEUE_CTRL,
	VNET_VIRTQUEUE_RDMA_CQ1,
	VNET_VIRTQUEUE_RDMA_CQ2,
	VNET_VIRTQUEUE_RDMA_CQ3,
	VNET_VIRTQUEUE_RDMA_SQ0, // SGI
	VNET_VIRTQUEUE_RDMA_RQ0,
	VNET_VIRTQUEUE_RDMA_SQ1, // GSI
	VNET_VIRTQUEUE_RDMA_RQ1,
	VNET_VIRTQUEUE_RDMA_SQ2, // for user
	VNET_VIRTQUEUE_RDMA_RQ2,
};

struct epf_vnet_dma_done_param {
	struct epf_vnet *vnet;
	struct virtqueue *vq;
	struct vringh *kvrh;
	struct epf_virtio *evio;
	size_t total_len;
	int vq_index;
	u16 khead, ehead;
};

static void epf_vnet_dma_done(void *param)
{
	struct epf_vnet_dma_done_param *p = param;
	struct epf_vnet *vnet = p->vnet;

	vringh_complete_kern(p->kvrh, p->khead, p->total_len);
	epf_virtio_iov_complete(p->evio, p->vq_index, p->ehead, p->total_len);

	vring_interrupt(0, p->vq);
	queue_work(vnet->task_wq, &vnet->raise_irq_work);

	kfree(p);
}

static struct epf_vnet_dma_done_param *
epf_vnet_edma_create_cb_param(struct epf_vnet *vnet, size_t total_len,
			      struct vringh *vrh, struct epf_virtio *evio,
			      u16 khead, u16 ehead,
			      enum dma_transfer_direction dir)
{
	struct epf_vnet_dma_done_param *dma_done_param;
	unsigned local_vq_index, remote_vq_index;

	if (dir == DMA_MEM_TO_DEV) {
		local_vq_index = VNET_VIRTQUEUE_TX;
		remote_vq_index = VNET_VIRTQUEUE_RX;
	} else {
		local_vq_index = VNET_VIRTQUEUE_RX;
		remote_vq_index = VNET_VIRTQUEUE_TX;
	}

	dma_done_param = kmalloc(sizeof(*dma_done_param), GFP_KERNEL);
	if (!dma_done_param)
		return ERR_PTR(-ENOMEM);

	dma_done_param->vnet = vnet;
	dma_done_param->vq = vnet->vdev_vqs[local_vq_index];
	dma_done_param->total_len = total_len;
	dma_done_param->kvrh = vrh;
	dma_done_param->evio = evio;
	dma_done_param->vq_index = remote_vq_index;
	dma_done_param->khead = khead;
	dma_done_param->ehead = ehead;

	return dma_done_param;
}

static void epf_vnet_rx_handler(struct work_struct *work)
{
	struct epf_vnet *vnet = container_of(work, struct epf_vnet, rx_work);
	struct epf_virtio *evio = &vnet->evio;
	struct vringh *dvrh;
	struct vringh_kiov *siov, *diov;
	int ret;

	dvrh = &vnet->vdev_vrhs[VNET_VIRTQUEUE_RX];
	siov = &vnet->rdev_iovs[VNET_VIRTQUEUE_TX];
	diov = &vnet->vdev_iovs[VNET_VIRTQUEUE_RX];

	do {
		u16 shead, dhead;
		size_t total_len;
		struct epf_vnet_dma_done_param *dma_done_param;

		ret = epf_virtio_getdesc(evio, VNET_VIRTQUEUE_TX, siov, NULL,
					 &shead);
		if (ret <= 0)
			continue;

		ret = vringh_getdesc_kern(dvrh, NULL, diov, &dhead, GFP_KERNEL);
		if (ret <= 0) {
			epf_virtio_abandon(evio, VNET_VIRTQUEUE_TX, 1);
			continue;
		}

		total_len = vringh_kiov_length(siov);

		if (vnet->enable_edma) {
			dma_done_param = epf_vnet_edma_create_cb_param(
				vnet, total_len, dvrh, evio, dhead, shead,
				DMA_DEV_TO_MEM);
			if (IS_ERR(dma_done_param)) {
				pr_err("Failed to setup dma callback: %ld\n",
				       PTR_ERR(dma_done_param));
				return;
			}

			ret = epf_virtio_dma_kiov2kiov(vnet->rx_dma_chan, siov,
						       diov, epf_vnet_dma_done,
						       dma_done_param,
						       DMA_DEV_TO_MEM);
		} else {
			epf_virtio_memcpy_kiov2kiov(evio, siov, diov,
						    DMA_DEV_TO_MEM);

			epf_virtio_iov_complete(evio, VNET_VIRTQUEUE_TX, shead,
						total_len);
			vringh_complete_kern(dvrh, dhead, total_len);

			vring_interrupt(0, vnet->vdev_vqs[VNET_VIRTQUEUE_RX]);
		}
	} while (ret > 0);
}

static void epf_vnet_tx_handler(struct work_struct *work)
{
	struct epf_vnet *vnet = container_of(work, struct epf_vnet, tx_work);
	struct epf_virtio *evio = &vnet->evio;
	struct vringh *svrh;
	struct vringh_kiov *siov, *diov;
	struct epf_vnet_dma_done_param *dma_done_param;
	int ret;

	svrh = &vnet->vdev_vrhs[VNET_VIRTQUEUE_TX];
	siov = &vnet->vdev_iovs[VNET_VIRTQUEUE_TX];
	diov = &vnet->rdev_iovs[VNET_VIRTQUEUE_RX];

	do {
		u16 shead, dhead;
		size_t total_len;

		ret = vringh_getdesc_kern(svrh, siov, NULL, &shead, GFP_KERNEL);
		if (ret <= 0)
			continue;

		ret = epf_virtio_getdesc(evio, VNET_VIRTQUEUE_RX, NULL, diov,
					 &dhead);
		if (ret <= 0) {
			vringh_abandon_kern(svrh, 1);
			continue;
		}

		total_len = vringh_kiov_length(siov);

		if (vnet->enable_edma) {
			dma_done_param = epf_vnet_edma_create_cb_param(
				vnet, total_len, svrh, evio, shead, dhead,
				DMA_MEM_TO_DEV);
			if (IS_ERR(dma_done_param)) {
				pr_err("Failed to setup dma callback: %ld\n",
				       PTR_ERR(dma_done_param));
				return;
			}

			ret = epf_virtio_dma_kiov2kiov(vnet->tx_dma_chan, siov,
						       diov, epf_vnet_dma_done,
						       dma_done_param,
						       DMA_MEM_TO_DEV);
		} else {
			epf_virtio_memcpy_kiov2kiov(evio, siov, diov,
						    DMA_MEM_TO_DEV);

			epf_virtio_iov_complete(evio, VNET_VIRTQUEUE_RX, dhead,
						total_len);
			vringh_complete_kern(svrh, shead, total_len);

			vring_interrupt(0, vnet->vdev_vqs[VNET_VIRTQUEUE_TX]);
			queue_work(vnet->task_wq, &vnet->raise_irq_work);
		}
	} while (ret > 0);
}

static int epf_vnet_ep_handle_roce_query_device(struct epf_vnet *vnet,
						struct vringh_kiov *riov,
						struct vringh_kiov *wiov)
{
	struct virtio_rdma_ack_query_device *ack;
	struct epf_virtio *evio = &vnet->evio;
	struct pci_epf *epf = evio->epf;
	size_t len;
	phys_addr_t phys;

	len = wiov->iov[wiov->i].iov_len;
	ack = pci_epc_map_addr(epf->epc, epf->func_no, epf->vfunc_no,
			       (u64)wiov->iov[wiov->i].iov_base, &phys, len);
	if (IS_ERR(ack))
		return PTR_ERR(ack);

	memcpy_toio(ack, &vnet->rdma_attr, sizeof(vnet->rdma_attr));

	pci_epc_unmap_addr(epf->epc, epf->func_no, epf->vfunc_no, phys, ack,
			   len);

	return 0;
}

static int epf_vnet_ep_handle_roce_query_port(struct epf_vnet *vnet,
					      struct vringh_kiov *riov,
					      struct vringh_kiov *wiov)
{
	struct virtio_rdma_ack_query_port *ack;
	struct epf_virtio *evio = &vnet->evio;
	struct pci_epf *epf = evio->epf;
	size_t len;
	phys_addr_t phys;

	len = wiov->iov[wiov->i].iov_len;
	ack = pci_epc_map_addr(epf->epc, epf->func_no, epf->vfunc_no,
			       (u64)wiov->iov[wiov->i].iov_base, &phys, len);
	if (IS_ERR(ack))
		return PTR_ERR(ack);

	iowrite32(EPF_VNET_ROCE_GID_TBL_LEN, &ack->gid_tbl_len);
	//TODO remove magic number
	iowrite32(0x800000, &ack->max_msg_sz);

	pci_epc_unmap_addr(epf->epc, epf->func_no, epf->vfunc_no, phys, ack,
			   len);
	return 0;
}

static int epf_vnet_ep_handle_create_cq(struct epf_vnet *vnet,
					struct vringh_kiov *riov,
					struct vringh_kiov *wiov)
{
	struct virtio_rdma_cmd_create_cq *cmd;
	struct virtio_rdma_ack_create_cq *ack;
	struct epf_virtio *evio = &vnet->evio;
	struct pci_epf *epf = evio->epf;
	size_t clen, alen;
	int err = 0;
	phys_addr_t cphys, aphys;

	clen = riov->iov[riov->i].iov_len;
	cmd = pci_epc_map_addr(epf->epc, epf->func_no, epf->vfunc_no,
			       (u64)wiov->iov[riov->i].iov_base, &cphys, clen);
	if (IS_ERR(cmd))
		return PTR_ERR(cmd);

	alen = wiov->iov[wiov->i].iov_len;
	ack = pci_epc_map_addr(epf->epc, epf->func_no, epf->vfunc_no,
			       (u64)wiov->iov[wiov->i].iov_base, &aphys, alen);
	if (IS_ERR(ack)) {
		err = PTR_ERR(ack);
		goto unmap_cmd;
	}

	if (ioread32(&cmd->cqe) > virtio_queue_size) {
		err = -EINVAL;
		goto unmap_ack;
	}

	//TODO
	iowrite32(vnet->ep_ncq++, &ack->cqn);

unmap_ack:
	pci_epc_unmap_addr(epf->epc, epf->func_no, epf->vfunc_no, aphys, ack,
			   alen);
unmap_cmd:
	pci_epc_unmap_addr(epf->epc, epf->func_no, epf->vfunc_no, cphys, cmd,
			   clen);
	return err;
}

static int epf_vnet_ep_handle_destroy_cq(struct epf_vnet *vnet,
					 struct vringh_kiov *riov,
					 struct vringh_kiov *wiov)
{
	vnet->ep_ncq--;
	return 0;
}

static int epf_vnet_ep_handle_create_pd(struct epf_vnet *vnet,
					struct vringh_kiov *riov,
					struct vringh_kiov *wiov)
{
	struct virtio_rdma_ack_create_pd *ack;
	struct epf_virtio *evio = &vnet->evio;
	struct pci_epf *epf = evio->epf;
	size_t len;
	phys_addr_t phys;

	len = wiov->iov[wiov->i].iov_len;
	ack = pci_epc_map_addr(epf->epc, epf->func_no, epf->vfunc_no,
			       (u64)wiov->iov[wiov->i].iov_base, &phys, len);
	if (IS_ERR(ack))
		return PTR_ERR(ack);

	iowrite32(vnet->ep_npd++, &ack->pdn);

	pci_epc_unmap_addr(epf->epc, epf->func_no, epf->vfunc_no, phys, ack,
			   len);

	return 0;
}

static int epf_vnet_ep_handle_destroy_pd(struct epf_vnet *vnet,
					 struct vringh_kiov *riov,
					 struct vringh_kiov *wiov)
{
	vnet->ep_npd--;
	return 0;
}

static int epf_vnet_ep_handle_get_dma_mr(struct epf_vnet *vnet,
					 struct vringh_kiov *riov,
					 struct vringh_kiov *wiov)
{
	// 	struct virtio_rdma_cmd_get_dma_mr *cmd;
	struct virtio_rdma_ack_get_dma_mr *ack;
	struct epf_virtio *evio = &vnet->evio;
	struct pci_epf *epf = evio->epf;
	size_t len;
	phys_addr_t phys;

	len = wiov->iov[wiov->i].iov_len;
	ack = pci_epc_map_addr(epf->epc, epf->func_no, epf->vfunc_no,
			       (u64)wiov->iov[wiov->i].iov_base, &phys, len);
	if (IS_ERR(ack))
		return PTR_ERR(ack);

	iowrite32(vnet->ep_nmr++, &ack->mrn);

	pci_epc_unmap_addr(epf->epc, epf->func_no, epf->vfunc_no, phys, ack,
			   len);

	return 0;
}

static int epf_vnet_ep_handle_reg_user_mr(struct epf_vnet *vnet,
					  struct vringh_kiov *riov,
					  struct vringh_kiov *wiov)
{
	// 	struct virtio_rdma_cmd_reg_user_mr *cmd;
	struct virtio_rdma_ack_reg_user_mr *ack;
	struct epf_virtio *evio = &vnet->evio;
	struct pci_epf *epf = evio->epf;
	size_t len;
	phys_addr_t phys;

	len = wiov->iov[wiov->i].iov_len;
	ack = pci_epc_map_addr(epf->epc, epf->func_no, epf->vfunc_no,
			       (u64)wiov->iov[wiov->i].iov_base, &phys, len);
	if (IS_ERR(ack))
		return PTR_ERR(ack);

	iowrite32(vnet->ep_nmr++, &ack->mrn);

	pci_epc_unmap_addr(epf->epc, epf->func_no, epf->vfunc_no, phys, ack,
			   len);
	return 0;
}

static int epf_vnet_ep_handle_dereg_mr(struct epf_vnet *vnet,
				       struct vringh_kiov *riov,
				       struct vringh_kiov *wiov)
{
	vnet->ep_nmr--;
	return 0;
}

static int epf_vnet_ep_handle_create_qp(struct epf_vnet *vnet,
					struct vringh_kiov *riov,
					struct vringh_kiov *wiov)
{
	// 	struct virtio_rdma_cmd_create_qp *cmd;
	struct virtio_rdma_ack_create_qp *ack;
	struct epf_virtio *evio = &vnet->evio;
	struct pci_epf *epf = evio->epf;
	size_t len;
	phys_addr_t phys;

	len = wiov->iov[wiov->i].iov_len;
	ack = pci_epc_map_addr(epf->epc, epf->func_no, epf->vfunc_no,
			       (u64)wiov->iov[wiov->i].iov_base, &phys, len);
	if (IS_ERR(ack))
		return PTR_ERR(ack);

	iowrite32(vnet->ep_nqp++, ack);

	pci_epc_unmap_addr(epf->epc, epf->func_no, epf->vfunc_no, phys, ack,
			   len);
	return 0;
}

static int epf_vnet_ep_handle_modify_qp(struct epf_vnet *vnet,
					struct vringh_kiov *riov,
					struct vringh_kiov *wiov)
{
	// 	struct virtio_rdma_cmd_modify_qp *cmd;
	return 0;
}

static int epf_vnet_ep_handle_query_qp(struct epf_vnet *vnet,
				       struct vringh_kiov *riov,
				       struct vringh_kiov *wiov)
{
	// 	struct virtio_rdma_cmd_query_qp *cmd;
	// 	struct virtio_rdma_ack_query_qp *ack;
	return 0;
}

static int epf_vnet_ep_handle_destroy_qp(struct epf_vnet *vnet,
					 struct vringh_kiov *riov,
					 struct vringh_kiov *wiov)
{
	vnet->ep_nqp--;
	return 0;
}

static int epf_vnet_ep_handle_create_ah(struct epf_vnet *vnet,
					struct vringh_kiov *riov,
					struct vringh_kiov *wiov)
{
	struct virtio_rdma_cmd_create_ah *cmd;
	struct virtio_rdma_ack_create_ah *ack;
	struct epf_virtio *evio = &vnet->evio;
	struct pci_epf *epf = evio->epf;
	size_t clen, alen;
	int err = 0;
	phys_addr_t cphys, aphys;

	clen = riov->iov[riov->i].iov_len;
	cmd = pci_epc_map_addr(epf->epc, epf->func_no, epf->vfunc_no,
			       (u64)wiov->iov[riov->i].iov_base, &cphys, clen);
	if (IS_ERR(cmd))
		return PTR_ERR(cmd);

	alen = wiov->iov[wiov->i].iov_len;
	ack = pci_epc_map_addr(epf->epc, epf->func_no, epf->vfunc_no,
			       (u64)wiov->iov[wiov->i].iov_base, &aphys, alen);
	if (IS_ERR(ack)) {
		err = PTR_ERR(ack);
		goto unmap_cmd;
	}

	iowrite32(vnet->ep_nah++, &ack->ah);

	pci_epc_unmap_addr(epf->epc, epf->func_no, epf->vfunc_no, aphys, ack,
			   alen);
unmap_cmd:
	pci_epc_unmap_addr(epf->epc, epf->func_no, epf->vfunc_no, cphys, cmd,
			   clen);

	return err;
}

static int epf_vnet_ep_handle_destroy_ah(struct epf_vnet *vnet,
					 struct vringh_kiov *riov,
					 struct vringh_kiov *wiov)
{
	vnet->ep_nah--;
	return 0;
}

static int epf_vnet_ep_handle_roce_add_gid(struct epf_vnet *vnet,
					   struct vringh_kiov *riov,
					   struct vringh_kiov *wiov)
{
	struct virtio_rdma_cmd_add_gid __iomem *cmd;
	struct epf_virtio *evio = &vnet->evio;
	struct pci_epf *epf = evio->epf;
	size_t len;
	phys_addr_t phys;
	u16 index;

	len = riov->iov[riov->i].iov_len;
	cmd = pci_epc_map_addr(epf->epc, epf->func_no, epf->vfunc_no,
			       (u64)riov->iov[riov->i].iov_base, &phys, len);
	if (IS_ERR(cmd))
		return PTR_ERR(cmd);

	index = ioread16(&cmd->index);

	memcpy_fromio(&vnet->ep_roce_gid_tbl[index], cmd->gid,
		      sizeof(cmd->gid));

	pci_epc_unmap_addr(epf->epc, epf->func_no, epf->vfunc_no, phys, cmd,
			   len);

	return 0;
}

static int epf_vnet_ep_handle_roce_del_gid(struct epf_vnet *vnet,
					   struct vringh_kiov *riov,
					   struct vringh_kiov *wiov)
{
	struct virtio_rdma_cmd_del_gid *cmd;
	struct epf_virtio *evio = &vnet->evio;
	struct pci_epf *epf = evio->epf;
	size_t len;
	phys_addr_t phys;
	u16 index;

	len = riov->iov[riov->i].iov_len;
	cmd = pci_epc_map_addr(epf->epc, epf->func_no, epf->vfunc_no,
			       (u64)riov->iov[riov->i].iov_base, &phys, len);
	if (IS_ERR(cmd))
		return PTR_ERR(cmd);

	index = ioread16(&cmd->index);

	pci_epc_unmap_addr(epf->epc, epf->func_no, epf->vfunc_no, phys, cmd,
			   len);

	return 0;
}

static int epf_vnet_ep_handle_roce_req_notify_cq(struct epf_vnet *vnet,
						 struct vringh_kiov *riov,
						 struct vringh_kiov *wiov)
{
	// 	struct virtio_rdma_cmd_req_notify *cmd;

	return 0;
}

static int (*virtio_rdma_ep_cmd_handler[])(struct epf_vnet *vnet,
					   struct vringh_kiov *riov,
					   struct vringh_kiov *wiov) = {
	[VIRTIO_NET_CTRL_ROCE_QUERY_DEVICE] =
		epf_vnet_ep_handle_roce_query_device,
	[VIRTIO_NET_CTRL_ROCE_QUERY_PORT] = epf_vnet_ep_handle_roce_query_port,
	[VIRTIO_NET_CTRL_ROCE_CREATE_CQ] = epf_vnet_ep_handle_create_cq,
	[VIRTIO_NET_CTRL_ROCE_DESTROY_CQ] = epf_vnet_ep_handle_destroy_cq,
	[VIRTIO_NET_CTRL_ROCE_CREATE_PD] = epf_vnet_ep_handle_create_pd,
	[VIRTIO_NET_CTRL_ROCE_DESTROY_PD] = epf_vnet_ep_handle_destroy_pd,
	[VIRTIO_NET_CTRL_ROCE_GET_DMA_MR] = epf_vnet_ep_handle_get_dma_mr,
	[VIRTIO_NET_CTRL_ROCE_REG_USER_MR] = epf_vnet_ep_handle_reg_user_mr,
	[VIRTIO_NET_CTRL_ROCE_DEREG_MR] = epf_vnet_ep_handle_dereg_mr,
	[VIRTIO_NET_CTRL_ROCE_CREATE_QP] = epf_vnet_ep_handle_create_qp,
	[VIRTIO_NET_CTRL_ROCE_MODIFY_QP] = epf_vnet_ep_handle_modify_qp,
	[VIRTIO_NET_CTRL_ROCE_QUERY_QP] = epf_vnet_ep_handle_query_qp,
	[VIRTIO_NET_CTRL_ROCE_DESTROY_QP] = epf_vnet_ep_handle_destroy_qp,
	[VIRTIO_NET_CTRL_ROCE_CREATE_AH] = epf_vnet_ep_handle_create_ah,
	[VIRTIO_NET_CTRL_ROCE_DESTROY_AH] = epf_vnet_ep_handle_destroy_ah,
	[VIRTIO_NET_CTRL_ROCE_ADD_GID] = epf_vnet_ep_handle_roce_add_gid,
	[VIRTIO_NET_CTRL_ROCE_DEL_GID] = epf_vnet_ep_handle_roce_del_gid,
	[VIRTIO_NET_CTRL_ROCE_REQ_NOTIFY_CQ] =
		epf_vnet_ep_handle_roce_req_notify_cq,
};

static void epf_vnet_ep_ctrl_handler(struct work_struct *work)
{
	struct epf_vnet *vnet =
		container_of(work, struct epf_vnet, ep_ctrl_work);
	struct epf_virtio *evio = &vnet->evio;
	struct vringh_kiov riov, wiov;
	struct vringh *vrh = &evio->vrhs[VNET_VIRTQUEUE_CTRL]->vrh;
	struct pci_epf *epf = evio->epf;
	struct virtio_net_ctrl_hdr *hdr;
	int err;
	u16 head;
	size_t total_len, rlen, wlen;
	u8 class, cmd;
	void __iomem *rvirt, *wvirt;
	phys_addr_t rphys, wphys;
	virtio_net_ctrl_ack __iomem *ack;

	vringh_kiov_init(&riov, NULL, 0);
	vringh_kiov_init(&wiov, NULL, 0);

	err = vringh_getdesc_iomem(vrh, &riov, &wiov, &head, GFP_KERNEL);
	if (err <= 0)
		return;

	total_len = vringh_kiov_length(&riov);

	rlen = riov.iov[riov.i].iov_len;
	rvirt = pci_epc_map_addr(epf->epc, epf->func_no, epf->vfunc_no,
				 (u64)riov.iov[riov.i].iov_base, &rphys, rlen);
	if (IS_ERR(rvirt)) {
		err = PTR_ERR(rvirt);
		goto err_out;
	}

	wlen = wiov.iov[wiov.i].iov_len;
	wvirt = pci_epc_map_addr(epf->epc, epf->func_no, epf->vfunc_no,
				 (u64)wiov.iov[wiov.i].iov_base, &wphys, wlen);
	if (IS_ERR(wvirt)) {
		err = PTR_ERR(wvirt);
		goto err_unmap_command;
	}
	ack = wvirt;

	riov.i++;
	wiov.i++;

	hdr = rvirt;
	class = ioread8(&hdr->class);
	cmd = ioread8(&hdr->cmd);
	switch (class) {
	case VIRTIO_NET_CTRL_ANNOUNCE:
		if (cmd != VIRTIO_NET_CTRL_ANNOUNCE_ACK) {
			pr_err("Found invalid command: announce: %d\n", cmd);
			break;
		}
		epf_virtio_cfg_clear16(
			evio,
			VIRTIO_PCI_CONFIG_OFF(false) +
				offsetof(struct virtio_net_config, status),
			VIRTIO_NET_S_ANNOUNCE);
		epf_virtio_cfg_clear16(evio, VIRTIO_PCI_ISR,
				       VIRTIO_PCI_ISR_CONFIG);

		iowrite8(VIRTIO_NET_OK, ack);
		break;
	case VIRTIO_NET_CTRL_ROCE:
		if (ARRAY_SIZE(virtio_rdma_ep_cmd_handler) < hdr->cmd) {
			err = -EIO;
			pr_debug("found invalid command\n");
			break;
		}
		// TODO this is for debug, finally should be deleted.
		if (!virtio_rdma_ep_cmd_handler[hdr->cmd]) {
			pr_info("A handler for cmd %d is not yet implemented\n",
				hdr->cmd);
			err = -ENOTSUPP;
			iowrite8(VIRTIO_NET_ERR, ack);
			break;
		}

		err = virtio_rdma_ep_cmd_handler[hdr->cmd](vnet, &riov, &wiov);
		iowrite8(err ? VIRTIO_NET_ERR : VIRTIO_NET_OK, ack);
		break;
	default:
		pr_err("Found unsupported class in control queue: %d\n", class);
		break;
	}

	vringh_complete_iomem(vrh, head, total_len);
	pci_epc_unmap_addr(epf->epc, epf->func_no, epf->vfunc_no, rphys, rvirt,
			   rlen);
	pci_epc_unmap_addr(epf->epc, epf->func_no, epf->vfunc_no, wphys, wvirt,
			   wlen);

	vringh_kiov_cleanup(&riov);
	vringh_kiov_cleanup(&wiov);

	return;

err_unmap_command:
	pci_epc_unmap_addr(epf->epc, epf->func_no, epf->vfunc_no, rphys, rvirt,
			   rlen);
err_out:
	return;
}

static void epf_vnet_vdev_cfg_set_status(struct epf_vnet *vnet, u16 status)
{
	vnet->vdev_vnet_cfg.status |= status;
}

static void epf_vnet_vdev_cfg_clear_status(struct epf_vnet *vnet, u16 status)
{
	vnet->vdev_vnet_cfg.status &= ~status;
}

static void epf_vnet_vdev_announce_linkup(struct epf_vnet *vnet)
{
	epf_vnet_vdev_cfg_set_status(vnet, VIRTIO_NET_S_LINK_UP |
						   VIRTIO_NET_S_ANNOUNCE);
	virtio_config_changed(&vnet->vdev);
}

static int epf_vnet_vdev_handle_roce_query_device(struct epf_vnet *vnet,
						  struct vringh_kiov *riov,
						  struct vringh_kiov *wiov)
{
	struct virtio_rdma_ack_query_device *ack;

	ack = phys_to_virt((unsigned long)wiov->iov[wiov->i].iov_base);

	memcpy(ack, &vnet->rdma_attr, sizeof(vnet->rdma_attr));

	return 0;
}

static int epf_vnet_vdev_handle_roce_query_port(struct epf_vnet *vnet,
						struct vringh_kiov *riov,
						struct vringh_kiov *wiov)
{
	struct virtio_rdma_ack_query_port *ack;

	ack = phys_to_virt((unsigned long)wiov->iov[wiov->i].iov_base);
	ack->gid_tbl_len = EPF_VNET_ROCE_GID_TBL_LEN;
	ack->max_msg_sz = 0x800000;

	return 0;
}

static int epf_vnet_vdev_handle_roce_create_cq(struct epf_vnet *vnet,
					       struct vringh_kiov *riov,
					       struct vringh_kiov *wiov)
{
	struct virtio_rdma_cmd_create_cq *cmd;
	struct virtio_rdma_ack_create_cq *ack;

	cmd = phys_to_virt((unsigned long)riov->iov[riov->i].iov_base);

	pr_info("%s create cq: cqe %d\n", __func__, cmd->cqe);
	if (cmd->cqe > virtio_queue_size)
		return 1;

	ack = phys_to_virt((unsigned long)wiov->iov[wiov->i].iov_base);
	ack->cqn = vnet->ncq++;

	return 0;
}

static int epf_vnet_vdev_handle_roce_destroy_cq(struct epf_vnet *vnet,
						struct vringh_kiov *riov,
						struct vringh_kiov *wiov)
{
	vnet->ncq--;
	return 0;
}

static int epf_vnet_rdma_init_pd(struct epf_vnet_rdma_pd *pd)
{
	return 0;
}

static struct epf_vnet_rdma_pd *epf_vnet_vdev_alloc_pd(struct epf_vnet *vnet)
{
	struct epf_vnet_rdma_pd *pd;

	for (int i = 0; i < EPF_VNET_RDMA_MAX_PD; i++) {
		if (vnet->pds[i])
			continue;

		pd = kmem_cache_alloc(vnet->pd_slab, GFP_KERNEL);

		vnet->pds[i] = pd;
		pd->pdn = i;

		return pd;
	}

	return NULL;
}

static int epf_vnet_vdev_dealloc_pd(struct epf_vnet *vnet, int pdi)
{
	if (pdi >= EPF_VNET_RDMA_MAX_PD)
		return -EINVAL;

	if (!vnet->pds[pdi])
		return -EINVAL;

	kmem_cache_free(vnet->pd_slab, vnet->pds[pdi]);
	vnet->pds[pdi] = NULL;

	return 0;
}

static struct epf_vnet_rdma_pd *epf_vnet_rdma_lookup_pd(struct epf_vnet *vnet,
							int index)
{
	return index < EPF_VNET_RDMA_MAX_PD ? vnet->pds[index] : NULL;
}

static struct epf_vnet_rdma_mr *epf_vnet_rdma_alloc_mr(struct epf_vnet *vnet)
{
	struct epf_vnet_rdma_mr *mr;

	for (int i = 0; i < EPF_VNET_RDMA_MAX_MR; i++) {
		if (vnet->mrs[i])
			continue;

		mr = kmem_cache_alloc(vnet->mr_slab, GFP_KERNEL);

		mr->mrn = i;
		vnet->mrs[i] = mr;

		return mr;
	}

	return NULL;
}

static int epf_vnet_rdma_dealloc_mr(struct epf_vnet *vnet, int index)
{
	if (index >= EPF_VNET_RDMA_MAX_MR)
		return -EINVAL;

	if (!vnet->mrs[index])
		return -EINVAL;

	kmem_cache_free(vnet->mr_slab, vnet->mrs[index]);

	vnet->mrs[index] = NULL;

	return 0;
}

static struct epf_vnet_rdma_mr *epf_vnet_rdma_lookup_mr(struct epf_vnet *vnet,
							int index)
{
	return index < EPF_VNET_RDMA_MAX_MR ? vnet->mrs[index] : NULL;
}

static int epf_vnet_vdev_handle_roce_create_pd(struct epf_vnet *vnet,
					       struct vringh_kiov *riov,
					       struct vringh_kiov *wiov)
{
	struct virtio_rdma_ack_create_pd *ack;
	struct epf_vnet_rdma_pd *pd;

	ack = phys_to_virt((unsigned long)wiov->iov[wiov->i].iov_base);

	pd = epf_vnet_vdev_alloc_pd(vnet);
	if (!pd)
		return -ENOMEM;

	epf_vnet_rdma_init_pd(pd);

	ack->pdn = pd->pdn;

	return 0;
}

static int epf_vnet_vdev_handle_roce_destroy_pd(struct epf_vnet *vnet,
						struct vringh_kiov *riov,
						struct vringh_kiov *wiov)
{
	struct virtio_rdma_cmd_destroy_pd *cmd;

	cmd = phys_to_virt((unsigned long)riov->iov[riov->i].iov_base);

	return epf_vnet_vdev_dealloc_pd(vnet, cmd->pdn);
}

static int epf_vnet_vdev_handle_roce_dma_mr(struct epf_vnet *vnet,
					    struct vringh_kiov *riov,
					    struct vringh_kiov *wiov)
{
	// 	struct virtio_rdma_cmd_get_dma_mr *cmd;
	struct virtio_rdma_ack_get_dma_mr *ack;
	struct epf_vnet_rdma_mr *mr;

	ack = phys_to_virt((unsigned long)wiov->iov[wiov->i].iov_base);

	mr = epf_vnet_rdma_alloc_mr(vnet);
	if (!mr)
		return -EINVAL;

	ack->lkey = mr->mrn;
	ack->rkey = mr->mrn;
	ack->mrn = mr->mrn;

	return 0;
}

static int epf_vnet_vdev_handle_roce_reg_user_mr(struct epf_vnet *vnet,
						 struct vringh_kiov *riov,
						 struct vringh_kiov *wiov)
{
	struct virtio_rdma_cmd_reg_user_mr *cmd;
	struct virtio_rdma_ack_reg_user_mr *ack;
	struct epf_vnet_rdma_pd *pd;
	struct epf_vnet_rdma_mr *mr;

	cmd = phys_to_virt((unsigned long)riov->iov[riov->i].iov_base);

	pr_info("%s: pdn: %d, aflag %x, addr 0x%llx, size 0x%llx, npages %d\n",
		__func__, cmd->pdn, cmd->access_flags, cmd->virt_addr,
		cmd->length, cmd->npages);

	pd = epf_vnet_rdma_lookup_pd(vnet, cmd->pdn);
	if (!pd)
		return -EINVAL;

	mr = epf_vnet_rdma_alloc_mr(vnet);
	if (!mr)
		return -EINVAL;

	ack = phys_to_virt((unsigned long)wiov->iov[wiov->i].iov_base);

	if (cmd->access_flags & VIRTIO_IB_ACCESS_LOCAL_WRITE) {
		ack->lkey = mr->mrn;
	}

	if (cmd->access_flags & VIRTIO_IB_ACCESS_REMOTE_WRITE) {
		ack->rkey = mr->mrn;
	}

	if (cmd->access_flags & VIRTIO_IB_ACCESS_REMOTE_READ) {
		ack->rkey = mr->mrn;
	}

	mr->virt_addr = cmd->virt_addr;
	mr->length = cmd->length;
	mr->npages = cmd->npages;
	mr->pages =
		kmalloc_array(cmd->npages, sizeof(mr->pages[0]), GFP_KERNEL);

	memcpy(mr->pages, cmd->pages, sizeof(mr->pages[0]) * mr->npages);
	for (int i = 0; i < mr->npages; i++)
		pr_info("reg_user_mr: page[%d] 0x%llx\n", i, cmd->pages[i]);

	ack->mrn = mr->mrn;

	return 0;
}

static int epf_vnet_vdev_handle_roce_dereg_mr(struct epf_vnet *vnet,
					      struct vringh_kiov *riov,
					      struct vringh_kiov *wiov)
{
	struct virtio_rdma_cmd_dereg_mr *cmd;

	cmd = phys_to_virt((unsigned long)riov->iov[riov->i].iov_base);

	epf_vnet_rdma_dealloc_mr(vnet, cmd->mrn);

	return 0;
}

static int epf_vnet_vdev_handle_roce_create_qp(struct epf_vnet *vnet,
					       struct vringh_kiov *riov,
					       struct vringh_kiov *wiov)
{
	struct virtio_rdma_cmd_create_qp *cmd;
	struct virtio_rdma_ack_create_qp *ack;

	cmd = phys_to_virt((unsigned long)riov->iov[riov->i].iov_base);

	pr_info("%s: create qp: pdn %d\n", __func__, cmd->pdn);

	ack = phys_to_virt((unsigned long)wiov->iov[wiov->i].iov_base);

	switch (cmd->qp_type) {
	case VIRTIO_IB_QPT_GSI:
		ack->qpn = 1;
		break;
	case VIRTIO_IB_QPT_UD:
		ack->qpn = 2 + vnet->nqp++;
		break;
	default:
		return -ENOTSUPP;
	}

	return 0;
}

static int epf_vnet_vdev_handle_roce_modify_qp(struct epf_vnet *vnet,
					       struct vringh_kiov *riov,
					       struct vringh_kiov *wiov)
{
	struct virtio_rdma_cmd_modify_qp *cmd;

	cmd = phys_to_virt((unsigned long)riov->iov[riov->i].iov_base);

	pr_info("%s: modify qp: qpn %d, mask %x\n", __func__, cmd->qpn,
		cmd->attr_mask);

	if (cmd->attr_mask & VIRTIO_IB_QP_STATE) {
		pr_info("change qp state: %x -> %x\n", cmd->cur_qp_state,
			cmd->qp_state);
	}

	if (cmd->attr_mask & VIRTIO_IB_QP_CUR_STATE) {
		goto err_out;
	}

	if (cmd->attr_mask & VIRTIO_IB_QP_ACCESS_FLAGS) {
		goto err_out;
	}

	if (cmd->attr_mask & VIRTIO_IB_QP_QKEY) {
		pr_info("set queue key 0x%x\n", cmd->qkey);
	}

	if (cmd->attr_mask & VIRTIO_IB_QP_AV) {
		goto err_out;
	}

	if (cmd->attr_mask & VIRTIO_IB_QP_PATH_MTU) {
		goto err_out;
	}

	if (cmd->attr_mask & VIRTIO_IB_QP_TIMEOUT) {
		goto err_out;
	}

	if (cmd->attr_mask & VIRTIO_IB_QP_RETRY_CNT) {
		goto err_out;
	}

	if (cmd->attr_mask & VIRTIO_IB_QP_RNR_RETRY) {
		goto err_out;
	}

	if (cmd->attr_mask & VIRTIO_IB_QP_RQ_PSN) {
		goto err_out;
	}

	if (cmd->attr_mask & VIRTIO_IB_QP_MAX_QP_RD_ATOMIC) {
		goto err_out;
	}

	if (cmd->attr_mask & VIRTIO_IB_QP_MIN_RNR_TIMER) {
		goto err_out;
	}

	if (cmd->attr_mask & VIRTIO_IB_QP_SQ_PSN) {
		pr_info("set psn for sq: %d\n", cmd->sq_psn);
	}

	if (cmd->attr_mask & VIRTIO_IB_QP_MAX_DEST_RD_ATOMIC) {
		goto err_out;
	}

	if (cmd->attr_mask & VIRTIO_IB_QP_CAP) {
		goto err_out;
	}

	if (cmd->attr_mask & VIRTIO_IB_QP_DEST_QPN) {
		goto err_out;
	}

	if (cmd->attr_mask & VIRTIO_IB_QP_RATE_LIMIT) {
		goto err_out;
	}

	return 0;

err_out:
	return 1;
}

static int epf_vnet_vdev_handle_roce_query_qp(struct epf_vnet *vnet,
					      struct vringh_kiov *riov,
					      struct vringh_kiov *wiov)
{
	struct virtio_rdma_cmd_query_qp *cmd;
	struct virtio_rdma_ack_query_qp *ack;

	cmd = phys_to_virt((unsigned long)riov->iov[riov->i].iov_base);

	pr_info("query qp: qpn %d, mask %x\n", cmd->qpn, cmd->attr_mask);

	ack = phys_to_virt((unsigned long)wiov->iov[wiov->i].iov_base);

	if (cmd->attr_mask & VIRTIO_IB_QP_STATE) {
		pr_info("not yet implemented 0x%x", VIRTIO_IB_QP_STATE);
		goto err_out;
	}

	if (cmd->attr_mask & VIRTIO_IB_QP_CUR_STATE) {
		pr_info("not yet implemented 0x%x", VIRTIO_IB_QP_CUR_STATE);
		goto err_out;
	}

	if (cmd->attr_mask & VIRTIO_IB_QP_ACCESS_FLAGS) {
		pr_info("not yet implemented 0x%x", VIRTIO_IB_QP_ACCESS_FLAGS);
		goto err_out;
	}

	if (cmd->attr_mask & VIRTIO_IB_QP_QKEY) {
		pr_info("not yet implemented 0x%x", VIRTIO_IB_QP_QKEY);
		goto err_out;
	}

	if (cmd->attr_mask & VIRTIO_IB_QP_AV) {
		pr_info("not yet implemented 0x%x", VIRTIO_IB_QP_AV);
		goto err_out;
	}

	if (cmd->attr_mask & VIRTIO_IB_QP_PATH_MTU) {
		pr_info("not yet implemented 0x%x", VIRTIO_IB_QP_PATH_MTU);
		goto err_out;
	}

	if (cmd->attr_mask & VIRTIO_IB_QP_TIMEOUT) {
		pr_info("not yet implemented 0x%x", VIRTIO_IB_QP_TIMEOUT);
		goto err_out;
	}

	if (cmd->attr_mask & VIRTIO_IB_QP_RETRY_CNT) {
		pr_info("not yet implemented 0x%x", VIRTIO_IB_QP_RETRY_CNT);
		goto err_out;
	}

	if (cmd->attr_mask & VIRTIO_IB_QP_RNR_RETRY) {
		pr_info("not yet implemented 0x%x", VIRTIO_IB_QP_RNR_RETRY);
		goto err_out;
	}

	if (cmd->attr_mask & VIRTIO_IB_QP_RQ_PSN) {
		pr_info("not yet implemented 0x%x", VIRTIO_IB_QP_RQ_PSN);
		goto err_out;
	}

	if (cmd->attr_mask & VIRTIO_IB_QP_MAX_QP_RD_ATOMIC) {
		pr_info("not yet implemented 0x%x",
			VIRTIO_IB_QP_MAX_QP_RD_ATOMIC);
		goto err_out;
	}

	if (cmd->attr_mask & VIRTIO_IB_QP_MIN_RNR_TIMER) {
		pr_info("not yet implemented 0x%x", VIRTIO_IB_QP_MIN_RNR_TIMER);
		goto err_out;
	}

	if (cmd->attr_mask & VIRTIO_IB_QP_SQ_PSN) {
		pr_info("not yet implemented 0x%x", VIRTIO_IB_QP_SQ_PSN);
		goto err_out;
	}

	if (cmd->attr_mask & VIRTIO_IB_QP_MAX_DEST_RD_ATOMIC) {
		pr_info("not yet implemented 0x%x",
			VIRTIO_IB_QP_MAX_DEST_RD_ATOMIC);
		goto err_out;
	}

	if (cmd->attr_mask & VIRTIO_IB_QP_CAP) {
		pr_info("qp cap 0x%x\n", VIRTIO_IB_QP_CAP);
		// TODO these are temporary and should be updated.
		ack->cap.max_send_wr = 100;
		ack->cap.max_send_sge = 32;
		ack->cap.max_inline_data = 32 * sizeof(struct virtio_rdma_sge);
		ack->cap.max_recv_wr = 100;
		ack->cap.max_recv_sge = 32;
	}

	if (cmd->attr_mask & VIRTIO_IB_QP_DEST_QPN) {
		pr_info("not yet implemented 0x%x", VIRTIO_IB_QP_DEST_QPN);
		goto err_out;
	}

	if (cmd->attr_mask & VIRTIO_IB_QP_RATE_LIMIT) {
		pr_info("not yet implemented 0x%x", VIRTIO_IB_QP_RATE_LIMIT);
		goto err_out;
	}

	return 0;

err_out:
	return 1;
}

static int epf_vnet_vdev_handle_roce_destroy_qp(struct epf_vnet *vnet,
						struct vringh_kiov *riov,
						struct vringh_kiov *wiov)
{
	vnet->nqp--;
	return 0;
}

static int epf_vnet_vdev_handle_roce_create_ah(struct epf_vnet *vnet,
					       struct vringh_kiov *riov,
					       struct vringh_kiov *wiov)
{
	struct virtio_rdma_cmd_create_ah *cmd;
	struct virtio_rdma_ack_create_ah *ack;

	cmd = phys_to_virt((unsigned long)riov->iov[riov->i].iov_base);

	ack = phys_to_virt((unsigned long)wiov->iov[wiov->i].iov_base);

	ack->ah = vnet->nah++;

	return 0;
}

static int epf_vnet_vdev_handle_roce_destroy_ah(struct epf_vnet *vnet,
						struct vringh_kiov *riov,
						struct vringh_kiov *wiov)
{
	vnet->nah--;
	return 0;
}

static int epf_vnet_vdev_handle_roce_add_gid(struct epf_vnet *vnet,
					     struct vringh_kiov *riov,
					     struct vringh_kiov *wiov)
{
	struct virtio_rdma_cmd_add_gid *cmd;

	cmd = phys_to_virt((unsigned long)riov->iov[riov->i].iov_base);
	if (cmd->index >= EPF_VNET_ROCE_GID_TBL_LEN)
		return -EINVAL;

	memcpy(vnet->vdev_roce_gid_tbl[cmd->index].raw, cmd->gid,
	       sizeof(cmd->gid));

	return 0;
}

static int epf_vnet_vdev_handle_roce_del_gid(struct epf_vnet *vnet,
					     struct vringh_kiov *riov,
					     struct vringh_kiov *wiov)
{
	return 0;
}

static int epf_vnet_vdev_handle_roce_notify_cq(struct epf_vnet *vnet,
					       struct vringh_kiov *riov,
					       struct vringh_kiov *wiov)
{
	return 0;
}

static int (*virtio_rdma_vdev_cmd_handler[])(struct epf_vnet *vnet,
					     struct vringh_kiov *riov,
					     struct vringh_kiov *wiov) = {
	[VIRTIO_NET_CTRL_ROCE_QUERY_DEVICE] =
		epf_vnet_vdev_handle_roce_query_device,
	[VIRTIO_NET_CTRL_ROCE_QUERY_PORT] = epf_vnet_vdev_handle_roce_query_port,
	[VIRTIO_NET_CTRL_ROCE_CREATE_CQ] = epf_vnet_vdev_handle_roce_create_cq,
	[VIRTIO_NET_CTRL_ROCE_DESTROY_CQ] = epf_vnet_vdev_handle_roce_destroy_cq,
	[VIRTIO_NET_CTRL_ROCE_CREATE_PD] = epf_vnet_vdev_handle_roce_create_pd,
	[VIRTIO_NET_CTRL_ROCE_DESTROY_PD] = epf_vnet_vdev_handle_roce_destroy_pd,
	[VIRTIO_NET_CTRL_ROCE_GET_DMA_MR] = epf_vnet_vdev_handle_roce_dma_mr,
	[VIRTIO_NET_CTRL_ROCE_REG_USER_MR] =
		epf_vnet_vdev_handle_roce_reg_user_mr,
	[VIRTIO_NET_CTRL_ROCE_DEREG_MR] = epf_vnet_vdev_handle_roce_dereg_mr,
	[VIRTIO_NET_CTRL_ROCE_CREATE_QP] = epf_vnet_vdev_handle_roce_create_qp,
	[VIRTIO_NET_CTRL_ROCE_MODIFY_QP] = epf_vnet_vdev_handle_roce_modify_qp,
	[VIRTIO_NET_CTRL_ROCE_QUERY_QP] = epf_vnet_vdev_handle_roce_query_qp,
	[VIRTIO_NET_CTRL_ROCE_DESTROY_QP] = epf_vnet_vdev_handle_roce_destroy_qp,
	[VIRTIO_NET_CTRL_ROCE_CREATE_AH] = epf_vnet_vdev_handle_roce_create_ah,
	[VIRTIO_NET_CTRL_ROCE_DESTROY_AH] = epf_vnet_vdev_handle_roce_destroy_ah,
	[VIRTIO_NET_CTRL_ROCE_ADD_GID] = epf_vnet_vdev_handle_roce_add_gid,
	[VIRTIO_NET_CTRL_ROCE_DEL_GID] = epf_vnet_vdev_handle_roce_del_gid,
	[VIRTIO_NET_CTRL_ROCE_REQ_NOTIFY_CQ] =
		epf_vnet_vdev_handle_roce_notify_cq,
};

static void epf_vnet_vdev_ctrl_handler(struct work_struct *work)
{
	struct epf_vnet *vnet =
		container_of(work, struct epf_vnet, vdev_ctrl_work);

	struct vringh *vrh = &vnet->vdev_vrhs[VNET_VIRTQUEUE_CTRL];
	struct vringh_kiov riov, wiov;
	struct virtio_net_ctrl_hdr *hdr;
	virtio_net_ctrl_ack *ack;
	int err;
	u16 head;
	size_t len;

	vringh_kiov_init(&riov, NULL, 0);
	vringh_kiov_init(&wiov, NULL, 0);

	err = vringh_getdesc_kern(vrh, &riov, &wiov, &head, GFP_KERNEL);
	if (err <= 0)
		goto done;

	len = vringh_kiov_length(&riov);
	if (len < sizeof(*hdr)) {
		pr_debug("Command is too short: %ld\n", len);
		err = -EIO;
		goto done;
	}

	if (vringh_kiov_length(&wiov) < sizeof(*ack)) {
		pr_debug("Space for ack is not enough\n");
		err = -EIO;
		goto done;
	}

	hdr = phys_to_virt((unsigned long)riov.iov[riov.i].iov_base);
	ack = phys_to_virt((unsigned long)wiov.iov[wiov.i].iov_base);

	riov.i++;
	wiov.i++;

	switch (hdr->class) {
	case VIRTIO_NET_CTRL_ANNOUNCE:
		if (hdr->cmd != VIRTIO_NET_CTRL_ANNOUNCE_ACK) {
			pr_debug("Invalid command: announce: %d\n", hdr->cmd);
			goto done;
		}

		epf_vnet_vdev_cfg_clear_status(vnet, VIRTIO_NET_S_ANNOUNCE);
		*ack = VIRTIO_NET_OK;
		break;
	case VIRTIO_NET_CTRL_ROCE:
		if (ARRAY_SIZE(virtio_rdma_vdev_cmd_handler) < hdr->cmd) {
			err = -EIO;
			pr_debug("found invalid command\n");
			break;
		}
		// TODO this is for debug, finally should be deleted.
		if (!virtio_rdma_vdev_cmd_handler[hdr->cmd]) {
			pr_info("A handler for cmd %d is not yet implemented\n",
				hdr->cmd);
			err = -ENOTSUPP;
			*ack = VIRTIO_NET_ERR;
			break;
		}

		err = virtio_rdma_vdev_cmd_handler[hdr->cmd](vnet, &riov,
							     &wiov);
		*ack = err ? VIRTIO_NET_ERR : VIRTIO_NET_OK;
		break;
	default:
		pr_debug("Found not supported class: %d\n", hdr->class);
		err = -EIO;
	}

done:
	vringh_complete_kern(vrh, head, len);

	vringh_kiov_cleanup(&riov);
	vringh_kiov_cleanup(&wiov);
	return;
}

static void epf_vnet_raise_irq_handler(struct work_struct *work)
{
	struct epf_vnet *vnet =
		container_of(work, struct epf_vnet, raise_irq_work);
	struct pci_epf *epf = vnet->evio.epf;

	pci_epc_raise_irq(epf->epc, epf->func_no, epf->vfunc_no,
			  PCI_EPC_IRQ_INTX, 0);
}

static void epf_vnet_roce_rx_handler(struct work_struct *work)
{
	// 	struct epf_vnet *vnet =
	// 		container_of(work, struct epf_vnet, roce_rx_work);

	pr_info("Should operate a receive work request\n");
}

static int epf_vnet_roce_handle_send_wr(struct epf_vnet *vnet,
					struct virtio_rdma_sq_req *sreq)
{
	struct epf_vnet_rdma_mr *mr;

	pr_info("send wr\n");
	if (sreq->send_flags & VIRTIO_IB_SEND_INLINE) {
		pr_err("inline data is not supported\n");
		return -ENOTSUPP;
	}

	for (int i = 0; i < sreq->num_sge; i++) {
		struct virtio_rdma_sge *sge = &sreq->sg_list[i];
		void *buf;

		if (sge->addr & 0xfff) {
			pr_info("there is offset that is not supporeted\n");
		}

		pr_info("send wr: len %d\n", sge->length);

		mr = epf_vnet_rdma_lookup_mr(vnet, sge->lkey);
		if (!mr)
			return -EINVAL;

		buf = phys_to_virt(mr->pages[0]);

		{
			char *b = buf;
			for (int i = 0; i < sge->length / 16; i++, b += 16) {
				pr_info("%02x:"
					" %02x %02x %02x %02x %02x %02x %02x %02x "
					" %02x %02x %02x %02x %02x %02x %02x %02x ",
					i, b[0], b[1], b[2], b[3], b[4], b[5],
					b[6], b[7], b[8], b[9], b[10], b[11],
					b[12], b[13], b[14], b[15]);
			}

			for (int i = 0; i < sge->length % 16; i++)
				pr_info("%02x: %02x\n", i, b[i]);
		}
	}

	return -EINVAL;
}

static void epf_vnet_roce_tx_handler(struct work_struct *work)
{
	struct epf_vnet *vnet =
		container_of(work, struct epf_vnet, roce_tx_work);
	// 	struct epf_virtio *evio = &vnet->evio;
	struct vringh *vrh;
	struct vringh_kiov *iov;
	int err;
	u16 head;
	struct virtio_rdma_sq_req *sreq;

	vrh = &vnet->vdev_vrhs[VNET_VIRTQUEUE_RDMA_SQ2];
	iov = &vnet->vdev_iovs[VNET_VIRTQUEUE_RDMA_SQ2];

	err = vringh_getdesc_kern(vrh, iov, NULL, &head, GFP_KERNEL);
	if (err <= 0) {
		if (err < 0)
			pr_err("err on vringh_getdesc_kern: %d\n", err);
		return;
	}

	sreq = phys_to_virt((unsigned long)iov->iov[iov->i].iov_base);
	pr_info("%s:%d id %lld, opcode %d\n", __func__, __LINE__, sreq->wr_id,
		sreq->opcode);

	switch (sreq->opcode) {
	case VIRTIO_IB_WR_SEND:
		err = epf_vnet_roce_handle_send_wr(vnet, sreq);
		if (err) {
			pr_err("failed to process send work request: %d\n",
			       err);
			return;
		}
		break;
		// 	case VIRTIO_IB_WR_RDMA_WRITE:
		// 	case VIRTIO_IB_WR_RDMA_WRITE_WITH_IMM:
		// 	case VIRTIO_IB_WR_SEND_WITH_IMM:
		// 	case VIRTIO_IB_WR_RDMA_READ:
		// 		break;
	default:
		pr_err("Found unsupported work request type %d\n",
		       sreq->opcode);
	}

	// TODO wor rreq
}

static int epf_vnet_setup_common(struct epf_vnet *vnet)
{
	vnet->features =
		BIT(VIRTIO_F_ACCESS_PLATFORM) | //BIT(VIRTIO_NET_F_MTU) |
		BIT(VIRTIO_NET_F_STATUS) |
		/* Following features are to skip any of checking and offloading, Like a
		 * transmission between virtual machines on same system. Details are on
		 * section 5.1.5 in virtio specification.
		 */
		BIT(VIRTIO_NET_F_GUEST_CSUM) | BIT(VIRTIO_NET_F_GUEST_TSO4) |
		BIT(VIRTIO_NET_F_GUEST_TSO6) | BIT(VIRTIO_NET_F_GUEST_ECN) |
		BIT(VIRTIO_NET_F_GUEST_UFO) |
		/* The control queue is just used for linkup announcement. */
		BIT(VIRTIO_NET_F_CTRL_VQ) | BIT(VIRTIO_NET_F_ROCE);

	vnet->vnet_cfg.max_virtqueue_pairs = 1;
	vnet->vnet_cfg.status = 0;
	/* GSI is used 1 qps and cq */
	vnet->vnet_cfg.max_rdma_qps = 3;
	vnet->vnet_cfg.max_rdma_cqs = 3;
	// 	vnet->vnet_cfg.mtu = PAGE_SIZE;

	memcpy(&vnet->vdev_vnet_cfg, &vnet->vnet_cfg, sizeof(vnet->vnet_cfg));

	vnet->task_wq =
		alloc_workqueue("pci-epf-vnet/task-wq",
				WQ_MEM_RECLAIM | WQ_HIGHPRI | WQ_UNBOUND, 0);
	if (!vnet->task_wq)
		return -ENOMEM;

	INIT_WORK(&vnet->rx_work, epf_vnet_rx_handler);
	INIT_WORK(&vnet->tx_work, epf_vnet_tx_handler);
	INIT_WORK(&vnet->ep_ctrl_work, epf_vnet_ep_ctrl_handler);
	INIT_WORK(&vnet->vdev_ctrl_work, epf_vnet_vdev_ctrl_handler);
	INIT_WORK(&vnet->raise_irq_work, epf_vnet_raise_irq_handler);

	INIT_WORK(&vnet->roce_rx_work, epf_vnet_roce_rx_handler);
	INIT_WORK(&vnet->roce_tx_work, epf_vnet_roce_tx_handler);

	vnet->pd_slab = kmem_cache_create(
		"pci-epf-vnet/pd", sizeof(struct epf_vnet_rdma_pd), 0, 0, NULL);
	if (IS_ERR(vnet->pd_slab))
		return PTR_ERR(vnet->pd_slab);

	vnet->mr_slab = kmem_cache_create(
		"pci-epf-vnet/mr", sizeof(struct epf_vnet_rdma_mr), 0, 0, NULL);
	if (IS_ERR(vnet->mr_slab))
		return PTR_ERR(vnet->mr_slab);

	// *1 There is no resone for the value.
	vnet->rdma_attr.device_cap_flags = 0;
	vnet->rdma_attr.max_mr_size = 1 << 30;
	vnet->rdma_attr.page_size_cap = 0xfffff000;
	vnet->rdma_attr.hw_ver = 0xdeafbeaf;
	vnet->rdma_attr.max_qp_wr = virtio_queue_size;
	vnet->rdma_attr.max_send_sge = 32; // *1
	vnet->rdma_attr.max_recv_sge = 32; // *1
	vnet->rdma_attr.max_sge_rd = 32; // *1
	vnet->rdma_attr.max_cqe = virtio_queue_size;
	vnet->rdma_attr.max_mr = EPF_VNET_RDMA_MAX_MR;
	vnet->rdma_attr.max_pd = EPF_VNET_RDMA_MAX_PD;
	vnet->rdma_attr.max_qp_rd_atom = 32; // *1
	vnet->rdma_attr.max_qp_init_rd_atom = 32; // *1
	vnet->rdma_attr.max_ah = EPF_VNET_RDMA_MAX_AH;
	vnet->rdma_attr.local_ca_ack_delay = 15;

	return 0;
}

static void epf_vnet_cleanup_common(struct epf_vnet *vnet)
{
}

/*
 * Functions for local virtio device operation
 */
static u64 epf_vnet_vdev_get_features(struct virtio_device *vdev)
{
	struct epf_vnet *vnet = vdev_to_vnet(vdev);

	return vnet->features;
}

static int epf_vnet_vdev_finalize_features(struct virtio_device *vdev)
{
	struct epf_vnet *vnet = vdev_to_vnet(vdev);

	return vdev->features != vnet->features;
}

static void epf_vnet_vdev_get_config(struct virtio_device *vdev,
				     unsigned int offset, void *buf,
				     unsigned int len)
{
	struct epf_vnet *vnet = vdev_to_vnet(vdev);
	const unsigned int mac_len = sizeof(vnet->vdev_vnet_cfg.mac);
	const unsigned int status_len = sizeof(vnet->vdev_vnet_cfg.status);
	unsigned int copy_len;

	switch (offset) {
	case offsetof(struct virtio_net_config, mac):
		/* This PCIe EP function doesn't provide a VIRTIO_NET_F_MAC feature, so just
		 * clear the buffer.
		 */
		copy_len = len >= mac_len ? mac_len : len;
		memset(buf, 0x00, copy_len);
		len -= copy_len;
		buf += copy_len;
		fallthrough;
	case offsetof(struct virtio_net_config, status):
		copy_len = len >= status_len ? status_len : len;
		memcpy(buf, &vnet->vdev_vnet_cfg.status, copy_len);
		len -= copy_len;
		buf += copy_len;
		fallthrough;
	default:
		if (offset > sizeof(vnet->vdev_vnet_cfg)) {
			memset(buf, 0x00, len);
			break;
		}
		memcpy(buf, (void *)&vnet->vdev_vnet_cfg + offset, len);
	}
}

static void epf_vnet_vdev_set_config(struct virtio_device *vdev,
				     unsigned int offset, const void *buf,
				     unsigned int len)
{
	/* Do nothing because this console device doesn't any support features */
}

static u8 epf_vnet_vdev_get_status(struct virtio_device *vdev)
{
	return 0;
}

static void epf_vnet_vdev_set_status(struct virtio_device *vdev, u8 status)
{
	struct epf_vnet *vnet = vdev_to_vnet(vdev);

	if (status & VIRTIO_CONFIG_S_DRIVER_OK)
		epf_vnet_init_complete(vnet, EPF_VNET_INIT_COMPLETE_VDEV);
}

static void epf_vnet_vdev_reset(struct virtio_device *vdev)
{
	pr_debug("doesn't support yet");
}

static bool epf_vnet_vdev_vq_notify(struct virtqueue *vq)
{
	struct epf_vnet *vnet = vdev_to_vnet(vq->vdev);

	/* Support only one queue pair */
	switch (vq->index) {
	case VNET_VIRTQUEUE_RX:
		break;
	case VNET_VIRTQUEUE_TX:
		queue_work(vnet->task_wq, &vnet->tx_work);
		break;
	case VNET_VIRTQUEUE_CTRL:
		queue_work(vnet->task_wq, &vnet->vdev_ctrl_work);
		break;
	case VNET_VIRTQUEUE_RDMA_RQ1:
		queue_work(vnet->task_wq, &vnet->roce_rx_work);
		break;
	case VNET_VIRTQUEUE_RDMA_SQ2:
		queue_work(vnet->task_wq, &vnet->roce_tx_work);
		break;
	case VNET_VIRTQUEUE_RDMA_RQ2:
		queue_work(vnet->task_wq, &vnet->roce_rx_work);
		break;
	default:
		pr_info("Found unsupported notify for vq %d\n", vq->index);
		return false;
	}

	return true;
}

static int epf_vnet_vdev_find_vqs(struct virtio_device *vdev, unsigned int nvqs,
				  struct virtqueue *vqs[],
				  vq_callback_t *callback[],
				  const char *const names[], const bool *ctx,
				  struct irq_affinity *desc)
{
	struct epf_vnet *vnet = vdev_to_vnet(vdev);
	int i;
	int err;

	if (nvqs > epf_vnet_get_nvq(vnet)) {
		pr_info("Number of queue is too much: %d > %d\n", nvqs,
			epf_vnet_get_nvq(vnet));
		return -EINVAL;
	}

	for (i = 0; i < nvqs; i++) {
		struct virtqueue *vq;
		const struct vring *vring;

		if (!names[i]) {
			vqs[i] = NULL;
			continue;
		}

		vq = vring_create_virtqueue(i, virtio_queue_size,
					    VIRTIO_PCI_VRING_ALIGN, vdev, true,
					    false, ctx ? ctx[i] : false,
					    epf_vnet_vdev_vq_notify,
					    callback[i], names[i]);
		if (!vq) {
			err = -ENOMEM;
			goto err_del_vqs;
		}

		vqs[i] = vq;
		vnet->vdev_vqs[i] = vq;
		vring = virtqueue_get_vring(vq);

		err = vringh_init_kern(&vnet->vdev_vrhs[i], vnet->features,
				       virtio_queue_size, false, vring->desc,
				       vring->avail, vring->used);
		if (err) {
			pr_err("failed to init vringh for vring %d\n", i);
			goto err_del_vqs;
		}
	}

	return 0;

err_del_vqs:
	for (; i >= 0; i--) {
		if (!names[i])
			continue;

		if (!vqs[i])
			continue;

		vring_del_virtqueue(vqs[i]);
	}
	return err;
}

static void epf_vnet_vdev_del_vqs(struct virtio_device *vdev)
{
	struct epf_vnet *vnet = vdev_to_vnet(vdev);

	for (int i = 0; i < epf_vnet_get_nvq(vnet); i++) {
		if (!vnet->vdev_vqs[i])
			continue;

		vring_del_virtqueue(vnet->vdev_vqs[i]);
	}
}

static void epf_vnet_vdev_release(struct device *dev)
{
	/* Do nothing, because the struct virtio_device will be reused. */
}

static const struct virtio_config_ops epf_vnet_vdev_config_ops = {
	.get_features = epf_vnet_vdev_get_features,
	.finalize_features = epf_vnet_vdev_finalize_features,
	.get = epf_vnet_vdev_get_config,
	.set = epf_vnet_vdev_set_config,
	.get_status = epf_vnet_vdev_get_status,
	.set_status = epf_vnet_vdev_set_status,
	.reset = epf_vnet_vdev_reset,
	.find_vqs = epf_vnet_vdev_find_vqs,
	.del_vqs = epf_vnet_vdev_del_vqs,
};

static int epf_vnet_setup_vdev(struct epf_vnet *vnet, struct device *parent)
{
	u16 nvq = epf_vnet_get_nvq(vnet);
	struct virtio_device *vdev = &vnet->vdev;
	int err;

	vnet->vdev_vrhs =
		kmalloc_array(nvq, sizeof(vnet->vdev_vrhs[0]), GFP_KERNEL);
	if (!vnet->vdev_vrhs)
		return -ENOMEM;

	vnet->vdev_iovs =
		kmalloc_array(nvq, sizeof(vnet->vdev_iovs[0]), GFP_KERNEL);
	if (!vnet->vdev_iovs) {
		err = -ENOMEM;
		goto err_free_vrhs;
	}

	for (int i = 0; i < nvq; i++)
		vringh_kiov_init(&vnet->vdev_iovs[i], NULL, 0);

	vnet->vdev_vqs =
		kmalloc_array(nvq, sizeof(vnet->vdev_vrhs[0]), GFP_KERNEL);
	if (!vnet->vdev_vqs) {
		err = -ENOMEM;
		goto err_cleanup_kiov;
	}

	vdev->dev.parent = parent;
	vdev->dev.release = epf_vnet_vdev_release;
	vdev->config = &epf_vnet_vdev_config_ops;
	vdev->id.vendor = PCI_VENDOR_ID_REDHAT_QUMRANET;
	vdev->id.device = VIRTIO_ID_NET;

	err = register_virtio_device(vdev);
	if (err)
		goto err_free_vdev_vqs;

	return 0;

err_free_vdev_vqs:
	kfree(vnet->vdev_vqs);

err_cleanup_kiov:
	for (int i = 0; i < nvq; i++)
		vringh_kiov_cleanup(&vnet->vdev_iovs[i]);

	kfree(vnet->vdev_iovs);

err_free_vrhs:
	kfree(vnet->vdev_vrhs);

	return err;
}

static void epf_vnet_cleanup_vdev(struct epf_vnet *vnet)
{
	unregister_virtio_device(&vnet->vdev);
	/* Cleanup struct virtio_device that has kobject, otherwise error occures when
	 * reregister the virtio device. */
	memset(&vnet->vdev, 0x00, sizeof(vnet->vdev));

	kfree(vnet->vdev_vqs);

	for (int i = 0; i < epf_vnet_get_nvq(vnet); i++)
		vringh_kiov_cleanup(&vnet->vdev_iovs[i]);

	kfree(vnet->vdev_iovs);
	kfree(vnet->vdev_vrhs);
}

static int epf_vnet_setup_edma(struct epf_vnet *vnet, struct device *dma_dev)
{
	int err;

	vnet->tx_dma_chan = epf_request_dma_chan(dma_dev, DMA_MEM_TO_DEV);
	if (!vnet->tx_dma_chan)
		return -EOPNOTSUPP;

	vnet->rx_dma_chan = epf_request_dma_chan(dma_dev, DMA_DEV_TO_MEM);
	if (!vnet->rx_dma_chan) {
		goto err_release_tx_chan;
		err = -EOPNOTSUPP;
	}

	return 0;

err_release_tx_chan:
	dma_release_channel(vnet->tx_dma_chan);

	return err;
}

static void epf_vnet_cleanup_edma(struct epf_vnet *vnet)
{
	dma_release_channel(vnet->tx_dma_chan);
	dma_release_channel(vnet->rx_dma_chan);
}

static int epf_vnet_bind(struct pci_epf *epf)
{
	struct epf_vnet *vnet = epf_get_drvdata(epf);
	int err;

	err = epf_vnet_setup_common(vnet);
	if (err)
		return err;

	err = epf_vnet_setup_edma(vnet, epf->epc->dev.parent);
	if (err) {
		pr_info("PCIe embedded DMAC wasn't found. Rollback to cpu transfer\n");
		vnet->enable_edma = false;
	} else {
		vnet->enable_edma = true;
	}

	err = epf_vnet_setup_ep_func(vnet, epf);
	if (err)
		goto err_cleanup_edma;

	err = epf_vnet_setup_vdev(vnet, epf->epc->dev.parent);
	if (err)
		goto err_cleanup_ep_func;

err_cleanup_ep_func:
	epf_vnet_cleanup_ep_func(vnet);

err_cleanup_edma:
	epf_vnet_cleanup_edma(vnet);

	return err;
}

static void epf_vnet_unbind(struct pci_epf *epf)
{
	struct epf_vnet *vnet = epf_get_drvdata(epf);

	epf_vnet_cleanup_common(vnet);
	epf_vnet_cleanup_ep_func(vnet);
	epf_vnet_cleanup_vdev(vnet);
}

static struct pci_epf_ops epf_vnet_ops = {
	.bind = epf_vnet_bind,
	.unbind = epf_vnet_unbind,
};

static const struct pci_epf_device_id epf_vnet_ids[] = {
	{ .name = "pci_epf_vnet" },
	{}
};

static int epf_vnet_probe(struct pci_epf *epf)
{
	struct epf_vnet *vnet;

	vnet = devm_kzalloc(&epf->dev, sizeof(*vnet), GFP_KERNEL);
	if (!vnet)
		return -ENOMEM;

	epf_set_drvdata(epf, vnet);

	return 0;
}

static struct pci_epf_driver epf_vnet_drv = {
	.driver.name = "pci_epf_vnet",
	.ops = &epf_vnet_ops,
	.id_table = epf_vnet_ids,
	.probe = epf_vnet_probe,
	.owner = THIS_MODULE,
};

static int __init epf_vnet_init(void)
{
	int err;

	err = pci_epf_register_driver(&epf_vnet_drv);
	if (err) {
		pr_err("Failed to register epf vnet driver\n");
		return err;
	}

	return 0;
}
module_init(epf_vnet_init);

static void epf_vnet_exit(void)
{
	pci_epf_unregister_driver(&epf_vnet_drv);
}
module_exit(epf_vnet_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Shunsuke Mie <mie@igel.co.jp>");
MODULE_DESCRIPTION("PCI endpoint function acts as virtio net device");
