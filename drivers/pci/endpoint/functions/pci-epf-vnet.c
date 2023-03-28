// SPDX-License-Identifier: GPL-2.0
/*
 * PCI Endpoint function driver to impliment virtio-net device.
 */
#include <linux/dmaengine.h>
#include <linux/module.h>
#include <linux/pci-epc.h>
#include <linux/pci-epf.h>
#include <linux/virtio.h>
#include <linux/virtio_net.h>
#include <linux/virtio_pci.h>
#include <linux/virtio_ring.h>
#include <linux/vringh.h>
#include <linux/bitmap.h>

#include "pci-epf-virtio.h"

static int virtio_queue_size = 0x400;
module_param(virtio_queue_size, int, 0444);
MODULE_PARM_DESC(virtio_queue_size, "A length of virtqueue");

#define EPF_VNET_ROCE_GID_TBL_LEN 0x200
#define EPF_VNET_ROCE_MAX_RDMA_CQS 4
#define EPF_VNET_ROCE_MAX_RDMA_QPS 2

static int epf_vnet_roce_alloc_idx(unsigned long *bitmap, const size_t max)
{
	int idx;

	idx = bitmap_find_free_region(bitmap, max,
				      0);
	if (idx < 0)
		return idx;

	bitmap_set(bitmap, idx, 1);

	return idx;
}

static int epf_vnet_roce_release_idx(unsigned long *bitmap, const size_t max, int idx)
{
	if (idx >= max)
		return -EINVAL;

	bitmap_clear(bitmap, idx, 1);

	return 0;
}

struct epf_vnet_roce {
	u32 npd;
	u32 nmr;
	u32 nqp;
	DECLARE_BITMAP(qp_bmap, EPF_VNET_ROCE_MAX_RDMA_QPS);
	DECLARE_BITMAP(cq_bmap, EPF_VNET_ROCE_MAX_RDMA_CQS);
};

struct epf_vnet {
	//TODO Should this variable be placed here?
	struct pci_epf *epf;
	struct virtio_net_config vnet_cfg;
	u64 virtio_features;

	// dma channels for local to remote(lr) and remote to local(rl)
	struct dma_chan *lr_dma_chan, *rl_dma_chan;

	struct {
		void __iomem *cfg_base;
		struct task_struct *device_setup_task;
		struct task_struct *notify_monitor_task;
		struct workqueue_struct *tx_wq, *irq_wq, *ctl_wq;
		struct work_struct tx_work, raise_irq_work, ctl_work;
		struct epf_vringh *txvrh, *rxvrh, *ctlvrh, *rcqvrh[4],
			*rsqvrh[2], *rrqvrh[2];
		struct vringh_kiov tx_iov, rx_iov, ctl_riov, ctl_wiov;
	} rhost;

	struct {
		struct virtqueue *rxvq, *txvq, *ctlvq, *rcqvq, *rsqvq, *rrqvq;
		struct vringh txvrh, rxvrh, ctlvrh, rcqvrh[4], rsqvrh[2],
			rrqvrh[2];
		struct vringh_kiov tx_iov, rx_iov, ctl_riov, ctl_wiov, rcq_iov,
			rsq_iov, rrq_iov;
		struct virtio_device vdev;
		struct workqueue_struct *tx_wq;
		struct work_struct tx_work;
		u16 net_config_status;
	} lhost;

#define EPF_VNET_INIT_COMPLETE_LHOST BIT(0)
#define EPF_VNET_INIT_COMPLETE_RHOST BIT(1)
	u8 init_complete;

	spinlock_t slock;

#if defined(CONFIG_PCI_EPF_VNET_ROCE)
	struct virtio_rdma_ack_query_device roce_attr;
	struct epf_vnet_roce rroce, lroce;
#endif
};

int epf_vnet_transfer(struct epf_vnet *vnet, struct vringh *tx_vrh,
		      struct vringh *rx_vrh, struct vringh_kiov *tx_iov,
		      struct vringh_kiov *rx_iov,
		      enum dma_transfer_direction dir);

static void epf_vnet_init_complete(struct epf_vnet *vnet, u8 from);
static u16 epf_vnet_get_nqueues(struct epf_vnet *vnet);

/*
 * For remote host functions
 */
#define VIRTIO_NET_LEGACY_CFG_BAR BAR_0

static void epf_vnet_rhost_memcpy_config(struct epf_vnet *vnet, size_t offset,
					 void *buf, size_t len)
{
	void __iomem *base = vnet->rhost.cfg_base + offset;

	memcpy_toio(base, buf, len);
}

static u8 epf_vnet_rhost_get_config8(struct epf_vnet *vnet, size_t offset)
{
	void __iomem *base = vnet->rhost.cfg_base + offset;

	return ioread8(base);
}

static void epf_vnet_rhost_set_config8(struct epf_vnet *vnet, size_t offset,
				       u8 config)
{
	void __iomem *base = vnet->rhost.cfg_base + offset;

	iowrite8(ioread8(base) | config, base);
}

static void epf_vnet_rhost_clear_config16(struct epf_vnet *vnet, size_t offset,
					  u16 config)
{
	void __iomem *base = vnet->rhost.cfg_base + offset;

	iowrite16(ioread16(base) & ~config, base);
}

static void epf_vnet_rhost_set_config32(struct epf_vnet *vnet, size_t offset,
					u32 config)
{
	void __iomem *base = vnet->rhost.cfg_base + offset;

	iowrite32(ioread32(base) | config, base);
}

static void epf_vnet_rhost_set_config16(struct epf_vnet *vnet, size_t offset,
					u16 config)
{
	void __iomem *base = vnet->rhost.cfg_base + offset;

	iowrite16(ioread16(base) | config, base);
}

static void epf_vnet_rhost_raise_config_irq(struct epf_vnet *vnet)
{
	epf_vnet_rhost_set_config16(vnet, VIRTIO_PCI_ISR,
				    VIRTIO_PCI_ISR_CONFIG);
	queue_work(vnet->rhost.irq_wq, &vnet->rhost.raise_irq_work);
}

static void epf_vnet_rhost_announce_linkup(struct epf_vnet *vnet)
{
	epf_vnet_rhost_set_config16(
		vnet,
		VIRTIO_PCI_CONFIG_OFF(false) +
			offsetof(struct virtio_net_config, status),
		VIRTIO_NET_S_LINK_UP | VIRTIO_NET_S_ANNOUNCE);
	epf_vnet_rhost_raise_config_irq(vnet);
}

/*
 * For the PCIe host, this driver shows legacy virtio-net device. Because,
 * virtio structure pci capabilities is mandatory for modern virtio device,
 * but there is no PCIe EP hardware that can be configured with any pci
 * capabilities and Linux PCIe EP framework doesn't support it.
 */
static struct pci_epf_header epf_vnet_pci_header = {
	.vendorid = PCI_VENDOR_ID_REDHAT_QUMRANET,
	.deviceid = VIRTIO_TRANS_ID_NET,
	.subsys_vendor_id = PCI_VENDOR_ID_REDHAT_QUMRANET,
	.subsys_id = VIRTIO_ID_NET,
	.revid = 0,
	.baseclass_code = PCI_BASE_CLASS_NETWORK,
	.interrupt_pin = PCI_INTERRUPT_PIN,
};

static void epf_vnet_rhost_setup_configs(struct epf_vnet *vnet,
					 void __iomem *cfg_base)
{
	u16 default_qindex = epf_vnet_get_nqueues(vnet);

	epf_vnet_rhost_set_config32(vnet, VIRTIO_PCI_HOST_FEATURES,
				    vnet->virtio_features);

	epf_vnet_rhost_set_config16(vnet, VIRTIO_PCI_ISR, VIRTIO_PCI_ISR_QUEUE);
	/*
	 * Initialize the queue notify and selector to outside of the appropriate
	 * virtqueue index. It is used to detect change with polling because there is
	 * no other ways to detect host side driver updateing those values
	 */
	epf_vnet_rhost_set_config16(vnet, VIRTIO_PCI_QUEUE_NOTIFY,
				    default_qindex);
	epf_vnet_rhost_set_config16(vnet, VIRTIO_PCI_QUEUE_SEL, default_qindex);
	/* This pfn is also set to 0 for the polling as well */
	epf_vnet_rhost_set_config16(vnet, VIRTIO_PCI_QUEUE_PFN, 0);

	epf_vnet_rhost_set_config16(vnet, VIRTIO_PCI_QUEUE_NUM,
				    virtio_queue_size);
	epf_vnet_rhost_set_config8(vnet, VIRTIO_PCI_STATUS, 0);
	epf_vnet_rhost_memcpy_config(vnet, VIRTIO_PCI_CONFIG_OFF(false),
				     &vnet->vnet_cfg, sizeof(vnet->vnet_cfg));
}

static void epf_vnet_cleanup_bar(struct epf_vnet *vnet)
{
	struct pci_epf *epf = vnet->epf;

	pci_epc_clear_bar(epf->epc, epf->func_no, epf->vfunc_no,
			  &epf->bar[VIRTIO_NET_LEGACY_CFG_BAR]);
	pci_epf_free_space(epf, vnet->rhost.cfg_base, VIRTIO_NET_LEGACY_CFG_BAR,
			   PRIMARY_INTERFACE);
}

static int epf_vnet_setup_bar(struct epf_vnet *vnet)
{
	int err;
	size_t cfg_bar_size =
		VIRTIO_PCI_CONFIG_OFF(false) + sizeof(struct virtio_net_config);
	struct pci_epf *epf = vnet->epf;
	const struct pci_epc_features *features;
	struct pci_epf_bar *config_bar = &epf->bar[VIRTIO_NET_LEGACY_CFG_BAR];

	features = pci_epc_get_features(epf->epc, epf->func_no, epf->vfunc_no);
	if (!features) {
		pr_debug("Failed to get PCI EPC features\n");
		return -EOPNOTSUPP;
	}

	if (features->reserved_bar & BIT(VIRTIO_NET_LEGACY_CFG_BAR)) {
		pr_debug("Cannot use the PCI BAR for legacy virtio pci\n");
		return -EOPNOTSUPP;
	}

	if (features->bar_fixed_size[VIRTIO_NET_LEGACY_CFG_BAR]) {
		if (cfg_bar_size >
		    features->bar_fixed_size[VIRTIO_NET_LEGACY_CFG_BAR]) {
			pr_debug("PCI BAR size is not enough\n");
			return -ENOMEM;
		}
	}

	config_bar->flags |= PCI_BASE_ADDRESS_MEM_TYPE_64;

	vnet->rhost.cfg_base = pci_epf_alloc_space(epf, cfg_bar_size,
						   VIRTIO_NET_LEGACY_CFG_BAR,
						   features->align,
						   PRIMARY_INTERFACE);
	if (!vnet->rhost.cfg_base) {
		pr_debug("Failed to allocate virtio-net config memory\n");
		return -ENOMEM;
	}

	epf_vnet_rhost_setup_configs(vnet, vnet->rhost.cfg_base);

	err = pci_epc_set_bar(epf->epc, epf->func_no, epf->vfunc_no,
			      config_bar);
	if (err) {
		pr_debug("Failed to set PCI BAR");
		goto err_free_space;
	}

	return 0;

err_free_space:
	pci_epf_free_space(epf, vnet->rhost.cfg_base, VIRTIO_NET_LEGACY_CFG_BAR,
			   PRIMARY_INTERFACE);
	return err;
}

static void epf_vnet_rhost_notify_callback(void *param)
{
	struct epf_vnet *vnet = param;

	queue_work(vnet->rhost.tx_wq, &vnet->rhost.tx_work);
	queue_work(vnet->rhost.ctl_wq, &vnet->rhost.ctl_work);
	epf_vnet_rhost_raise_config_irq(vnet);
}

static int epf_vnet_rhost_device_setup(void *data)
{
	struct epf_vnet *vnet = data;
	struct pci_epf *epf = vnet->epf;
	const size_t vq_size = virtio_queue_size;
	u16 __iomem *queue_notify =
		vnet->rhost.cfg_base + VIRTIO_PCI_QUEUE_NOTIFY;
	const u16 notify_default = epf_vnet_get_nqueues(vnet);
	int err;
	u16 nqueues = epf_vnet_get_nqueues(vnet);
	struct epf_virtio_qinfo *qinfo;
	struct epf_vringh *vrh;

	qinfo = kmalloc_array(nqueues, sizeof(*qinfo), GFP_KERNEL);
	if (!qinfo)
		return -ENOMEM;

	err = epf_virtio_negotiate_qinfo(vnet->rhost.cfg_base, qinfo, nqueues);
	if (err < 0) {
		pr_err("failed to negoticate configs with driver\n");
		goto err_free_qinfo;
	}

	/* Polling phase is finished. This thread backs to normal priority. */
	sched_set_normal(vnet->rhost.device_setup_task, 19);

	while (!(epf_vnet_rhost_get_config8(vnet, VIRTIO_PCI_STATUS) &
		 VIRTIO_CONFIG_S_DRIVER_OK))
		;

	for (int i = 0; i < nqueues; ++i) {
		vrh = epf_virtio_alloc_vringh(epf, vnet->virtio_features,
					      qinfo[i].pci_addr, vq_size);
		if (IS_ERR(vrh)) {
			err = PTR_ERR(vrh);
			goto err_free_epf_vringh;
		}

		switch (qinfo[i].sel) {
		case 0:
			vnet->rhost.rxvrh = vrh;
			break;
		case 1:
			vnet->rhost.txvrh = vrh;
			break;
		case 2:
			vnet->rhost.ctlvrh = vrh;
			break;
		case 3:
			vnet->rhost.rcqvrh[0] = vrh;
			break;
		case 4:
			vnet->rhost.rcqvrh[1] = vrh;
			break;
		case 5:
			vnet->rhost.rcqvrh[2] = vrh;
			break;
		case 6:
			vnet->rhost.rcqvrh[3] = vrh;
			break;
		case 7:
			vnet->rhost.rsqvrh[0] = vrh;
			break;
		case 8:
			vnet->rhost.rrqvrh[0] = vrh;
			break;
		case 9:
			vnet->rhost.rsqvrh[1] = vrh;
			break;
		case 10:
			vnet->rhost.rrqvrh[1] = vrh;
			break;
		default:
			return -EIO;
		}
	}

	vringh_kiov_init(&vnet->rhost.tx_iov, NULL, 0);
	vringh_kiov_init(&vnet->rhost.rx_iov, NULL, 0);
	vringh_kiov_init(&vnet->rhost.ctl_riov, NULL, 0);
	vringh_kiov_init(&vnet->rhost.ctl_wiov, NULL, 0);

	vnet->rhost.notify_monitor_task = epf_virtio_start_notify_monitor(
		queue_notify, notify_default, epf_vnet_rhost_notify_callback,
		vnet);
	if (IS_ERR(vnet->rhost.notify_monitor_task)) {
		pr_debug("Failed to create notify monitor thread\n");
		goto err_free_epf_vringh;
	}

	epf_vnet_init_complete(vnet, EPF_VNET_INIT_COMPLETE_RHOST);

	return 0;

err_free_epf_vringh:
	epf_virtio_free_vringh(epf, vnet->rhost.ctlvrh);
	epf_virtio_free_vringh(epf, vnet->rhost.rxvrh);
	epf_virtio_free_vringh(epf, vnet->rhost.txvrh);
err_free_qinfo:
	kfree(qinfo);

	return err;
}

static int epf_vnet_rhost_spawn_device_setup_task(struct epf_vnet *vnet)
{
	vnet->rhost.device_setup_task =
		kthread_create(epf_vnet_rhost_device_setup, vnet,
			       "pci-epf-vnet/cfg_negotiator");
	if (IS_ERR(vnet->rhost.device_setup_task))
		return PTR_ERR(vnet->rhost.device_setup_task);

	/* Change the thread priority to high for the polling. */
	sched_set_fifo(vnet->rhost.device_setup_task);
	wake_up_process(vnet->rhost.device_setup_task);

	return 0;
}

static void epf_vnet_rhost_tx_handler(struct work_struct *work)
{
	struct epf_vnet *vnet =
		container_of(work, struct epf_vnet, rhost.tx_work);
	struct vringh *tx_vrh = &vnet->rhost.txvrh->vrh;
	struct vringh *rx_vrh = &vnet->lhost.rxvrh;
	struct vringh_kiov *tx_iov = &vnet->rhost.tx_iov;
	struct vringh_kiov *rx_iov = &vnet->lhost.rx_iov;
	int err;

	while (true) {
		err = epf_vnet_transfer(vnet, tx_vrh, rx_vrh, tx_iov, rx_iov,
					DMA_DEV_TO_MEM);
		if (err <= 0)
			break;
	}

	if (err < 0)
		pr_debug("Failed to transmit: Host -> Endpoint: %d\n", err);
}

static void epf_vnet_rhost_raise_irq_handler(struct work_struct *work)
{
	struct epf_vnet *vnet =
		container_of(work, struct epf_vnet, rhost.raise_irq_work);
	struct pci_epf *epf = vnet->epf;

	pci_epc_raise_irq(epf->epc, epf->func_no, epf->vfunc_no,
			  PCI_EPC_IRQ_LEGACY, 0);
}

static void __iomem *epf_vnet_epf_map_iov(struct pci_epf *epf,
					  struct vringh_kiov *iov,
					  phys_addr_t *phys)
{
	return pci_epc_map_addr(epf->epc, epf->func_no, epf->vfunc_no,
				(unsigned long)iov->iov[iov->i].iov_base, phys,
				iov->iov[iov->i].iov_len);
}

static void epf_vnet_epf_unmap_iov(struct pci_epf *epf, struct vringh_kiov *iov,
				   void __iomem *virt, phys_addr_t phys)
{
	pci_epc_unmap_addr(epf->epc, epf->func_no, epf->vfunc_no, phys, virt,
			   iov->iov[iov->i].iov_len);
}

static int epf_vnet_handle_rroce_query_device(struct epf_vnet *vnet,
					      struct virtio_net_ctrl_hdr *hdr,
					      struct vringh_kiov *riov,
					      struct vringh_kiov *wiov)
{
	struct virtio_rdma_ack_query_device *ack;
	phys_addr_t phys;

	if (wiov->i >= wiov->used)
		return -EINVAL;

	if (wiov->iov[wiov->i].iov_len < sizeof(*ack))
		return -EINVAL;

	ack = epf_vnet_epf_map_iov(vnet->epf, wiov, &phys);
	if (!ack)
		return -EIO;

	memcpy_toio(ack, &vnet->roce_attr, sizeof(vnet->roce_attr));

	epf_vnet_epf_unmap_iov(vnet->epf, wiov, ack, phys);

	return 0;
}

static int epf_vnet_handle_rroce_query_port(struct epf_vnet *vnet,
					    struct virtio_net_ctrl_hdr *hdr,
					    struct vringh_kiov *riov,
					    struct vringh_kiov *wiov)
{
	struct virtio_rdma_ack_query_port *ack, ack_tmp;
	phys_addr_t phys;

	if (wiov->i >= wiov->used)
		return -EINVAL;

	if (wiov->iov[wiov->i].iov_len < sizeof(*ack))
		return -EINVAL;

	ack = epf_vnet_epf_map_iov(vnet->epf, wiov, &phys);
	if (!ack)
		return -EIO;

	ack_tmp.gid_tbl_len = EPF_VNET_ROCE_GID_TBL_LEN;
	ack_tmp.max_msg_sz = 0x800000; // TODO remove magic number

	memcpy_toio(ack, &ack_tmp, sizeof(ack_tmp));

	epf_vnet_epf_unmap_iov(vnet->epf, wiov, ack, phys);

	return 0;
}

static int epf_vnet_handle_rroce_create_cq(struct epf_vnet *vnet,
					   struct virtio_net_ctrl_hdr *hdr,
					   struct vringh_kiov *riov,
					   struct vringh_kiov *wiov)
{
	struct virtio_rdma_cmd_create_cq __iomem *cmd;
	struct virtio_rdma_ack_create_cq __iomem *ack;
	phys_addr_t rphys, wphys;
	int err = 0;
	int idx;

	if (riov->i >= riov->used)
		return -EINVAL;

	if (riov->iov[riov->i].iov_len < sizeof(*cmd))
		return -EINVAL;

	if (wiov->i >= wiov->used)
		return -EINVAL;

	if (wiov->iov[wiov->i].iov_len < sizeof(*ack))
		return -EINVAL;

	cmd = epf_vnet_epf_map_iov(vnet->epf, riov, &rphys);
	if (!cmd) {
		err = -EIO;
		goto done;
	}

	if (virtio_queue_size < ioread32(&cmd->cqe)) {
		pr_err("virtqueue length not enough: < %d",
		       ioread32(&cmd->cqe));
		err = -EINVAL;
		goto done;
	}

	ack = epf_vnet_epf_map_iov(vnet->epf, wiov, &wphys);
	if (!ack) {
		err = -EIO;
		goto done;
	}

	idx = epf_vnet_roce_alloc_idx(vnet->rroce.cq_bmap, EPF_VNET_ROCE_MAX_RDMA_CQS);
	if (idx < 0) {
		err = idx;
		goto done;
	}

	// TODO change this dummy data.
	iowrite32(idx, &ack->cqn);

done:
	epf_vnet_epf_unmap_iov(vnet->epf, riov, cmd, rphys);
	epf_vnet_epf_unmap_iov(vnet->epf, wiov, ack, wphys);

	return err;
}

static int epf_vnet_handle_rroce_destroy_cq(struct epf_vnet *vnet,
					    struct virtio_net_ctrl_hdr *hdr,
					    struct vringh_kiov *riov,
					    struct vringh_kiov *wiov)
{
	struct virtio_rdma_cmd_destroy_cq *cmd;
	phys_addr_t phys;
	int err;

	if (riov->i >= riov->used)
		return -EINVAL;

	if (riov->iov[riov->i].iov_len < sizeof(*cmd))
		return -EINVAL;

	cmd = epf_vnet_epf_map_iov(vnet->epf, riov, &phys);
	if (!cmd) {
		err = -EIO;
		goto done;
	}

	err = epf_vnet_roce_release_idx(vnet->rroce.cq_bmap, EPF_VNET_ROCE_MAX_RDMA_CQS, ioread32(&cmd->cqn));

done:
	epf_vnet_epf_unmap_iov(vnet->epf, riov, cmd, phys);

	return err;
}

static int epf_vnet_handle_rroce_create_pd(struct epf_vnet *vnet,
					   struct virtio_net_ctrl_hdr *hdr,
					   struct vringh_kiov *riov,
					   struct vringh_kiov *wiov)
{
	struct virtio_rdma_ack_create_pd __iomem *ack;
	phys_addr_t phys;

	if (wiov->i >= wiov->used)
		return -EINVAL;

	if (wiov->iov[wiov->i].iov_len < sizeof(*ack))
		return -EINVAL;

	ack = epf_vnet_epf_map_iov(vnet->epf, wiov, &phys);
	if (!ack)
		return -EIO;

	// TODO fix this constat response
	iowrite32(1, &ack->pdn);

	epf_vnet_epf_unmap_iov(vnet->epf, wiov, ack, phys);

	return 0;
}

static int epf_vnet_handle_rroce_destry_pd(struct epf_vnet *vnet,
					   struct virtio_net_ctrl_hdr *hdr,
					   struct vringh_kiov *riov,
					   struct vringh_kiov *wiov)
{
	return 0;
}

static int epf_vnet_handle_rroce_get_dma_mr(struct epf_vnet *vnet,
					    struct virtio_net_ctrl_hdr *hdr,
					    struct vringh_kiov *riov,
					    struct vringh_kiov *wiov)
{
	struct virtio_rdma_cmd_get_dma_mr __iomem *cmd;
	struct virtio_rdma_ack_get_dma_mr __iomem *ack, tmp_ack;
	phys_addr_t rphys, wphys;

	if (riov->i >= riov->used)
		return -EINVAL;

	if (riov->iov[riov->i].iov_len < sizeof(*cmd))
		return -EINVAL;

	if (wiov->i >= wiov->used)
		return -EINVAL;

	if (wiov->iov[wiov->i].iov_len < sizeof(*ack))
		return -EINVAL;

	cmd = epf_vnet_epf_map_iov(vnet->epf, riov, &rphys);
	if (!cmd)
		return -EIO;

	//TODO checkpdn
	pr_info("pdn %d\n", ioread32(cmd));

	ack = epf_vnet_epf_map_iov(vnet->epf, wiov, &wphys);
	if (!ack)
		return -EIO;

	//TODO
	tmp_ack.mrn = vnet->rroce.nmr++;
	tmp_ack.lkey = 0;
	tmp_ack.rkey = 0;

	memcpy_toio(ack, &tmp_ack, sizeof(tmp_ack));

	epf_vnet_epf_unmap_iov(vnet->epf, riov, cmd, rphys);
	epf_vnet_epf_unmap_iov(vnet->epf, wiov, ack, wphys);

	return 0;
}

static int epf_vnet_handle_rroce_user_mr(struct epf_vnet *vnet,
					 struct virtio_net_ctrl_hdr *hdr,
					 struct vringh_kiov *riov,
					 struct vringh_kiov *wiov)
{
	struct virtio_rdma_cmd_reg_user_mr __iomem *cmd;
	struct virtio_rdma_ack_reg_user_mr __iomem *ack, tmp_ack;
	phys_addr_t rphys, wphys;
	int err = 0;

	if (riov->i >= riov->used)
		return -EINVAL;

	if (riov->iov[riov->i].iov_len < sizeof(*cmd))
		return -EINVAL;

	if (wiov->i >= wiov->used)
		return -EINVAL;

	if (wiov->iov[wiov->i].iov_len < sizeof(*ack))
		return -EINVAL;

	cmd = epf_vnet_epf_map_iov(vnet->epf, riov, &rphys);
	if (!cmd)
		return -EIO;

	ack = epf_vnet_epf_map_iov(vnet->epf, wiov, &wphys);
	if (!ack) {
		err = -EIO;
		goto err_unmap;
	}

	tmp_ack.lkey = 0;
	tmp_ack.rkey = 0;
	tmp_ack.mrn = vnet->rroce.nmr++;

	memcpy_toio(ack, &tmp_ack, sizeof(tmp_ack));

err_unmap:
	epf_vnet_epf_unmap_iov(vnet->epf, riov, cmd, rphys);
	epf_vnet_epf_unmap_iov(vnet->epf, wiov, ack, wphys);

	return err;
}

static int epf_vnet_handle_rroce_dereg_mr(struct epf_vnet *vnet,
					  struct virtio_net_ctrl_hdr *hdr,
					  struct vringh_kiov *riov,
					  struct vringh_kiov *wiov)
{
	return 0;
}

static int epf_vnet_handle_rroce_create_qp(struct epf_vnet *vnet,
					   struct virtio_net_ctrl_hdr *hdr,
					   struct vringh_kiov *riov,
					   struct vringh_kiov *wiov)
{
	struct virtio_rdma_cmd_create_qp __iomem *cmd;
	struct virtio_rdma_ack_create_qp __iomem *ack;
	phys_addr_t rphys, wphys;
	int err = 0;
	int idx;

	if (riov->i >= riov->used)
		return -EINVAL;

	if (riov->iov[riov->i].iov_len < sizeof(*cmd))
		return -EINVAL;

	if (wiov->i >= wiov->used)
		return -EINVAL;

	if (wiov->iov[wiov->i].iov_len < sizeof(*ack))
		return -EINVAL;

	cmd = epf_vnet_epf_map_iov(vnet->epf, riov, &rphys);
	if (!cmd)
		return -EIO;

	ack = epf_vnet_epf_map_iov(vnet->epf, wiov, &wphys);
	if (!ack) {
		err = -EIO;
		goto err_unmap;
	}

	idx = epf_vnet_roce_alloc_idx(vnet->rroce.qp_bmap, EPF_VNET_ROCE_MAX_RDMA_QPS);
	if (idx < 0) {
		err = idx;
		goto err_unmap;
	}

	iowrite32(vnet->rroce.nqp++, &ack->qpn);

err_unmap:
	epf_vnet_epf_unmap_iov(vnet->epf, riov, cmd, rphys);
	epf_vnet_epf_unmap_iov(vnet->epf, wiov, ack, wphys);

	return err;
}

static int epf_vnet_handle_rroce_modify_qp(struct epf_vnet *vnet,
					 struct virtio_net_ctrl_hdr *hdr,
					 struct vringh_kiov *riov,
					 struct vringh_kiov *wiov)
{
	return 0;
}

static int epf_vnet_handle_rroce_add_gid(struct epf_vnet *vnet,
					 struct virtio_net_ctrl_hdr *hdr,
					 struct vringh_kiov *riov,
					 struct vringh_kiov *wiov)
{
	struct virtio_rdma_cmd_add_gid __iomem *cmd, cmd_tmp;
	int err = 0;
	phys_addr_t phys;

	if (riov->i >= riov->used)
		return -EINVAL;

	if (riov->iov[riov->i].iov_len < sizeof(*cmd))
		return -EINVAL;

	cmd = epf_vnet_epf_map_iov(vnet->epf, riov, &phys);
	if (!cmd)
		return -EIO;

	memcpy_fromio(&cmd_tmp, cmd, sizeof(cmd_tmp));

	if (cmd_tmp.index >= EPF_VNET_ROCE_GID_TBL_LEN) {
		err = -EINVAL;
		goto done;
	}

	// TODO save gid to gid table

done:
	epf_vnet_epf_unmap_iov(vnet->epf, riov, cmd, phys);

	return err;
}

static int epf_vnet_handle_rroce_del_gid(struct epf_vnet *vnet,
					 struct virtio_net_ctrl_hdr *hdr,
					 struct vringh_kiov *riov,
					 struct vringh_kiov *wiov)
{
	return 0;
}

static int epf_vnet_handle_rroce_req_notify_cq(struct epf_vnet *vnet,
					       struct virtio_net_ctrl_hdr *hdr,
					       struct vringh_kiov *riov,
					       struct vringh_kiov *wiov)
{
	return 0;
}

static const int (*epf_vnet_roce_rcmd_handlers[])(struct epf_vnet *,
						  struct virtio_net_ctrl_hdr *,
						  struct vringh_kiov *,
						  struct vringh_kiov *) = {
	[VIRTIO_NET_CTRL_ROCE_QUERY_DEVICE] = epf_vnet_handle_rroce_query_device,
	[VIRTIO_NET_CTRL_ROCE_QUERY_PORT] = epf_vnet_handle_rroce_query_port,
	[VIRTIO_NET_CTRL_ROCE_CREATE_CQ] = epf_vnet_handle_rroce_create_cq,
	[VIRTIO_NET_CTRL_ROCE_DESTROY_CQ] = epf_vnet_handle_rroce_destroy_cq,
	[VIRTIO_NET_CTRL_ROCE_CREATE_PD] = epf_vnet_handle_rroce_create_pd,
	[VIRTIO_NET_CTRL_ROCE_DESTROY_PD] = epf_vnet_handle_rroce_destry_pd,
	[VIRTIO_NET_CTRL_ROCE_GET_DMA_MR] = epf_vnet_handle_rroce_get_dma_mr,
	[VIRTIO_NET_CTRL_ROCE_REG_USER_MR] = epf_vnet_handle_rroce_user_mr,
	[VIRTIO_NET_CTRL_ROCE_DEREG_MR] = epf_vnet_handle_rroce_dereg_mr,
	[VIRTIO_NET_CTRL_ROCE_CREATE_QP] = epf_vnet_handle_rroce_create_qp,
	[VIRTIO_NET_CTRL_ROCE_MODIFY_QP] = epf_vnet_handle_rroce_modify_qp,
	[VIRTIO_NET_CTRL_ROCE_QUERY_QP] = NULL,
	[VIRTIO_NET_CTRL_ROCE_DESTROY_QP] = NULL,
	[VIRTIO_NET_CTRL_ROCE_CREATE_AH] = NULL,
	[VIRTIO_NET_CTRL_ROCE_DESTROY_AH] = NULL,
	[VIRTIO_NET_CTRL_ROCE_ADD_GID] = epf_vnet_handle_rroce_add_gid,
	[VIRTIO_NET_CTRL_ROCE_DEL_GID] = epf_vnet_handle_rroce_del_gid,
	[VIRTIO_NET_CTRL_ROCE_REQ_NOTIFY_CQ] =
		epf_vnet_handle_rroce_req_notify_cq,
};

static int epf_vnet_rhost_process_ctrlq_entry(struct epf_vnet *vnet)
{
	struct vringh_kiov *riov = &vnet->rhost.ctl_riov;
	struct vringh_kiov *wiov = &vnet->rhost.ctl_wiov;
	struct vringh *vrh = &vnet->rhost.ctlvrh->vrh;
	struct pci_epf *epf = vnet->epf;
	struct virtio_net_ctrl_hdr *hdr;
	virtio_net_ctrl_ack *ack;
	int err;
	u16 head;
	size_t total_len, rlen, wlen;
	u8 class, cmd;
	void __iomem *rvirt, *wvirt;
	phys_addr_t rphys, wphys;

	err = vringh_getdesc(vrh, riov, wiov, &head);
	if (err <= 0)
		return err;

	total_len = vringh_kiov_length(riov);

	rlen = riov->iov[riov->i].iov_len;
	rvirt = pci_epc_map_addr(epf->epc, epf->func_no, epf->vfunc_no,
				 (u64)riov->iov[riov->i].iov_base, &rphys,
				 rlen);
	if (IS_ERR(rvirt)) {
		err = PTR_ERR(rvirt);
		goto err_out;
	}

	wlen = wiov->iov[wiov->i].iov_len;
	wvirt = pci_epc_map_addr(epf->epc, epf->func_no, epf->vfunc_no,
				 (u64)wiov->iov[wiov->i].iov_base, &wphys,
				 wlen);
	if (IS_ERR(wvirt)) {
		err = PTR_ERR(wvirt);
		goto err_unmap_command;
	}

	hdr = rvirt;
	ack = wvirt;

	riov->i++;
	wiov->i++;

	class = ioread8(&hdr->class);
	cmd = ioread8(&hdr->cmd);
	switch (class) {
	case VIRTIO_NET_CTRL_ANNOUNCE:
		if (cmd != VIRTIO_NET_CTRL_ANNOUNCE_ACK) {
			pr_err("Found invalid command: announce: %d\n", cmd);
			break;
		}
		epf_vnet_rhost_clear_config16(
			vnet,
			VIRTIO_PCI_CONFIG_OFF(false) +
				offsetof(struct virtio_net_config, status),
			VIRTIO_NET_S_ANNOUNCE);
		epf_vnet_rhost_clear_config16(vnet, VIRTIO_PCI_ISR,
					      VIRTIO_PCI_ISR_CONFIG);

		iowrite8(VIRTIO_NET_OK, ack);
		break;
#if defined(CONFIG_PCI_EPF_VNET_ROCE)
	case VIRTIO_NET_CTRL_ROCE:
		if (ARRAY_SIZE(epf_vnet_roce_rcmd_handlers) < hdr->cmd) {
			err = -EIO;
			pr_err("out of range\n");
			iowrite8(VIRTIO_NET_ERR, ack);
			break;
		}

		// TODO finally remove this condition. it is for debug.
		if (!epf_vnet_roce_rcmd_handlers[hdr->cmd]) {
			pr_info("%s the roce cmd not yet implemented: %d\n",
				__func__, hdr->cmd);
			iowrite8(VIRTIO_NET_ERR, ack);
			break;
		}

		err = epf_vnet_roce_rcmd_handlers[hdr->cmd](vnet, hdr, riov,
							    wiov);
		iowrite8(err ? VIRTIO_NET_ERR : VIRTIO_NET_OK, ack);
		break;
#endif /* define(CONFIG_PCI_EPF_VNET_ROCE) */
	default:
		pr_err("Found unsupported class in control queue: %d\n", class);
		iowrite8(VIRTIO_NET_ERR, ack);
		break;
	}

	vringh_complete(vrh, head, total_len);
	pci_epc_unmap_addr(epf->epc, epf->func_no, epf->vfunc_no, rphys, rvirt,
			   rlen);
	pci_epc_unmap_addr(epf->epc, epf->func_no, epf->vfunc_no, wphys, wvirt,
			   wlen);

	return 1;

err_unmap_command:
	pci_epc_unmap_addr(epf->epc, epf->func_no, epf->vfunc_no, rphys, rvirt,
			   rlen);
err_out:
	return err;
}

static void epf_vnet_rhost_process_ctrlq_entries(struct work_struct *work)
{
	struct epf_vnet *vnet =
		container_of(work, struct epf_vnet, rhost.ctl_work);

	while (epf_vnet_rhost_process_ctrlq_entry(vnet) > 0)
		;
}

void epf_vnet_rhost_notify(struct epf_vnet *vnet)
{
	queue_work(vnet->rhost.irq_wq, &vnet->rhost.raise_irq_work);
}

void epf_vnet_rhost_cleanup(struct epf_vnet *vnet)
{
	epf_vnet_cleanup_bar(vnet);
	destroy_workqueue(vnet->rhost.tx_wq);
	destroy_workqueue(vnet->rhost.irq_wq);
	destroy_workqueue(vnet->rhost.ctl_wq);

	kthread_stop(vnet->rhost.device_setup_task);
}

int epf_vnet_rhost_setup(struct epf_vnet *vnet)
{
	int err;
	struct pci_epf *epf = vnet->epf;

	err = pci_epc_write_header(epf->epc, epf->func_no, epf->vfunc_no,
				   &epf_vnet_pci_header);
	if (err)
		return err;

	err = epf_vnet_setup_bar(vnet);
	if (err)
		return err;

	vnet->rhost.tx_wq =
		alloc_workqueue("pci-epf-vnet/rhost/tx-wq",
				WQ_MEM_RECLAIM | WQ_HIGHPRI | WQ_UNBOUND, 0);
	if (!vnet->rhost.tx_wq) {
		pr_debug(
			"Failed to allocate workqueue for rhost -> ep transmission\n");
		err = -ENOMEM;
		goto err_cleanup_bar;
	}

	INIT_WORK(&vnet->rhost.tx_work, epf_vnet_rhost_tx_handler);

	vnet->rhost.irq_wq =
		alloc_workqueue("pci-epf-vnet/irq-wq",
				WQ_MEM_RECLAIM | WQ_HIGHPRI | WQ_UNBOUND, 0);
	if (!vnet->rhost.irq_wq) {
		pr_debug("Failed to allocate workqueue for irq\n");
		err = -ENOMEM;
		goto err_destory_tx_wq;
	}

	INIT_WORK(&vnet->rhost.raise_irq_work,
		  epf_vnet_rhost_raise_irq_handler);

	vnet->rhost.ctl_wq =
		alloc_workqueue("pci-epf-vnet/ctl-wq",
				WQ_MEM_RECLAIM | WQ_HIGHPRI | WQ_UNBOUND, 0);
	if (!vnet->rhost.ctl_wq) {
		pr_err("Failed to allocate work queue for control queue processing\n");
		err = -ENOMEM;
		goto err_destory_irq_wq;
	}

	INIT_WORK(&vnet->rhost.ctl_work, epf_vnet_rhost_process_ctrlq_entries);

	err = epf_vnet_rhost_spawn_device_setup_task(vnet);
	if (err)
		goto err_destory_ctl_wq;

	return 0;

err_cleanup_bar:
	epf_vnet_cleanup_bar(vnet);
err_destory_tx_wq:
	destroy_workqueue(vnet->rhost.tx_wq);
err_destory_irq_wq:
	destroy_workqueue(vnet->rhost.irq_wq);
err_destory_ctl_wq:
	destroy_workqueue(vnet->rhost.ctl_wq);

	return err;
}

/*
 * For local host functions
 */
static inline struct epf_vnet *vdev_to_vnet(struct virtio_device *vdev)
{
	return container_of(vdev, struct epf_vnet, lhost.vdev);
}

static void epf_vnet_lhost_set_status(struct epf_vnet *vnet, u16 status)
{
	vnet->lhost.net_config_status |= status;
}

static void epf_vnet_lhost_clear_status(struct epf_vnet *vnet, u16 status)
{
	vnet->lhost.net_config_status &= ~status;
}

static void epf_vnet_lhost_raise_config_irq(struct epf_vnet *vnet)
{
	virtio_config_changed(&vnet->lhost.vdev);
}

static void epf_vnet_lhost_announce_linkup(struct epf_vnet *vnet)
{
	epf_vnet_lhost_set_status(vnet,
				  VIRTIO_NET_S_LINK_UP | VIRTIO_NET_S_ANNOUNCE);
	epf_vnet_lhost_raise_config_irq(vnet);
}

static void epf_vnet_lhost_notify(struct epf_vnet *vnet, struct virtqueue *vq)
{
	vring_interrupt(0, vq);
}

static int epf_vnet_handle_lroce_query_device(struct epf_vnet *vnet,
					      struct virtio_net_ctrl_hdr *hdr,
					      struct vringh_kiov *riov,
					      struct vringh_kiov *wiov)
{
	struct virtio_rdma_ack_query_device *ack;

	if (wiov->i >= wiov->used)
		return -EINVAL;

	if (wiov->iov[wiov->i].iov_len < sizeof(*ack))
		return -EINVAL;

	ack = phys_to_virt((unsigned long)wiov->iov[wiov->i].iov_base);

	memcpy(ack, &vnet->roce_attr, sizeof(*ack));

	return 0;
}

static int epf_vnet_handle_lroce_query_port(struct epf_vnet *vnet,
					    struct virtio_net_ctrl_hdr *hdr,
					    struct vringh_kiov *riov,
					    struct vringh_kiov *wiov)
{
	struct virtio_rdma_ack_query_port *ack;

	if (wiov->i >= wiov->used)
		return -EINVAL;

	if (wiov->iov[wiov->i].iov_len < sizeof(*ack))
		return -EINVAL;

	ack = phys_to_virt((unsigned long)wiov->iov[wiov->i].iov_base);

	ack->gid_tbl_len = EPF_VNET_ROCE_GID_TBL_LEN;
	ack->max_msg_sz = 0x8000000; //TODO remote magic number

	return 0;
}

static int epf_vnet_handle_lroce_create_cq(struct epf_vnet *vnet,
					   struct virtio_net_ctrl_hdr *hdr,
					   struct vringh_kiov *riov,
					   struct vringh_kiov *wiov)
{
	struct virtio_rdma_cmd_create_cq *cmd;
	struct virtio_rdma_ack_create_cq *ack;
	int idx;

	if (riov->i >= riov->used)
		return -EINVAL;

	if (riov->iov[riov->i].iov_len < sizeof(*cmd))
		return -EINVAL;

	cmd = phys_to_virt((unsigned long)riov->iov[riov->i].iov_base);

	if (wiov->i >= wiov->used)
		return -EINVAL;

	if (wiov->iov[wiov->i].iov_len < sizeof(*ack))
		return -EINVAL;

	ack = phys_to_virt((unsigned long)wiov->iov[wiov->i].iov_base);

	idx = epf_vnet_roce_alloc_idx(vnet->lroce.cq_bmap, EPF_VNET_ROCE_MAX_RDMA_CQS);
	if (idx < 0)
		return idx;

	ack->cqn = idx;

	return 0;
}

static int epf_vnet_handle_lroce_destroy_cq(struct epf_vnet *vnet,
					    struct virtio_net_ctrl_hdr *hdr,
					    struct vringh_kiov *riov,
					    struct vringh_kiov *wiov)
{
	struct virtio_rdma_cmd_destroy_cq *cmd;

	if (riov->i >= riov->used)
		return -EINVAL;

	if (riov->iov[riov->i].iov_len < sizeof(*cmd))
		return -EINVAL;

	cmd = phys_to_virt((unsigned long)riov->iov[riov->i].iov_base);

	return epf_vnet_roce_release_idx(vnet->lroce.cq_bmap, EPF_VNET_ROCE_MAX_RDMA_CQS, cmd->cqn);
}

static int epf_vnet_handle_lroce_create_pd(struct epf_vnet *vnet,
					   struct virtio_net_ctrl_hdr *hdr,
					   struct vringh_kiov *riov,
					   struct vringh_kiov *wiov)
{
	struct virtio_rdma_ack_create_pd *ack;

	if (wiov->i >= wiov->used)
		return -EINVAL;

	if (wiov->iov[wiov->i].iov_len < sizeof(*ack))
		return -EINVAL;

	ack = phys_to_virt((unsigned long)wiov->iov[wiov->i].iov_base);

	ack->pdn = vnet->lroce.npd++;

	return 0;
}

static int epf_vnet_handle_lroce_destry_pd(struct epf_vnet *vnet,
					   struct virtio_net_ctrl_hdr *hdr,
					   struct vringh_kiov *riov,
					   struct vringh_kiov *wiov)
{
	return 0;
}

static int epf_vnet_handle_lroce_get_dma_mr(struct epf_vnet *vnet,
					    struct virtio_net_ctrl_hdr *hdr,
					    struct vringh_kiov *riov,
					    struct vringh_kiov *wiov)
{
	struct virtio_rdma_cmd_get_dma_mr *cmd;
	struct virtio_rdma_ack_get_dma_mr *ack;

	if (riov->i >= riov->used)
		return -EINVAL;

	if (riov->iov[riov->i].iov_len < sizeof(*cmd))
		return -EINVAL;

	cmd = phys_to_virt((unsigned long)riov->iov[riov->i].iov_base);

	if (wiov->i >= wiov->used)
		return -EINVAL;

	if (wiov->iov[wiov->i].iov_len < sizeof(*ack))
		return -EINVAL;

	ack = phys_to_virt((unsigned long)wiov->iov[wiov->i].iov_base);

	ack->lkey = 0;
	ack->rkey = 0;
	ack->mrn = vnet->lroce.nmr++;

	return 0;
}

static int epf_vnet_handle_lroce_reg_user_mr(struct epf_vnet *vnet,
					     struct virtio_net_ctrl_hdr *hdr,
					     struct vringh_kiov *riov,
					     struct vringh_kiov *wiov)
{
	struct virtio_rdma_cmd_reg_user_mr *cmd;
	struct virtio_rdma_ack_reg_user_mr *ack;

	if (riov->i >= riov->used)
		return -EINVAL;

	if (riov->iov[riov->i].iov_len < sizeof(*cmd))
		return -EINVAL;

	if (wiov->i >= wiov->used)
		return -EINVAL;

	if (wiov->iov[wiov->i].iov_len < sizeof(*ack))
		return -EINVAL;

	ack = phys_to_virt((unsigned long)wiov->iov[wiov->i].iov_base);

	ack->lkey = 0;
	ack->rkey = 0;
	ack->mrn = vnet->lroce.nmr++;

	return 0;
}

static int epf_vnet_handle_lroce_dereg_mr(struct epf_vnet *vnet,
					  struct virtio_net_ctrl_hdr *hdr,
					  struct vringh_kiov *riov,
					  struct vringh_kiov *wiov)
{
	return 0;
}

static int epf_vnet_handle_lroce_create_qp(struct epf_vnet *vnet,
					   struct virtio_net_ctrl_hdr *hdr,
					   struct vringh_kiov *riov,
					   struct vringh_kiov *wiov)
{
	struct virtio_rdma_cmd_create_qp *cmd;
	struct virtio_rdma_ack_create_qp *ack;
	int idx;

	if (riov->i >= riov->used)
		return -EINVAL;

	if (riov->iov[riov->i].iov_len < sizeof(*cmd))
		return -EINVAL;

	cmd = phys_to_virt((unsigned long)riov->iov[riov->i].iov_base);

	if (wiov->i >= wiov->used)
		return -EINVAL;

	if (wiov->iov[wiov->i].iov_len < sizeof(*ack))
		return -EINVAL;

	ack = phys_to_virt((unsigned long)wiov->iov[wiov->i].iov_base);

	switch (cmd->qp_type) {
	case VIRTIO_IB_QPT_GSI:
		break;
	case VIRTIO_IB_QPT_RC:
		break;
	default:
		pr_err("this qp type %d is not supported\n", cmd->qp_type);
		return -EIO;
	}

	idx = epf_vnet_roce_alloc_idx(vnet->lroce.qp_bmap, EPF_VNET_ROCE_MAX_RDMA_QPS);
	if (idx < 0)
		return idx;

	ack->qpn = idx;

	return 0;
}

static int epf_vnet_handle_lroce_modify_qp(struct epf_vnet *vnet,
					   struct virtio_net_ctrl_hdr *hdr,
					   struct vringh_kiov *riov,
					   struct vringh_kiov *wiov)
{
	struct virtio_rdma_cmd_modify_qp *cmd;

	if (riov->i >= riov->used)
		return -EINVAL;

	if (riov->iov[riov->i].iov_len < sizeof(*cmd))
		return -EINVAL;

	cmd = phys_to_virt((unsigned long)riov->iov[riov->i].iov_base);

#define SHOW_ATTR(bit)                                       \
	do {                                                 \
		if (cmd->attr_mask & bit) {                  \
			pr_info("%s: " #bit "\n", __func__); \
		}                                            \
	} while (0)
	SHOW_ATTR(VIRTIO_IB_QP_STATE);
	SHOW_ATTR(VIRTIO_IB_QP_CUR_STATE);
	SHOW_ATTR(VIRTIO_IB_QP_ACCESS_FLAGS);
	SHOW_ATTR(VIRTIO_IB_QP_QKEY);
	SHOW_ATTR(VIRTIO_IB_QP_AV);
	SHOW_ATTR(VIRTIO_IB_QP_PATH_MTU);
	SHOW_ATTR(VIRTIO_IB_QP_TIMEOUT);
	SHOW_ATTR(VIRTIO_IB_QP_RETRY_CNT);
	SHOW_ATTR(VIRTIO_IB_QP_RNR_RETRY);
	SHOW_ATTR(VIRTIO_IB_QP_RQ_PSN);
	SHOW_ATTR(VIRTIO_IB_QP_MAX_QP_RD_ATOMIC);
	SHOW_ATTR(VIRTIO_IB_QP_MIN_RNR_TIMER);
	SHOW_ATTR(VIRTIO_IB_QP_SQ_PSN);
	SHOW_ATTR(VIRTIO_IB_QP_MAX_DEST_RD_ATOMIC);
	SHOW_ATTR(VIRTIO_IB_QP_CAP);
	SHOW_ATTR(VIRTIO_IB_QP_DEST_QPN);
	SHOW_ATTR(VIRTIO_IB_QP_RATE_LIMIT);

	return 0;
}

static int epf_vnet_handle_lroce_destroy_qp(struct epf_vnet *vnet,
					    struct virtio_net_ctrl_hdr *hdr,
					    struct vringh_kiov *riov,
					    struct vringh_kiov *wiov)
{
	return 0;
}

static int epf_vnet_handle_lroce_add_gid(struct epf_vnet *vnet,
					 struct virtio_net_ctrl_hdr *hdr,
					 struct vringh_kiov *riov,
					 struct vringh_kiov *wiov)
{
	struct virtio_rdma_cmd_add_gid *cmd;

	if (riov->i >= riov->used)
		return -EINVAL;

	if (riov->iov[riov->i].iov_len < sizeof(*cmd))
		return -EINVAL;

	cmd = phys_to_virt((unsigned long)riov->iov[riov->i].iov_base);

	if (cmd->index >= EPF_VNET_ROCE_GID_TBL_LEN)
		return -EINVAL;

	return 0;
}

static int epf_vnet_handle_lroce_del_gid(struct epf_vnet *vnet,
					 struct virtio_net_ctrl_hdr *hdr,
					 struct vringh_kiov *riov,
					 struct vringh_kiov *wiov)
{
	return 0;
}

static int epf_vnet_handle_lroce_req_notify_cq(struct epf_vnet *vnet,
					       struct virtio_net_ctrl_hdr *hdr,
					       struct vringh_kiov *riov,
					       struct vringh_kiov *wiov)
{
	struct virtio_rdma_cmd_req_notify *cmd;

	if (riov->i >= riov->used)
		return -EINVAL;

	if (riov->iov[riov->i].iov_len < sizeof(*cmd))
		return -EINVAL;

	cmd = phys_to_virt((unsigned long)riov->iov[riov->i].iov_base);

	return 0;
}

static const int (*epf_vnet_roce_lcmd_handlers[])(struct epf_vnet *,
						  struct virtio_net_ctrl_hdr *,
						  struct vringh_kiov *,
						  struct vringh_kiov *) = {
	[VIRTIO_NET_CTRL_ROCE_QUERY_DEVICE] = epf_vnet_handle_lroce_query_device,
	[VIRTIO_NET_CTRL_ROCE_QUERY_PORT] = epf_vnet_handle_lroce_query_port,
	[VIRTIO_NET_CTRL_ROCE_CREATE_CQ] = epf_vnet_handle_lroce_create_cq,
	[VIRTIO_NET_CTRL_ROCE_DESTROY_CQ] = epf_vnet_handle_lroce_destroy_cq,
	[VIRTIO_NET_CTRL_ROCE_CREATE_PD] = epf_vnet_handle_lroce_create_pd,
	[VIRTIO_NET_CTRL_ROCE_DESTROY_PD] = epf_vnet_handle_lroce_destry_pd,
	[VIRTIO_NET_CTRL_ROCE_GET_DMA_MR] = epf_vnet_handle_lroce_get_dma_mr,
	[VIRTIO_NET_CTRL_ROCE_REG_USER_MR] = epf_vnet_handle_lroce_reg_user_mr,
	[VIRTIO_NET_CTRL_ROCE_DEREG_MR] = epf_vnet_handle_lroce_dereg_mr,
	[VIRTIO_NET_CTRL_ROCE_CREATE_QP] = epf_vnet_handle_lroce_create_qp,
	[VIRTIO_NET_CTRL_ROCE_MODIFY_QP] = epf_vnet_handle_lroce_modify_qp,
	// 	[VIRTIO_NET_CTRL_ROCE_QUERY_QP] = epf_vnet_handle_lroce_query_qp,
	[VIRTIO_NET_CTRL_ROCE_DESTROY_QP] = epf_vnet_handle_lroce_destroy_qp,
	[VIRTIO_NET_CTRL_ROCE_CREATE_AH] = NULL,
	[VIRTIO_NET_CTRL_ROCE_DESTROY_AH] = NULL,
	[VIRTIO_NET_CTRL_ROCE_ADD_GID] = epf_vnet_handle_lroce_add_gid,
	[VIRTIO_NET_CTRL_ROCE_DEL_GID] = epf_vnet_handle_lroce_del_gid,
	[VIRTIO_NET_CTRL_ROCE_REQ_NOTIFY_CQ] =
		epf_vnet_handle_lroce_req_notify_cq
};

static int epf_vnet_lhost_process_ctrlq_entry(struct epf_vnet *vnet)
{
	struct vringh *vrh = &vnet->lhost.ctlvrh;
	struct vringh_kiov *wiov = &vnet->lhost.ctl_riov;
	struct vringh_kiov *riov = &vnet->lhost.ctl_wiov;
	struct virtio_net_ctrl_hdr *hdr;
	virtio_net_ctrl_ack *ack;
	int err;
	u16 head;
	size_t len;

	err = vringh_getdesc(vrh, riov, wiov, &head);
	if (err <= 0)
		goto done;

	len = vringh_kiov_length(riov);
	if (len < sizeof(*hdr)) {
		pr_debug("Command is too short: %ld\n", len);
		err = -EIO;
		goto done;
	}

	if (vringh_kiov_length(wiov) < sizeof(*ack)) {
		pr_debug("Space for ack is not enough\n");
		err = -EIO;
		goto done;
	}

	hdr = phys_to_virt((unsigned long)riov->iov[riov->i].iov_base);
	ack = phys_to_virt((unsigned long)wiov->iov[wiov->i].iov_base);

	wiov->i++;
	riov->i++;

	switch (hdr->class) {
	case VIRTIO_NET_CTRL_ANNOUNCE:
		if (hdr->cmd != VIRTIO_NET_CTRL_ANNOUNCE_ACK) {
			pr_debug("Invalid command: announce: %d\n", hdr->cmd);
			*ack = VIRTIO_NET_ERR;
			break;
		}

		epf_vnet_lhost_clear_status(vnet, VIRTIO_NET_S_ANNOUNCE);
		*ack = VIRTIO_NET_OK;
		break;
#if defined(CONFIG_PCI_EPF_VNET_ROCE)
	case VIRTIO_NET_CTRL_ROCE:
		if (ARRAY_SIZE(epf_vnet_roce_lcmd_handlers) < hdr->cmd) {
			err = -EIO;
			pr_err("out of range\n");
			*ack = VIRTIO_NET_ERR;
			break;
		}

		// TODO finally remove this condition. it is for debug.
		if (!epf_vnet_roce_lcmd_handlers[hdr->cmd]) {
			pr_info("%s the roce cmd not yet implemented: %d\n",
				__func__, hdr->cmd);
			*ack = VIRTIO_NET_ERR;
			break;
		}

		err = epf_vnet_roce_lcmd_handlers[hdr->cmd](vnet, hdr, riov,
							    wiov);
		*ack = err ? VIRTIO_NET_ERR : VIRTIO_NET_OK;
		break;
#endif
	default:
		pr_debug("Found not supported class: %d\n", hdr->class);
		*ack = VIRTIO_NET_ERR;
		err = -EIO;
	}

done:
	vringh_complete(vrh, head, len);
	return err;
}

static u64 epf_vnet_lhost_vdev_get_features(struct virtio_device *vdev)
{
	struct epf_vnet *vnet = vdev_to_vnet(vdev);

	return vnet->virtio_features;
}

static int epf_vnet_lhost_vdev_finalize_features(struct virtio_device *vdev)
{
	struct epf_vnet *vnet = vdev_to_vnet(vdev);

	if (vdev->features != vnet->virtio_features)
		return -EINVAL;

	return 0;
}

static void epf_vnet_lhost_vdev_get_config(struct virtio_device *vdev,
					   unsigned int offset, void *buf,
					   unsigned int len)
{
	struct epf_vnet *vnet = vdev_to_vnet(vdev);
	const unsigned int mac_len = sizeof(vnet->vnet_cfg.mac);
	const unsigned int status_len = sizeof(vnet->vnet_cfg.status);
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
		memcpy(buf, &vnet->lhost.net_config_status, copy_len);
		len -= copy_len;
		buf += copy_len;
		fallthrough;
	default:
		if (offset > sizeof(vnet->vnet_cfg)) {
			memset(buf, 0x00, len);
			break;
		}
		memcpy(buf, (void *)&vnet->vnet_cfg + offset, len);
	}
}

static void epf_vnet_lhost_vdev_set_config(struct virtio_device *vdev,
					   unsigned int offset, const void *buf,
					   unsigned int len)
{
	/* Do nothing, because all of virtio net config space is readonly. */
}

static u8 epf_vnet_lhost_vdev_get_status(struct virtio_device *vdev)
{
	return 0;
}

static void epf_vnet_lhost_vdev_set_status(struct virtio_device *vdev,
					   u8 status)
{
	struct epf_vnet *vnet = vdev_to_vnet(vdev);

	if (status & VIRTIO_CONFIG_S_DRIVER_OK)
		epf_vnet_init_complete(vnet, EPF_VNET_INIT_COMPLETE_LHOST);
}

static void epf_vnet_lhost_vdev_reset(struct virtio_device *vdev)
{
	pr_debug("doesn't support yet");
}

static bool epf_vnet_lhost_vdev_vq_notify(struct virtqueue *vq)
{
	struct epf_vnet *vnet = vdev_to_vnet(vq->vdev);

	/* Support only one queue pair */
	switch (vq->index) {
	case 0: // rx queue
		break;
	case 1: // tx queue
		// TODO: maybe the workqueue is not required.
		queue_work(vnet->lhost.tx_wq, &vnet->lhost.tx_work);
		break;
	case 2: // control queue
		epf_vnet_lhost_process_ctrlq_entry(vnet);
		break;
	case 3: // rdma completion queue
	case 4: // rdma senq queue
	case 5: // rdma receive queue
	case 6: // rdma receive queue
	case 7: // rdma receive queue
	case 8: // rdma receive queue
	case 9: // rdma receive queue
	case 10: // rdma receive queue
		pr_info_ratelimited("notify %d\n", vq->index);
		break;
	default:
		return false;
	}

	return true;
}

static int
epf_vnet_lhost_vdev_find_vqs(struct virtio_device *vdev, unsigned int nvqs,
			     struct virtqueue *vqs[], vq_callback_t *callback[],
			     const char *const names[], const bool *ctx,
			     struct irq_affinity *desc)
{
	struct epf_vnet *vnet = vdev_to_vnet(vdev);
	const size_t vq_size = virtio_queue_size;
	int i;
	int err;
	int qidx;

	for (qidx = 0, i = 0; i < nvqs; i++) {
		struct virtqueue *vq;
		struct vring *vring;
		struct vringh *vrh;

		if (!names[i]) {
			vqs[i] = NULL;
			continue;
		}

		vq = vring_create_virtqueue(qidx++, vq_size,
					    VIRTIO_PCI_VRING_ALIGN, vdev, true,
					    false, ctx ? ctx[i] : false,
					    epf_vnet_lhost_vdev_vq_notify,
					    callback[i], names[i]);
		if (!vq) {
			err = -ENOMEM;
			goto err_del_vqs;
		}

		vqs[i] = vq;
		vring = virtqueue_get_vring(vq);

		//TODO Fix this case lists. it cannot extend easily.
		switch (i) {
		case 0: // rx
			vrh = &vnet->lhost.rxvrh;
			vnet->lhost.rxvq = vq;
			break;
		case 1: // tx
			vrh = &vnet->lhost.txvrh;
			vnet->lhost.txvq = vq;
			break;
		case 2: // control
			vrh = &vnet->lhost.ctlvrh;
			vnet->lhost.ctlvq = vq;
			break;
		case 3:
			vrh = &vnet->lhost.rcqvrh[0];
			vnet->lhost.rcqvq = vq;
			break;
		case 4:
			vrh = &vnet->lhost.rcqvrh[1];
			vnet->lhost.rcqvq = vq;
			break;
		case 5:
			vrh = &vnet->lhost.rcqvrh[2];
			vnet->lhost.rcqvq = vq;
			break;
		case 6:
			vrh = &vnet->lhost.rcqvrh[3];
			vnet->lhost.rcqvq = vq;
			break;
		case 7:
			vrh = &vnet->lhost.rsqvrh[0];
			vnet->lhost.rsqvq = vq;
			break;
		case 8:
			vrh = &vnet->lhost.rrqvrh[0];
			vnet->lhost.rrqvq = vq;
			break;
		case 9:
			vrh = &vnet->lhost.rsqvrh[1];
			vnet->lhost.rsqvq = vq;
			break;
		case 10:
			vrh = &vnet->lhost.rrqvrh[1];
			vnet->lhost.rrqvq = vq;
			break;
		default:
			err = -EIO;
			goto err_del_vqs;
		}

		err = vringh_init_kern(vrh, vnet->virtio_features, vq_size,
				       false, GFP_KERNEL, vring->desc,
				       vring->avail, vring->used);
		if (err) {
			pr_err("failed to init vringh for vring %d\n", i);
			goto err_del_vqs;
		}
	}

	vringh_kiov_init(&vnet->lhost.tx_iov, NULL, 0);
	vringh_kiov_init(&vnet->lhost.rx_iov, NULL, 0);
	vringh_kiov_init(&vnet->lhost.ctl_riov, NULL, 0);
	vringh_kiov_init(&vnet->lhost.ctl_wiov, NULL, 0);
	vringh_kiov_init(&vnet->lhost.rcq_iov, NULL, 0);
	vringh_kiov_init(&vnet->lhost.rsq_iov, NULL, 0);
	vringh_kiov_init(&vnet->lhost.rsq_iov, NULL, 0);

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

static void epf_vnet_lhost_vdev_del_vqs(struct virtio_device *vdev)
{
	struct virtqueue *vq, *n;
	struct epf_vnet *vnet = vdev_to_vnet(vdev);

	list_for_each_entry_safe(vq, n, &vdev->vqs, list)
		vring_del_virtqueue(vq);

	vringh_kiov_cleanup(&vnet->lhost.tx_iov);
	vringh_kiov_cleanup(&vnet->lhost.rx_iov);
	vringh_kiov_cleanup(&vnet->lhost.ctl_riov);
	vringh_kiov_cleanup(&vnet->lhost.ctl_wiov);
}

static const struct virtio_config_ops epf_vnet_lhost_vdev_config_ops = {
	.get_features = epf_vnet_lhost_vdev_get_features,
	.finalize_features = epf_vnet_lhost_vdev_finalize_features,
	.get = epf_vnet_lhost_vdev_get_config,
	.set = epf_vnet_lhost_vdev_set_config,
	.get_status = epf_vnet_lhost_vdev_get_status,
	.set_status = epf_vnet_lhost_vdev_set_status,
	.reset = epf_vnet_lhost_vdev_reset,
	.find_vqs = epf_vnet_lhost_vdev_find_vqs,
	.del_vqs = epf_vnet_lhost_vdev_del_vqs,
};

void epf_vnet_lhost_cleanup(struct epf_vnet *vnet)
{
	unregister_virtio_device(&vnet->lhost.vdev);
}

static void epf_vnet_lhost_tx_handler(struct work_struct *work)
{
	struct epf_vnet *vnet =
		container_of(work, struct epf_vnet, lhost.tx_work);
	struct vringh *tx_vrh = &vnet->lhost.txvrh;
	struct vringh *rx_vrh = &vnet->rhost.rxvrh->vrh;
	struct vringh_kiov *tx_iov = &vnet->lhost.tx_iov;
	struct vringh_kiov *rx_iov = &vnet->rhost.rx_iov;
	int err;

	while (true) {
		err = epf_vnet_transfer(vnet, tx_vrh, rx_vrh, tx_iov, rx_iov,
					DMA_MEM_TO_DEV);
		if (err <= 0) {
			break;
		}
	}
	if (err < 0)
		pr_debug("Failed to transmit: EP -> Host: %d\n", err);
}

int epf_vnet_lhost_setup(struct epf_vnet *vnet)
{
	int err;
	struct virtio_device *vdev = &vnet->lhost.vdev;

	vnet->lhost.tx_wq =
		alloc_workqueue("pci-epf-vnet/ep/tx-wq",
				WQ_MEM_RECLAIM | WQ_HIGHPRI | WQ_UNBOUND, 0);
	if (!vnet->lhost.tx_wq) {
		pr_debug(
			"Failed to allocate workqueue for rc -> ep transmission\n");
		err = -ENOMEM;
	}

	INIT_WORK(&vnet->lhost.tx_work, epf_vnet_lhost_tx_handler);

	vdev->dev.parent = vnet->epf->epc->dev.parent;
	vdev->config = &epf_vnet_lhost_vdev_config_ops;
	vdev->id.vendor = PCI_VENDOR_ID_REDHAT_QUMRANET;
	vdev->id.device = VIRTIO_ID_NET;

	err = register_virtio_device(vdev);
	if (err)
		return err;

	return 0;
}

struct epf_dma_filter_param {
	struct device *dev;
	u32 dma_mask;
};

static bool epf_virtnet_dma_filter(struct dma_chan *chan, void *param)
{
	struct epf_dma_filter_param *fparam = param;
	struct dma_slave_caps caps;

	memset(&caps, 0, sizeof(caps));
	dma_get_slave_caps(chan, &caps);

	return chan->device->dev == fparam->dev &&
	       (fparam->dma_mask & caps.directions);
}

static int epf_vnet_init_edma(struct epf_vnet *vnet, struct device *dma_dev)
{
	struct epf_dma_filter_param param;
	dma_cap_mask_t mask;
	int err;

	dma_cap_zero(mask);
	dma_cap_set(DMA_SLAVE, mask);

	param.dev = dma_dev;
	param.dma_mask = BIT(DMA_MEM_TO_DEV);
	vnet->lr_dma_chan =
		dma_request_channel(mask, epf_virtnet_dma_filter, &param);
	if (!vnet->lr_dma_chan)
		return -EOPNOTSUPP;

	param.dma_mask = BIT(DMA_DEV_TO_MEM);
	vnet->rl_dma_chan =
		dma_request_channel(mask, epf_virtnet_dma_filter, &param);
	if (!vnet->rl_dma_chan) {
		err = -EOPNOTSUPP;
		goto err_release_channel;
	}

	return 0;

err_release_channel:
	dma_release_channel(vnet->lr_dma_chan);

	return err;
}

static void epf_vnet_deinit_edma(struct epf_vnet *vnet)
{
	dma_release_channel(vnet->lr_dma_chan);
	dma_release_channel(vnet->rl_dma_chan);
}

static int epf_vnet_dma_single(struct dma_chan *chan, phys_addr_t pci,
			       dma_addr_t dma, size_t len,
			       enum dma_transfer_direction dir,
			       void (*callback)(void *), void *param)
{
	struct dma_slave_config sconf;
	struct dma_async_tx_descriptor *desc;
	int err;
	dma_cookie_t cookie;
	unsigned long flags = 0;

	if (dir == DMA_MEM_TO_DEV) {
		sconf.dst_addr = pci;
	} else {
		sconf.src_addr = pci;
	}

	err = dmaengine_slave_config(chan, &sconf);
	if (unlikely(err))
		return err;

	if (callback)
		flags = DMA_PREP_INTERRUPT | DMA_PREP_FENCE;

	desc = dmaengine_prep_slave_single(chan, dma, len, dir, flags);
	if (unlikely(!desc))
		return -EIO;

	desc->callback = callback;
	desc->callback_param = param;

	cookie = dmaengine_submit(desc);
	err = dma_submit_error(cookie);
	if (unlikely(err))
		return err;

	dma_async_issue_pending(chan);

	return 0;
}

struct epf_vnet_dma_post_task_params {
	struct vringh *txvrh, *rxvrh;
	struct device *dma_dev;
	struct epf_vnet *vnet;
	struct virtqueue *vq;
	dma_addr_t addr;
	u32 len, total_len;
	u16 txhead, rxhead;
	bool is_last;
};

static void epf_vnet_dma_post_task(void *arg)
{
	struct epf_vnet_dma_post_task_params *p = arg;
	unsigned long flags;

	if (p->dma_dev)
		dma_sync_single_for_cpu(p->dma_dev, p->addr, p->len,
					DMA_DEV_TO_MEM);

	if (p->is_last) {
		spin_lock_irqsave(&p->vnet->slock, flags);
		vringh_complete(p->txvrh, p->txhead, p->total_len);
		vringh_complete(p->rxvrh, p->rxhead, p->total_len);

		epf_vnet_rhost_notify(p->vnet);
		epf_vnet_lhost_notify(p->vnet, p->vq);
		spin_unlock_irqrestore(&p->vnet->slock, flags);
	}

	kfree(p);
}

/**
 * epf_vnet_transfer() - transfer data between tx vring to rx vring using edma
 * @vnet: epf virtio net device to do dma
 * @tx_vrh: vringh related to source tx vring
 * @rx_vrh: vringh related to target rx vring
 * @tx_iov: buffer to use tx
 * @rx_iov: buffer to use rx
 * @dir: a direction of DMA. local to remote or local from remote
 *
 * This function returns 0, 1 or error number. The 0 indicates there is not
 * data to send. The 1 indicates a request to DMA is succeeded. Other error
 * numbers shows error, however, ENOSPC means there is no buffer on target
 * vring, so should retry to call later.
 */
int epf_vnet_transfer(struct epf_vnet *vnet, struct vringh *tx_vrh,
		      struct vringh *rx_vrh, struct vringh_kiov *tx_iov,
		      struct vringh_kiov *rx_iov,
		      enum dma_transfer_direction dir)
{
	struct virtqueue *vq;
	struct device *dma_dev;
	u16 tx_head, rx_head;
	struct vringh_kiov *liov, *riov;
	struct dma_chan *chan;
	int err;
	u32 total_len;
	unsigned long flags;

	spin_lock_irqsave(&vnet->slock, flags);
	err = vringh_getdesc(tx_vrh, tx_iov, NULL, &tx_head);
	if (err <= 0) {
		if (!err)
			pr_debug("no data to send: %d\n", dir);
		spin_unlock_irqrestore(&vnet->slock, flags);
		return err;
	}

	total_len = vringh_kiov_length(tx_iov);

	err = vringh_getdesc(rx_vrh, NULL, rx_iov, &rx_head);
	if (err < 0) {
		spin_unlock_irqrestore(&vnet->slock, flags);
		goto err_abandon_tx;
	} else if (!err) {
		pr_debug("no buffer to receive: %d\n", dir);
		spin_unlock_irqrestore(&vnet->slock, flags);
		goto err_abandon_rx;
	}
	spin_unlock_irqrestore(&vnet->slock, flags);

	switch (dir) {
	case DMA_MEM_TO_DEV:
		liov = tx_iov;
		riov = rx_iov;
		vq = vnet->lhost.txvq;
		chan = vnet->lr_dma_chan;
		break;
	case DMA_DEV_TO_MEM:
		liov = rx_iov;
		riov = tx_iov;
		vq = vnet->lhost.rxvq;
		chan = vnet->rl_dma_chan;
		break;
	default:
		err = -EINVAL;
		goto err_abandon_rx;
	}

	total_len = vringh_kiov_length(tx_iov);
	dma_dev = vnet->epf->epc->dev.parent;

	for (; tx_iov->i < tx_iov->used; tx_iov->i++, rx_iov->i++) {
		size_t len;
		u64 lbase, rbase;
		struct epf_vnet_dma_post_task_params *params;

		lbase = (u64)liov->iov[liov->i].iov_base;
		rbase = (u64)riov->iov[riov->i].iov_base;
		len = tx_iov->iov[tx_iov->i].iov_len;

		// TODO change to use kmem_cache
		params = kzalloc(sizeof(*params), GFP_KERNEL);
		if (!params)
			goto err_abandon_rx;

		params->txvrh = tx_vrh;
		params->rxvrh = rx_vrh;
		params->dma_dev = dir == DMA_DEV_TO_MEM ? dma_dev : NULL;
		params->vnet = vnet;
		params->addr = lbase;
		params->len = len;
		params->txhead = tx_head;
		params->rxhead = rx_head;
		params->total_len = total_len;
		params->is_last = tx_iov->i == tx_iov->used - 1;
		params->vq = vq;

		err = epf_vnet_dma_single(chan, rbase, lbase, len, dir,
					  epf_vnet_dma_post_task, params);
		if (err)
			goto err_abandon_rx;
	}

	return 0;

err_abandon_rx:
err_abandon_tx:

	return err;
}

static void epf_vnet_init_complete(struct epf_vnet *vnet, u8 from)
{
	vnet->init_complete |= from;

	if (!(vnet->init_complete & EPF_VNET_INIT_COMPLETE_LHOST))
		return;

	if (!(vnet->init_complete & EPF_VNET_INIT_COMPLETE_RHOST))
		return;

	epf_vnet_lhost_announce_linkup(vnet);
	epf_vnet_rhost_announce_linkup(vnet);
}

static int epf_vnet_bind(struct pci_epf *epf)
{
	int err;
	struct epf_vnet *vnet = epf_get_drvdata(epf);

	err = epf_vnet_init_edma(vnet, epf->epc->dev.parent);
	if (err)
		return err;

	err = epf_vnet_rhost_setup(vnet);
	if (err)
		goto err_free_edma;

	err = epf_vnet_lhost_setup(vnet);
	if (err)
		goto err_cleanup_rc;

	return 0;

err_free_edma:
	epf_vnet_deinit_edma(vnet);
err_cleanup_rc:
	epf_vnet_rhost_cleanup(vnet);

	return err;
}

static void epf_vnet_unbind(struct pci_epf *epf)
{
	struct epf_vnet *vnet = epf_get_drvdata(epf);

	epf_vnet_deinit_edma(vnet);
	epf_vnet_rhost_cleanup(vnet);
	epf_vnet_lhost_cleanup(vnet);
}

static struct pci_epf_ops epf_vnet_ops = {
	.bind = epf_vnet_bind,
	.unbind = epf_vnet_unbind,
};

static const struct pci_epf_device_id epf_vnet_ids[] = {
	{ .name = "pci_epf_vnet" },
	{}
};

static u16 epf_vnet_get_nqueues(struct epf_vnet *vnet)
{
	u16 rdma_qps =
		vnet->vnet_cfg.max_rdma_qps * 2 + vnet->vnet_cfg.max_rdma_cqs;

	pr_info("%s %d\n", __func__,
		(vnet->vnet_cfg.max_virtqueue_pairs *
		 2) + (!!(vnet->virtio_features & BIT(VIRTIO_NET_F_CTRL_VQ))) +
			rdma_qps);
	// 		   (vnet->virtio_features & BIT(VIRTIO_NET_F_ROCE)) ? rdma_qps : 0);

	/* tx and rx queue pair and control queue. */
	return (vnet->vnet_cfg.max_virtqueue_pairs * 2) +
	       (!!(vnet->virtio_features & BIT(VIRTIO_NET_F_CTRL_VQ))) +
	       rdma_qps;
	// 		   (vnet->virtio_features & BIT(VIRTIO_NET_F_ROCE)) ? rdma_qps : 0;
}

static void epf_vnet_virtio_init(struct epf_vnet *vnet)
{
	vnet->virtio_features =
		BIT(VIRTIO_F_ACCESS_PLATFORM) | BIT(VIRTIO_NET_F_MTU) |
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
	vnet->vnet_cfg.mtu = PAGE_SIZE;

#if defined(CONFIG_PCI_EPF_VNET_ROCE)
	vnet->vnet_cfg.max_rdma_qps = EPF_VNET_ROCE_MAX_RDMA_QPS;
	vnet->vnet_cfg.max_rdma_cqs = EPF_VNET_ROCE_MAX_RDMA_CQS;

	vnet->roce_attr.max_mr_size = 1 << 30;
	vnet->roce_attr.page_size_cap = 0xfffff000;
	vnet->roce_attr.hw_ver = 0xdeadbeef;
	vnet->roce_attr.max_qp_wr = 1024;
	vnet->roce_attr.device_cap_flags = VIRTIO_IB_DEVICE_RC_RNR_NAK_GEN;
	vnet->roce_attr.max_send_sge = 32;
	vnet->roce_attr.max_recv_sge = 32;
	vnet->roce_attr.max_sge_rd = 32;
	vnet->roce_attr.max_cqe = 1024;
	vnet->roce_attr.max_mr = 0x1000;
	vnet->roce_attr.max_pd = 0x7ffc;
	vnet->roce_attr.max_qp_rd_atom = 128;
	vnet->roce_attr.max_qp_init_rd_atom = 128;
	vnet->roce_attr.max_ah = 100;
	vnet->roce_attr.local_ca_ack_delay = 15;
#endif
}

static int epf_vnet_probe(struct pci_epf *epf)
{
	struct epf_vnet *vnet;

	vnet = devm_kzalloc(&epf->dev, sizeof(*vnet), GFP_KERNEL);
	if (!vnet)
		return -ENOMEM;

	epf_set_drvdata(epf, vnet);
	vnet->epf = epf;

	epf_vnet_virtio_init(vnet);

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
