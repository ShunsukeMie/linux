// SPDX-License-Identifier: GPL-2.0
/*
 * PCI Endpoint function driver to impliment virtio-net device.
 */
#include <linux/module.h>
#include <linux/pci-epf.h>
#include <linux/pci-epc.h>
#include <linux/vringh.h>
#include <linux/dmaengine.h>

#include "pci-epf-vnet.h"

static int virtio_queue_size = 0x100;
module_param(virtio_queue_size, int, 0444);
MODULE_PARM_DESC(virtio_queue_size, "A length of virtqueue");

int epf_vnet_get_vq_size(void)
{
	return virtio_queue_size;
}

int epf_vnet_init_kiov(struct vringh_kiov *kiov, const size_t vq_size)
{
	struct kvec *kvec;

	kvec = kmalloc_array(vq_size, sizeof(*kvec), GFP_KERNEL);
	if (!kvec)
		return -ENOMEM;

	vringh_kiov_init(kiov, kvec, vq_size);

	return 0;
}

void epf_vnet_deinit_kiov(struct vringh_kiov *kiov)
{
	kfree(kiov->iov);
}

void epf_vnet_init_complete(struct epf_vnet *vnet, u8 from)
{
	vnet->init_complete |= from;

	if (!(vnet->init_complete & EPF_VNET_INIT_COMPLETE_EP))
		return;

	if (!(vnet->init_complete & EPF_VNET_INIT_COMPLETE_RC))
		return;

	epf_vnet_ep_announce_linkup(vnet);
	epf_vnet_rc_announce_linkup(vnet);
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

static int epf_vnet_dma_single(struct epf_vnet *vnet, phys_addr_t pci,
			       dma_addr_t dma, size_t len,
			       void (*callback)(void *), void *param,
			       enum dma_transfer_direction dir)
{
	struct dma_async_tx_descriptor *desc;
	int err;
	struct dma_chan *chan;
	struct dma_slave_config sconf;
	dma_cookie_t cookie;
	unsigned long flags = 0;

	if (dir == DMA_MEM_TO_DEV) {
		sconf.dst_addr = pci;
		chan = vnet->lr_dma_chan;
	} else {
		sconf.src_addr = pci;
		chan = vnet->rl_dma_chan;
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

struct epf_vnet_dma_callback_param {
	struct epf_vnet *vnet;
	struct vringh *tx_vrh, *rx_vrh;
	struct virtqueue *vq;
	size_t total_len;
	u16 tx_head, rx_head;
};

static void epf_vnet_dma_callback(void *p)
{
	struct epf_vnet_dma_callback_param *param = p;
	struct epf_vnet *vnet = param->vnet;

	vringh_complete(param->tx_vrh, param->tx_head, param->total_len);
	vringh_complete(param->rx_vrh, param->rx_head, param->total_len);

	epf_vnet_rc_notify(vnet);
	epf_vnet_ep_notify(vnet, param->vq);

	kfree(param);
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
	int err;
	u16 tx_head, rx_head;
	size_t total_tx_len;
	struct epf_vnet_dma_callback_param *cb_param;
	struct vringh_kiov *liov, *riov;

	err = vringh_getdesc(tx_vrh, tx_iov, NULL, &tx_head);
	if (err <= 0)
		return err;

	total_tx_len = vringh_kiov_length(tx_iov);

	err = vringh_getdesc(rx_vrh, NULL, rx_iov, &rx_head);
	if (err < 0) {
		goto err_tx_complete;
	} else if (!err) {
		/* There is not space on a vring of destination to transmit data, so
		 * rollback tx vringh
		 */
		vringh_abandon(tx_vrh, tx_head);
		return -ENOSPC;
	}

	cb_param = kmalloc(sizeof(*cb_param), GFP_KERNEL);
	if (!cb_param) {
		err = -ENOMEM;
		goto err_rx_complete;
	}

	cb_param->tx_vrh = tx_vrh;
	cb_param->rx_vrh = rx_vrh;
	cb_param->tx_head = tx_head;
	cb_param->rx_head = rx_head;
	cb_param->total_len = total_tx_len;
	cb_param->vnet = vnet;

	switch (dir) {
	case DMA_MEM_TO_DEV:
		liov = tx_iov;
		riov = rx_iov;
		cb_param->vq = vnet->ep.txvq;
		break;
	case DMA_DEV_TO_MEM:
		liov = rx_iov;
		riov = tx_iov;
		cb_param->vq = vnet->ep.rxvq;
		break;
	default:
		err = -EINVAL;
		goto err_free_param;
	}

	for (; tx_iov->i < tx_iov->used; tx_iov->i++, rx_iov->i++) {
		size_t len;
		u64 lbase, rbase;
		void (*callback)(void *) = NULL;

		lbase = (u64)liov->iov[liov->i].iov_base;
		rbase = (u64)riov->iov[riov->i].iov_base;
		len = tx_iov->iov[tx_iov->i].iov_len;

		if (tx_iov->i + 1 == tx_iov->used)
			callback = epf_vnet_dma_callback;

		err = epf_vnet_dma_single(vnet, rbase, lbase, len, callback,
					  cb_param, dir);
		if (err)
			goto err_free_param;
	}

	return 1;

err_free_param:
	kfree(cb_param);
err_rx_complete:
	vringh_complete(rx_vrh, rx_head, vringh_kiov_length(rx_iov));
err_tx_complete:
	vringh_complete(tx_vrh, tx_head, total_tx_len);

	return err;
}

static int epf_vnet_bind(struct pci_epf *epf)
{
	int err;
	struct epf_vnet *vnet = epf_get_drvdata(epf);

	err = epf_vnet_init_edma(vnet, epf->epc->dev.parent);
	if (err)
		return err;

	err = epf_vnet_rc_setup(vnet);
	if (err)
		goto err_free_edma;

	err = epf_vnet_ep_setup(vnet);
	if (err)
		goto err_cleanup_rc;

	return 0;

err_free_edma:
	epf_vnet_deinit_edma(vnet);
err_cleanup_rc:
	epf_vnet_rc_cleanup(vnet);

	return err;
}

static void epf_vnet_unbind(struct pci_epf *epf)
{
	struct epf_vnet *vnet = epf_get_drvdata(epf);

	epf_vnet_deinit_edma(vnet);
	epf_vnet_rc_cleanup(vnet);
	epf_vnet_ep_cleanup(vnet);
}

static struct pci_epf_ops epf_vnet_ops = {
	.bind = epf_vnet_bind,
	.unbind = epf_vnet_unbind,
};

static const struct pci_epf_device_id epf_vnet_ids[] = {
	{ .name = "pci_epf_vnet" },
	{}
};

static void epf_vnet_virtio_init(struct epf_vnet *vnet)
{
	vnet->virtio_features =
		BIT(VIRTIO_NET_F_MTU) | BIT(VIRTIO_NET_F_STATUS) |
		/* Following features are to skip any of checking and offloading, Like a
		 * transmission between virtual machines on same system. Details are on
		 * section 5.1.5 in virtio specification.
		 */
		BIT(VIRTIO_NET_F_GUEST_CSUM) | BIT(VIRTIO_NET_F_GUEST_TSO4) |
		BIT(VIRTIO_NET_F_GUEST_TSO6) | BIT(VIRTIO_NET_F_GUEST_ECN) |
		BIT(VIRTIO_NET_F_GUEST_UFO) |
		// The control queue is just used for linkup announcement.
		BIT(VIRTIO_NET_F_CTRL_VQ) |
		BIT(VIRTIO_NET_F_ROCE);

	vnet->vnet_cfg.max_virtqueue_pairs = 1;
	vnet->vnet_cfg.status = 0;
	vnet->vnet_cfg.mtu = PAGE_SIZE;

#if defined(CONFIG_PCI_EPF_VNET_ROCE)
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
	vnet->roce_attr.max_mw = 0;
	vnet->roce_attr.max_pd = 0x7ffc;
	vnet->roce_attr.max_qp_rd_atom = 128;
	vnet->roce_attr.max_qp_init_rd_atom = 128;
	vnet->roce_attr.max_ah = 100;
	vnet->roce_attr.max_fast_reg_page_list_len = 512;
	vnet->roce_attr.local_ca_ack_delay = 15;
#endif // CONFIG_PCI_EPF_VNET_ROCE
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
