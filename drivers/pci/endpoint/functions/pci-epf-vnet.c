// SPDX-License-Identifier: GPL-2.0
/*
 * PCI Endpoint function driver to impliment virtio-net device.
 *
 */
#include <linux/module.h>
#include <linux/pci-epf.h>
#include <linux/pci-epc.h>
#include <linux/vringh.h>
#include <linux/dmaengine.h>

#include "pci-epf-vnet.h"

static int virtio_queue_size = 0x100;
module_param(virtio_queue_size, int, S_IRUGO);

int epf_vnet_get_vq_size(void)
{
	return virtio_queue_size;
}

void epf_vnet_init_complete(struct epf_vnet *vnet, u8 from)
{
	int err;

	vnet->init_complete |= from;

	//TODO change to use kernel utililty functions
	if ((vnet->init_complete & EPF_VNET_INIT_COMPLETE_EP) &&
	    (vnet->init_complete & EPF_VNET_INIT_COMPLETE_RC)) {

		err = epf_vnet_ep_announce_linkup(vnet);
		if (err) {
			pr_err("failed to announce linkup to ep driver\n");
			return;
		}
		err = epf_vnet_rc_raise_config_irq(vnet);
		if (err) {
			pr_err("failed to announce linkup to rc driver\n");
			return;
		}

		epf_vnet_ep_raise_config_irq(vnet);
		epf_vnet_rc_raise_config_irq(vnet);
		return;
	}
}

struct epf_dma_filter_param {
	struct device *dev;
	u32 dma_mask;
};

static bool epf_virtnet_dma_filter(struct dma_chan *chan, void *param)
{
	struct epf_dma_filter_param *fparam = param;
	struct dma_slave_caps caps;

	memset(&caps, 0, sizeof caps);
	dma_get_slave_caps(chan, &caps);

	return chan->device->dev == fparam->dev &&
	       (fparam->dma_mask & caps.directions);
}

static int epf_vnet_init_edma(struct epf_vnet *vnet, struct device *dma_dev)
{
	dma_cap_mask_t mask;
	struct epf_dma_filter_param param;

	dma_cap_zero(mask);
	dma_cap_set(DMA_SLAVE, mask);

	param.dev = dma_dev;
	param.dma_mask = BIT(DMA_MEM_TO_DEV);
	vnet->lr_dma_chan =
		dma_request_channel(mask, epf_virtnet_dma_filter, &param);
	if (!vnet->lr_dma_chan) {
		pr_info("failed to request dma channel\n");
		return -EOPNOTSUPP;
	}

	param.dma_mask = BIT(DMA_DEV_TO_MEM);
	vnet->rl_dma_chan =
		dma_request_channel(mask, epf_virtnet_dma_filter, &param);
	if (!vnet->rl_dma_chan) {
		pr_info("failed to request dma channel\n");
		return -EOPNOTSUPP;
	}

	vnet->use_dma = true;

	return 0;
	//TODO error handling
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

	if (DMA_MEM_TO_DEV == dir) {
		sconf.dst_addr = pci;
		chan = vnet->lr_dma_chan;
	} else {
		sconf.src_addr = pci;
		chan = vnet->rl_dma_chan;
	}

	err = dmaengine_slave_config(chan, &sconf);
	if (unlikely(err)) {
		pr_err("failed to setup");
		return err;
	}

	if (callback)
		flags = DMA_PREP_INTERRUPT | DMA_PREP_FENCE;

	desc = dmaengine_prep_slave_single(chan, dma, len, dir, flags);
	if (unlikely(!desc))
		return EIO;

	desc->callback = callback;
	desc->callback_param = param;

	cookie = dmaengine_submit(desc);
	err = dma_submit_error(cookie);
	if (unlikely(err)) {
		pr_err("failed to submit dma\n");
		return err;
	}

	dma_async_issue_pending(chan);

	return 0;
}

struct epf_vnet_dma_callback_param {
	struct vringh *tx_vrh, *rx_vrh;
	size_t total_len;
	u16 tx_head, rx_head;
};

static void epf_vnet_dma_callback(void *p)
{
	struct epf_vnet_dma_callback_param *param = p;
	pr_info("callback is called!\n");

	vringh_complete(param->tx_vrh, param->tx_head, param->total_len);
	vringh_complete(param->rx_vrh, param->rx_head, param->total_len);

	//TODO interrupt to each drivers

	kfree(param);
}

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
	if (err < 0) {
		pr_info("Failed to get vring descriptor\n");
		return err;
	} else if (!err) {
		// No data in vring
		return 0;
	}

	total_tx_len = vringh_kiov_length(tx_iov);

	err = vringh_getdesc(rx_vrh, NULL, rx_iov, &rx_head);
	if (err < 0) {
		pr_info("Failed to get vring descriptor\n");
		return err;
	} else if (!err) {
		// No data in vring
		return 0;
	}

	cb_param = kmalloc(sizeof *cb_param, GFP_KERNEL);
	if (!cb_param)
		return -ENOMEM;

	cb_param->tx_vrh = tx_vrh;
	cb_param->rx_vrh = rx_vrh;
	cb_param->tx_head = tx_head;
	cb_param->rx_head = rx_head;
	cb_param->total_len = total_tx_len;

	switch (dir) {
	case DMA_MEM_TO_DEV:
		liov = tx_iov;
		riov = rx_iov;
		break;
	case DMA_DEV_TO_MEM:
		liov = rx_iov;
		riov = tx_iov;
		break;
	default:
		return -EINVAL;
	}

	// TODO the rx_iov range should be checked.
	for (; tx_iov->i < tx_iov->used; tx_iov->i++, rx_iov->i++) {
		size_t len;
		u64 lbase, rbase;
		void (*callback)(void *) = NULL;

		lbase = (u64)liov->iov[liov->i].iov_base;
		rbase = (u64)riov->iov[riov->i].iov_base;
		len = tx_iov->iov[tx_iov->i].iov_len;

		if (tx_iov->i + 1 == tx_iov->used)
			callback = epf_vnet_dma_callback;

		epf_vnet_dma_single(vnet, rbase, lbase, len, callback, cb_param,
				    dir);
	}

	return 1;
}

static int epf_vnet_bind(struct pci_epf *epf)
{
	int err;
	struct epf_vnet *vnet = epf_get_drvdata(epf);

	err = epf_vnet_rc_setup(vnet);
	if (err)
		return err;

	err = epf_vnet_ep_setup(vnet);
	if (err)
		return err;

	return 0;
}

static void epf_vnet_unbind(struct pci_epf *epf)
{
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
	// Common configurations
	pci_epf_virtio_init(&vnet->virtio,
			    BIT(VIRTIO_NET_F_MAC) | BIT(VIRTIO_NET_F_MTU) |
				    BIT(VIRTIO_NET_F_STATUS) |
				    BIT(VIRTIO_NET_F_GUEST_CSUM) |
				    BIT(VIRTIO_NET_F_GUEST_TSO4) |
				    BIT(VIRTIO_NET_F_GUEST_TSO6) |
				    BIT(VIRTIO_NET_F_GUEST_ECN) |
				    BIT(VIRTIO_NET_F_GUEST_UFO) |
				    BIT(VIRTIO_NET_F_CTRL_VQ));

	vnet->vnet_cfg.max_virtqueue_pairs = 1;
	vnet->vnet_cfg.status = 0;
	//TODO fix the mtu
	vnet->vnet_cfg.mtu = PAGE_SIZE;
}

static int epf_vnet_probe(struct pci_epf *epf)
{
	struct epf_vnet *vnet;
	int err;

	vnet = devm_kzalloc(&epf->dev, sizeof *vnet, GFP_KERNEL);
	if (!vnet)
		return -ENOMEM;

	epf_set_drvdata(epf, vnet);
	vnet->epf = epf;

	epf_vnet_virtio_init(vnet);

	err = epf_vnet_init_edma(vnet, epf->epc->dev.parent);
	if (err)
		pr_info("Cannot found PCIe Embedded DMA controller. Fallback to CPU transfer.\n");

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
MODULE_AUTHOR("");
MODULE_DESCRIPTION("PCI endpoint function acts as virtio net device");
