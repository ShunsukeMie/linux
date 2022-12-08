#include <linux/module.h>
#include <linux/pci-epc.h>
#include <linux/pci-epf.h>
#include <linux/virtio_pci.h>
#include <linux/dmaengine.h>

#include "pci-epf-vnet.h"

static int virtio_queue_size = 0x100;
module_param(virtio_queue_size, int, S_IRUGO);

int epf_vnet_virtqueue_size(void)
{
	return virtio_queue_size;
}

int epf_vnet_dma_single(struct epf_vnet *vnet, phys_addr_t pci, dma_addr_t dma,
			size_t len, void (*callback)(void *), void *param,
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

static int epf_vnet_init_dma(struct epf_vnet *vnet, struct device *dma_dev)
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
		return -EINVAL;
	}

	param.dma_mask = BIT(DMA_DEV_TO_MEM);
	vnet->rl_dma_chan =
		dma_request_channel(mask, epf_virtnet_dma_filter, &param);
	if (!vnet->rl_dma_chan) {
		pr_info("failed to request dma channel\n");
		return -EINVAL;
	}

	return 0;
}

static int epf_vnet_bind(struct pci_epf *epf)
{
	int err;
	struct epf_vnet *vnet = epf_get_drvdata(epf);

	err = epf_vnet_init_dma(vnet, epf->epc->dev.parent);
	if (err)
		goto err_out;

	err = epf_vnet_setup_rc(epf);
	if (err)
		goto err_out;

	err = epf_vnet_setup_local(vnet, epf->epc->dev.parent);
	if (err)
		goto err_clean_epf;

	return 0;

err_clean_epf:
	epf_vnet_cleanup_rc(epf);
err_out:
	return err;
}

static void epf_vnet_unbind(struct pci_epf *epf)
{
	// epf_vent_cleanup_local(epf);
	epf_vnet_cleanup_rc(epf);
}

static struct pci_epf_ops epf_vnet_ops = {
	.bind = epf_vnet_bind,
	.unbind = epf_vnet_unbind,
};

static const struct pci_epf_device_id epf_vnet_ids[] = {
	{ .name = "pci_epf_virtio_net" },
	{},
};

static void epf_vnet_init_configs(struct epf_vnet *vnet)
{
	//TODO consider to set other features.
	vnet->features = 0
// 		| BIT(VIRTIO_NET_F_MAC)
// 		| BIT(VIRTIO_NET_F_MTU)
// 		| BIT(VIRTIO_NET_F_STATUS)
		| BIT(VIRTIO_NET_F_GUEST_CSUM)
		| BIT(VIRTIO_NET_F_GUEST_TSO4)
		| BIT(VIRTIO_NET_F_GUEST_TSO6)
		| BIT(VIRTIO_NET_F_GUEST_ECN)
		| BIT(VIRTIO_NET_F_GUEST_UFO);
		;

	vnet->net_cfg.max_virtqueue_pairs = 1;
	vnet->net_cfg.status = VIRTIO_NET_S_LINK_UP;
	vnet->net_cfg.mtu = PAGE_SIZE - ETH_HLEN;
}

static int epf_vnet_probe(struct pci_epf *epf)
{
	int err;
	struct epf_vnet *vnet;

	vnet = devm_kzalloc(&epf->dev, sizeof *vnet, GFP_KERNEL);
	if (!vnet) {
		err = -ENOMEM;
		goto err_out;
	}

	epf_vnet_init_configs(vnet);

	vnet->epf = epf;
	epf_set_drvdata(epf, vnet);

	return 0;

err_out:
	return err;
}

static struct pci_epf_driver epf_vnet_drv = {
	.driver.name = "epf_vnet",
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
		pr_err("Failed to register a epf driver: %d\n", err);
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
MODULE_AUTHOR("author is author");
MODULE_DESCRIPTION("PCI endpoint function acts as virtio-net");
