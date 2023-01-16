// SPDX-License-Identifier: GPL-2.0
/*
 * PCI Endpoint function driver to impliment virtio-net device.
 *
 */
#include <linux/module.h>
#include <linux/pci-epf.h>

#include "pci-epf-vnet.h"

static int epf_vnet_bind(struct pci_epf *epf)
{
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
				    BIT(VIRTIO_NET_F_STATUS)
				    //
				    | BIT(VIRTIO_NET_F_GUEST_CSUM) |
				    BIT(VIRTIO_NET_F_GUEST_TSO4) |
				    BIT(VIRTIO_NET_F_GUEST_TSO6) |
				    BIT(VIRTIO_NET_F_GUEST_ECN) |
				    BIT(VIRTIO_NET_F_GUEST_UFO));

	vnet->vnet_cfg.max_virtqueue_pairs = 1;
	//TODO enable the control queue
	vnet->vnet_cfg.status = VIRTIO_NET_S_LINK_UP;
	//TODO fix the mtu
	vnet->vnet_cfg.mtu = PAGE_SIZE;
}

static int epf_vnet_probe(struct pci_epf *epf)
{
	struct epf_vnet *vnet;

	vnet = devm_kzalloc(&epf->dev, sizeof *vnet, GFP_KERNEL);
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
MODULE_AUTHOR("");
MODULE_DESCRIPTION("PCI endpoint function acts as virtio net device");
