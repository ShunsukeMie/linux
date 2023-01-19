// SPDX-License-Identifier: GPL-2.0
/*
 * PCI Endpoint function driver to impliment virtio-net device.
 *
 */
#include <linux/module.h>
#include <linux/pci-epf.h>
#include <linux/vringh.h>

#include "pci-epf-vnet.h"

static int virtio_queue_size = 0x100;
module_param(virtio_queue_size, int, S_IRUGO);

int epf_vnet_get_vq_size(void)
{
	return virtio_queue_size;
}

int epf_vnet_transfer(struct epf_vnet *vnet, enum epf_vnet_tx_dir dir)
{
	struct vringh *tx_vrh, *rx_vrh;
	struct vringh_kiov *tx_iov, *rx_iov;
	int err;
	u16 tx_head, rx_head;
	size_t total_tx_len;

	switch (dir) {
	case EPF_VNET_TX_DIR_EP_TO_RC:
		tx_vrh = &vnet->rc.txvrh->vrh;
		// 			rx_vrh = &vnet->ep.rxvrh->vrh;
		tx_iov = &vnet->rc.tx_iov;
		// 			rx_iov = &vnet->ep.rx_iov;
		break;
	case EPF_VNET_TX_DIR_RC_TO_EP:
		// 			tx_vrh = &vnet->ep.txvrh->vrh;
		rx_vrh = &vnet->rc.rxvrh->vrh;
		// 			tx_iov = &vnet->ep.tx_iov;
		rx_iov = &vnet->rc.rx_iov;
		break;
	}

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

	// TODO the rx_iov range should be checked.
	for (; tx_iov->i < tx_iov->used; tx_iov->i++, rx_iov->i++) {
	}

	vringh_complete(tx_vrh, tx_head, total_tx_len);
	vringh_complete(rx_vrh, rx_head, total_tx_len);

	return 1;
}

static int epf_vnet_bind(struct pci_epf *epf)
{
	int err;
	struct epf_vnet *vnet = epf_get_drvdata(epf);

	err = epf_vnet_rc_setup(vnet);
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
