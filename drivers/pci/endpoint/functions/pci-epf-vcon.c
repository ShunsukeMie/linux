// SPDX-License-Identifier: GPL-2.0
/*
 * PCI Endpoint function driver to impliment virtio-console device.
 */

#include <linux/module.h>
#include <linux/pci-epf.h>
#include <linux/virtio_console.h>
#include <linux/virtio_pci.h>

#include "pci-epf-virtio.h"

#define EPF_VCON_VQSIZE 0x100

struct epf_vcon {
	struct epf_virtio *evio;
};

static struct pci_epf_header epf_vcon_pci_header = {
	.vendorid = PCI_VENDOR_ID_REDHAT_QUMRANET,
	.deviceid = VIRTIO_TRANS_ID_CONSOLE,
	.subsys_vendor_id = PCI_VENDOR_ID_REDHAT_QUMRANET,
	.subsys_id = VIRTIO_ID_CONSOLE,
	.revid = 0,
	.baseclass_code = PCI_BASE_CLASS_COMMUNICATION,
	.interrupt_pin = PCI_INTERRUPT_PIN,
};

static void epf_vcon_done_initialize(void *arg)
{
// 	struct epf_vcon *vcon = arg;
	pr_info("done\n");
}

static void epf_vcon_rhost_setup_configs(struct epf_virtio *evio)
{
	u16 default_qindex = evio->nvqs;

	epf_virtio_pcicfg_write32(evio, VIRTIO_PCI_HOST_FEATURES, 0);
	epf_virtio_pcicfg_write16(evio, VIRTIO_PCI_ISR, VIRTIO_PCI_ISR_QUEUE);
	/*
	 * Initialize the queue notify and selector to outside of the appropriate
	 * virtqueue index. It is used to detect change with polling because there is
	 * no other ways to detect host side driver updateing those values
	 */
	epf_virtio_pcicfg_write16(evio, VIRTIO_PCI_QUEUE_NOTIFY, default_qindex);
	epf_virtio_pcicfg_write16(evio, VIRTIO_PCI_QUEUE_SEL, default_qindex);
	/* This pfn is also set to 0 for the polling as well */
	epf_virtio_pcicfg_write16(evio, VIRTIO_PCI_QUEUE_PFN, 0);

	epf_virtio_pcicfg_write16(evio, VIRTIO_PCI_QUEUE_NUM, evio->nvqs);
	epf_virtio_pcicfg_write16(evio, VIRTIO_PCI_STATUS, 0);
}

int epf_vcon_rhost_setup(struct epf_vcon *vcon, struct pci_epf *epf)
{
	struct epf_virtio *evio;
	int err;

	//TODO remove magic number
	evio = epf_virtio_alloc(epf, EPF_VCON_VQSIZE, 2, 0);
	if (IS_ERR(evio))
		return PTR_ERR(evio);

	vcon->evio = evio;

	err = epf_virtio_setup_pci(evio, &epf_vcon_pci_header, sizeof(struct virtio_console_config));
	if (err)
		goto err_free_epf_virtio;

	epf_vcon_rhost_setup_configs(evio);

	err = epf_virtio_run_negotiator(evio, epf_vcon_done_initialize, vcon);
	if (err)
		goto err_free_epf_virtio;

	return 0;

err_free_epf_virtio:
	//TODO epf_virtio_free(evio);

	return err;
}

static int epf_vcon_bind(struct pci_epf *epf)
{
	int err;
	struct epf_vcon *vcon = epf_get_drvdata(epf);

	err = epf_vcon_rhost_setup(vcon, epf);
	if (err)
		return err;

	return 0;
}

static void epf_vcon_unbind(struct pci_epf *epf)
{
}

static struct pci_epf_ops epf_vcon_ops = {
	.bind = epf_vcon_bind,
	.unbind = epf_vcon_unbind,
};

static const struct pci_epf_device_id epf_vcon_ids[] = {
	{ .name = "pci_epf_vcon" },
	{}
};

static int epf_vcon_probe(struct pci_epf *epf)
{
	struct epf_vcon *vcon;

	vcon = devm_kzalloc(&epf->dev, sizeof(*vcon), GFP_KERNEL);
	if (!vcon)
		return -ENOMEM;

	epf_set_drvdata(epf, vcon);

	return 0;
}

static struct pci_epf_driver epf_vcon_drv = {
	.driver.name = "pci_epf_vcon",
	.ops = &epf_vcon_ops,
	.id_table = epf_vcon_ids,
	.probe = epf_vcon_probe,
	.owner = THIS_MODULE,
};

static int __init epf_vcon_init(void)
{
	int err;

	err = pci_epf_register_driver(&epf_vcon_drv);
	if (err) {
		pr_err("Failed to register epf vcon driver\n");
		return err;
	}

	return 0;
}
module_init(epf_vcon_init);

static void epf_vcon_exit(void)
{
	pci_epf_unregister_driver(&epf_vcon_drv);
}
module_exit(epf_vcon_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Shunsuke Mie <mie@igel.co.jp>");
