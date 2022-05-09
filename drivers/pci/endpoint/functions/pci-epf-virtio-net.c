/*
 * Endpoint function driver to implement pci virtio-net functionality.
 *
 */

#include <linux/module.h>
#include <linux/pci-epf.h>

static int epf_virtio_net_bind(struct pci_epf *epf)
{
	return 0;
}

static void epf_virtio_net_unbind(struct pci_epf *epf)
{
}

static struct pci_epf_ops epf_virtio_net_ops = {
	.bind = epf_virtio_net_bind,
	.unbind = epf_virtio_net_unbind,
};

static int epf_virtio_net_probe(struct pci_epf *epf)
{
	return 0;
}

static struct pci_epf_driver virtio_net_driver = {
	.driver.name = "pci_epf_virtio_net",
	.ops = &epf_virtio_net_ops,
	.probe = epf_virtio_net_probe,
	.owner = THIS_MODULE
};

static int __init epf_virtio_net_init(void)
{
	int ret;

	ret = pci_epf_register_driver(&virtio_net_driver);
	if (ret) {
		pr_err("Failed to register pci epf virtio-net driver: %d\n",
		       ret);
		return ret;
	}

	return 0;
}
module_init(epf_virtio_net_init);

static void epf_virtio_net_exit(void)
{
}
module_exit(epf_virtio_net_exit);

MODULE_LICENSE("GPL");
