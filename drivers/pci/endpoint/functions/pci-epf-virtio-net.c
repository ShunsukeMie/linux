/*
 * Endpoint function driver to implement pci virtio-net functionality.
 *
 */

#include <linux/module.h>

static int __init pci_epf_virtio_net_init(void)
{
	return 0;
}
module_init(pci_epf_virtio_net_init);

static void pci_epf_virtio_net_exit(void)
{
}
module_exit(pci_epf_virtio_net_exit);

MODULE_LICENSE("GPL");
