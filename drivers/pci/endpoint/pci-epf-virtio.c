// SPDX-License-Identifier: GPL-2.0
/*
 * Virtio library for PCI Endpoint function
 */

#include <linux/pci-epf-virtio.h>

void pci_epf_virtio_init(struct pci_epf_virtio *virtio, u32 features)
{
	virtio->features = features;
}
