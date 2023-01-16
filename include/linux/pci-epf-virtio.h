/* SPDX-License-Identifier: GPL-2.0 */
/*
 * PCI Endpoint Function (EPF) for virtio definitions
 */
#ifndef __LINUX_PCI_EPF_VIRTIO_H
#define __LINUX_PCI_EPF_VIRTIO_H

#include <linux/types.h>

/**
 * struct pci_epf_virtio - represent virtio common data structure.
 * @features: TODO update comment
 *
 */
struct pci_epf_virtio {
	u32 features;
};

void pci_epf_virtio_init(struct pci_epf_virtio *virtio, u32 features);

#endif // __LINUX_PCI_EPF_VIRTIO_H
