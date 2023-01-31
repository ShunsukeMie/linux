/* SPDX-License-Identifier: GPL-2.0 */
/*
 * PCI Endpoint Function (EPF) for virtio definitions
 */
#ifndef __LINUX_PCI_EPF_VIRTIO_H
#define __LINUX_PCI_EPF_VIRTIO_H

#include <linux/types.h>
#include <linux/vringh.h>
#include <linux/pci-epf.h>

/**
 * struct pci_epf_virtio - represent virtio common data structure.
 * @features: TODO update comment
 *
 */
struct pci_epf_virtio {
	u32 features;
};

struct pci_epf_vringh {
	struct vringh vrh;
	void __iomem *virt;
	phys_addr_t phys;
	size_t size;
};

void pci_epf_virtio_init(struct pci_epf_virtio *virtio, u32 features);

struct pci_epf_vringh *
pci_epf_virtio_alloc_vringh(struct pci_epf *epf, u64 features, u16 pfn,
			    size_t size);
void pci_epf_virtio_free_vringh(struct pci_epf *epf,
				struct pci_epf_vringh *evrh);

#endif // __LINUX_PCI_EPF_VIRTIO_H
