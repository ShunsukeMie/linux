// SPDX-License-Identifier: GPL-2.0
#ifndef __PCI_EPF_VIRTIO_H__
#define __PCI_EPF_VIRTIO_H__

#include <linux/sched.h>

struct epf_vringh {
	struct vringh vrh;
	void __iomem *virt;
	phys_addr_t phys;
	unsigned int num;
};

struct epf_vringh *epf_virtio_alloc_vringh(struct pci_epf *epf, u64 features,
					   phys_addr_t pci_addr,
					   unsigned int num);
void epf_virtio_free_vringh(struct pci_epf *epf, struct epf_vringh *evrh);

struct task_struct *epf_virtio_start_notify_monitor(u16 __iomem *queue_notify,
						    u16 notify_default,
						    void (*callback)(void *),
						    void *param);

struct epf_virtio_qinfo {
	phys_addr_t pci_addr;
	u16 sel;
};

int epf_virtio_negotiate_qinfo(void __iomem *pci_cfg_base,
			       struct epf_virtio_qinfo *qinfo, size_t nqinfo);

#endif /* __PCI_EPF_VIRTIO_H__ */
