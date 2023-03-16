// SPDX-License-Identifier: GPL-2.0
#ifndef __PCI_EPF_VIRTIO_H__
#define __PCI_EPF_VIRTIO_H__

#include <linux/sched.h>
#include <linux/vringh.h>

struct epf_virtio {
	struct pci_epf *epf;
	void __iomem *bar_base;
	struct task_struct *negotiate_task;
	struct epf_vringh **vrh;
	size_t nvqs;
	size_t vqsize;
	u64 features;
};

struct epf_virtio *epf_virtio_alloc(struct pci_epf *epf, unsigned nvqs,
				    size_t vqsize, u64 features);
int epf_virtio_setup_pci(struct epf_virtio *evio, struct pci_epf_header *header,
			 size_t bar_size);
int epf_virtio_run_negotiator(struct epf_virtio *evio,
			      void (*complete_callback)(void *arg),
			      void *callback_arg);

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

inline static u8 epf_virtio_pcicfg_read8(struct epf_virtio *evio, size_t offset)
{
	return ioread8(evio->bar_base + offset);
}

inline static void epf_virtio_pcicfg_write8(struct epf_virtio *evio,
					    size_t offset, u8 value)
{
	iowrite8(value, evio->bar_base + offset);
}

inline static u16 epf_virtio_pcicfg_read16(struct epf_virtio *evio,
					   size_t offset)
{
	return ioread16(evio->bar_base + offset);
}

inline static void epf_virtio_pcicfg_write16(struct epf_virtio *evio,
					     size_t offset, u16 value)
{
	iowrite16(value, evio->bar_base + offset);
}

inline static u32 epf_virtio_pcicfg_read32(struct epf_virtio *evio,
					   size_t offset)
{
	return ioread32(evio->bar_base + offset);
}

inline static void epf_virtio_pcicfg_write32(struct epf_virtio *evio,
					     size_t offset, u32 value)
{
	iowrite32(value, evio->bar_base + offset);
}

#endif /* __PCI_EPF_VIRTIO_H__ */
