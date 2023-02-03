// SPDX-License-Identifier: GPL-2.0
#ifndef __PCI_EPF_VIRTIO_H__
#define __PCI_EPF_VIRTIO_H__

#include <linux/pci-epf.h>
#include <linux/pci-epc.h>
#include <linux/vringh.h>

struct epf_vringh {
	struct vringh vrh;
	void __iomem *virt;
	phys_addr_t phys;
	unsigned int num;
};

struct epf_virtio {
	/* Base PCI endpoint function */
	struct pci_epf *epf;

	/* Virtio parameters */
	u64 features;
	size_t bar_size;
	size_t nvq;
	size_t vqlen;

	/* struct to access virtqueue on remote host */
	struct epf_vringh **vrhs;

	/* struct for thread to emulate virtio device */
	struct task_struct *bgtask;

	/* Virtual address of pci configuration space */
	void __iomem *bar;

	/* Callback function and parameter for queue notifcation */
	void (*qn_callback)(void *);
	void *qn_param;

	/* Callback function and parameter for initialize complete */
	void (*ic_callback)(void *);
	void *ic_param;

	bool running;
};

#define DEFINE_EPF_VIRTIO_CFG_READ(size)                 \
	static inline u##size epf_virtio_cfg_read##size( \
		struct epf_virtio *evio, size_t offset)  \
	{                                                \
		void __iomem *base = evio->bar + offset; \
		return ioread##size(base);               \
	}

DEFINE_EPF_VIRTIO_CFG_READ(8)
DEFINE_EPF_VIRTIO_CFG_READ(16)
DEFINE_EPF_VIRTIO_CFG_READ(32)

#define DEFINE_EPF_VIRTIO_CFG_WRITE(size)                              \
	static inline void epf_virtio_cfg_write##size(                 \
		struct epf_virtio *evio, size_t offset, u##size value) \
	{                                                              \
		void __iomem *base = evio->bar + offset;               \
		iowrite##size(value, base);                            \
	}

DEFINE_EPF_VIRTIO_CFG_WRITE(8);
DEFINE_EPF_VIRTIO_CFG_WRITE(16);
DEFINE_EPF_VIRTIO_CFG_WRITE(32);

int epf_virtio_init(struct epf_virtio *evio, struct pci_epf_header *hdr,
		    size_t bar_size);
void epf_virtio_final(struct epf_virtio *evio);
int epf_virtio_launch_bgtask(struct epf_virtio *evio);
void epf_virtio_terminate_bgtask(struct epf_virtio *evio);
int epf_virtio_reset(struct epf_virtio *evio);

enum epf_virtio_copy_dir {
	EPF_VIRTIO_COPY_DIR_FROM_DEV,
	EPF_VIRTIO_COPY_DIR_TO_DEV,
};

int epf_virtio_vrh_memcpy(struct epf_virtio *evio, struct vringh *svrh,
			  struct vringh_kiov *siov, struct vringh *dvrh,
			  struct vringh_kiov *diov,
			  enum epf_virtio_copy_dir dir);

#endif /* __PCI_EPF_VIRTIO_H__ */
