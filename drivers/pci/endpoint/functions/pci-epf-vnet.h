/* SPDX-License-Identifier: GPL-2.0 */
#ifndef PCI_EPF_VNET_H
#define PCI_EPF_VNET_H

#include <linux/virtio.h>
#include <linux/virtio_net.h>
#include <linux/vringh.h>
#include <linux/pci-epf.h>
#include <linux/dmaengine.h>

struct epf_vnet {
	// common
	u32 features;
	struct virtio_net_config net_cfg;
	struct dma_chan *rl_dma_chan, *lr_dma_chan;
	struct workqueue_struct *irq_wq;
	struct work_struct raise_irq_work;
	struct pci_epf *epf;

	// for ep
	struct virtio_device vdev;
	void *pci_cfg_base;
	struct _ep {
		struct vringh rx_vrh, tx_vrh;
		struct vringh_kiov txiov, rxiov;
		struct workqueue_struct *tx_wq;
		struct work_struct tx_work;
		struct virtqueue *rxvq;
	} ep;

	// for rc
	struct task_struct *monitor_config_task;
	struct task_struct *monitor_notify_task;
	struct _rc {
		struct vringh rx_vrh, tx_vrh;
		struct vringh_kiov txiov, rxiov;
		struct workqueue_struct *tx_wq;
		struct work_struct tx_work; //, rx_work;
	} rc;
	bool rc_init_done;
};

extern struct pci_epf_header epf_vnet_pci_header;

int epf_vnet_virtqueue_size(void);

int epf_vnet_setup_local(struct epf_vnet *vnet, struct device *parent);
int epf_vnet_setup_rc(struct pci_epf *epf);
void epf_vnet_cleanup_rc(struct pci_epf *epf);

int epf_vnet_dma_single(struct epf_vnet *vnet, phys_addr_t pci, dma_addr_t dma,
			size_t len, void (*callback)(void *), void *param,
			enum dma_transfer_direction dir);

#endif // PCI_EPF_VNET_H
