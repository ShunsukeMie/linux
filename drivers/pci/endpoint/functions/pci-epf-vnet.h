// SPDX-License-Identifier: GPL-2.0
#ifndef _PCI_EPF_VNET_H
#define _PCI_EPF_VNET_H

#include <linux/pci-epf.h>
#include <linux/pci-epf-virtio.h>
#include <linux/virtio_net.h>
#include <linux/dmaengine.h>
#include <linux/virtio.h>

struct epf_vnet {
	//TODO Should this variable be placed here?
	struct pci_epf *epf;
	struct pci_epf_virtio virtio;
	struct virtio_net_config vnet_cfg;

	// dma channels, local to remote(lr) and remote to local(rl)
	struct dma_chan *lr_dma_chan, *rl_dma_chan;
	bool use_dma;

	struct {
		void __iomem *cfg_base;
		struct task_struct *device_setup_task;
		struct task_struct *notify_monitor_task;
		struct workqueue_struct *tx_wq;
		struct work_struct tx_work;
		struct workqueue_struct *irq_wq;
		struct work_struct raise_irq_work;
		struct pci_epf_vringh *txvrh, *rxvrh, *ctlvrh;
		struct vringh_kiov tx_iov, rx_iov, ctl_iov;
	} rc;

	struct {
		struct pci_epf_vringh *txvrh, *rxvrh, *ctlvrh;
		struct vringh_kiov tx_iov, rx_iov, ctl_iov;
		struct virtio_device vdev;
	} ep;
#define EPF_VNET_INIT_COMPLETE_EP BIT(0)
#define EPF_VNET_INIT_COMPLETE_RC BIT(1)
	u8 init_complete;
};

int epf_vnet_rc_setup(struct epf_vnet *vnet);
int epf_vnet_ep_setup(struct epf_vnet *vnet);

int epf_vnet_get_vq_size(void);
int epf_vnet_transfer(struct epf_vnet *vnet, struct vringh *tx_vrh,
		      struct vringh *rx_vrh, struct vringh_kiov *tx_iov,
		      struct vringh_kiov *rx_iov,
		      enum dma_transfer_direction dir);

void epf_vnet_init_complete(struct epf_vnet *vnet, u8 from);
int epf_vnet_ep_announce_linkup(struct epf_vnet *vnet);
int epf_vnet_rc_announce_linkup(struct epf_vnet *vnet);

#endif // _PCI_EPF_VNET_H
