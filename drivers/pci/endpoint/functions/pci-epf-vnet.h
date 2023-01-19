// SPDX-License-Identifier: GPL-2.0
#ifndef _PCI_EPF_VNET_H
#define _PCI_EPF_VNET_H

#include <linux/pci-epf.h>
#include <linux/pci-epf-virtio.h>
#include <linux/virtio_net.h>

enum epf_vnet_tx_dir { EPF_VNET_TX_DIR_EP_TO_RC, EPF_VNET_TX_DIR_RC_TO_EP };

struct epf_vnet {
	//TODO Should this variable be placed here?
	struct pci_epf *epf;
	struct pci_epf_virtio virtio;
	struct virtio_net_config vnet_cfg;

	struct {
		void __iomem *cfg_base;
		struct task_struct *device_setup_task;
		struct task_struct *notify_monitor_task;
		struct workqueue_struct *tx_wq;
		struct work_struct tx_work;
		struct pci_epf_vringh *txvrh, *rxvrh;
		struct vringh_kiov tx_iov, rx_iov;
	} rc;
};

int epf_vnet_rc_setup(struct epf_vnet *vnet);
int epf_vnet_get_vq_size(void);

#endif // _PCI_EPF_VNET_H
