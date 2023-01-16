// SPDX-License-Identifier: GPL-2.0
#ifndef _PCI_EPF_VNET_H
#define _PCI_EPF_VNET_H

#include <linux/pci-epf.h>
#include <linux/pci-epf-virtio.h>
#include <linux/virtio_net.h>

struct epf_vnet {
	//TODO Should this variable be placed here?
	struct pci_epf *epf;
	struct pci_epf_virtio virtio;
	struct virtio_net_config vnet_cfg;

	struct _rc {
		void __iomem *cfg_base;
	} rc;
};

int epf_vnet_rc_setup(struct epf_vnet *vnet);

#endif // _PCI_EPF_VNET_H
