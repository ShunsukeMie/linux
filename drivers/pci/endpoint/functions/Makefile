# SPDX-License-Identifier: GPL-2.0
#
# Makefile for PCI Endpoint Functions
#

obj-$(CONFIG_PCI_EPF_TEST)		+= pci-epf-test.o
obj-$(CONFIG_PCI_EPF_NTB)		+= pci-epf-ntb.o
obj-$(CONFIG_PCI_EPF_VNTB) 		+= pci-epf-vntb.o
obj-$(CONFIG_PCI_EPF_VIRTIO_NET) += pci-epf-vnet.o
pci-epf-vnet-y := pci-epf-vnet-core.o pci-epf-vnet-rc.o pci-epf-vnet-local.o
