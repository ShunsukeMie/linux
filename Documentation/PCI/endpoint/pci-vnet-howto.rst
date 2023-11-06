.. SPDX-License-Identifier: GPL-2.0

===================================================================
PCI Virtio-Net Endpoint Function (EPF) User Guide
===================================================================

:Author: Shunsuke Mie <mie@igel.co.jp>

This document is a guide to help users use pci-epf-vnet function driver.

Endpoint Device
===============

Endpoint Controller Devices
---------------------------

To find the list of endpoint controller devices in the system::

	# ls /sys/class/pci_epc/
	e65d0000.pcie-ep

If PCI_ENDPOINT_CONFIGFS is enabled::

	# ls /sys/kernel/config/pci_ep/controllers
	e65d0000.pcie-ep

To find the list of endpoint function drivers in the system::

	# ls /sys/bus/pci-epf/drivers
	pci_epf_vnet

If PCI_ENDPOINT_CONFIGFS is enabled::

	# ls /sys/kernel/config/pci_ep/functions
	pci_epf_vnet


 Creating pci-epf-vnet Device
----------------------------

PCI endpoint function device can be created using the configfs. To create
pci-epf-vnet device, the following commands can be used::

	# mount -t configfs none /sys/kernel/config
	# cd /sys/kernel/config/pci_ep/
	# mkdir functions/pci_epf_vnet/func1

The "mkdir func1" above creates the pci-epf-vnet function device that will
be probed by pci_epf_vnet driver.

After that, a new network devices will show to system, the following
command ca be used to confirm::

  # ip a s eth0
  ...
  5: eth0: <BROADCAST,MULTICAST> mtu 1500 qdisc noop state DOWN group default qlen 1000
      link/ether c6:3b:58:2c:0f:7a brd ff:ff:ff:ff:ff:ff

RootComplex Device
==================

lspci Output
------------

Note that the devices listed here correspond to the value populated in 1.4
above::

  # lspci
  00:00.0 PCI bridge: Renesas Technology Corp. Device 0025
  01:00.0 Ethernet controller: Red Hat, Inc. Virtio network device
  01:00.1 Unassigned class [ff00]: Renesas Technology Corp. Device 0031


ip Output
---

Generated a network interface. The name of the interface is depend on environments.
following command can be used to see the interface::

  # ip a s dev enp1s0f0
  2: enp1s0f0: <BROADCAST,MULTICAST> mtu 1500 qdisc noop state DOWN group default qlen 1000
      link/ether 7e:fb:3a:ba:87:08 brd ff:ff:ff:ff:ff:ff
