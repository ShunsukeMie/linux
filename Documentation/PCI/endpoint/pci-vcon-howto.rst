.. SPDX-License-Identifier: GPL-2.0

===================================================================
PCI VirtIo Console Endpoint Function (EPF) User Guide
===================================================================

:Author: Shunsuke Mie <mie@igel.co.jp>

This document is a guide to help users use pci-epf-vcon function driver.

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


 Endpoint Function Drivers
-------------------------

To find the list of endpoint function drivers in the system::

	# ls /sys/bus/pci-epf/drivers
	  pci_epf_vcon

If PCI_ENDPOINT_CONFIGFS is enabled::

	# ls /sys/kernel/config/pci_ep/functions
	  pci_epf_vcon


 Creating pci-epf-test Device
----------------------------

PCI endpoint function device can be created using the configfs. To create
pci-epf-test device, the following commands can be used::

	# mount -t configfs none /sys/kernel/config
	# cd /sys/kernel/config/pci_ep/
	# mkdir functions/pci_epf_test/func1

The "mkdir func1" above creates the pci-epf-test function device that will
be probed by pci_epf_test driver.
                                                                                                                                   │         #################################################################

Binding pci-epf-test Device to EP Controller
--------------------------------------------

In order for the endpoint function device to be useful, it has to be bound to
a PCI endpoint controller driver. Use the configfs to bind the function
device to one of the controller driver present in the system::

	# ln -s functions/pci_epf_test/func1 controllers/e65d0000.pcie-ep/

Once the above step is completed, the PCI endpoint is ready to establish a link
with the host.


Start the Link
--------------

In order for the endpoint device to establish a link with the host, the _start_
field should be populated with '1'::

	# echo 1 > controllers/e65d0000.pcie-ep/start


RootComplex Device
==================

lspci Output
------------

Note that the devices listed here correspond to the value populated in 1.4
above::

  00:00.0 PCI bridge: Renesas Technology Corp. Device 0025
  01:00.0 Serial controller: Red Hat, Inc. Virtio console
  01:00.1 Unassigned class [ff00]: Renesas Technology Corp. Device 0031


Acess to Root complex tty
=========================


Check if it is start tty
------------------------

On root complex, systemd-getty automatically start agetty for the virtio console device(/dev/hvc0).
You can check like this::
  
  # ps -aux | grep agetty
  316 root      5028 S    /sbin/agetty -o -p -- \u --noclear tty1 linux
  317 root      2056 S    /sbin/agetty -8 -L hvc0 115200 xterm


Connect to the tty
--------------

On endpoint, you can connect the tty using terminal emulator (minicom or picocom, for example).
Connect like this::

  # picocom /dev/hvc0
  Poky (Yocto Project Reference Distro) 3.1.3 salvator-x hvc0
  salvator-x login:
