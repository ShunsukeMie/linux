/* SPDX-License-Identifier: GPL-2.0 */

#ifndef __PCI_EPF_TEST_H
#define __PCI_EPF_TEST_H

struct pci_epf_test_reg {
	u32	magic;
#define PCI_ENDPOINT_TEST_COMMAND offsetof(struct pci_epf_test_reg, command)
#define COMMAND_RAISE_LEGACY_IRQ		BIT(0)
#define COMMAND_RAISE_MSI_IRQ			BIT(1)
#define COMMAND_RAISE_MSIX_IRQ			BIT(2)
#define COMMAND_READ				BIT(3)
#define COMMAND_WRITE				BIT(4)
#define COMMAND_COPY				BIT(5)
	u32	command;
#define STATUS_READ_SUCCESS			BIT(0)
#define STATUS_READ_FAIL			BIT(1)
#define STATUS_WRITE_SUCCESS			BIT(2)
#define STATUS_WRITE_FAIL			BIT(3)
#define STATUS_COPY_SUCCESS			BIT(4)
#define STATUS_COPY_FAIL			BIT(5)
#define STATUS_IRQ_RAISED			BIT(6)
#define STATUS_SRC_ADDR_INVALID			BIT(7)
#define STATUS_DST_ADDR_INVALID			BIT(8)
#define PCI_ENDPOINT_TEST_STATUS offsetof(struct pci_epf_test_reg, status)
	u32	status;
#define PCI_ENDPOINT_TEST_SRC_ADDR offsetof(struct pci_epf_test_reg, src_addr)
	u64	src_addr;
#define PCI_ENDPOINT_TEST_DST_ADDR offsetof(struct pci_epf_test_reg, dst_addr)
	u64	dst_addr;
#define PCI_ENDPOINT_TEST_SIZE offsetof(struct pci_epf_test_reg, size)
	u32	size;
#define PCI_ENDPOINT_TEST_COUNT offsetof(struct pci_epf_test_reg, count)
	u32 count;
#define PCI_ENDPOINT_TEST_CHECKSUM offsetof(struct pci_epf_test_reg, checksum)
	u32	checksum;
#define PCI_ENDPOINT_TEST_IRQ_TYPE offsetof(struct pci_epf_test_reg, irq_type)
#define IRQ_TYPE_UNDEFINED			-1
#define IRQ_TYPE_LEGACY				0
#define IRQ_TYPE_MSI				1
#define IRQ_TYPE_MSIX				2
	u32	irq_type;
#define PCI_ENDPOINT_TEST_IRQ_NUMBER offsetof(struct pci_epf_test_reg, irq_number)
	u32	irq_number;
#define PCI_ENDPOINT_TEST_FLAGS offsetof(struct pci_epf_test_reg, flags)
#define FLAG_USE_DMA				BIT(0)
	u32	flags;
} __packed;

#endif /* __PCI_EPF_TEST_H */
