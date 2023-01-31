// SPDX-License-Identifier: GPL-2.0
/*
 * Virtio library for PCI Endpoint function
 */

#include <linux/kernel.h>
#include <linux/pci-epf-virtio.h>
#include <linux/pci-epc.h>
#include <linux/virtio_pci.h>

void pci_epf_virtio_init(struct pci_epf_virtio *virtio, u32 features)
{
	virtio->features = features;
}

void __iomem *_epf_virtio_map_vq(struct pci_epf *epf, u32 pfn, size_t size,
				 phys_addr_t *vq_phys)
{
	int err;
	phys_addr_t vq_addr;
	size_t vq_size;
	void __iomem *vq_virt;

	vq_addr = (phys_addr_t)pfn << VIRTIO_PCI_QUEUE_ADDR_SHIFT;

	vq_size = vring_size(size, VIRTIO_PCI_VRING_ALIGN); // + 100;

	vq_virt = pci_epc_mem_alloc_addr(epf->epc, vq_phys, vq_size);
	if (!vq_virt) {
		pr_err("Failed to allocate epc memory\n");
		return ERR_PTR(-ENOMEM);
	}

	err = pci_epc_map_addr(epf->epc, epf->func_no, epf->vfunc_no, *vq_phys,
			       vq_addr, vq_size);
	if (err) {
		pr_err("Failed to map virtuqueue to local");
		goto err_free;
	}

	return vq_virt;

err_free:
	pci_epc_mem_free_addr(epf->epc, *vq_phys, vq_virt, vq_size);

	return ERR_PTR(err);
}

void _epf_virtio_unmap_vq(struct pci_epf *epf, void __iomem *vq_virt,
			  phys_addr_t vq_phys, size_t size)
{
	pci_epc_unmap_addr(epf->epc, epf->func_no, epf->vfunc_no, vq_phys);
	pci_epc_mem_free_addr(epf->epc, vq_phys, vq_virt,
			      vring_size(size, VIRTIO_PCI_VRING_ALIGN));
}

struct pci_epf_vringh *pci_epf_virtio_alloc_vringh(struct pci_epf *epf,
						   u64 features, u16 pfn,
						   size_t size)
{
	int err;
	struct vring vring;
	struct pci_epf_vringh *evrh;

	evrh = kmalloc(sizeof *evrh, GFP_KERNEL);
	if (!evrh) {
		err = -ENOMEM;
		goto err_unmap_vq;
	}

	evrh->size = size;

	evrh->virt = _epf_virtio_map_vq(epf, pfn, size, &evrh->phys);
	if (IS_ERR(evrh->virt))
		return evrh->virt;

	vring_init(&vring, size, evrh->virt, VIRTIO_PCI_VRING_ALIGN);

	err = vringh_init_iomem(&evrh->vrh, features, size, false, GFP_KERNEL,
				vring.desc, vring.avail, vring.used);
	if (err)
		goto err_free_epf_vq;

	return evrh;

err_free_epf_vq:
	kfree(evrh);

err_unmap_vq:
	_epf_virtio_unmap_vq(epf, evrh->virt, evrh->phys, evrh->size);

	return ERR_PTR(err);
}

void pci_epf_virtio_free_vringh(struct pci_epf *epf,
				struct pci_epf_vringh *evrh)
{
	_epf_virtio_unmap_vq(epf, evrh->virt, evrh->phys, evrh->size);
	kfree(evrh);
}
