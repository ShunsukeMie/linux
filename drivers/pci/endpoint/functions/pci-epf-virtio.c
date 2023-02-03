// SPDX-License-Identifier: GPL-2.0
/*
 *
 */
#include <asm/io.h>
#include <linux/slab.h>
#include <linux/kthread.h>
#include <linux/vringh.h>
#include <linux/pci-epf.h>
#include <linux/pci-epc.h>
#include <linux/virtio_pci.h>

#include "pci-epf-virtio.h"

struct epf_virtio_monitor_param {
	void __iomem *queue_notify;
	u16 notify_default;
	void (*callback)(void *);
	void *param;
};

static int epf_virtio_monitor_notify(void *param)
{
	struct epf_virtio_monitor_param *mparam = param;
	const u16 notify_default = mparam->notify_default;

	while (true) {
		while (ioread16(mparam->queue_notify) == notify_default)
			;
		iowrite16(notify_default, mparam->queue_notify);

		mparam->callback(mparam->param);
	}

	return 0;
}

/**
 * epf_virtio_start_notify_monitor() - launch a thread polling notify queue
 * register to detect changes.
 * @queue_notify:
 * @notify_default:
 * @callback:
 * @param:
 */
struct task_struct *epf_virtio_start_notify_monitor(u16 __iomem *queue_notify,
						    u16 notify_default,
						    void (*callback)(void *),
						    void *param)
{
	struct epf_virtio_monitor_param *monitor_param;
	struct task_struct *monitor_task;

	monitor_param = kmalloc(sizeof(*monitor_param), GFP_KERNEL);
	if (!monitor_param)
		return ERR_PTR(-ENOMEM);

	monitor_param->queue_notify = queue_notify;
	monitor_param->notify_default = notify_default;
	monitor_param->callback = callback;
	monitor_param->param = param;

	monitor_task = kthread_create(epf_virtio_monitor_notify, monitor_param,
				      "epf-virtio/notify_monitor");

	/* Change the thread priority to high for polling. */
	sched_set_fifo(monitor_task);
	wake_up_process(monitor_task);

	return monitor_task;
}
EXPORT_SYMBOL_GPL(epf_virtio_start_notify_monitor);

static void __iomem *epf_virtio_map_vq(struct pci_epf *epf,
				       phys_addr_t vq_pci_addr,
				       unsigned int num, phys_addr_t *vq_phys)
{
	int err;
	size_t vq_size;
	void __iomem *vq_virt;

	vq_size = vring_size(num, VIRTIO_PCI_VRING_ALIGN);

	vq_virt = pci_epc_map_addr(epf->epc, epf->func_no, epf->vfunc_no,
				   vq_pci_addr, vq_phys, vq_size);
	if (IS_ERR(vq_virt)) {
		pr_err("Failed to map virtuqueue to local");
		goto err_free;
	}

	return vq_virt;

err_free:
	pci_epc_mem_free_addr(epf->epc, *vq_phys, vq_virt, vq_size);

	return ERR_PTR(err);
}

static void epf_virtio_unmap_vq(struct pci_epf *epf, void __iomem *vq_virt,
				phys_addr_t vq_phys, unsigned int num)
{
	size_t vq_size = vring_size(num, VIRTIO_PCI_VRING_ALIGN);

	pci_epc_unmap_addr(epf->epc, epf->func_no, epf->vfunc_no, vq_phys,
			   vq_virt, vq_size);
	pci_epc_mem_free_addr(epf->epc, vq_phys, vq_virt, vq_size);
}

/**
 * epf_virtio_alloc_vringh() - allocate epf vringh from @pfn
 * @epf: the EPF device that communicates to host virtio dirver
 * @features: the virtio features of device
 * @pfn: page frame number of virtqueue located on host memory. It is
 *		passed during virtqueue negotiation.
 * @size: a length of virtqueue
 */
struct epf_vringh *epf_virtio_alloc_vringh(struct pci_epf *epf, u64 features,
					   phys_addr_t pci_addr,
					   unsigned int num)
{
	int err;
	struct vring vring;
	struct epf_vringh *evrh;

	evrh = kmalloc(sizeof(*evrh), GFP_KERNEL);
	if (!evrh) {
		err = -ENOMEM;
		goto err_unmap_vq;
	}

	evrh->num = num;

	evrh->virt = epf_virtio_map_vq(epf, pci_addr, num, &evrh->phys);
	if (IS_ERR(evrh->virt))
		return evrh->virt;

	vring_init(&vring, num, evrh->virt, VIRTIO_PCI_VRING_ALIGN);

	err = vringh_init_iomem(&evrh->vrh, features, num, false, GFP_KERNEL,
				vring.desc, vring.avail, vring.used);
	if (err)
		goto err_free_epf_vq;

	return evrh;

err_free_epf_vq:
	kfree(evrh);

err_unmap_vq:
	epf_virtio_unmap_vq(epf, evrh->virt, evrh->phys, evrh->num);

	return ERR_PTR(err);
}
EXPORT_SYMBOL_GPL(epf_virtio_alloc_vringh);

/**
 * epf_virtio_free_vringh() - release allocated epf vring
 * @epf: the EPF device that communicates to host virtio dirver
 * @evrh: epf vringh to free
 */
void epf_virtio_free_vringh(struct pci_epf *epf, struct epf_vringh *evrh)
{
	epf_virtio_unmap_vq(epf, evrh->virt, evrh->phys, evrh->num);
	kfree(evrh);
}
EXPORT_SYMBOL_GPL(epf_virtio_free_vringh);

int epf_virtio_negotiate_qinfo(void __iomem *pci_cfg_base,
			       struct epf_virtio_qinfo *qinfo, size_t nqinfo)
{
	u32 __iomem *qpfn = pci_cfg_base + VIRTIO_PCI_QUEUE_PFN;
	u16 __iomem *qsel = pci_cfg_base + VIRTIO_PCI_QUEUE_SEL;
	u32 pfn;
	u16 sel;
	int _qinfo_index = 0;
	struct {
		u32 pfn;
		u16 sel;
	} *_qinfo;
	u16 default_sel = nqinfo;

	_qinfo = kmalloc_array(nqinfo, sizeof(*_qinfo), GFP_KERNEL);
	if (!_qinfo)
		return -ENOMEM;

	iowrite16(default_sel, qsel);

	while (_qinfo_index < nqinfo) {
		pfn = ioread32(qpfn);
		if (pfn == 0)
			continue;

		iowrite32(0, qpfn);

		sel = ioread16(qsel);
		if (sel == default_sel)
			continue;

		_qinfo[_qinfo_index].pfn = pfn;
		_qinfo[_qinfo_index].sel = sel;
		_qinfo_index++;
	}

	for (int i = 0; i < _qinfo_index; i++) {
		qinfo[i].pci_addr = (phys_addr_t)_qinfo[i].pfn
				    << VIRTIO_PCI_QUEUE_ADDR_SHIFT;
		qinfo[i].sel = _qinfo[i].sel;
	}

	kfree(_qinfo);

	return _qinfo_index;
}
EXPORT_SYMBOL_GPL(epf_virtio_negotiate_qinfo);

#if 0
int epf_vnet_rhost_negotiate_configs(struct epf_vnet *vnet,
				     struct epf_virtio_qinfo *qinfo,
				     size_t nqinfo)
{
	const u16 default_sel = epf_vnet_rhost_get_number_of_queues(vnet);
	u32 __iomem *queue_pfn = vnet->rhost.cfg_base + VIRTIO_PCI_QUEUE_PFN;
	u16 __iomem *queue_sel = vnet->rhost.cfg_base + VIRTIO_PCI_QUEUE_SEL;
	u8 __iomem *pci_status = vnet->rhost.cfg_base + VIRTIO_PCI_STATUS;
	u32 pfn;
	u16 sel;
	int _qinfo_index = 0;
	struct {
		u32 pfn;
		u16 sel;
	} *_qinfo;

	_qinfo = kmalloc_array(nqinfo, sizeof(*_qinfo), GFP_KERNEL);
	if (!_qinfo)
		return -ENOMEM;

	while (_qinfo_index < nqinfo) {
		pfn = ioread32(queue_pfn);
		if (pfn == 0)
			continue;

		iowrite32(0, queue_pfn);

		sel = ioread16(queue_sel);
		if (sel == default_sel)
			continue;

		_qinfo[_qinfo_index].pfn = pfn;
		_qinfo[_qinfo_index].sel = sel;
		_qinfo_index++;
	}

	while (!(ioread8(pci_status) & VIRTIO_CONFIG_S_DRIVER_OK))
		;

	for (int i = 0; i < _qinfo_index; i++) {
		qinfo[i].pci_addr = (phys_addr_t)_qinfo[i].pfn
				    << VIRTIO_PCI_QUEUE_ADDR_SHIFT;
		qinfo[i].sel = _qinfo[i].sel;
	}

	kfree(_qinfo);

	return _qinfo_index;
}
#endif
