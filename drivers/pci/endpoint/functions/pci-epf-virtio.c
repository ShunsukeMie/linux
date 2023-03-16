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

#define VIRTIO_PCI_LEGACY_CONFIG_BAR BAR_0
static void __iomem *epf_virtio_alloc_bar(struct pci_epf *epf, size_t bar_size)
{
	const struct pci_epc_features *features;
	struct pci_epf_bar *config_bar =
		&epf->bar[VIRTIO_PCI_LEGACY_CONFIG_BAR];
	void __iomem *cfg_base;
	int err;

	features = pci_epc_get_features(epf->epc, epf->func_no, epf->vfunc_no);
	if (!features) {
		pr_debug("Failed to get PCI EPC features\n");
		return ERR_PTR(-EOPNOTSUPP);
	}

	if (features->bar_fixed_size[VIRTIO_PCI_LEGACY_CONFIG_BAR]) {
		if (bar_size >
		    features->bar_fixed_size[VIRTIO_PCI_LEGACY_CONFIG_BAR]) {
			pr_debug("PCI BAR size is not enough\n");
			return ERR_PTR(-ENOMEM);
		}
	}

	config_bar->flags |= PCI_BASE_ADDRESS_MEM_TYPE_64;

	cfg_base = pci_epf_alloc_space(epf, bar_size,
				       VIRTIO_PCI_LEGACY_CONFIG_BAR,
				       features->align, PRIMARY_INTERFACE);
	if (!cfg_base)
		return ERR_PTR(-ENOMEM);

	err = pci_epc_set_bar(epf->epc, epf->func_no, epf->vfunc_no,
			      config_bar);
	if (err)
		return ERR_PTR(err);

	return cfg_base;
}

struct epf_virtio *epf_virtio_alloc(struct pci_epf *epf, unsigned nvqs,
				    size_t vqsize, u64 features)
{
	struct epf_virtio *evio;

	evio = kzalloc(sizeof(*evio), GFP_KERNEL);
	if (!evio)
		return ERR_PTR(-ENOMEM);

	evio->epf = epf;
	evio->nvqs = nvqs;
	evio->vqsize = vqsize;
	evio->features = features;

	return evio;
}
EXPORT_SYMBOL_GPL(epf_virtio_alloc);

int epf_virtio_setup_pci(struct epf_virtio *evio, struct pci_epf_header *header,
			 size_t bar_size)
{
	int err;
	void __iomem *bar;
	struct pci_epf *epf = evio->epf;

	err = pci_epc_write_header(epf->epc, epf->func_no, epf->vfunc_no,
				   header);
	if (err)
		return err;

	bar = epf_virtio_alloc_bar(epf, bar_size);
	if (IS_ERR(bar))
		return PTR_ERR(bar);

	evio->bar_base = bar;

	return 0;
}
EXPORT_SYMBOL_GPL(epf_virtio_setup_pci);

static int epf_virtio_negotiate_qinfo(struct epf_virtio *evio)
{
	u32 pfn;
	u16 sel;
	int _qinfo_index = 0;
	struct {
		u32 pfn;
		u16 sel;
	} *_qinfo;
	u16 default_sel = evio->nvqs;
	int err;

	if (!evio->bar_base)
		return -EINVAL;

	_qinfo = kmalloc_array(evio->nvqs, sizeof(*_qinfo), GFP_KERNEL);
	if (!_qinfo)
		return -ENOMEM;

	evio->vrh = kmalloc_array(evio->nvqs, sizeof(evio->vrh[0]), GFP_KERNEL);
	if (!evio->vrh) {
		//TODO free(_qinfo); or goto
		return -ENOMEM;
	}

	epf_virtio_pcicfg_write16(evio, VIRTIO_PCI_QUEUE_SEL, default_sel);

	while (_qinfo_index < evio->nvqs) {
		pfn = epf_virtio_pcicfg_read32(evio, VIRTIO_PCI_QUEUE_PFN);
		if (pfn == 0)
			continue;

		epf_virtio_pcicfg_write32(evio, VIRTIO_PCI_QUEUE_PFN, 0);

		sel = epf_virtio_pcicfg_read16(evio, VIRTIO_PCI_QUEUE_SEL);
		if (sel == default_sel)
			continue;

		_qinfo[_qinfo_index].pfn = pfn;
		_qinfo[_qinfo_index].sel = sel;
		_qinfo_index++;
	}

	for (int i = 0; i < evio->nvqs; ++i) {
		struct epf_vringh *vrh;
		phys_addr_t pci_addr = (phys_addr_t)_qinfo[i].pfn
				       << VIRTIO_PCI_QUEUE_ADDR_SHIFT;
		vrh = epf_virtio_alloc_vringh(evio->epf, evio->features, pci_addr,
					      evio->vqsize);
		if (IS_ERR(vrh)) {
			err = PTR_ERR(vrh);
			goto err_free_epf_vringh;
		}
		if (_qinfo[i].sel >= evio->nvqs) {
			// invalid queue selector;
			err = -EIO;
			goto err_free_epf_vringh;
		}
		evio->vrh[_qinfo[i].sel] = vrh;
	}

	kfree(_qinfo);

	return 0;

err_free_epf_vringh:
	//TODO epf_virtio_free_vringh()

	return err;
}

struct negotiator_param {
	struct epf_virtio *evio;
	void (*callback)(void *);
	void *arg;
};

static int epf_virtio_reg_negotiator(void *data)
{
	struct negotiator_param *param = data;
	struct epf_virtio *evio = param->evio;
	int err;

	err = epf_virtio_negotiate_qinfo(evio);
	if (err) {
		pr_info("failed to negotiate virtqueue info\n");
		return err;
	}

	param->callback(param->arg);

	return 0;
}

int epf_virtio_run_negotiator(struct epf_virtio *evio,
			      void (*complete_callback)(void *arg),
			      void *callback_arg)
{
	struct negotiator_param *thread_param;

	thread_param = kmalloc(sizeof(*thread_param), GFP_KERNEL);
	if (!thread_param) {
		return -ENOMEM;
	}

	thread_param->evio = evio;
	thread_param->callback = complete_callback;
	thread_param->arg = callback_arg;

	evio->negotiate_task = kthread_create(epf_virtio_reg_negotiator,
					      thread_param,
					      "epf-virtio/cfg_negotiator");
	if (IS_ERR(evio->negotiate_task))
		return PTR_ERR(evio->negotiate_task);

	/* Change the thread priority to high for the polling. */
	sched_set_fifo(evio->negotiate_task);
	wake_up_process(evio->negotiate_task);

	return 0;
}
EXPORT_SYMBOL_GPL(epf_virtio_run_negotiator);

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
