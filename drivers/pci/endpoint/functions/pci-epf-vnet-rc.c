// SPDX-License-Identifier: GPL-2.0
/*
 * Functions work for PCie Host side(remote) using EPF framework.
 */
#include <linux/pci-epf.h>
#include <linux/pci-epc.h>
#include <linux/pci_ids.h>
#include <linux/sched.h>
#include <linux/virtio_pci.h>

#include "pci-epf-vnet.h"

#define VIRTIO_NET_LEGACY_CFG_BAR BAR_0

static inline u16 epf_vnet_rc_get_default_queue_index(struct epf_vnet *vnet)
{
	// end of queue is used for control queue (2N)
	// TODO rewrite the comment to be useful.
	return vnet->vnet_cfg.max_virtqueue_pairs * 2 + 1;
}

static void epf_vnet_rc_memcpy_config(struct epf_vnet *vnet, size_t offset,
				      void *buf, size_t len)
{
	void __iomem *base = vnet->rc.cfg_base + offset;
	memcpy_toio(base, buf, len);
}

static void epf_vnet_rc_set_config8(struct epf_vnet *vnet, size_t offset,
				    u8 config)
{
	void __iomem *base = vnet->rc.cfg_base + offset;
	iowrite8(ioread8(base) | config, base);
}

// static void epf_vnet_rc_clear_config8(struct epf_vnet *vnet, size_t offset,
// 				      u8 config)
// {
// 	void __iomem *base = vnet->rc.cfg_base + offset;
// 	iowrite8(ioread8(base) & ~config, base);
// }

static void epf_vnet_rc_set_config16(struct epf_vnet *vnet, size_t offset,
				     u16 config)
{
	void __iomem *base = vnet->rc.cfg_base + offset;
	iowrite16(ioread16(base) | config, base);
}

static void epf_vnet_rc_clear_config16(struct epf_vnet *vnet, size_t offset,
				       u16 config)
{
	void __iomem *base = vnet->rc.cfg_base + offset;
	iowrite16(ioread16(base) & ~config, base);
}

static void epf_vnet_rc_set_config32(struct epf_vnet *vnet, size_t offset,
				     u32 config)
{
	void __iomem *base = vnet->rc.cfg_base + offset;
	iowrite32(ioread32(base) | config, base);
}

// static void epf_vnet_rc_clear_config32(struct epf_vnet *vnet, size_t offset,
// 				       u32 config)
// {
// 	void __iomem *base = vnet->rc.cfg_base + offset;
// 	iowrite32(ioread32(base) & ~config, base);
// }

static void epf_vnet_rc_raise_config_irq(struct epf_vnet *vnet)
{
	/* Add a configuration change flag to isr. The flag is deasserted at tx
	 * handler. */
	epf_vnet_rc_set_config16(vnet, VIRTIO_PCI_ISR, VIRTIO_PCI_ISR_CONFIG);

	// interrupt
	queue_work(vnet->rc.irq_wq, &vnet->rc.raise_irq_work);
}

void epf_vnet_rc_announce_linkup(struct epf_vnet *vnet)
{
	epf_vnet_rc_set_config16(vnet,
				 VIRTIO_PCI_CONFIG_OFF(false) +
					 offsetof(struct virtio_net_config,
						  status),
				 VIRTIO_NET_S_LINK_UP | VIRTIO_NET_S_ANNOUNCE);
	;
	epf_vnet_rc_raise_config_irq(vnet);
}

static struct pci_epf_header epf_vnet_pci_header = {
	.vendorid = PCI_VENDOR_ID_REDHAT_QUMRANET,
	.deviceid = VIRTIO_TRANS_ID_NET,
	.subsys_vendor_id = PCI_VENDOR_ID_REDHAT_QUMRANET,
	.subsys_id = VIRTIO_ID_NET,
	.revid = 0,
	.baseclass_code = PCI_BASE_CLASS_NETWORK,
	.interrupt_pin = PCI_INTERRUPT_PIN,
};

static void epf_vnet_rc_setup_configs(struct epf_vnet *vnet,
				      void __iomem *cfg_base)
{
	u16 default_qindex = epf_vnet_rc_get_default_queue_index(vnet);

	epf_vnet_rc_set_config32(vnet, VIRTIO_PCI_HOST_FEATURES,
				 vnet->virtio_features);

	epf_vnet_rc_set_config16(vnet, VIRTIO_PCI_ISR_QUEUE,
				 VIRTIO_PCI_ISR_QUEUE);
	epf_vnet_rc_set_config16(vnet, VIRTIO_PCI_QUEUE_NOTIFY, default_qindex);
	epf_vnet_rc_set_config16(vnet, VIRTIO_PCI_QUEUE_SEL, default_qindex);
	epf_vnet_rc_set_config16(vnet, VIRTIO_PCI_QUEUE_NUM,
				 epf_vnet_get_vq_size());
	epf_vnet_rc_set_config16(vnet, VIRTIO_PCI_QUEUE_PFN, 0);

	epf_vnet_rc_set_config8(vnet, VIRTIO_PCI_STATUS, 0);
	epf_vnet_rc_memcpy_config(vnet, VIRTIO_PCI_CONFIG_OFF(false),
				  &vnet->vnet_cfg, sizeof vnet->vnet_cfg);
}

static int epf_vnet_setup_bar(struct epf_vnet *vnet)
{
	int err;
	size_t cfg_bar_size =
		VIRTIO_PCI_CONFIG_OFF(false) + sizeof(struct virtio_net_config);
	struct pci_epf *epf = vnet->epf;
	const struct pci_epc_features *features;
	struct pci_epf_bar *config_bar = &epf->bar[VIRTIO_NET_LEGACY_CFG_BAR];

	features = pci_epc_get_features(epf->epc, epf->func_no, epf->vfunc_no);
	if (!features) {
		pr_err("Failed to get PCI EPC features\n");
		return -EOPNOTSUPP;
	}

	if (features->reserved_bar & BIT(VIRTIO_NET_LEGACY_CFG_BAR)) {
		pr_err("Cannot use the PCI BAR for legacy virtio pci\n");
		return -EOPNOTSUPP;
	}

	if (features->bar_fixed_size[VIRTIO_NET_LEGACY_CFG_BAR]) {
		if (cfg_bar_size >
		    features->bar_fixed_size[VIRTIO_NET_LEGACY_CFG_BAR]) {
			pr_err("PCI BAR size is not enough\n");
			return -ENOMEM;
		}
	}

	config_bar->flags |= PCI_BASE_ADDRESS_MEM_TYPE_64;

	vnet->rc.cfg_base = pci_epf_alloc_space(epf, cfg_bar_size,
						VIRTIO_NET_LEGACY_CFG_BAR,
						features->align,
						PRIMARY_INTERFACE);
	if (!vnet->rc.cfg_base) {
		pr_err("Failed to allocate virtio-net config memory\n");
		return -ENOMEM;
	}

	epf_vnet_rc_setup_configs(vnet, vnet->rc.cfg_base);

	err = pci_epc_set_bar(epf->epc, epf->func_no, epf->vfunc_no,
			      config_bar);
	if (err) {
		pr_err("Failed to set PCI BAR");
		goto err_free_space;
	}

	return 0;

err_free_space:
	pci_epf_free_space(epf, vnet->rc.cfg_base, VIRTIO_NET_LEGACY_CFG_BAR,
			   PRIMARY_INTERFACE);
	return err;
}

struct pfn_sel {
	u32 pfn;
	u16 sel;
};

static int epf_vnet_rc_negotiate_configs(struct epf_vnet *vnet, u32 *txpfn,
					 u32 *rxpfn, u32 *ctlpfn)
{
	const u16 default_sel = epf_vnet_rc_get_default_queue_index(vnet);
	u32 __iomem *queue_pfn = vnet->rc.cfg_base + VIRTIO_PCI_QUEUE_PFN;
	u16 __iomem *queue_sel = vnet->rc.cfg_base + VIRTIO_PCI_QUEUE_SEL;
	u8 __iomem *pci_status = vnet->rc.cfg_base + VIRTIO_PCI_STATUS;
	u32 pfn;
	u16 sel;

	struct pfn_sel tmp[3];
	int tmp_index = 0;

	while (tmp_index < 3) {
		pfn = ioread32(queue_pfn);
		if (pfn == 0)
			continue;

		iowrite32(0, queue_pfn);

		sel = ioread16(queue_sel);
		if (sel == default_sel)
			continue;

		tmp[tmp_index].pfn = pfn;
		tmp[tmp_index].sel = sel;
		tmp_index++;
	}

	while (!((ioread8(pci_status) & VIRTIO_CONFIG_S_DRIVER_OK)))
		;

	for (int i = 0; i < 3; ++i) {
		switch (tmp[i].sel) {
		case 0:
			*rxpfn = tmp[i].pfn;
			break;
		case 1:
			*txpfn = tmp[i].pfn;
			break;
		case 2:
			*ctlpfn = tmp[i].pfn;
			break;
		}
	}

	return 0;
}

static int epf_vnet_rc_monitor_notify(void *data)
{
	struct epf_vnet *vnet = data;
	u16 __iomem *queue_notify = vnet->rc.cfg_base + VIRTIO_PCI_QUEUE_NOTIFY;
	const u16 notify_default = epf_vnet_rc_get_default_queue_index(vnet);

	epf_vnet_init_complete(vnet, EPF_VNET_INIT_COMPLETE_RC);

	while (true) {
		while (ioread16(queue_notify) == notify_default)
			;
		iowrite16(notify_default, queue_notify);

		queue_work(vnet->rc.tx_wq, &vnet->rc.tx_work);
		queue_work(vnet->rc.ctl_wq, &vnet->rc.ctl_work);
	}

	return 0;
}

static int epf_vnet_rc_spawn_notify_monitor(struct epf_vnet *vnet)
{
	vnet->rc.notify_monitor_task =
		kthread_create(epf_vnet_rc_monitor_notify, vnet,
			       "pci-epf-vnet/cfg_negotiator");
	if (IS_ERR(vnet->rc.notify_monitor_task))
		return PTR_ERR(vnet->rc.notify_monitor_task);

	sched_set_fifo(vnet->rc.notify_monitor_task);
	wake_up_process(vnet->rc.notify_monitor_task);

	return 0;
}

static int epf_vnet_rc_device_setup(void *data)
{
	struct epf_vnet *vnet = data;
	struct pci_epf *epf = vnet->epf;
	u32 txpfn, rxpfn, ctlpfn;
	const size_t vq_size = epf_vnet_get_vq_size();
	int err;
	struct kvec *kvec;

	err = epf_vnet_rc_negotiate_configs(vnet, &txpfn, &rxpfn, &ctlpfn);
	if (err) {
		pr_err("Failed to negatiate configs with driver\n");
		return err;
	}

	sched_set_normal(vnet->rc.device_setup_task, 19);

	vnet->rc.txvrh = pci_epf_virtio_alloc_vringh(epf, vnet->virtio_features,
						     txpfn, vq_size);
	if (IS_ERR(vnet->rc.txvrh)) {
		pr_err("Failed to setup virtqueue\n");
		return PTR_ERR(vnet->rc.txvrh);
	}

	kvec = kmalloc_array(vq_size, sizeof *kvec, GFP_KERNEL);
	if (!kvec) {
		err = -ENOMEM;
		// 		goto;
	}
	vringh_kiov_init(&vnet->rc.tx_iov, kvec, vq_size);

	vnet->rc.rxvrh = pci_epf_virtio_alloc_vringh(epf, vnet->virtio_features,
						     rxpfn, vq_size);
	if (IS_ERR(vnet->rc.rxvrh)) {
		pr_err("Failed to setup virtqueue\n");
		return PTR_ERR(vnet->rc.rxvrh);
	}

	kvec = kmalloc_array(vq_size, sizeof *kvec, GFP_KERNEL);
	if (!kvec) {
		err = -ENOMEM;
		// 		goto;
	}
	vringh_kiov_init(&vnet->rc.rx_iov, kvec, vq_size);

	vnet->rc.ctlvrh = pci_epf_virtio_alloc_vringh(
		epf, vnet->virtio_features, ctlpfn, vq_size);
	if (IS_ERR(vnet->rc.ctlvrh)) {
		pr_err("failed to setup virtqueue\n");
		return PTR_ERR(vnet->rc.ctlvrh);
	}

	kvec = kmalloc_array(vq_size, sizeof *kvec, GFP_KERNEL);
	if (!kvec) {
		err = -ENOMEM;
		// 		goto;
	}
	vringh_kiov_init(&vnet->rc.ctl_riov, kvec, vq_size);

	kvec = kmalloc_array(vq_size, sizeof *kvec, GFP_KERNEL);
	if (!kvec) {
		err = -ENOMEM;
		// 		goto;
	}
	vringh_kiov_init(&vnet->rc.ctl_wiov, kvec, vq_size);

	err = epf_vnet_rc_spawn_notify_monitor(vnet);
	if (err) {
		pr_err("Failed to create notify monitor thread\n");
		return err;
	}

	return 0;

	//TODO write error handling
}

static int epf_vnet_rc_spawn_device_setup_task(struct epf_vnet *vnet)
{
	vnet->rc.device_setup_task = kthread_create(
		epf_vnet_rc_device_setup, vnet, "pci-epf-vnet/cfg_negotiator");
	if (IS_ERR(vnet->rc.device_setup_task))
		return PTR_ERR(vnet->rc.device_setup_task);

	sched_set_fifo(vnet->rc.device_setup_task);
	wake_up_process(vnet->rc.device_setup_task);

	return 0;
}

static void epf_vnet_rc_tx_handler(struct work_struct *work)
{
	struct epf_vnet *vnet = container_of(work, struct epf_vnet, rc.tx_work);
	struct vringh *tx_vrh = &vnet->rc.txvrh->vrh;
	struct vringh *rx_vrh = &vnet->ep.rxvrh;
	struct vringh_kiov *tx_iov = &vnet->rc.tx_iov;
	struct vringh_kiov *rx_iov = &vnet->ep.rx_iov;

	while (epf_vnet_transfer(vnet, tx_vrh, rx_vrh, tx_iov, rx_iov,
				 DMA_DEV_TO_MEM) > 0)
		;
}

static void epf_vnet_rc_raise_irq_handler(struct work_struct *work)
{
	struct epf_vnet *vnet =
		container_of(work, struct epf_vnet, rc.raise_irq_work);
	struct pci_epf *epf = vnet->epf;

	pci_epc_raise_irq(epf->epc, epf->func_no, epf->vfunc_no,
			  PCI_EPC_IRQ_LEGACY, 0);
}

struct epf_vnet_rc_meminfo {
	void __iomem *addr, *virt;
	phys_addr_t phys;
	size_t len;
};

static struct epf_vnet_rc_meminfo *
epf_vnet_rc_epc_mmap(struct pci_epf *epf, phys_addr_t pci_addr, size_t len)
{
	int err;
	phys_addr_t aaddr, phys_addr;
	size_t asize, offset;
	void __iomem *virt_addr;
	struct epf_vnet_rc_meminfo *meminfo;

	err = pci_epc_mem_align(epf->epc, pci_addr, len, &aaddr, &asize);
	if (err) {
		pr_info("error at EPC memory: %d\n", err);
		return NULL;
	}

	offset = pci_addr - aaddr;

	virt_addr = pci_epc_mem_alloc_addr(epf->epc, &phys_addr, asize);
	if (!virt_addr) {
		pr_err("Failed to allocate epc memory\n");
		return NULL;
	}

	err = pci_epc_map_addr(epf->epc, epf->func_no, epf->vfunc_no, phys_addr,
			       aaddr, asize);
	if (err) {
		pr_err("Failed to map epc memory\n");
		// 		goto free_epc_mem;
	}

	meminfo = kmalloc(sizeof *meminfo, GFP_KERNEL);
	if (!meminfo)
		return NULL;

	meminfo->virt = virt_addr;
	meminfo->phys = phys_addr;
	meminfo->len = len;
	meminfo->addr = virt_addr + offset;

	return meminfo;

	//TODO error handling
}

static void epf_vnet_rc_epc_munmap(struct pci_epf *epf,
				   struct epf_vnet_rc_meminfo *meminfo)
{
	pci_epc_unmap_addr(epf->epc, epf->func_no, epf->vfunc_no,
			   meminfo->phys);
	pci_epc_mem_free_addr(epf->epc, meminfo->phys, meminfo->virt,
			      meminfo->len);
	kfree(meminfo);
}

static void epf_vnet_rc_process_ctrlq_entry(struct work_struct *work)
{
	struct epf_vnet *vnet =
		container_of(work, struct epf_vnet, rc.ctl_work);
	int err;
	u16 head;
	size_t total_len;
	struct virtio_net_ctrl_hdr *hdr;
	struct pci_epf *epf = vnet->epf;
	struct vringh *vrh = &vnet->rc.ctlvrh->vrh;
	struct vringh_kiov *riov = &vnet->rc.ctl_riov;
	struct vringh_kiov *wiov = &vnet->rc.ctl_wiov;
	u8 class, cmd;
	struct epf_vnet_rc_meminfo *rmem, *wmem;

	err = vringh_getdesc(vrh, riov, wiov, &head);
	if (err < 0) {
		pr_err("%s failed to get vq content: %d\n", __func__, err);
		return;
	} else if (!err) {
		// no entry
		return;
	}

	total_len = vringh_kiov_length(riov);

	rmem = epf_vnet_rc_epc_mmap(epf, (u64)riov->iov[riov->i].iov_base,
				    riov->iov[riov->i].iov_len);
	if (!rmem) {
		//TODO
	}

	wmem = epf_vnet_rc_epc_mmap(epf, (u64)wiov->iov[wiov->i].iov_base,
				    wiov->iov[wiov->i].iov_len);
	if (!wmem) {
		//TODO
	}

	hdr = rmem->addr;
	class = ioread8(&hdr->class);
	cmd = ioread8(&hdr->cmd);
	switch (ioread8(&hdr->class)) {
	case VIRTIO_NET_CTRL_ANNOUNCE:
		if (cmd != VIRTIO_NET_CTRL_ANNOUNCE_ACK) {
			pr_err("Found invalid command: announce: %d\n", cmd);
			goto out_munmap;
		}
		epf_vnet_rc_clear_config16(
			vnet,
			VIRTIO_PCI_CONFIG_OFF(false) +
				offsetof(struct virtio_net_config, status),
			VIRTIO_NET_S_ANNOUNCE);
		epf_vnet_rc_clear_config16(vnet, VIRTIO_PCI_ISR,
					   VIRTIO_PCI_ISR_CONFIG);

		iowrite8(VIRTIO_NET_OK, wmem->addr);
		break;
	default:
		pr_err("Found unsupported class in control queue: %d\n", class);
		break;
	}

out_munmap:
	epf_vnet_rc_epc_munmap(epf, rmem);
	epf_vnet_rc_epc_munmap(epf, wmem);

	vringh_complete(vrh, head, total_len);
}

int epf_vnet_rc_setup(struct epf_vnet *vnet)
{
	int err;
	struct pci_epf *epf = vnet->epf;

	err = pci_epc_write_header(epf->epc, epf->func_no, epf->vfunc_no,
				   &epf_vnet_pci_header);
	if (err) {
		pr_err("Failed to setup pci header\n");
		return err;
	}

	err = epf_vnet_setup_bar(vnet);
	if (err) {
		pr_err("Failed to setup PCI BAR\n");
		return err;
	}

	vnet->rc.tx_wq =
		alloc_workqueue("pci-epf-vnet/tx-wq",
				WQ_MEM_RECLAIM | WQ_HIGHPRI | WQ_UNBOUND, 0);
	if (!vnet->rc.tx_wq) {
		pr_err("Failed to allocate workqueue for rc -> ep transmission\n");
		return -ENOMEM;
	}

	INIT_WORK(&vnet->rc.tx_work, epf_vnet_rc_tx_handler);
	//TODO setup workqueues for tx and irq

	vnet->rc.irq_wq =
		alloc_workqueue("pci-epf-vnet/irq-wq",
				WQ_MEM_RECLAIM | WQ_HIGHPRI | WQ_UNBOUND, 0);
	if (!vnet->rc.irq_wq)
		return -ENOMEM;

	INIT_WORK(&vnet->rc.raise_irq_work, epf_vnet_rc_raise_irq_handler);

	vnet->rc.ctl_wq =
		alloc_workqueue("pci-epf-vnet/ctl-wq",
				WQ_MEM_RECLAIM | WQ_HIGHPRI | WQ_UNBOUND, 0);
	if (!vnet->rc.ctl_wq) {
		pr_err("Failed to allocate work queue for control queue processing\n");
		return -ENOMEM;
	}

	INIT_WORK(&vnet->rc.ctl_work, epf_vnet_rc_process_ctrlq_entry);

	return epf_vnet_rc_spawn_device_setup_task(vnet);
}
