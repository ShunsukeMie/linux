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

/* Returns an out side of the valid queue index. */
static inline u16 epf_vnet_rc_get_number_of_queues(struct epf_vnet *vnet)

{
	/* number of queue pairs and control queue */
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

static void epf_vnet_rc_raise_config_irq(struct epf_vnet *vnet)
{
	epf_vnet_rc_set_config16(vnet, VIRTIO_PCI_ISR, VIRTIO_PCI_ISR_CONFIG);
	queue_work(vnet->rc.irq_wq, &vnet->rc.raise_irq_work);
}

void epf_vnet_rc_announce_linkup(struct epf_vnet *vnet)
{
	epf_vnet_rc_set_config16(vnet,
				 VIRTIO_PCI_CONFIG_OFF(false) +
					 offsetof(struct virtio_net_config,
						  status),
				 VIRTIO_NET_S_LINK_UP | VIRTIO_NET_S_ANNOUNCE);
	epf_vnet_rc_raise_config_irq(vnet);
}

/*
 * For the PCIe host, this driver shows legacy virtio-net device. Because,
 * virtio structure pci capabilities is mandatory for modern virtio device,
 * but there is no PCIe EP hardware that can be configured with any pci
 * capabilities and Linux PCIe EP framework doesn't support it.
 */
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
	u16 default_qindex = epf_vnet_rc_get_number_of_queues(vnet);

	epf_vnet_rc_set_config32(vnet, VIRTIO_PCI_HOST_FEATURES,
				 vnet->virtio_features);

	epf_vnet_rc_set_config16(vnet, VIRTIO_PCI_ISR, VIRTIO_PCI_ISR_QUEUE);
	/*
	 * Initialize the queue notify and selector to outside of the appropriate
	 * virtqueue index. It is used to detect change with polling. There is no
	 * other ways to detect host side driver updateing those values
	 */
	epf_vnet_rc_set_config16(vnet, VIRTIO_PCI_QUEUE_NOTIFY, default_qindex);
	epf_vnet_rc_set_config16(vnet, VIRTIO_PCI_QUEUE_SEL, default_qindex);
	/* This pfn is also set to 0 for the polling as well */
	epf_vnet_rc_set_config16(vnet, VIRTIO_PCI_QUEUE_PFN, 0);

	epf_vnet_rc_set_config16(vnet, VIRTIO_PCI_QUEUE_NUM,
				 epf_vnet_get_vq_size());
	epf_vnet_rc_set_config8(vnet, VIRTIO_PCI_STATUS, 0);
	epf_vnet_rc_memcpy_config(vnet, VIRTIO_PCI_CONFIG_OFF(false),
				  &vnet->vnet_cfg, sizeof(vnet->vnet_cfg));
}

static void epf_vnet_cleanup_bar(struct epf_vnet *vnet)
{
	struct pci_epf *epf = vnet->epf;

	pci_epc_clear_bar(epf->epc, epf->func_no, epf->vfunc_no,
			  &epf->bar[VIRTIO_NET_LEGACY_CFG_BAR]);
	pci_epf_free_space(epf, vnet->rc.cfg_base, VIRTIO_NET_LEGACY_CFG_BAR,
			   PRIMARY_INTERFACE);
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
		pr_debug("Failed to get PCI EPC features\n");
		return -EOPNOTSUPP;
	}

	if (features->reserved_bar & BIT(VIRTIO_NET_LEGACY_CFG_BAR)) {
		pr_debug("Cannot use the PCI BAR for legacy virtio pci\n");
		return -EOPNOTSUPP;
	}

	if (features->bar_fixed_size[VIRTIO_NET_LEGACY_CFG_BAR]) {
		if (cfg_bar_size >
		    features->bar_fixed_size[VIRTIO_NET_LEGACY_CFG_BAR]) {
			pr_debug("PCI BAR size is not enough\n");
			return -ENOMEM;
		}
	}

	config_bar->flags |= PCI_BASE_ADDRESS_MEM_TYPE_64;

	vnet->rc.cfg_base = pci_epf_alloc_space(epf, cfg_bar_size,
						VIRTIO_NET_LEGACY_CFG_BAR,
						features->align,
						PRIMARY_INTERFACE);
	if (!vnet->rc.cfg_base) {
		pr_debug("Failed to allocate virtio-net config memory\n");
		return -ENOMEM;
	}

	epf_vnet_rc_setup_configs(vnet, vnet->rc.cfg_base);

	err = pci_epc_set_bar(epf->epc, epf->func_no, epf->vfunc_no,
			      config_bar);
	if (err) {
		pr_debug("Failed to set PCI BAR");
		goto err_free_space;
	}

	return 0;

err_free_space:
	pci_epf_free_space(epf, vnet->rc.cfg_base, VIRTIO_NET_LEGACY_CFG_BAR,
			   PRIMARY_INTERFACE);
	return err;
}

static int epf_vnet_rc_negotiate_configs(struct epf_vnet *vnet, u32 *txpfn,
					 u32 *rxpfn, u32 *ctlpfn)
{
	const u16 nqueues = epf_vnet_rc_get_number_of_queues(vnet);
	const u16 default_sel = nqueues;
	u32 __iomem *queue_pfn = vnet->rc.cfg_base + VIRTIO_PCI_QUEUE_PFN;
	u16 __iomem *queue_sel = vnet->rc.cfg_base + VIRTIO_PCI_QUEUE_SEL;
	u8 __iomem *pci_status = vnet->rc.cfg_base + VIRTIO_PCI_STATUS;
	u32 pfn;
	u16 sel;
	struct {
		u32 pfn;
		u16 sel;
	} tmp[3] = {};
	int tmp_index = 0;

	*rxpfn = *txpfn = *ctlpfn = 0;

	/* To avoid to miss a getting the pfn and selector for virtqueue wrote by
	 * host driver, we need to implement fast polling with saving.
	 *
	 * This implementation suspects that the host driver writes pfn only once
	 * for each queues
	 */
	while (tmp_index < nqueues) {
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

	for (int i = 0; i < nqueues; ++i) {
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

	if (!*rxpfn || !*txpfn || !*ctlpfn)
		return -EIO;

	return 0;
}

static int epf_vnet_rc_monitor_notify(void *data)
{
	struct epf_vnet *vnet = data;
	u16 __iomem *queue_notify = vnet->rc.cfg_base + VIRTIO_PCI_QUEUE_NOTIFY;
	const u16 notify_default = epf_vnet_rc_get_number_of_queues(vnet);

	epf_vnet_init_complete(vnet, EPF_VNET_INIT_COMPLETE_RC);

	/* Poll to detect a change of the queue_notify register. Sometimes this
	 * polling misses the change, so try to check each virtqueues
	 * everytime.
	 */
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

	/* Change the thread priority to high for polling. */
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

	err = epf_vnet_rc_negotiate_configs(vnet, &txpfn, &rxpfn, &ctlpfn);
	if (err) {
		pr_debug("Failed to negatiate configs with driver\n");
		return err;
	}

	/* Polling phase is finished. This thread backs to normal priority. */
	sched_set_normal(vnet->rc.device_setup_task, 19);

	vnet->rc.txvrh = pci_epf_virtio_alloc_vringh(epf, vnet->virtio_features,
						     txpfn, vq_size);
	if (IS_ERR(vnet->rc.txvrh)) {
		pr_debug("Failed to setup virtqueue for tx\n");
		return PTR_ERR(vnet->rc.txvrh);
	}

	err = epf_vnet_init_kiov(&vnet->rc.tx_iov, vq_size);
	if (err)
		goto err_free_epf_tx_vringh;

	vnet->rc.rxvrh = pci_epf_virtio_alloc_vringh(epf, vnet->virtio_features,
						     rxpfn, vq_size);
	if (IS_ERR(vnet->rc.rxvrh)) {
		pr_debug("Failed to setup virtqueue for rx\n");
		err = PTR_ERR(vnet->rc.rxvrh);
		goto err_deinit_tx_kiov;
	}

	err = epf_vnet_init_kiov(&vnet->rc.rx_iov, vq_size);
	if (err)
		goto err_free_epf_rx_vringh;

	vnet->rc.ctlvrh = pci_epf_virtio_alloc_vringh(
		epf, vnet->virtio_features, ctlpfn, vq_size);
	if (IS_ERR(vnet->rc.ctlvrh)) {
		pr_err("failed to setup virtqueue\n");
		err = PTR_ERR(vnet->rc.ctlvrh);
		goto err_deinit_rx_kiov;
	}

	err = epf_vnet_init_kiov(&vnet->rc.ctl_riov, vq_size);
	if (err)
		goto err_free_epf_ctl_vringh;

	err = epf_vnet_init_kiov(&vnet->rc.ctl_wiov, vq_size);
	if (err)
		goto err_deinit_ctl_riov;

	err = epf_vnet_rc_spawn_notify_monitor(vnet);
	if (err) {
		pr_debug("Failed to create notify monitor thread\n");
		goto err_deinit_ctl_wiov;
	}

	return 0;

err_deinit_ctl_wiov:
	epf_vnet_deinit_kiov(&vnet->rc.ctl_wiov);
err_deinit_ctl_riov:
	epf_vnet_deinit_kiov(&vnet->rc.ctl_riov);
err_free_epf_ctl_vringh:
	pci_epf_virtio_free_vringh(epf, vnet->rc.ctlvrh);
err_deinit_rx_kiov:
	epf_vnet_deinit_kiov(&vnet->rc.rx_iov);
err_free_epf_rx_vringh:
	pci_epf_virtio_free_vringh(epf, vnet->rc.rxvrh);
err_deinit_tx_kiov:
	epf_vnet_deinit_kiov(&vnet->rc.tx_iov);
err_free_epf_tx_vringh:
	pci_epf_virtio_free_vringh(epf, vnet->rc.txvrh);

	return err;
}

static int epf_vnet_rc_spawn_device_setup_task(struct epf_vnet *vnet)
{
	vnet->rc.device_setup_task = kthread_create(
		epf_vnet_rc_device_setup, vnet, "pci-epf-vnet/cfg_negotiator");
	if (IS_ERR(vnet->rc.device_setup_task))
		return PTR_ERR(vnet->rc.device_setup_task);

	/* Change the thread priority to high for the polling. */
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

/* Util function to access PCIe host side memory from local CPU.  */
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
		pr_debug("Failed to get EPC align: %d\n", err);
		return NULL;
	}

	offset = pci_addr - aaddr;

	virt_addr = pci_epc_mem_alloc_addr(epf->epc, &phys_addr, asize);
	if (!virt_addr) {
		pr_debug("Failed to allocate epc memory\n");
		return NULL;
	}

	err = pci_epc_map_addr(epf->epc, epf->func_no, epf->vfunc_no, phys_addr,
			       aaddr, asize);
	if (err) {
		pr_debug("Failed to map epc memory\n");
		goto err_epc_free_addr;
	}

	meminfo = kmalloc(sizeof(*meminfo), GFP_KERNEL);
	if (!meminfo)
		goto err_epc_unmap_addr;

	meminfo->virt = virt_addr;
	meminfo->phys = phys_addr;
	meminfo->len = len;
	meminfo->addr = virt_addr + offset;

	return meminfo;

err_epc_unmap_addr:
	pci_epc_unmap_addr(epf->epc, epf->func_no, epf->vfunc_no,
			   meminfo->phys);
err_epc_free_addr:
	pci_epc_mem_free_addr(epf->epc, meminfo->phys, meminfo->virt,
			      meminfo->len);

	return NULL;
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

static int epf_vnet_rc_process_ctrlq_entry(struct epf_vnet *vnet)
{
	struct vringh_kiov *riov = &vnet->rc.ctl_riov;
	struct vringh_kiov *wiov = &vnet->rc.ctl_wiov;
	struct vringh *vrh = &vnet->rc.ctlvrh->vrh;
	struct pci_epf *epf = vnet->epf;
	struct epf_vnet_rc_meminfo *rmem, *wmem;
	struct virtio_net_ctrl_hdr *hdr;
	int err;
	u16 head;
	size_t total_len;
	u8 class, cmd;

	err = vringh_getdesc(vrh, riov, wiov, &head);
	if (err <= 0)
		return err;

	total_len = vringh_kiov_length(riov);

	rmem = epf_vnet_rc_epc_mmap(epf, (u64)riov->iov[riov->i].iov_base,
				    riov->iov[riov->i].iov_len);
	if (!rmem) {
		err = -ENOMEM;
		goto err_abandon_descs;
	}

	wmem = epf_vnet_rc_epc_mmap(epf, (u64)wiov->iov[wiov->i].iov_base,
				    wiov->iov[wiov->i].iov_len);
	if (!wmem) {
		err = -ENOMEM;
		goto err_epc_unmap_rmem;
	}

	hdr = rmem->addr;
	class = ioread8(&hdr->class);
	cmd = ioread8(&hdr->cmd);
	switch (ioread8(&hdr->class)) {
	case VIRTIO_NET_CTRL_ANNOUNCE:
		if (cmd != VIRTIO_NET_CTRL_ANNOUNCE_ACK) {
			pr_err("Found invalid command: announce: %d\n", cmd);
			break;
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

	epf_vnet_rc_epc_munmap(epf, rmem);
	epf_vnet_rc_epc_munmap(epf, wmem);
	vringh_complete(vrh, head, total_len);

	return 1;

err_epc_unmap_rmem:
	epf_vnet_rc_epc_munmap(epf, rmem);
err_abandon_descs:
	vringh_abandon(vrh, head);

	return err;
}

static void epf_vnet_rc_process_ctrlq_entries(struct work_struct *work)
{
	struct epf_vnet *vnet =
		container_of(work, struct epf_vnet, rc.ctl_work);

	while (epf_vnet_rc_process_ctrlq_entry(vnet) > 0)
		;
}

void epf_vnet_rc_notify(struct epf_vnet *vnet)
{
	queue_work(vnet->rc.irq_wq, &vnet->rc.raise_irq_work);
}

void epf_vnet_rc_cleanup(struct epf_vnet *vnet)
{
	epf_vnet_cleanup_bar(vnet);
	destroy_workqueue(vnet->rc.tx_wq);
	destroy_workqueue(vnet->rc.irq_wq);
	destroy_workqueue(vnet->rc.ctl_wq);

	kthread_stop(vnet->rc.device_setup_task);
}

int epf_vnet_rc_setup(struct epf_vnet *vnet)
{
	int err;
	struct pci_epf *epf = vnet->epf;

	err = pci_epc_write_header(epf->epc, epf->func_no, epf->vfunc_no,
				   &epf_vnet_pci_header);
	if (err)
		return err;

	err = epf_vnet_setup_bar(vnet);
	if (err)
		return err;

	vnet->rc.tx_wq =
		alloc_workqueue("pci-epf-vnet/tx-wq",
				WQ_MEM_RECLAIM | WQ_HIGHPRI | WQ_UNBOUND, 0);
	if (!vnet->rc.tx_wq) {
		pr_debug(
			"Failed to allocate workqueue for rc -> ep transmission\n");
		err = -ENOMEM;
		goto err_cleanup_bar;
	}

	INIT_WORK(&vnet->rc.tx_work, epf_vnet_rc_tx_handler);

	vnet->rc.irq_wq =
		alloc_workqueue("pci-epf-vnet/irq-wq",
				WQ_MEM_RECLAIM | WQ_HIGHPRI | WQ_UNBOUND, 0);
	if (!vnet->rc.irq_wq) {
		pr_debug("Failed to allocate workqueue for irq\n");
		err = -ENOMEM;
		goto err_destory_tx_wq;
	}

	INIT_WORK(&vnet->rc.raise_irq_work, epf_vnet_rc_raise_irq_handler);

	vnet->rc.ctl_wq =
		alloc_workqueue("pci-epf-vnet/ctl-wq",
				WQ_MEM_RECLAIM | WQ_HIGHPRI | WQ_UNBOUND, 0);
	if (!vnet->rc.ctl_wq) {
		pr_err("Failed to allocate work queue for control queue processing\n");
		err = -ENOMEM;
		goto err_destory_irq_wq;
	}

	INIT_WORK(&vnet->rc.ctl_work, epf_vnet_rc_process_ctrlq_entries);

	err = epf_vnet_rc_spawn_device_setup_task(vnet);
	if (err)
		goto err_destory_ctl_wq;

	return 0;

err_cleanup_bar:
	epf_vnet_cleanup_bar(vnet);
err_destory_tx_wq:
	destroy_workqueue(vnet->rc.tx_wq);
err_destory_irq_wq:
	destroy_workqueue(vnet->rc.irq_wq);
err_destory_ctl_wq:
	destroy_workqueue(vnet->rc.ctl_wq);

	return err;
}
