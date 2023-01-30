// SPDX-License-Identifier: GPL-2.0
/*
 * Functions work for Root complext(remote) side using EPF framework
 */
#include <linux/pci-epf.h>
#include <linux/pci-epc.h>
#include <linux/pci_ids.h>
#include <linux/sched.h>

#include <linux/virtio_pci.h>

#include "pci-epf-vnet.h"

#define VIRTIO_NET_LEGACY_CFG_BAR BAR_0

int epf_vnet_rc_announce_linkup(struct epf_vnet *vnet)
{
	// The control virtqueue is only used for link up annoucement
	struct virtio_net_ctrl_hdr hdr;
	int err;
	u16 head;
	size_t len;
	u64 base;
	phys_addr_t phys_addr, aaddr;
	void __iomem *virt_base;
	struct pci_epf *epf = vnet->epf;
	struct vringh *vrh = &vnet->ep.ctlvrh->vrh;
	struct vringh_kiov *iov = &vnet->ep.ctl_iov;
	size_t asize, offset;

	err = vringh_getdesc(vrh, iov, NULL, &head);
	if (err < 0) {
		return err;
	} else if (!err) {
		return 0;
	}

	len = vringh_kiov_length(iov);

	if (iov->i + 1 != iov->used) {
		pr_err("found multiple entries, but expected is one\n");
		return -EOPNOTSUPP;
	}

	base = (u64)iov->iov[iov->i].iov_base;
	len = iov->iov[iov->i].iov_len;

	err = pci_epc_mem_align(epf->epc, base, len, &aaddr, &asize);
	if (err)
		goto err_out;

	offset = base - aaddr;

	virt_base = pci_epc_mem_alloc_addr(epf->epc, &phys_addr, asize);
	if (!virt_base) {
		err = -ENOMEM;
		goto err_out;
	}

	err = pci_epc_map_addr(epf->epc, epf->func_no, epf->vfunc_no, phys_addr,
			       aaddr, asize);
	if (err) {
		goto err_epc_free;
	}

	memcpy_fromio(&hdr, virt_base, sizeof hdr);

	if (hdr.class != VIRTIO_NET_CTRL_ANNOUNCE) {
		pr_err("found unknown command on control queue\n");
		err = -EOPNOTSUPP;
		goto err_epc_unmap;
	}

	if (hdr.cmd != VIRTIO_NET_CTRL_ANNOUNCE_ACK) {
		pr_err("[announce] invalid command found :%d\n", hdr.cmd);
		err = -EOPNOTSUPP;
		goto err_epc_unmap;
	}

	memcpy_toio(virt_base, VIRTIO_NET_OK, sizeof(u8));

	vringh_complete(vrh, head, len);

	pci_epc_unmap_addr(epf->epc, epf->func_no, epf->vfunc_no, phys_addr);
	pci_epc_mem_free_addr(epf->epc, phys_addr, virt_base, asize);

	return 0;

err_epc_unmap:
	pci_epc_unmap_addr(epf->epc, epf->func_no, epf->vfunc_no, phys_addr);
err_epc_free:
	pci_epc_mem_free_addr(epf->epc, phys_addr, virt_base, asize);
err_out:
	return err;
}

void epf_vnet_rc_raise_config_irq(struct epf_vnet *vnet)
{
	void __iomem *cfg_base = vnet->rc.cfg_base;

	/* Add a configuration change flag to isr. The flag is deasserted at tx
	 * handler. */
	iowrite16(VIRTIO_PCI_ISR_QUEUE | VIRTIO_PCI_ISR_CONFIG,
		  cfg_base + VIRTIO_PCI_ISR);

	// interrupt
	queue_work(vnet->rc.irq_wq, &vnet->rc.raise_irq_work);
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
	u16 nvq = vnet->vnet_cfg.max_virtqueue_pairs * 2;
	struct virtio_net_config net_cfg;

	iowrite32(vnet->virtio.features, cfg_base + VIRTIO_PCI_HOST_FEATURES);

	iowrite32(0, cfg_base + VIRTIO_PCI_QUEUE_PFN);
	iowrite16(epf_vnet_get_vq_size(), cfg_base + VIRTIO_PCI_QUEUE_NUM);
	iowrite16(1, cfg_base + VIRTIO_PCI_ISR);
	iowrite16(nvq, cfg_base + VIRTIO_PCI_QUEUE_NOTIFY);
	iowrite16(nvq, cfg_base + VIRTIO_PCI_QUEUE_SEL);
	iowrite8(0, cfg_base + VIRTIO_PCI_STATUS);

	memcpy(&net_cfg, &vnet->vnet_cfg, sizeof net_cfg);
	eth_random_addr(net_cfg.mac);
	memcpy_toio(cfg_base + VIRTIO_PCI_CONFIG_OFF(false), &net_cfg,
		    sizeof net_cfg);
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

static int epf_vnet_rc_negotiate_configs(struct epf_vnet *vnet, u16 *txpfn,
					 u16 *rxpfn, u16 *ctlpfn)
{
	const u16 default_sel = vnet->vnet_cfg.max_virtqueue_pairs * 2;
	u32 __iomem *queue_pfn = vnet->rc.cfg_base + VIRTIO_PCI_QUEUE_PFN;
	u16 __iomem *queue_sel = vnet->rc.cfg_base + VIRTIO_PCI_QUEUE_SEL;
	u8 __iomem *pci_status = vnet->rc.cfg_base + VIRTIO_PCI_STATUS;
	u16 _txpfn, _rxpfn, _ctlpfn;
	u32 pfn;
	u16 sel;
	int err;

	_txpfn = _rxpfn = _ctlpfn = 0;

	while (true) {
		pfn = ioread32(queue_pfn);
		if (pfn == 0)
			continue;

		iowrite32(0, queue_pfn);

		sel = ioread16(queue_sel);
		if (sel == default_sel)
			continue;

		switch (sel) {
		case 0:
			_rxpfn = pfn;
			break;
		case 1:
			_txpfn = pfn;
			break;
		case 2:
			_ctlpfn = pfn;
			break;
		default:
			pr_err("Driver attpmt to use invalid queue (%d)\n",
			       sel);
			// TODO: consider the error state of this device
			err = -EIO;
			goto err_out;
		}

		if (_rxpfn && _txpfn && _ctlpfn)
			break;
	}

	while (!((ioread8(pci_status) & VIRTIO_CONFIG_S_DRIVER_OK)))
		;

	*rxpfn = _rxpfn;
	*txpfn = _txpfn;
	*ctlpfn = _ctlpfn;

	return 0;

err_out:
	return err;
}

static int epf_vnet_rc_monitor_notify(void *data)
{
	struct epf_vnet *vnet = data;

	u16 __iomem *queue_notify = vnet->rc.cfg_base + VIRTIO_PCI_QUEUE_NOTIFY;
	const u16 notify_default = vnet->vnet_cfg.max_virtqueue_pairs * 2;

	while (true) {
		while (ioread16(queue_notify) == notify_default)
			;
		iowrite16(notify_default, queue_notify);

		queue_work(vnet->rc.tx_wq, &vnet->rc.tx_work);
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
	u16 txpfn, rxpfn, ctlpfn;
	const size_t vq_size = epf_vnet_get_vq_size();
	int err;
	struct kvec *kvec;

	err = epf_vnet_rc_negotiate_configs(vnet, &txpfn, &rxpfn, &ctlpfn);
	if (err) {
		pr_err("Failed to negatiate configs with driver\n");
		return err;
	}

	sched_set_normal(vnet->rc.device_setup_task, 19);

	vnet->rc.txvrh = pci_epf_virtio_alloc_vringh(epf, vnet->virtio.features,
						     txpfn, vq_size,
						     PCI_EPF_VQ_LOCATE_REMOTE);
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

	vnet->rc.rxvrh = pci_epf_virtio_alloc_vringh(epf, vnet->virtio.features,
						     rxpfn, vq_size,
						     PCI_EPF_VQ_LOCATE_REMOTE);
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

	vnet->rc.ctlvrh =
		pci_epf_virtio_alloc_vringh(epf, vnet->virtio.features, ctlpfn,
					    vq_size, PCI_EPF_VQ_LOCATE_REMOTE);
	if (IS_ERR(vnet->rc.ctlvrh)) {
		pr_err("failed to setup virtqueue\n");
		return PTR_ERR(vnet->rc.ctlvrh);
	}

	kvec = kmalloc_array(vq_size, sizeof *kvec, GFP_KERNEL);
	if (!kvec) {
		err = -ENOMEM;
		// 		goto;
	}
	vringh_kiov_init(&vnet->rc.ctl_iov, kvec, vq_size);

	err = epf_vnet_rc_spawn_notify_monitor(vnet);
	if (err) {
		pr_err("Failed to create notify monitor thread\n");
		return err;
	}

	pr_info("success to setup virtqueue: %s:%d\n", __func__, __LINE__);
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
	struct vringh *rx_vrh = &vnet->ep.rxvrh->vrh;
	struct vringh_kiov *tx_iov = &vnet->rc.tx_iov;
	struct vringh_kiov *rx_iov = &vnet->ep.rx_iov;
	u16 isr;
	void __iomem *cfg_base = vnet->rc.cfg_base;

	while (epf_vnet_transfer(vnet, tx_vrh, rx_vrh, tx_iov, rx_iov,
				 DMA_DEV_TO_MEM) > 0)
		;

	// deassert config changed flag
	isr = ioread16(cfg_base + VIRTIO_PCI_ISR);
	if (unlikely(isr & VIRTIO_PCI_ISR_CONFIG)) {
		isr &= ~VIRTIO_PCI_ISR_CONFIG;
		iowrite16(isr, cfg_base + VIRTIO_PCI_ISR);
	}
}

static void epf_vnet_rc_raise_irq_handler(struct work_struct *work)
{
	struct epf_vnet *vnet =
		container_of(work, struct epf_vnet, rc.raise_irq_work);
	struct pci_epf *epf = vnet->epf;

	pci_epc_raise_irq(epf->epc, epf->func_no, epf->vfunc_no,
			  PCI_EPC_IRQ_LEGACY, 0);
}

int epf_vnet_rc_setup(struct epf_vnet *vnet)
{
	int err;
	struct pci_epf *epf = vnet->epf;

	pr_info("%s:%d\n", __func__, __LINE__);

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

	return epf_vnet_rc_spawn_device_setup_task(vnet);
}
