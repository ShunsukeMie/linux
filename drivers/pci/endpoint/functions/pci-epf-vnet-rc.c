// #include <linux/module.h>
#include <linux/pci-epf.h>
#include <linux/pci-epc.h>
#include <linux/virtio_ring.h>
#include <linux/virtio_pci.h>
#include <linux/virtio_ids.h>
#include <linux/virtio_net.h>
#include <linux/vringh.h>

#include "pci-epf-vnet.h"

static void epf_vnet_cleanup_bar(struct pci_epf *epf)
{
	struct epf_vnet *vnet = epf_get_drvdata(epf);
	const enum pci_barno cfg_bar = BAR_0;

	pci_epf_free_space(epf, vnet->pci_cfg_base, cfg_bar, PRIMARY_INTERFACE);
}

static int epf_vnet_setup_bar(struct pci_epf *epf)
{
	int err;
	const struct pci_epc_features *feature;
	const enum pci_barno cfg_bar = BAR_0;
	size_t cfg_bar_size =
		VIRTIO_PCI_CONFIG_OFF(false) + sizeof(struct virtio_net_config);
	struct epf_vnet *vnet = epf_get_drvdata(epf);

	feature = pci_epc_get_features(epf->epc, epf->func_no, epf->vfunc_no);
	if (!feature) {
		pr_err("Failed to get EPC feature\n");
		err = -EOPNOTSUPP;
		goto err_out;
	}

	if (feature->reserved_bar & BIT(cfg_bar)) {
		pr_err("Cannot use the PCI BAR %d\n", cfg_bar);
		err = -EOPNOTSUPP;
		goto err_out;
	}

	// some epc drivers doesn't specify the BAR size.
	if (feature->bar_fixed_size[cfg_bar]) {
		if (cfg_bar_size > feature->bar_fixed_size[cfg_bar]) {
			pr_info("PCI BAR size is not enough: %ld > %lld",
				cfg_bar_size, feature->bar_fixed_size[cfg_bar]);
			err = -ENOMEM;
			goto err_out;
		}
	}

	epf->bar[cfg_bar].flags |= PCI_BASE_ADDRESS_MEM_TYPE_64;

	vnet->pci_cfg_base = pci_epf_alloc_space(
		epf, cfg_bar_size, cfg_bar, feature->align, PRIMARY_INTERFACE);
	if (!vnet->pci_cfg_base) {
		pr_info("Failed to allocate BAR memory\n");
		err = -ENOMEM;
		goto err_out;
	}

	err = pci_epc_set_bar(epf->epc, epf->func_no, epf->vfunc_no,
			      &epf->bar[cfg_bar]);
	if (err) {
		pr_info("Failed to set PCI BAR\n");
		goto err_free_space;
	}

	return 0;

err_free_space:
	pci_epf_free_space(epf, vnet->pci_cfg_base, cfg_bar, PRIMARY_INTERFACE);
err_out:
	return err;
}

struct pci_epf_header epf_vnet_pci_header = {
	.vendorid = PCI_VENDOR_ID_REDHAT_QUMRANET,
	.deviceid = VIRTIO_TRANS_ID_NET,
	.subsys_vendor_id = PCI_VENDOR_ID_REDHAT_QUMRANET,
	.subsys_id = VIRTIO_ID_NET,
	.revid = 0,
	.baseclass_code = PCI_BASE_CLASS_NETWORK, //TODO consider
	//TODO subclass
	.interrupt_pin = PCI_INTERRUPT_PIN,
};

static void epf_vnet_cleanup_epf(struct pci_epf *epf)
{
	epf_vnet_cleanup_bar(epf);
}

static int epf_vnet_setup_epf(struct pci_epf *epf)
{
	int err;

	err = pci_epc_write_header(epf->epc, epf->func_no, epf->vfunc_no,
				   &epf_vnet_pci_header);
	if (err) {
		pr_err("Failed to setup pci header\n");
		goto err_out;
	}

	err = epf_vnet_setup_bar(epf);
	if (err)
		goto err_out;

	return 0;

err_out:
	return err;
}

static u16 epf_vnet_get_nvq(struct epf_vnet *vnet)
{
	return vnet->net_cfg.max_virtqueue_pairs * 2;
}

#if 1
static void __iomem *epf_vnet_map_host_vq(struct pci_epf *epf, u32 pfn)
{
	void __iomem *ioaddr;
	phys_addr_t vq_addr;
	phys_addr_t phys_addr;
	int err;
	size_t vq_size;
	struct pci_epc *epc = epf->epc;

	vq_addr = (phys_addr_t)pfn << VIRTIO_PCI_QUEUE_ADDR_SHIFT;
	/* XXX: by a virtio spec and an impl(vring_size) returns sufficient size,
	 * but we cannot access the avail_index located end of the ring correctly.
	 * probably, the epc map has problem.
	 */
	vq_size =
		vring_size(epf_vnet_virtqueue_size(), VIRTIO_PCI_VRING_ALIGN) +
		100;

	ioaddr = pci_epc_mem_alloc_addr(epc, &phys_addr, vq_size);
	if (!ioaddr) {
		pr_err("Failed to allocate epc memory area\n");
		return NULL;
	}

	err = pci_epc_map_addr(epc, epf->func_no, epf->vfunc_no, phys_addr,
			       vq_addr, vq_size);
	if (err) {
		pr_err("failed to map virtqueue address\n");
		goto err_alloc;
	}

	return ioaddr;

err_alloc:
	pci_epc_mem_free_addr(epc, phys_addr, ioaddr, vq_size);

	return NULL;
}

static void epf_vnet_unmap_host_vq(struct pci_epf *epf)
{
	// 	pci_epc_unmap_addr(epf->epc, epf->func_no, epf->vfunc_no, );
	// 	pci_epc_mem_free_addr();
}

static int epf_vnet_rc_setup_vringh(struct pci_epf *epf, struct vringh *vrh,
				    struct vringh_kiov *kiov, u32 pfn)
{
	int err;
	void __iomem *tmp;
	struct vring vring;
	struct kvec *kvec;
	struct epf_vnet *vnet = epf_get_drvdata(epf);

	tmp = epf_vnet_map_host_vq(epf, pfn);
	if (!tmp) {
		pr_err("failed to map host virtqueue\n");
		err = -ENOMEM;
		goto err_out;
	}
	vring_init(&vring, epf_vnet_virtqueue_size(), tmp,
		   VIRTIO_PCI_VRING_ALIGN);

	err = vringh_init_kern(vrh, vnet->features, epf_vnet_virtqueue_size(),
			       false, vring.desc, vring.avail, vring.used);
	if (err) {
		pr_err("failed to init tx vringh\n");
		goto err_unmap_host_vq;
	}

	kvec = kmalloc_array(epf_vnet_virtqueue_size(), sizeof *kvec,
			     GFP_KERNEL);
	if (!kvec) {
		err = -ENOMEM;
		goto err_unmap_host_vq;
	}
	vringh_kiov_init(kiov, kvec, epf_vnet_virtqueue_size());

	vringh_notify_enable_iomem(vrh);

	return 0;

err_unmap_host_vq:
	epf_vnet_unmap_host_vq(epf);
err_out:
	return err;
}
#endif

static void epf_vnet_rc_cleanup_vringh(struct pci_epf *epf)
{
	//TODO
}

static int epf_vnet_notify_monitor(void *data)
{
	struct epf_vnet *vnet = data;
	u16 __iomem *queue_notify_reg =
		vnet->pci_cfg_base + VIRTIO_PCI_QUEUE_NOTIFY;
	u16 notify_default = epf_vnet_get_nvq(vnet);

	while (true) {
		while (ioread16(queue_notify_reg) == notify_default)
			;
		iowrite16(notify_default, queue_notify_reg);

		/* polling q_notify register, but sometimes it missed to read
		 * the register.  */
		// 		queue_work(vnet->rx_wq, &vnet->rx_work);
		queue_work(vnet->rc.tx_wq, &vnet->rc.tx_work);
	}

	return 0;
}

static int epf_vnet_spawn_notify_monitor(struct epf_vnet *vnet)
{
	vnet->monitor_notify_task = kthread_create(epf_vnet_notify_monitor,
						   vnet, "epf-vnet/nmonit");
	if (IS_ERR(vnet->monitor_notify_task)) {
		pr_err("failed to create a kernel thread (notify monitor)\n");
		return PTR_ERR(vnet->monitor_notify_task);
	}

	sched_set_fifo(vnet->monitor_notify_task);
	wake_up_process(vnet->monitor_notify_task);

	return 0;
}

static int epf_vnet_monitor_configs(struct epf_vnet *vnet, u32 *txpfn,
				    u32 *rxpfn)
{
	int err;
	u32 sel = 0;
	u32 pfn;
	const u16 qsel_default = epf_vnet_get_nvq(vnet);
	void *cfg_base = vnet->pci_cfg_base;
	u32 _txpfn = 0;
	u32 _rxpfn = 0;

	*txpfn = 0;
	*rxpfn = 0;

	while (true) {
		pfn = ioread32(cfg_base + VIRTIO_PCI_QUEUE_PFN);
		if (pfn == 0)
			continue;

		iowrite32(0, cfg_base + VIRTIO_PCI_QUEUE_PFN);

		sel = ioread16(cfg_base + VIRTIO_PCI_QUEUE_SEL);
		if (sel == qsel_default)
			continue;

		switch (sel) {
		case 0:
			_rxpfn = pfn;
			break;
		case 1:
			_txpfn = pfn;
			break;
		default:
			pr_warn("driver tries to use invalid queue: %d\n", sel);
			err = -EIO;
			goto err_out;
		}

		if (_txpfn && _rxpfn)
			break;
	}

	while (!((ioread8(cfg_base + VIRTIO_PCI_STATUS) &
		  VIRTIO_CONFIG_S_DRIVER_OK)))
		;

	*rxpfn = _rxpfn;
	*txpfn = _txpfn;

	return 0;

err_out:
	return err;
}

static int epf_vnet_config_monitor(void *data)
{
	int err;
	struct pci_epf *epf = data;
	struct epf_vnet *vnet = epf_get_drvdata(epf);
	u32 txpfn, rxpfn;

	err = epf_vnet_monitor_configs(vnet, &txpfn, &rxpfn);
	if (err)
		goto err_out;

	// put back the kthread priority.
	sched_set_normal(vnet->monitor_config_task, 19);
	/*
	 * setup virtqueues
	 */
	// for tx
	err = epf_vnet_rc_setup_vringh(epf, &vnet->rc.tx_vrh, &vnet->rc.txiov,
				       txpfn);
	if (err) {
		pr_err("");
		goto err_out;
	}

	err = epf_vnet_rc_setup_vringh(epf, &vnet->rc.rx_vrh, &vnet->rc.rxiov,
				       rxpfn);
	if (err) {
		pr_err("");
		goto err_cleanup_tx_vrh;
	}

	err = epf_vnet_spawn_notify_monitor(vnet);
	if (err)
		goto err_cleanup_rx_vrh;

	vnet->rc_init_done = true;

	return 0;

err_cleanup_rx_vrh:
	epf_vnet_rc_cleanup_vringh(epf);
err_cleanup_tx_vrh:
	epf_vnet_rc_cleanup_vringh(epf);
err_out:
	return err;
}

static int epf_vnet_spawn_config_monitor(struct pci_epf *epf)
{
	struct epf_vnet *vnet = epf_get_drvdata(epf);

	vnet->monitor_config_task =
		kthread_create(epf_vnet_config_monitor, epf, "epf-vnet/cmonit");
	if (IS_ERR(vnet->monitor_config_task)) {
		pr_err("Failed to run a pci configuration monitor\n");
		return PTR_ERR(vnet->monitor_config_task);
	}

	sched_set_fifo(vnet->monitor_config_task);
	wake_up_process(vnet->monitor_config_task);

	return 0;
}

static void epf_vnet_rc_init_configs(struct pci_epf *epf)
{
	struct epf_vnet *vnet = epf_get_drvdata(epf);
	struct virtio_net_config *net_cfg;
	void *cfg_base = vnet->pci_cfg_base;

	iowrite32(vnet->features, cfg_base + VIRTIO_PCI_HOST_FEATURES);

	// Initialize the pfn to zero in order to detect change in config montor.
	iowrite32(0, cfg_base + VIRTIO_PCI_QUEUE_PFN);
	iowrite16(epf_vnet_virtqueue_size(), cfg_base + VIRTIO_PCI_QUEUE_NUM);
	iowrite16(1, cfg_base + VIRTIO_PCI_ISR);
	// set number of virtqueues to QUEUE_NOTIFY reg to detect changes in nofiy monitor.
	iowrite16(epf_vnet_get_nvq(vnet), cfg_base + VIRTIO_PCI_QUEUE_NOTIFY);
	iowrite8(0, cfg_base + VIRTIO_PCI_STATUS);

	net_cfg = cfg_base + VIRTIO_PCI_CONFIG_OFF(false);
	eth_random_addr(vnet->net_cfg.mac);
	memcpy_toio(net_cfg, &vnet->net_cfg, sizeof vnet->net_cfg);
}

static void tmp_callback(void *p)
{
	struct completion *c = p;
	complete(c);
}

static int _epf_vnet_rc_tx_handler(struct epf_vnet *vnet)
{
	struct vringh *tvrh = &vnet->rc.tx_vrh;
	struct vringh *rvrh = &vnet->ep.rx_vrh;
	struct vringh_kiov *tiov = &vnet->rc.txiov;
	struct vringh_kiov *riov = &vnet->ep.rxiov;
	struct device *dma_dev = vnet->vdev.dev.parent;
	u16 txhead, rxhead;
	size_t total_tx_len;
	int err;

	err = vringh_getdesc_iomem(tvrh, tiov, NULL, &txhead, GFP_KERNEL);
	if (err < 0) {
		pr_info("failed to get vringh\n");
		return err;
	} else if (!err) {
		// NO data in vring
		return 0;
	}

	total_tx_len = vringh_kiov_length(tiov);

	err = vringh_getdesc_kern(rvrh, NULL, riov, &rxhead, GFP_KERNEL);
	if (err < 0) {
		pr_info("failed to get descs from vringh");
		//TODO abondon txdesc
		return err;
	} else if (!err) {
		return 0;
	}

	for (; tiov->i < tiov->used; tiov->i++, riov->i++) {
		size_t txlen, rxlen;
		u64 txbase, rxbase;

		txlen = tiov->iov[tiov->i].iov_len;
		txbase = (u64)tiov->iov[tiov->i].iov_base;

		rxlen = riov->iov[riov->i].iov_len;
		rxbase = (u64)riov->iov[riov->i].iov_base;

		if (riov->i >= riov->used) {
			pr_err("not enough descriptors\n");
			//TODO goto abondon
			return 0;
		}

		if (txlen > rxlen) {
			pr_err("not ehough buffer\n");
			return 0;
		}

		{
			struct completion completion;
			init_completion(&completion);

			err = epf_vnet_dma_single(vnet, txbase, rxbase, txlen,
						  tmp_callback, &completion,
						  DMA_DEV_TO_MEM);
			if (err) {
				pr_err("failed to request dma\n");
				return err;
			}

			wait_for_completion(&completion);

			dma_sync_single_for_cpu(dma_dev, rxbase, txlen,
						DMA_DEV_TO_MEM);
		}
	}

	vringh_complete_iomem(tvrh, txhead, total_tx_len);
	vringh_complete_kern(rvrh, rxhead, total_tx_len);

	vring_interrupt(0, vnet->ep.rxvq);

	return 1;
}

static void epf_vnet_rc_tx_handler(struct work_struct *work)
{
	struct _rc *rc = container_of(work, struct _rc, tx_work);
	struct epf_vnet *vnet = container_of(rc, struct epf_vnet, rc);

	while (_epf_vnet_rc_tx_handler(vnet) > 0)
		;
}

static void epf_vnet_raise_irq_handler(struct work_struct *work)
{
	struct epf_vnet *vnet =
		container_of(work, struct epf_vnet, raise_irq_work);
	struct pci_epf *epf = vnet->epf;

	pci_epc_raise_irq(epf->epc, epf->func_no, epf->vfunc_no,
			  PCI_EPC_IRQ_LEGACY, 0);
}

static int epf_vnet_setup_rc_vnet(struct pci_epf *epf)
{
	struct epf_vnet *vnet = epf_get_drvdata(epf);

	epf_vnet_rc_init_configs(epf);

	vnet->rc.tx_wq = alloc_workqueue(
		"epf-vnet/tx-wq", WQ_MEM_RECLAIM | WQ_HIGHPRI | WQ_UNBOUND, 0);
	if (!vnet->rc.tx_wq) {
		pr_err("failed to create workqueue\n");
		return -ENOMEM;
	}

	INIT_WORK(&vnet->rc.tx_work, epf_vnet_rc_tx_handler);

	vnet->irq_wq = alloc_workqueue(
		"epf-vnet/irq-wq", WQ_MEM_RECLAIM | WQ_HIGHPRI | WQ_UNBOUND, 0);
	if (!vnet->irq_wq) {
		return -ENOMEM;
	}

	INIT_WORK(&vnet->raise_irq_work, epf_vnet_raise_irq_handler);

	return epf_vnet_spawn_config_monitor(epf);
}

int epf_vnet_setup_rc(struct pci_epf *epf)
{
	int err;

	err = epf_vnet_setup_epf(epf);
	if (err)
		goto err_out;

	err = epf_vnet_setup_rc_vnet(epf);
	if (err)
		goto err_clean_epf;

	return 0;

err_clean_epf:
	epf_vnet_cleanup_epf(epf);
err_out:
	return err;
}

void epf_vnet_cleanup_rc(struct pci_epf *epf)
{
	epf_vnet_cleanup_epf(epf);
	// epf_vnet_cleanup_rc_vnet(epf);
}

