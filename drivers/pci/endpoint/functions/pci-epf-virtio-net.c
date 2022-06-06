/*
 * Endpoint function driver to implement pci virtio-net functionality.
 *
 */

#include <linux/module.h>
#include <linux/pci-epf.h>
#include <linux/pci-epc.h>
#include <linux/virtio_ids.h>
#include <linux/virtio_net.h>
#include <linux/virtio_pci.h>
#include <linux/virtio_ring.h>
#include <linux/etherdevice.h>
#include <linux/dmaengine.h>
#include <linux/vringh.h>

//TODO care for native endianess
struct virtio_common_config {
	uint32_t dev_feat;
	uint32_t drv_feat;
	uint32_t q_addr;
	uint16_t q_size;
	uint16_t q_select;
	uint16_t q_notify;
	uint8_t dev_status;
	uint8_t isr_status;
} __packed;

struct epf_virtnet {
	struct pci_epf *epf;
	struct {
		struct virtio_common_config common_cfg;
		struct virtio_net_config net_cfg;
	} __packed *pci_config;
	const struct pci_epc_features *epc_features;
	struct task_struct *monitor_config_task;
	struct workqueue_struct *host_tx_wq, *irq_wq;
	struct delayed_work host_tx_handler;
	struct work_struct raise_irq_work;
	u16 rx_last_a_idx;

	struct dma_chan *tx_dma_chan, *rx_dma_chan;
	struct vringh rx_vrh, tx_vrh;
	struct vringh_kiov txiov, rxiov;
};

static int epf_virtnet_setup_bar(struct pci_epf *epf)
{
	struct pci_epc *epc = epf->epc;
	const enum pci_barno cfg_bar = BAR_0;
	struct pci_epf_bar *virt_cfg_bar = &epf->bar[cfg_bar];
	struct epf_virtnet *vnet = epf_get_drvdata(epf);
	size_t cfg_bar_size = sizeof(struct virtio_common_config) +
			      sizeof(struct virtio_net_config);
	const struct pci_epc_features *epc_features = vnet->epc_features;
	void *cfg_base;
	int ret;

	if (!!(epc_features->reserved_bar & (1 << cfg_bar)))
		return -EOPNOTSUPP;

	if (epc_features->bar_fixed_size[cfg_bar]) {
		if (cfg_bar_size > epc_features->bar_fixed_size[cfg_bar])
			return -ENOMEM;

		cfg_bar_size = epc_features->bar_fixed_size[cfg_bar];
	}

	virt_cfg_bar->flags |= PCI_BASE_ADDRESS_MEM_TYPE_64;

	cfg_base = pci_epf_alloc_space(epf, cfg_bar_size, cfg_bar,
				       epc_features->align, PRIMARY_INTERFACE);
	if (!cfg_base) {
		pr_err("Failed to allocate PCI BAR memory\n");
		return -ENOMEM;
	}
	vnet->pci_config = cfg_base;

	ret = pci_epc_set_bar(epc, epf->func_no, epf->vfunc_no, virt_cfg_bar);
	if (ret) {
		pr_err("Failed to set PCI BAR\n");
		return ret;
	}

	return 0;
}

static int epf_virtnet_load_epc_features(struct pci_epf *epf)
{
	const struct pci_epc_features *epc_features;
	struct epf_virtnet *epf_virtnet = epf_get_drvdata(epf);
	struct pci_epc *epc = epf->epc;

	epc_features = pci_epc_get_features(epc, epf->func_no, epf->vfunc_no);
	if (!epc_features) {
		pr_err("epc_features not implemented\n");
		return -EOPNOTSUPP;
	}

	epf_virtnet->epc_features = epc_features;

	return 0;
}

#define EPF_VIRTNET_Q_SIZE 0x100
#define EPF_VIRTNET_Q_MASK 0x0ff

static u16 epf_virtnet_get_default_q_sel(struct epf_virtnet *vnet)
{
	struct virtio_net_config *net_cfg = &vnet->pci_config->net_cfg;

	/*
	 * Initialy indicates out of ranged index to detect changing from host.
	 * See the `epf_virtnet_config_monitor()` to get details.
	 */
	return net_cfg->max_virtqueue_pairs * 2;
}

static void epf_virtnet_init_config(struct pci_epf *epf)
{
	struct epf_virtnet *vnet = epf_get_drvdata(epf);
	struct virtio_common_config *common_cfg = &vnet->pci_config->common_cfg;
	struct virtio_net_config *net_cfg = &vnet->pci_config->net_cfg;

	//TODO consider the device feature
	//TODO care about endianness (must be guest(root complex) endianness)
	common_cfg->dev_feat = BIT(VIRTIO_NET_F_MAC) |
			       BIT(VIRTIO_NET_F_GUEST_CSUM) |
			       BIT(VIRTIO_NET_F_STATUS) |
				   BIT(VIRTIO_NET_F_GUEST_TSO4) |
				   BIT(VIRTIO_NET_F_GUEST_TSO6) |
				   BIT(VIRTIO_NET_F_GUEST_ECN) |
				   BIT(VIRTIO_NET_F_GUEST_UFO);
	common_cfg->q_addr = 0;
	common_cfg->q_size = EPF_VIRTNET_Q_SIZE;
	common_cfg->q_notify = 2;
	common_cfg->isr_status = 1;

	net_cfg->max_virtqueue_pairs = 1;
	net_cfg->status = VIRTIO_NET_S_LINK_UP;
	net_cfg->mtu = PAGE_SIZE * 2;

	common_cfg->q_select = epf_virtnet_get_default_q_sel(vnet);

	eth_random_addr(net_cfg->mac);
}

static void __iomem *epf_virtnet_map_host_vq(struct epf_virtnet *vnet, u32 pfn)
{
	void __iomem *ioaddr;
	phys_addr_t vq_addr;
	phys_addr_t phys_addr;
	int ret;
	size_t vq_size;
	struct pci_epf *epf = vnet->epf;
	struct pci_epc *epc = epf->epc;

	vq_addr = (phys_addr_t)pfn << VIRTIO_PCI_QUEUE_ADDR_SHIFT;
	vq_size = vring_size(EPF_VIRTNET_Q_SIZE, VIRTIO_PCI_VRING_ALIGN);

	ioaddr = pci_epc_mem_alloc_addr(epc, &phys_addr, vq_size);
	if (!ioaddr) {
		pr_err("Failed to allocate epc memory area\n");
		return NULL;
	}

	ret = pci_epc_map_addr(epc, epf->func_no, epf->vfunc_no, phys_addr,
			       vq_addr, vq_size);
	if (ret) {
		pr_err("failed to map virtqueue address\n");
		goto err_alloc;
	}

	return ioaddr;

err_alloc:
	pci_epc_mem_free_addr(epc, phys_addr, ioaddr, vq_size);

	return NULL;
}

static int epf_virtnet_dma_single(struct epf_virtnet *vnet, phys_addr_t pci,
				  dma_addr_t dma, size_t len,
				  void (*callback)(void *), void *param,
				  enum dma_transfer_direction dir)
{
	struct dma_async_tx_descriptor *desc;
	int err;
	struct dma_chan *chan = DMA_MEM_TO_DEV == dir ? vnet->tx_dma_chan : vnet->rx_dma_chan;
	struct dma_slave_config sconf = {};
	dma_cookie_t cookie;
	unsigned long flags = DMA_PREP_FENCE;

	if (DMA_MEM_TO_DEV == dir) {
		sconf.dst_addr = pci;
	} else {
		sconf.src_addr = pci;
	}

	err = dmaengine_slave_config(chan, &sconf);
	if (err)
		return err;

	if (callback)
		flags |= DMA_PREP_INTERRUPT;

	desc = dmaengine_prep_slave_single(chan, dma, len, dir, flags);
	if (!desc)
		return EIO;

	desc->callback = callback;
	desc->callback_param = param;

	cookie = dmaengine_submit(desc);

	err = dma_submit_error(cookie);
	if (err)
		return err;

	dma_async_issue_pending(chan);

	return 0;
}

struct rx_cb_param {
	struct epf_virtnet *vnet;
	void *buf;
	dma_addr_t dma;
	size_t len;
	u16 head;
};

struct tx_cb_param {
	struct epf_virtnet *vnet;
	dma_addr_t dma;
	size_t len;
	void *buf;
	u16 head;
};

void epf_virtnet_tx_cb(void *p) {
	struct tx_cb_param *param = (struct tx_cb_param *)p;
	struct epf_virtnet *vnet = param->vnet;
	struct device *dma_dev = vnet->epf->epc->dev.parent;

	vringh_complete_iomem(&vnet->tx_vrh, param->head, param->len);

	dma_unmap_single(dma_dev, param->dma, param->len, DMA_MEM_TO_DEV);

	kfree(param);
	kfree(param->buf);
}

static void tmp_callback(void *p)
{
	struct completion *transfer_complete = p;
	complete(transfer_complete);
}

static void epf_virtnet_host_tx_handler(struct work_struct *work)
{
	u16 tx_head, rx_head;
	int err;
	size_t total_len;

	struct epf_virtnet *vnet =
		container_of(work, struct epf_virtnet, host_tx_handler.work);
	struct vringh_kiov *riov = &vnet->rxiov;
	struct vringh_kiov *tiov = &vnet->txiov;
	struct device *dma_dev = vnet->epf->epc->dev.parent;

	err = vringh_getdesc_iomem(&vnet->rx_vrh, riov, NULL, &rx_head, GFP_KERNEL);
	if (err < 0) {
		pr_err("Failed the vringh_getdesc_iomem with %d", err);
		goto next;
	} else if (!err){
		goto next;
	}

	total_len = vringh_kiov_length(riov);

	err = vringh_getdesc_iomem(&vnet->tx_vrh, NULL, tiov, &tx_head, GFP_KERNEL);
	if (err < 0) {
		pr_err("Failed the vringh_getdesc_iomem with %d", err);
		goto next;
	} else if (!err) {
		vringh_abandon_iomem(&vnet->rx_vrh, 1);
		goto next;
	}

	// iterate tx/rx iov simultaneously because we can suspect the size of those are same.
	for(;riov->i < riov->used; riov->i++, tiov->i++) {
		u32 len, tx_len;
		u64 base;
		void *buf;
		phys_addr_t dma;
		struct completion transfer_complete;

		// rx
		len = riov->iov[riov->i].iov_len;
		base = (u64)riov->iov[riov->i].iov_base;

		buf = kmalloc(len, GFP_KERNEL);
		if (!buf)
			BUG();

		dma = dma_map_single(dma_dev, buf, len, DMA_DEV_TO_MEM);

		init_completion(&transfer_complete);
		err = epf_virtnet_dma_single(vnet, base, dma, len, tmp_callback, &transfer_complete, DMA_DEV_TO_MEM);
		if (err) {
			pr_err("failed to request a dma\n");
			goto next;
		}

		err = wait_for_completion_interruptible(&transfer_complete);
		if (err < 0) {
			pr_err("failed to wait complete\n");
			goto next;
		}

		dma_unmap_single(dma_dev, dma, len, DMA_DEV_TO_MEM);

		tx_len = tiov->iov[tiov->i].iov_len;
		if (tx_len < len)  {
			pr_err("not enough buffer: %d < %d", tx_len, len);
			goto next;
		}

		base = (u64)tiov->iov[tiov->i].iov_base;

		dma = dma_map_single(dma_dev, buf, len, DMA_MEM_TO_DEV);
		init_completion(&transfer_complete);
		err = epf_virtnet_dma_single(vnet, base, dma, tx_len, tmp_callback, &transfer_complete, DMA_MEM_TO_DEV);
		if (err < 0){
			pr_err("failed the dma(tx)\n");
			goto next;
		}

		err = wait_for_completion_interruptible(&transfer_complete);
		if (err < 0) {
			pr_err("failed to wait complete\n");
			goto next;
		}
	}

	vringh_complete_iomem(&vnet->rx_vrh, rx_head, total_len);
	vringh_complete_iomem(&vnet->tx_vrh, tx_head, total_len);

	queue_work(vnet->irq_wq, &vnet->raise_irq_work);

next:
	queue_delayed_work(vnet->host_tx_wq, &vnet->host_tx_handler,
			   usecs_to_jiffies(1));
}

static void epf_virtnet_raise_irq_handler(struct work_struct *work)
{
	struct epf_virtnet *vnet =
		container_of(work, struct epf_virtnet, raise_irq_work);

	struct pci_epf *epf = vnet->epf;
	struct pci_epc *epc = epf->epc;

	pci_epc_raise_irq(epc, epf->func_no, epf->vfunc_no, PCI_EPC_IRQ_LEGACY, 0);
}

static int epf_virtnet_config_monitor(void *data)
{
	struct epf_virtnet *vnet = data;
	struct virtio_common_config *common_cfg = &vnet->pci_config->common_cfg;
	const u16 q_select_default = epf_virtnet_get_default_q_sel(vnet);
	register u32 sel, pfn;
	void __iomem *tmp;
	struct vring vring;
	u32 txvq_pfn, rxvq_pfn;
	int ret;
	struct kvec *kvec;

	//TODO
	for (int i = 0; i < q_select_default; i++) {
		while ((sel = READ_ONCE(common_cfg->q_select)) ==
		       q_select_default)
			;
		while ((pfn = READ_ONCE(common_cfg->q_addr)) == 0)
			;

		/* reset to default to detect changes */
		WRITE_ONCE(common_cfg->q_addr, 0);
		WRITE_ONCE(common_cfg->q_select, q_select_default);

		switch(sel) {
			case 0:
				txvq_pfn = pfn;
				break;
			case 1:
				rxvq_pfn = pfn;
				break;
			default:
				pr_err("found an unknown selector %d\n", sel);
		}
		//TODO check the selector to prevent out of range accessing
	}

	sched_set_normal(vnet->monitor_config_task, 19);

	/*
	 * setup virtqueues
	 */
	tmp = epf_virtnet_map_host_vq(vnet, rxvq_pfn);
	if (!tmp) {
		pr_err("failed to map host virtqueue\n");
		return -ENOMEM;
	}
	vring_init(&vring, EPF_VIRTNET_Q_SIZE, tmp,
		   VIRTIO_PCI_VRING_ALIGN);

	ret = vringh_init_kern(&vnet->rx_vrh, 0, EPF_VIRTNET_Q_SIZE, false,
			       vring.desc, vring.avail, vring.used);
	if (ret) {
		pr_err("failed to init tx vringh\n");
		return ret;
	}

	kvec = kmalloc_array(EPF_VIRTNET_Q_SIZE, sizeof kvec[0], GFP_KERNEL);
	if (!kvec) {
		pr_err("failed malloc\n");
		return -ENOMEM;
	}
	vringh_kiov_init(&vnet->rxiov, kvec, EPF_VIRTNET_Q_SIZE);

	tmp = epf_virtnet_map_host_vq(vnet, txvq_pfn);
	if (!tmp) {
		pr_err("failed to map host virtqueue\n");
		return -ENOMEM;
	}
	vring_init(&vring, EPF_VIRTNET_Q_SIZE, tmp,
		   VIRTIO_PCI_VRING_ALIGN);

	ret = vringh_init_kern(&vnet->tx_vrh, 0, EPF_VIRTNET_Q_SIZE, false,
			       vring.desc, vring.avail, vring.used);
	if (ret) {
		pr_err("failed to init tx vringh\n");
		return ret;
	}

	kvec = kmalloc_array(EPF_VIRTNET_Q_SIZE, sizeof kvec[0], GFP_KERNEL);
	if (!kvec) {
		pr_err("failed malloc\n");
		return -ENOMEM;
	}
	vringh_kiov_init(&vnet->txiov, kvec, EPF_VIRTNET_Q_SIZE);

	// TODO more investigate a last argument.
	vnet->host_tx_wq = alloc_workqueue("epf_vnet_host_tx",
					   WQ_MEM_RECLAIM | WQ_HIGHPRI, 0);
	if (!vnet->host_tx_wq) {
		pr_err("Failed to allocate a workqueue for host tx virtqueue");
		return -ENOMEM;
	}

	vnet->irq_wq = alloc_workqueue("epf-vnet/irq-wq",
			WQ_MEM_RECLAIM | WQ_HIGHPRI | WQ_UNBOUND, 0);
	if (!vnet->irq_wq) {
		return -ENOMEM;
	}

	vringh_notify_enable_iomem(&vnet->tx_vrh);
	vringh_notify_enable_iomem(&vnet->rx_vrh);

	INIT_DELAYED_WORK(&vnet->host_tx_handler, epf_virtnet_host_tx_handler);
	INIT_WORK(&vnet->raise_irq_work, epf_virtnet_raise_irq_handler);

	queue_work(vnet->host_tx_wq, &vnet->host_tx_handler.work);

	return 0;
}

static int epf_virtnet_spawn_config_monitor(struct pci_epf *epf)
{
	struct epf_virtnet *vnet = epf_get_drvdata(epf);

	vnet->monitor_config_task = kthread_create(epf_virtnet_config_monitor,
						   vnet, "config monitor");
	if (IS_ERR(vnet->monitor_config_task)) {
		pr_err("Run pci configuration monitor failed\n");
		return PTR_ERR(vnet->monitor_config_task);
	}

	sched_set_fifo(vnet->monitor_config_task);
	wake_up_process(vnet->monitor_config_task);

	return 0;
}

struct epf_dma_filter_param {
	struct device *dev;
	u32 dma_mask;
};

static bool epf_virtnet_dma_filter(struct dma_chan *chan, void *param)
{
	struct epf_dma_filter_param *fparam = param;
	struct dma_slave_caps caps;

	memset(&caps, 0, sizeof caps);
	dma_get_slave_caps(chan, &caps);

	return chan->device->dev == fparam->dev &&
	       (fparam->dma_mask & caps.directions);
}

static int epf_virtnet_init_dma(struct epf_virtnet *vnet)
{
	dma_cap_mask_t mask;
	struct epf_dma_filter_param param;
	struct device *dma_dev;

	dma_dev = vnet->epf->epc->dev.parent;

	dma_cap_zero(mask);
	dma_cap_set(DMA_SLAVE, mask);

	param.dev = vnet->epf->epc->dev.parent;
	param.dma_mask = BIT(DMA_MEM_TO_DEV);

	vnet->tx_dma_chan = dma_request_channel(
			mask, epf_virtnet_dma_filter, &param);

	param.dma_mask = BIT(DMA_DEV_TO_MEM);

	vnet->rx_dma_chan = dma_request_channel(
			mask, epf_virtnet_dma_filter, &param);

	return 0;
}

static int epf_virtnet_bind(struct pci_epf *epf)
{
	int ret;
	struct pci_epc *epc = epf->epc;

	ret = epf_virtnet_load_epc_features(epf);
	if (ret) {
		pr_err("Load epc feature failed\n");
		return ret;
	}

	ret = pci_epc_write_header(epc, epf->func_no, epf->vfunc_no,
				   epf->header);
	if (ret) {
		pr_err("Configuration header write failed\n");
		return ret;
	}

	ret = epf_virtnet_setup_bar(epf);
	if (ret) {
		pr_err("PCI bar set failed\n");
		return ret;
	}

	epf_virtnet_init_config(epf);

	epf_virtnet_init_dma(epf_get_drvdata(epf));

	ret = epf_virtnet_spawn_config_monitor(epf);
	if (ret) {
		pr_err("PCI config monitor task run failed\n");
		return ret;
	}

	return 0;
}

static void epf_virtnet_unbind(struct pci_epf *epf)
{
}

static struct pci_epf_ops epf_virtnet_ops = {
	.bind = epf_virtnet_bind,
	.unbind = epf_virtnet_unbind,
};

static struct pci_epf_header epf_virtnet_header = {
	.vendorid = PCI_VENDOR_ID_REDHAT_QUMRANET,
	.deviceid = VIRTIO_TRANS_ID_NET,
	.subsys_vendor_id = PCI_VENDOR_ID_REDHAT_QUMRANET,
	.subsys_id = VIRTIO_ID_NET,
	.revid = 0,
 	.baseclass_code = PCI_BASE_CLASS_NETWORK, //TODO consider
// 	.subclass_code = , //TODO add subclasse? like 00 ethernet
	.interrupt_pin = PCI_INTERRUPT_INTA,
};

static int epf_virtnet_probe(struct pci_epf *epf)
{
	struct epf_virtnet *vnet;
	struct device *dev;

	dev = &epf->dev;

	vnet = devm_kzalloc(dev, sizeof(*vnet), GFP_KERNEL);
	if (!vnet)
		return -ENOMEM;

	epf->header = &epf_virtnet_header;
	vnet->epf = epf;
	epf_set_drvdata(epf, vnet);

	return 0;
}

static const struct pci_epf_device_id epf_virtnet_ids[] = {
	{
		.name = "pci_epf_virtio_net"
	},
	{},
};

static struct pci_epf_driver virtnet_driver = {
	.driver.name = "pci_epf_virtio_net",
	.ops = &epf_virtnet_ops,
	.id_table = epf_virtnet_ids,
	.probe = epf_virtnet_probe,
	.owner = THIS_MODULE
};

static int __init epf_virtnet_init(void)
{
	int ret;

	ret = pci_epf_register_driver(&virtnet_driver);
	if (ret) {
		pr_err("Failed to register pci epf virtio-net driver: %d\n",
		       ret);
		return ret;
	}

	return 0;
}
module_init(epf_virtnet_init);

static void epf_virtnet_exit(void)
{
	pci_epf_unregister_driver(&virtnet_driver);
}
module_exit(epf_virtnet_exit);

MODULE_LICENSE("GPL");
