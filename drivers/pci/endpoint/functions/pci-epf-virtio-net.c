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
	struct workqueue_struct *host_tx_wq;
	struct delayed_work host_tx_handler;
	struct {
		u32 pfn;
		void __iomem *addr;
		struct vring vring;
	} *vqs;
	u16 rx_last_a_idx;
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
			       BIT(VIRTIO_NET_F_STATUS);
	common_cfg->q_addr = 0;
	common_cfg->q_size = EPF_VIRTNET_Q_SIZE;
	common_cfg->q_notify = 2;
	common_cfg->isr_status = 1;

	net_cfg->max_virtqueue_pairs = 1;
	net_cfg->status = VIRTIO_NET_S_LINK_UP;
	net_cfg->mtu = 1500;

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

static int memcpy_from_pci(struct epf_virtnet *vnet, void *dest, u64 pci_addr,
			   size_t len)
{
	void __iomem *addr;
	phys_addr_t phys;
	int ret;
	struct pci_epf *epf = vnet->epf;
	struct pci_epc *epc = epf->epc;

	addr = pci_epc_mem_alloc_addr(epc, &phys, len);
	if (!addr) {
		pr_err("failed to allocate epc mem %s:%d\n", __func__,
		       __LINE__);
		return -ENOMEM;
	}

	ret = pci_epc_map_addr(epc, epf->func_no, epf->vfunc_no, phys, pci_addr,
			       len);
	if (ret) {
		pr_err("failed to map addr\n");
		return ret;
	}

	memcpy_fromio(dest, addr, len);

	pci_epc_unmap_addr(epc, epf->func_no, epf->vfunc_no, phys);
	pci_epc_mem_free_addr(epc, phys, addr, len);

	return 0;
}

static int memcpy_to_pci(struct epf_virtnet *vnet, u64 pci_addr, void *src,
			 size_t len)
{
	void __iomem *addr;
	phys_addr_t phys;
	int ret;
	struct pci_epf *epf = vnet->epf;
	struct pci_epc *epc = epf->epc;

	addr = pci_epc_mem_alloc_addr(epc, &phys, len);
	if (!addr) {
		pr_info("failed to allocate epc mem %s:%d\n", __func__,
			__LINE__);
		return -ENOMEM;
	}

	ret = pci_epc_map_addr(epc, epf->func_no, epf->vfunc_no, phys, pci_addr,
			       len);
	if (ret) {
		pr_info("failed to map addr\n");
		return ret;
	}

	memcpy_toio(addr, src, len);

	pci_epc_unmap_addr(epc, epf->func_no, epf->vfunc_no, phys);
	pci_epc_mem_free_addr(epc, phys, addr, len);

	return 0;
}

/*
 * receive packet from root complex
 *
 * Returns an allocated memory from heap.
 */
static void *_tmp_recv_packet(struct epf_virtnet *vnet, struct vring *tx_vr,
			      u16 tx_u_idx, u32 *buf_len)
{
	struct vring_desc *tx_desc;
	u16 tx_next_d_idx;
	int ret;
	void *buf = NULL;

	tx_next_d_idx = ioread16(&tx_vr->avail->ring[tx_u_idx]);

	*buf_len = 0;

	while (true) {
		u64 tx_base;
		u32 tx_len;
		u16 tx_flags;
		size_t offset;
		void *cur;

		tx_desc = &tx_vr->desc[tx_next_d_idx];

		tx_base = ioread64(&tx_desc->addr);
		tx_len = ioread32(&tx_desc->len);
		tx_flags = ioread16(&tx_desc->flags);
		tx_next_d_idx = ioread16(&tx_desc->next);

		offset = *buf_len;
		*buf_len += tx_len;

		buf = krealloc(buf, *buf_len, GFP_KERNEL);
		if (!buf) {
			pr_err("Failed to alocate memory\n");
			goto err;
		}

		cur = buf + offset;

		ret = memcpy_from_pci(vnet, cur, tx_base, tx_len);
		if (ret) {
			pr_err("Failed to load data from pci address space\n");
			goto err;
		}

		if (!(tx_flags & VRING_DESC_F_NEXT)) {
			break;
		}
	}

	return buf;

err:
	kfree(buf);
	return NULL;
}

/*
 * send packet for root complex
 */
static int _tmp_send_packet(struct epf_virtnet *vnet, void *buf, size_t len)
{
	int ret;
	u16 rx_u_idx, rx_a_idx, rx_d_idx;
	u16 mod_u_idx, mod_last_a_idx;
	struct vring *vring;
	struct vring_desc *rx_desc;

	vring = &vnet->vqs[0].vring;

	rx_u_idx = ioread16(&vring->used->idx);
	rx_a_idx = ioread16(&vring->avail->idx);
	mod_u_idx = rx_u_idx & EPF_VIRTNET_Q_MASK;
	mod_last_a_idx = vnet->rx_last_a_idx & EPF_VIRTNET_Q_MASK;

	if (vnet->rx_last_a_idx == rx_a_idx) {
		pr_err("virtqueue is full\n");
		return -EAGAIN;
	}

	rx_d_idx = ioread16(&vring->avail->ring[mod_last_a_idx]);
	rx_desc = &vring->desc[rx_d_idx];
	ret = memcpy_to_pci(vnet, ioread64(&rx_desc->addr), buf, len);
	if (ret) {
		pr_err("Failed to store data to pci address space");
		return ret;
	}

	iowrite32(len, &rx_desc->len);
	iowrite16(ioread16(&rx_desc->flags) & ~0x1, &rx_desc->flags);

	iowrite32(len, &vring->used->ring[mod_u_idx].len);
	iowrite32(rx_d_idx, &vring->used->ring[mod_u_idx].id);

	vnet->rx_last_a_idx++;

	rx_u_idx++;
	iowrite16(rx_u_idx, &vring->used->idx);

	return 0;
}

static int _tmp_send_back(struct epf_virtnet *vnet, struct vring *tx_vr,
			  u16 tx_u_idx, u32 *total_len)
{
	void *buf;
	int ret;

	buf = _tmp_recv_packet(vnet, tx_vr, tx_u_idx, total_len);
	if (!buf) {
		pr_err("failed to receive packet from virtqueue\n");
		return -1;
	}

	// Update ARP sender ip
	// size of virtio-net header and offset of arp sender ip.
	((u8 *)buf)[0x0a + 0x1f]++;

	ret = _tmp_send_packet(vnet, buf, *total_len);

	kfree(buf);

	return ret;
}

static void epf_virtnet_host_tx_handler(struct work_struct *work)
{
	struct epf_virtnet *vnet =
		container_of(work, struct epf_virtnet, host_tx_handler.work);
	struct pci_epf *epf = vnet->epf;
	struct pci_epc *epc = epf->epc;
	struct vring *vring;
	u16 used_idx, pre_used_idx, desc_idx;
	u16 a_idx, pre_a_idx;
	u16 mod_u_idx;
	u32 total_len;

	vring = &vnet->vqs[1].vring;

	pre_used_idx = used_idx = ioread16(&vring->used->idx);
	pre_a_idx = a_idx = ioread16(&vring->avail->idx);

cont:
	while (used_idx != a_idx) {
		mod_u_idx = used_idx & EPF_VIRTNET_Q_MASK;
		desc_idx = ioread16(&vring->avail->ring[mod_u_idx]);

		if (_tmp_send_back(vnet, vring, mod_u_idx, &total_len))
			pr_err("failed at _tmp_send_back\n");

		iowrite16(desc_idx, &vring->used->ring[mod_u_idx].id);
		iowrite32(total_len, &vring->used->ring[mod_u_idx].len);

		used_idx++;
	}

	if (pre_used_idx != used_idx) {
		iowrite16(used_idx, &vring->used->idx);

		if (!ioread16(&vring->avail->flags) & VRING_AVAIL_F_NO_INTERRUPT)
			pci_epc_raise_irq(epc, epf->func_no, epf->vfunc_no, PCI_EPC_IRQ_LEGACY, 0);

	}

	a_idx = ioread16(&vring->avail->idx);
	if (pre_a_idx != a_idx) {
		pre_a_idx = a_idx;
		goto cont;
	}

	queue_delayed_work(vnet->host_tx_wq, &vnet->host_tx_handler,
			   usecs_to_jiffies(1));
}

static int epf_virtnet_config_monitor(void *data)
{
	struct epf_virtnet *vnet = data;
	struct virtio_common_config *common_cfg = &vnet->pci_config->common_cfg;
	const u16 q_select_default = epf_virtnet_get_default_q_sel(vnet);
	register u32 sel, pfn;
	void __iomem *tmp;

	vnet->vqs = kcalloc(2, sizeof vnet->vqs[0], GFP_KERNEL);

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

		//TODO check the selector to prevent out of range accessing
		vnet->vqs[sel].pfn = pfn;
	}

	sched_set_normal(vnet->monitor_config_task, 19);

	/*
	 * setup virtqueues
	 */
	tmp = epf_virtnet_map_host_vq(vnet, vnet->vqs[0].pfn);
	if (!tmp) {
		pr_err("failed to map host virtqueue\n");
		return -ENOMEM;
	}
	vring_init(&vnet->vqs[0].vring, EPF_VIRTNET_Q_SIZE, tmp, VIRTIO_PCI_VRING_ALIGN);

	tmp = epf_virtnet_map_host_vq(vnet, vnet->vqs[1].pfn);
	if (!tmp) {
		pr_err("failed to map host virtqueue\n");
		return -ENOMEM;
	}
	vring_init(&vnet->vqs[1].vring, EPF_VIRTNET_Q_SIZE, tmp, VIRTIO_PCI_VRING_ALIGN);

	// TODO more investigate a last argument.
	vnet->host_tx_wq = alloc_workqueue("epf_vnet_host_tx",
					   WQ_MEM_RECLAIM | WQ_HIGHPRI, 0);
	if (!vnet->host_tx_wq) {
		pr_err("Failed to allocate a workqueue for host tx virtqueue");
		return -ENOMEM;
	}

	INIT_DELAYED_WORK(&vnet->host_tx_handler, epf_virtnet_host_tx_handler);
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
