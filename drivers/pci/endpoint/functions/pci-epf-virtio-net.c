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
#include <linux/netdevice.h>

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
	struct net_device *ndev;
	struct {
		struct virtio_common_config common_cfg;
		struct virtio_net_config net_cfg;
	} __packed *pci_config;
	const struct pci_epc_features *epc_features;
	struct task_struct *monitor_config_task;
	struct task_struct *monitor_notify_task;
	void **rx_bufs;
	size_t rx_bufs_idx, rx_bufs_used_idx;
	struct workqueue_struct *workqueue;
	struct {
		u32 pfn;
		void __iomem *addr;
		struct vring vring;
	} * vqs;
	u16 rx_last_a_idx;

	void __iomem *tx_epc_mem, *rx_epc_mem;
	phys_addr_t tx_epc_mem_phys, rx_epc_mem_phys;
	struct work_struct raise_irq_work;
	struct work_struct tx_work;

	struct list_head tx_list;
	spinlock_t tx_list_lock;

	struct list_head rx_list;
	spinlock_t rx_list_lock;
};

struct local_ndev_adapter {
	struct net_device *dev;
	struct epf_virtnet *vnet;
	struct napi_struct napi;
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
	size_t offset, asize;
	phys_addr_t aaddr, aaddr_end;

	vq_addr = (phys_addr_t)pfn << VIRTIO_PCI_QUEUE_ADDR_SHIFT;
	vq_size = vring_size(EPF_VIRTNET_Q_SIZE, VIRTIO_PCI_VRING_ALIGN);

	offset = vq_addr & (0x1000 - 1);
	aaddr = vq_addr & ~(0x1000 - 1);
	aaddr_end = ((vq_addr + vq_size) + (0x1000 - 1))& ~(0x1000 - 1);
	asize = aaddr_end - aaddr;

	ioaddr = pci_epc_mem_alloc_addr(epc, &phys_addr, asize);
	if (!ioaddr) {
		pr_err("Failed to allocate epc memory area\n");
		return NULL;
	}

	ret = pci_epc_map_addr(epc, epf->func_no, epf->vfunc_no, phys_addr,
			       aaddr, asize);
	if (ret) {
		pr_err("failed to map virtqueue address\n");
		goto err_alloc;
	}

	return ioaddr + offset;

err_alloc:
	pci_epc_mem_free_addr(epc, phys_addr, ioaddr, asize);

	return NULL;
}

static void epf_virtnet_rx_packets(struct epf_virtnet *vnet);
static int epf_virtnet_notify_monitor(void *data)
{
	struct epf_virtnet *vnet = data;
	struct virtio_common_config *common_cfg = &vnet->pci_config->common_cfg;
	u16 queue;

	while (true) {
		while ((queue = READ_ONCE(common_cfg->q_notify)) == 2)
			;
		WRITE_ONCE(common_cfg->q_notify, 2);

		if (queue != 1)
			continue;

		epf_virtnet_rx_packets(vnet);
	}

	return 0;
}

static int epf_virtnet_spawn_notify_monitor(struct epf_virtnet *vnet)
{
	vnet->monitor_notify_task = kthread_create(epf_virtnet_notify_monitor,
						   vnet, "notify monitor");
	if (IS_ERR(vnet->monitor_notify_task)) {
		pr_err("failed to create a kernel thread (notify monitor)\n");
		return PTR_ERR(vnet->monitor_notify_task);
	}

	sched_set_fifo(vnet->monitor_notify_task);
	wake_up_process(vnet->monitor_notify_task);

	return 0;
}

static int epf_virtnet_config_monitor(void *data)
{
	struct epf_virtnet *vnet = data;
	struct virtio_common_config *common_cfg = &vnet->pci_config->common_cfg;
	const u16 q_select_default = epf_virtnet_get_default_q_sel(vnet);
	register u32 sel, pfn;
	void __iomem *tmp;
	int ret;

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
	vring_init(&vnet->vqs[0].vring, EPF_VIRTNET_Q_SIZE, tmp,
		   VIRTIO_PCI_VRING_ALIGN);

	tmp = epf_virtnet_map_host_vq(vnet, vnet->vqs[1].pfn);
	if (!tmp) {
		pr_err("failed to map host virtqueue\n");
		return -ENOMEM;
	}
	vring_init(&vnet->vqs[1].vring, EPF_VIRTNET_Q_SIZE, tmp,
		   VIRTIO_PCI_VRING_ALIGN);

	// TODO spawn kernel thread for monitoring queue_notify
	ret = epf_virtnet_spawn_notify_monitor(vnet);
	if (ret) {
		// stop tasks
		return ret;
	}

	// this call should be after an rc configuration
	netif_carrier_on(vnet->ndev);

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

static int local_ndev_open(struct net_device *dev)
{
	struct local_ndev_adapter *adapter = netdev_priv(dev);
	pr_debug("net_device_ops: open\n");

	napi_enable(&adapter->napi);
	// 	XXX:
	netif_start_queue(dev);

	return 0;
}

static int local_ndev_close(struct net_device *dev)
{
	return 0;
}

static int epf_virtnet_send_packet(struct epf_virtnet *vnet,
				   struct virtio_net_hdr *hdr, void *buf,
				   size_t len)
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

	/* transport data to root complex */
	{
		struct pci_epf *epf = vnet->epf;
		struct pci_epc *epc = epf->epc;
		size_t offset;
		u64 aaddr;
		u64 addr = ioread64(&rx_desc->addr);

		// alignment 0x1000 (vnet->alignment)
		offset = addr & (0x1000 - 1);
		aaddr = addr & ~(0x1000 - 1);

		ret = pci_epc_map_addr(epc, epf->func_no, epf->vfunc_no,
				       vnet->tx_epc_mem_phys,
				       aaddr, 0x1000);
		if (ret) {
			pr_err("failed to map addr\n");
			return ret;
		}

		memcpy_toio(vnet->tx_epc_mem + offset, hdr, sizeof *hdr);
		memcpy_toio(vnet->tx_epc_mem + offset + sizeof *hdr, buf, len);

		pci_epc_unmap_addr(epc, epf->func_no, epf->vfunc_no,
				   vnet->tx_epc_mem_phys);

		len += sizeof *hdr;
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

static void epf_virtnet_tx_handler(struct work_struct *work)
{
	struct epf_virtnet *vnet =
		container_of(work, struct epf_virtnet, tx_work);
	struct virtio_net_hdr hdr;
	struct sk_buff *skb;
	struct list_head *entry;
	int res;

	hdr.flags = 0;
	hdr.gso_type = VIRTIO_NET_HDR_GSO_NONE;

	while(true) {
		spin_lock(&vnet->tx_list_lock);
		if (list_empty(&vnet->tx_list)) {
			break;
		}
		entry = vnet->tx_list.next;
		list_del(entry);
		spin_unlock(&vnet->tx_list_lock);

		skb = list_entry(entry, struct sk_buff, list);

		res = epf_virtnet_send_packet(vnet, &hdr, skb->data, skb->len);
		if (res)
			pr_err("sending packet failed\n");

		napi_consume_skb(skb, 0);
	}

	INIT_LIST_HEAD(&vnet->tx_list);
	spin_unlock(&vnet->tx_list_lock);

	if (skb)
		queue_work(vnet->workqueue, &vnet->raise_irq_work);
}

static netdev_tx_t local_ndev_start_xmit(struct sk_buff *skb,
					 struct net_device *dev)
{
	struct local_ndev_adapter *adapter = netdev_priv(dev);
	struct epf_virtnet *vnet = adapter->vnet;

	spin_lock(&vnet->tx_list_lock);
	list_add_tail(&skb->list, &vnet->tx_list);
	spin_unlock(&vnet->tx_list_lock);

	queue_work(vnet->workqueue, &vnet->tx_work);

	return NETDEV_TX_OK;
}

static const struct net_device_ops epf_virtnet_ndev_ops = {
	.ndo_open = local_ndev_open,
	.ndo_stop = local_ndev_close,
	.ndo_start_xmit = local_ndev_start_xmit,
	// 	.ndo_get_stats64 = virtnet_stats,
};

static void *local_ndev_receive(struct epf_virtnet *vnet, struct vring *vring,
				u16 u_idx, u32 *total_size)
{
	struct vring_desc *desc;
	u16 d_idx, next_d_idx;
	void *buf, *cur;
	int ret;

	d_idx = ioread16(&vring->avail->ring[u_idx]);

	WARN_ON(d_idx > EPF_VIRTNET_Q_SIZE);
	buf = vnet->rx_bufs[vnet->rx_bufs_idx];
	vnet->rx_bufs_idx = (vnet->rx_bufs_idx + 1) & EPF_VIRTNET_Q_MASK;

	*total_size = 0;

	while (true) {
		u16 flags;
		u32 len;
		u64 addr;
		u64 offset;

		desc = &vring->desc[d_idx];

		flags = ioread16(&desc->flags);
		len = ioread32(&desc->len);
		addr = ioread64(&desc->addr);
		next_d_idx = ioread16(&desc->next);

		offset = *total_size;
		*total_size += len;
		cur = buf + offset;

		{
			struct pci_epf *epf = vnet->epf;
			struct pci_epc *epc = epf->epc;
			size_t off;
			u64 aaddr;

			// alignment 0x1000 (vnet->alignment)
			off = addr & (0x1000 - 1);
			aaddr = addr & ~(0x1000 - 1);

			ret = pci_epc_map_addr(epc, epf->func_no, epf->vfunc_no,
					       vnet->rx_epc_mem_phys, aaddr,
					       0x1000);
			if (ret) {
				pr_err("failed to map addr\n");
				return NULL;
			}

			memcpy_fromio(cur, vnet->rx_epc_mem + off, len);

			pci_epc_unmap_addr(epc, epf->func_no, epf->vfunc_no,
					   vnet->rx_epc_mem_phys);
		}

		if (!(flags & VRING_DESC_F_NEXT))
			break;

		d_idx = next_d_idx;
	}

	return buf;
}

static int local_ndev_rx_poll(struct napi_struct *napi, int budget)
{
 	struct local_ndev_adapter *adapter = container_of(napi, struct local_ndev_adapter, napi);
 	struct epf_virtnet *vnet = adapter->vnet;

	struct sk_buff *skb;
	int n_rx = 0;

	while(true) {
		spin_lock(&vnet->rx_list_lock);
		skb = list_first_entry_or_null(&vnet->rx_list, struct sk_buff, list);
		if (!skb) {
			spin_unlock(&vnet->rx_list_lock);
			break;
		}
		skb_list_del_init(skb);
		spin_unlock(&vnet->rx_list_lock);

		napi_gro_receive(&adapter->napi, skb);

		n_rx++;
	}

	if (n_rx < budget)
		napi_complete_done(&adapter->napi, n_rx);

	return n_rx;
}

static void epf_virtnet_refill_rx_bufs(struct epf_virtnet *vnet)
{
	size_t u_idx = vnet->rx_bufs_used_idx;
	size_t idx = vnet->rx_bufs_idx;

	while(u_idx != idx) {
		struct page* p = dev_alloc_page();
		if (!p) {
			pr_err("failed to allocate rx buffer");
			return;
		}

		vnet->rx_bufs[u_idx] = page_address(p);


		u_idx = (u_idx + 1) & EPF_VIRTNET_Q_MASK;
	}

	vnet->rx_bufs_used_idx = u_idx;
}

static void epf_virtnet_rx_packets(struct epf_virtnet *vnet)
{
	struct local_ndev_adapter *adapter = netdev_priv(vnet->ndev);
	struct net_device *dev = adapter->dev;

	struct vring *vring = &vnet->vqs[1].vring;
	u16 used_idx, pre_used_idx, desc_idx;
	u16 a_idx, pre_a_idx;
	u16 mod_u_idx;
	u32 total_len;
	int len;
	void *buf;
	struct sk_buff *skb;
	int rxs = 0;

	pre_used_idx = used_idx = ioread16(&vring->used->idx);
	pre_a_idx = a_idx = ioread16(&vring->avail->idx);

	while (used_idx != a_idx) {
		mod_u_idx = used_idx & EPF_VIRTNET_Q_MASK;
		desc_idx = ioread16(&vring->avail->ring[mod_u_idx]);

		buf = local_ndev_receive(vnet, vring, mod_u_idx, &total_len);
		if (!buf) {
			pr_err("failed to receive a packet");
			return;
		}

		// skip virito_net header
		len = SKB_DATA_ALIGN(total_len) + SKB_DATA_ALIGN(sizeof (struct skb_shared_info));
		skb = napi_build_skb(buf, len);
		if (!skb) {
			pr_err("failed to build skb");
			return;
		}

		skb_reserve(skb, sizeof (struct virtio_net_hdr));
		skb_put(skb, total_len - sizeof (struct virtio_net_hdr));

		skb->protocol = eth_type_trans(skb, dev);

		spin_lock(&vnet->rx_list_lock);
		list_add_tail(&skb->list, &vnet->rx_list);
		spin_unlock(&vnet->rx_list_lock);

		iowrite16(desc_idx, &vring->used->ring[mod_u_idx].id);
		iowrite32(total_len, &vring->used->ring[mod_u_idx].len);

		used_idx++;
		rxs++;
	}

	if (pre_used_idx != used_idx) {
		iowrite16(used_idx, &vring->used->idx);

		// TODO
// 		if (!ioread16(&vring->avail->flags) & VRING_AVAIL_F_NO_INTERRUPT)
// 			queue_work(vnet->workqueue, &vnet->raise_irq_work);

		napi_schedule(&adapter->napi);
	}

	{
		const size_t rx_bufs_refill_threshold = 16;
		int diff = vnet->rx_bufs_idx - vnet->rx_bufs_used_idx;
		if (diff < 0)
			diff += EPF_VIRTNET_Q_SIZE;

		if (diff > rx_bufs_refill_threshold)
			epf_virtnet_refill_rx_bufs(vnet);
	}
}

static void epf_virtnet_raise_irq_handler(struct work_struct *work)
{
	struct epf_virtnet *vnet =
		container_of(work, struct epf_virtnet, raise_irq_work);

	struct pci_epf *epf = vnet->epf;
	struct pci_epc *epc = epf->epc;

	pci_epc_raise_irq(epc, epf->func_no, epf->vfunc_no, PCI_EPC_IRQ_LEGACY, 0);
}

static int epf_virtnet_create_netdev(struct pci_epf *epf)
{
	int err;
	struct net_device *ndev;
	struct local_ndev_adapter *ndev_adapter;
	struct epf_virtnet *vnet = epf_get_drvdata(epf);
	struct virtio_net_config *net_cfg = &vnet->pci_config->net_cfg;

	vnet->tx_epc_mem = pci_epc_mem_alloc_addr(epf->epc, &vnet->tx_epc_mem_phys, 0x1000);
	if (!vnet->tx_epc_mem) {
		pr_err("failed to allocate epc mem %s:%d\n", __func__,
				__LINE__);
		return -ENOMEM;
	}

	vnet->rx_epc_mem = pci_epc_mem_alloc_addr(epf->epc, &vnet->rx_epc_mem_phys, 0x1000);
	if (!vnet->rx_epc_mem) {
		pr_err("failed to allocate epc mem %s:%d\n", __func__,
				__LINE__);
		return -ENOMEM;
	}

	ndev = alloc_etherdev_mq(0, net_cfg->max_virtqueue_pairs);
	if (!ndev)
		return -ENOMEM;

	ndev_adapter = netdev_priv(ndev);
	ndev_adapter->dev = ndev;
	ndev_adapter->vnet = vnet;
	vnet->ndev = ndev;

	ndev->priv_flags = 0;
	ndev->netdev_ops = &epf_virtnet_ndev_ops;
//
 	//TODO
// 	ndev->ethtool_ops;

	// setup hardware features
	SET_NETDEV_DEV(ndev, &epf->dev);

	ndev->hw_features = 0;
	ndev->features = 0;

	ndev->vlan_features = ndev->features;

	ndev->min_mtu = ETH_MIN_MTU;
	ndev->max_mtu = ETH_MAX_MTU;

	eth_hw_addr_random(ndev);

	ndev->mtu = ETH_MAX_MTU;

	ndev->needed_headroom = sizeof (struct virtio_net_hdr);

	// TODO examine GFP frags GFP_ATOMIC or GFP_KERNEL
	vnet->rx_bufs = kmalloc_array(sizeof (void *), EPF_VIRTNET_Q_SIZE, GFP_ATOMIC);
	if (!vnet->rx_bufs) {
		pr_err("failed to allocate rx buffer");
		return -ENOMEM;
	}
	for(int i=0; i< EPF_VIRTNET_Q_SIZE; ++i) {
		struct page* p = dev_alloc_page();
		if (!p) {
			pr_err("failed to allocate rx buffer");
			return -ENOMEM;
		}
		vnet->rx_bufs[i] = page_address(p);
	}

	// pci-epc core uses mutex.
	err = dev_set_threaded(ndev, true);
	if (err) {
		pr_err("network devince threading failed\n");
		return err;
	}

	netif_napi_add(ndev, &ndev_adapter->napi, local_ndev_rx_poll, NAPI_POLL_WEIGHT);

	netif_carrier_off(ndev);

	INIT_WORK(&vnet->raise_irq_work, epf_virtnet_raise_irq_handler);
	INIT_WORK(&vnet->tx_work, epf_virtnet_tx_handler);

	INIT_LIST_HEAD(&vnet->tx_list);
	spin_lock_init(&vnet->tx_list_lock);
	INIT_LIST_HEAD(&vnet->rx_list);
	spin_lock_init(&vnet->rx_list_lock);

	err = register_netdev(ndev);
	if (err) {
		pr_err("registering net device failed");
		return err;
	}

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

	ret = epf_virtnet_create_netdev(epf);
	if (ret) {
		pr_err("Network device creation failed\n");
		return ret;
	}

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

	vnet->workqueue = alloc_workqueue("epf-vnet-wq",
			WQ_MEM_RECLAIM | WQ_HIGHPRI, 0);
	if (!vnet->workqueue) {
		pr_err("failed to create workqueue\n");
		return -ENOMEM;
	}

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
