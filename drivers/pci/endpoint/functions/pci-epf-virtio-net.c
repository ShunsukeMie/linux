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
};

struct virtnet_info {
	struct net_device *dev;
	struct epf_virtnet *epf_vnet;

	/* Max # of queue pairs supported by the device */
	u16 max_queue_pairs;

	/* # of queue pairs currently used by the driver */
	u16 curr_queue_pairs;

	/* Packet virtio header size */
	u8 hdr_len;
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


		// TODO transfer
		// - by dma
		// - by cpu

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

static int epf_virtnet_init_netdev(struct epf_virtnet *epf_vnet)
{
	int i, err = -ENOMEM;
	struct net_device *dev;
	struct virtnet_info *vi;
	u16 max_queue_pairs;
	int mtu;

	/* Find if host supports multiqueue/rss virtio_net device */
	//TODO read from config space?
	max_queue_pairs = 1;
// 	if (virtio_has_feature(vdev, VIRTIO_NET_F_MQ) || virtio_has_feature(vdev, VIRTIO_NET_F_RSS))
// 		max_queue_pairs =
// 		     virtio_cread16(vdev, offsetof(struct virtio_net_config, max_virtqueue_pairs));

	/* We need at least 2 queue's */
// 	if (max_queue_pairs < VIRTIO_NET_CTRL_MQ_VQ_PAIRS_MIN ||
// 	    max_queue_pairs > VIRTIO_NET_CTRL_MQ_VQ_PAIRS_MAX ||
// 	    !virtio_has_feature(vdev, VIRTIO_NET_F_CTRL_VQ))
// 		max_queue_pairs = 1;

	/* Allocate ourselves a network device with room for our info */
	dev = alloc_etherdev_mq(sizeof(struct virtnet_info), max_queue_pairs);
	if (!dev)
		return -ENOMEM;

	/* Set up network device as normal. */
	dev->priv_flags |= IFF_UNICAST_FLT | IFF_LIVE_ADDR_CHANGE |
			   IFF_TX_SKB_NO_LINEAR;
	dev->netdev_ops = &virtnet_netdev;
	dev->features = NETIF_F_HIGHDMA;

	dev->ethtool_ops = &virtnet_ethtool_ops;
// 	SET_NETDEV_DEV(dev, &vdev->dev);
// 	XXX:
// 	SET_NETDEV_DEV(dev, &epf_vnet->epf->epc->dev);
	SET_NETDEV_DEV(dev, &epf_vnet->epf->dev);

	/* Do we support "hardware" checksums? */
// 	if (virtio_has_feature(vdev, VIRTIO_NET_F_CSUM)) {
// 		/* This opens up the world of extra features. */
// 		dev->hw_features |= NETIF_F_HW_CSUM | NETIF_F_SG;
// 		if (csum)
// 			dev->features |= NETIF_F_HW_CSUM | NETIF_F_SG;
//
// 		if (virtio_has_feature(vdev, VIRTIO_NET_F_GSO)) {
// 			dev->hw_features |= NETIF_F_TSO
// 				| NETIF_F_TSO_ECN | NETIF_F_TSO6;
// 		}
// 		/* Individual feature bits: what can host handle? */
// 		if (virtio_has_feature(vdev, VIRTIO_NET_F_HOST_TSO4))
// 			dev->hw_features |= NETIF_F_TSO;
// 		if (virtio_has_feature(vdev, VIRTIO_NET_F_HOST_TSO6))
// 			dev->hw_features |= NETIF_F_TSO6;
// 		if (virtio_has_feature(vdev, VIRTIO_NET_F_HOST_ECN))
// 			dev->hw_features |= NETIF_F_TSO_ECN;
//
// 		dev->features |= NETIF_F_GSO_ROBUST;
//
// 		if (gso)
// 			dev->features |= dev->hw_features & NETIF_F_ALL_TSO;
// 		/* (!csum && gso) case will be fixed by register_netdev() */
// 	}
// 	if (virtio_has_feature(vdev, VIRTIO_NET_F_GUEST_CSUM))
// 		dev->features |= NETIF_F_RXCSUM;
// 	if (virtio_has_feature(vdev, VIRTIO_NET_F_GUEST_TSO4) ||
// 	    virtio_has_feature(vdev, VIRTIO_NET_F_GUEST_TSO6))
// 		dev->features |= NETIF_F_GRO_HW;
// 	if (virtio_has_feature(vdev, VIRTIO_NET_F_CTRL_GUEST_OFFLOADS))
// 		dev->hw_features |= NETIF_F_GRO_HW;

	dev->vlan_features = dev->features;

	/* MTU range: 68 - 65535 */
	dev->min_mtu = MIN_MTU;
	dev->max_mtu = MAX_MTU;

	/* Configuration may specify what MAC to use.  Otherwise random. */
// 	if (virtio_has_feature(vdev, VIRTIO_NET_F_MAC)) {
// 		u8 addr[ETH_ALEN];
//
// 		virtio_cread_bytes(vdev,
// 				   offsetof(struct virtio_net_config, mac),
// 				   addr, ETH_ALEN);
// 		eth_hw_addr_set(dev, addr);
// 	} else {
// 		eth_hw_addr_random(dev);
// 	}

	/* Set up our device-specific information */
	vi = netdev_priv(dev);
	vi->dev = dev;
// 	vi->vdev = vdev;
	vi->epf_vnet = epf_vnet;
// 	vdev->priv = vi;
// 	XXX: is it reuqired?
// 	epf_vnet->net = dev;

	/* If we can receive ANY GSO packets, we must allocate large ones. */
// 	if (virtio_has_feature(vdev, VIRTIO_NET_F_GUEST_TSO4) ||
// 	    virtio_has_feature(vdev, VIRTIO_NET_F_GUEST_TSO6) ||
// 	    virtio_has_feature(vdev, VIRTIO_NET_F_GUEST_ECN) ||
// 	    virtio_has_feature(vdev, VIRTIO_NET_F_GUEST_UFO))
// 		vi->big_packets = true;

// 	if (virtio_has_feature(vdev, VIRTIO_NET_F_MRG_RXBUF))
// 		vi->mergeable_rx_bufs = true;
//
// 	if (virtio_has_feature(vdev, VIRTIO_NET_F_HASH_REPORT))
// 		vi->has_rss_hash_report = true;
//
// 	if (virtio_has_feature(vdev, VIRTIO_NET_F_RSS))
// 		vi->has_rss = true;

// 	if (vi->has_rss || vi->has_rss_hash_report) {
// 		vi->rss_indir_table_size =
// 			virtio_cread16(vdev, offsetof(struct virtio_net_config,
// 				rss_max_indirection_table_length));
// 		vi->rss_key_size =
// 			virtio_cread8(vdev, offsetof(struct virtio_net_config, rss_max_key_size));
//
// 		vi->rss_hash_types_supported =
// 		    virtio_cread32(vdev, offsetof(struct virtio_net_config, supported_hash_types));
// 		vi->rss_hash_types_supported &=
// 				~(VIRTIO_NET_RSS_HASH_TYPE_IP_EX |
// 				  VIRTIO_NET_RSS_HASH_TYPE_TCP_EX |
// 				  VIRTIO_NET_RSS_HASH_TYPE_UDP_EX);
//
// 		dev->hw_features |= NETIF_F_RXHASH;
// 	}

// 	if (vi->has_rss_hash_report)
// 		vi->hdr_len = sizeof(struct virtio_net_hdr_v1_hash);
// 	else if (virtio_has_feature(vdev, VIRTIO_NET_F_MRG_RXBUF) ||
// 		 virtio_has_feature(vdev, VIRTIO_F_VERSION_1))
// 		vi->hdr_len = sizeof(struct virtio_net_hdr_mrg_rxbuf);
// 	else
		vi->hdr_len = sizeof(struct virtio_net_hdr);

// 	if (virtio_has_feature(vdev, VIRTIO_F_ANY_LAYOUT) ||
// 	    virtio_has_feature(vdev, VIRTIO_F_VERSION_1))
// 		vi->any_header_sg = true;
//
// 	if (virtio_has_feature(vdev, VIRTIO_NET_F_CTRL_VQ))
// 		vi->has_cvq = true;
//
// 	if (virtio_has_feature(vdev, VIRTIO_NET_F_MTU)) {
// 		mtu = virtio_cread16(vdev,
// 				     offsetof(struct virtio_net_config,
// 					      mtu));
// 		if (mtu < dev->min_mtu) {
// 			/* Should never trigger: MTU was previously validated
// 			 * in virtnet_validate.
// 			 */
// 			dev_err(&vdev->dev,
// 				"device MTU appears to have changed it is now %d < %d",
// 				mtu, dev->min_mtu);
// 			err = -EINVAL;
// 			goto free;
// 		}
//
// 		dev->mtu = mtu;
// 		dev->max_mtu = mtu;
//
// 		/* TODO: size buffers correctly in this case. */
// 		if (dev->mtu > ETH_DATA_LEN)
// 			vi->big_packets = true;
// 	}

// 	if (vi->any_header_sg)
// 		dev->needed_headroom = vi->hdr_len;

	/* Enable multiqueue by default */
	if (num_online_cpus() >= max_queue_pairs)
		vi->curr_queue_pairs = max_queue_pairs;
	else
		vi->curr_queue_pairs = num_online_cpus();
	vi->max_queue_pairs = max_queue_pairs;

	/* Allocate/initialize the rx/tx queues, and invoke find_vqs */
	err = init_vqs(vi);
	if (err)
		goto free;

// #ifdef CONFIG_SYSFS
// 	if (vi->mergeable_rx_bufs)
// 		dev->sysfs_rx_queue_group = &virtio_net_mrg_rx_group;
// #endif
	netif_set_real_num_tx_queues(dev, vi->curr_queue_pairs);
	netif_set_real_num_rx_queues(dev, vi->curr_queue_pairs);

	//TODO: need to setup  vi->speed and vi->duplex;
	//virtnet_init_settings(dev);

// 	if (virtio_has_feature(vdev, VIRTIO_NET_F_STANDBY)) {
// 		vi->failover = net_failover_create(vi->dev);
// 		if (IS_ERR(vi->failover)) {
// 			err = PTR_ERR(vi->failover);
// 			goto free_vqs;
// 		}
// 	}

// 	if (vi->has_rss || vi->has_rss_hash_report)
// 		virtnet_init_default_rss(vi);

	err = register_netdev(dev);
	if (err) {
		pr_debug("virtio_net: registering device failed\n");
		goto free_failover;
	}

// 	virtio_device_ready(vdev);

	err = virtnet_cpu_notif_add(vi);
	if (err) {
		pr_debug("virtio_net: registering cpu notifier failed\n");
		goto free_unregister_netdev;
	}

	virtnet_set_queues(vi, vi->curr_queue_pairs);

	/* Assume link up if device can't report link status,
	   otherwise get link status from config. */
	netif_carrier_off(dev);
// 	if (virtio_has_feature(vi->vdev, VIRTIO_NET_F_STATUS)) {
//		INIT_WORK(&vi->config_work, virtnet_config_changed_work);
// 		schedule_work(&vi->config_work);
// 	} else {
		vi->status = VIRTIO_NET_S_LINK_UP;
		virtnet_update_settings(vi);
		netif_carrier_on(dev);
// 	}

// 	for (i = 0; i < ARRAY_SIZE(guest_offloads); i++)
// 		if (virtio_has_feature(vi->vdev, guest_offloads[i]))
// 			set_bit(guest_offloads[i], &vi->guest_offloads);
// 	vi->guest_offloads_capable = vi->guest_offloads;

	pr_info("virtnet: registered device %s with %d RX and TX vq's\n",
		 dev->name, max_queue_pairs);

	return 0;

free_unregister_netdev:
	virtio_reset_device(vdev);

	unregister_netdev(dev);
free_failover:
	net_failover_destroy(vi->failover);
free_vqs:
	cancel_delayed_work_sync(&vi->refill);
	free_receive_page_frags(vi);
	virtnet_del_vqs(vi);
free:
	free_netdev(dev);
	return err;
}

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
