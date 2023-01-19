// SPDX-License-Identifier: GPL-2.0
/*
 * Functions work for Root complext side using EPF framework
 */
#include <linux/pci-epf.h>
#include <linux/pci-epc.h>
#include <linux/pci_ids.h>
#include <linux/sched.h>

#include <linux/virtio_pci.h>

#include "pci-epf-vnet.h"

#define VIRTIO_NET_LEGACY_CFG_BAR BAR_0

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
					 u16 *rxpfn)
{
	u16 default_sel = vnet->vnet_cfg.max_virtqueue_pairs * 2;
	u32 __iomem *queue_pfn = vnet->rc.cfg_base + VIRTIO_PCI_QUEUE_PFN;
	u16 __iomem *queue_sel = vnet->rc.cfg_base + VIRTIO_PCI_QUEUE_SEL;
	u8 __iomem *pci_status = vnet->rc.cfg_base + VIRTIO_PCI_STATUS;
	u16 _txpfn, _rxpfn;
	u32 pfn;
	u16 sel;
	int err;

	_txpfn = _rxpfn = 0;

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
		default:
			pr_err("Driver attpmt to use invalid queue (%d)\n",
			       sel);
			// TODO: consider the error state of this device
			err = -EIO;
			goto err_out;
		}

		if (_rxpfn && _txpfn)
			break;
	}

	while (!((ioread8(pci_status) & VIRTIO_CONFIG_S_DRIVER_OK)))
		;

	*rxpfn = _rxpfn;
	*txpfn = _txpfn;

	return 0;

err_out:
	return err;
}

static int epf_vnet_rc_monitor_notify(void *data)
{
	// 	struct epf_vnet *vnet = data;

	//TODO
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
	u16 txpfn, rxpfn;
	int err;
	struct pci_epf_vringh *txvrh, *rxvrh;

	err = epf_vnet_rc_negotiate_configs(vnet, &txpfn, &rxpfn);
	if (err) {
		pr_err("Failed to negatiate configs with driver\n");
		return err;
	}

	sched_set_normal(vnet->rc.device_setup_task, 19);

	txvrh = pci_epf_virtio_alloc_vringh(epf, vnet->virtio.features, txpfn,
					    epf_vnet_get_vq_size(),
					    PCI_EPF_VQ_LOCATE_REMOTE);
	if (IS_ERR(txvrh)) {
		pr_err("Failed to setup virtqueue\n");
		return PTR_ERR(txvrh);
	}

	rxvrh = pci_epf_virtio_alloc_vringh(epf, vnet->virtio.features, rxpfn,
					    epf_vnet_get_vq_size(),
					    PCI_EPF_VQ_LOCATE_REMOTE);
	if (IS_ERR(rxvrh)) {
		pr_err("Failed to setup virtqueue\n");
		return PTR_ERR(rxvrh);
	}

	err = epf_vnet_rc_spawn_notify_monitor(vnet);
	if (err) {
		pr_err("Failed to create notify monitor thread\n");
		return err;
	}

	pr_info("success to setup virtqueue");
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

	//TODO setup workqueues for tx and irq

	return epf_vnet_rc_spawn_device_setup_task(vnet);
}
