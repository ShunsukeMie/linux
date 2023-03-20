// SPDX-License-Identifier: GPL-2.0

#include <linux/module.h>
#include <linux/pci-epf.h>
#include <linux/vringh.h>
#include <linux/pci-epc.h>
#include <linux/virtio_console.h>
#include <linux/virtio_pci.h>
#include <linux/kthread.h>

#include "pci-epf-virtio.h"

struct epf_vcon {
	struct pci_epf *epf;
	struct virtio_console_config config;
	void __iomem *cfg_base;
	struct task_struct *device_setup_task, *notify_monitor_task;
	struct vringh_kiov tx_iov, rx_iov;
	struct epf_vringh *txvrh, *rxvrh;
	struct vringh_kiov riov, wiov;
};

static struct pci_epf_header epf_vcon_pci_header = {
	.vendorid = PCI_VENDOR_ID_REDHAT_QUMRANET,
	.deviceid = VIRTIO_TRANS_ID_CONSOLE,
	.subsys_vendor_id = PCI_VENDOR_ID_REDHAT_QUMRANET,
	.subsys_id = VIRTIO_ID_CONSOLE,
	.revid = 0,
	.baseclass_code = PCI_BASE_CLASS_COMMUNICATION,
	.interrupt_pin = PCI_INTERRUPT_PIN,
};

#define EPF_VCON_NQUEUES 2

static void epf_vcon_rhost_memcpy_config(struct epf_vcon *vcon, size_t offset,
					 void *buf, size_t len)
{
	void __iomem *base = vcon->cfg_base + offset;

	memcpy_toio(base, buf, len);
}

static u8 epf_vcon_rhost_get_config8(struct epf_vcon *vcon, size_t offset)
{
	void __iomem *base = vcon->cfg_base + offset;

	return ioread8(base);
}

static void epf_vcon_rhost_set_config8(struct epf_vcon *vcon, size_t offset,
				       u8 config)
{
	void __iomem *base = vcon->cfg_base + offset;

	iowrite8(ioread8(base) | config, base);
}

static void epf_vcon_rhost_clear_config16(struct epf_vcon *vcon, size_t offset,
					  u16 config)
{
	void __iomem *base = vcon->cfg_base + offset;

	iowrite16(ioread16(base) & ~config, base);
}

static void epf_vcon_rhost_set_config32(struct epf_vcon *vcon, size_t offset,
					u32 config)
{
	void __iomem *base = vcon->cfg_base + offset;

	iowrite32(ioread32(base) | config, base);
}

static void epf_vcon_rhost_set_config16(struct epf_vcon *vcon, size_t offset,
					u16 config)
{
	void __iomem *base = vcon->cfg_base + offset;

	iowrite16(ioread16(base) | config, base);
}

static int epf_vcon_get_vq_size(void)
{
	return 256;
}

static void epf_vcon_rhost_setup_configs(struct epf_vcon *vcon)
{
	u16 default_qindex = EPF_VCON_NQUEUES;

	epf_vcon_rhost_set_config32(vcon, VIRTIO_PCI_HOST_FEATURES, 0);

	epf_vcon_rhost_set_config16(vcon, VIRTIO_PCI_ISR, VIRTIO_PCI_ISR_QUEUE);
	/*
	 * Initialize the queue notify and selector to outside of the appropriate
	 * virtqueue index. It is used to detect change with polling because there is
	 * no other ways to detect host side driver updateing those values
	 */
	epf_vcon_rhost_set_config16(vcon, VIRTIO_PCI_QUEUE_NOTIFY,
				    default_qindex);
	epf_vcon_rhost_set_config16(vcon, VIRTIO_PCI_QUEUE_SEL, default_qindex);
	/* This pfn is also set to 0 for the polling as well */
	epf_vcon_rhost_set_config16(vcon, VIRTIO_PCI_QUEUE_PFN, 0);

	epf_vcon_rhost_set_config16(vcon, VIRTIO_PCI_QUEUE_NUM,
				    epf_vcon_get_vq_size());
	epf_vcon_rhost_set_config8(vcon, VIRTIO_PCI_STATUS, 0);
	epf_vcon_rhost_memcpy_config(vcon, VIRTIO_PCI_CONFIG_OFF(false),
				     &vcon->config, sizeof(vcon->config));
}

#define VIRTIO_PCI_LEGACY_CFG_BAR 0

static int epf_vcon_setup_bar(struct epf_vcon *vcon)
{
	int err;
	size_t cfg_bar_size = sizeof(struct virtio_console_config);
	struct pci_epf *epf = vcon->epf;
	const struct pci_epc_features *features;
	struct pci_epf_bar *config_bar = &epf->bar[VIRTIO_PCI_LEGACY_CFG_BAR];

	features = pci_epc_get_features(epf->epc, epf->func_no, epf->vfunc_no);
	if (!features) {
		pr_debug("Failed to get PCI EPC features\n");
		return -EOPNOTSUPP;
	}

	if (features->reserved_bar & BIT(VIRTIO_PCI_LEGACY_CFG_BAR)) {
		pr_debug("Cannot use the PCI BAR for legacy virtio pci\n");
		return -EOPNOTSUPP;
	}

	if (features->bar_fixed_size[VIRTIO_PCI_LEGACY_CFG_BAR]) {
		if (cfg_bar_size >
		    features->bar_fixed_size[VIRTIO_PCI_LEGACY_CFG_BAR]) {
			pr_debug("PCI BAR size is not enough\n");
			return -ENOMEM;
		}
	}

	config_bar->flags |= PCI_BASE_ADDRESS_MEM_TYPE_64;

	vcon->cfg_base = pci_epf_alloc_space(epf, cfg_bar_size,
					     VIRTIO_PCI_LEGACY_CFG_BAR,
					     features->align,
					     PRIMARY_INTERFACE);
	if (!vcon->cfg_base) {
		pr_debug("Failed to allocate virtio-net config memory\n");
		return -ENOMEM;
	}

	epf_vcon_rhost_setup_configs(vcon);

	err = pci_epc_set_bar(epf->epc, epf->func_no, epf->vfunc_no,
			      config_bar);
	if (err) {
		pr_debug("Failed to set PCI BAR");
		goto err_free_space;
	}

	return 0;

err_free_space:
	pci_epf_free_space(epf, vcon->cfg_base, VIRTIO_PCI_LEGACY_CFG_BAR,
			   PRIMARY_INTERFACE);
	return err;
}

static void epf_vcon_notify_callback(void *param)
{
	struct epf_vcon *vcon = param;
	struct vringh_kiov *riov = &vcon->riov;
	struct vringh_kiov *wiov = &vcon->wiov;
	struct vringh *wvrh = &vcon->txvrh->vrh;
// 	struct vringh *rvrh = &vcon->rxvrh->vrh;
	struct pci_epf *epf = vcon->epf;
	int err;
	u16 rhead, whead;
	size_t rlen, wlen;
	void __iomem *rvirt, *wvirt;
	phys_addr_t rphys, wphys;


	pr_info("notify callback\n");
#if 0
	while (true) {
		err = vringh_getdesc(rvrh, riov, wiov, &rhead);
		if (err < 0) {
			pr_info("%d: failed to get vring desc\n", __LINE__);
			return;
		} else if (!err) {
			pr_info("%d: empty\n", __LINE__);
			return;
		}

		pr_info("succeeded: r: %ld w: %ld\n", vringh_kiov_length(riov), vringh_kiov_length(wiov));
		if (!vringh_kiov_length(riov)) {
			pr_info("r: no data\n");
			continue;
		}

		rlen = riov->iov[riov->i].iov_len;
		rvirt = pci_epc_map_addr(epf->epc, epf->func_no, epf->vfunc_no,
				(u64)riov->iov[riov->i].iov_base, &rphys,
				rlen);
		if (IS_ERR(rvirt)) {
			pr_info("failed to map to access the rx data\n");
			continue;
		}

// 		err = vringh_getdesc(rvrh, NULL, wiov, &whead);
// 		if (err < 0) {
// 			pr_info("%d: failed to get vring desc\n", __LINE__);
// 			return;
// 		} else  if(!err) {
// 			pr_info("%d: emprty\n", __LINE__);
// 			return;
// 		}
// 		if (!vringh_kiov_length(wiov)) {
// 			pr_info("w: no buf\n");
// 			continue;
// 		}_
// 
// 		wlen = wiov->iov[wiov->i].iov_len;
// 		wvirt = pci_epc_map_addr(epf->epc, epf->func_no, epf->vfunc_no,
// 				(u64)wiov->iov[wiov->i].iov_base, &wphys,
// 				wlen);
// 		if (IS_ERR(wvirt)) {
// 			pr_info("failed to map to access the echo back\n");
// 			return;
// 		}
// 
// 		// echo back
// 		iowrite8(ioread8(rvirt), wvirt);
// 
		vringh_complete(rvrh, rhead, rlen);
// 		vringh_complete(rvrh, whead, wlen);

		pci_epc_unmap_addr(epf->epc, epf->func_no, epf->vfunc_no, rphys, rvirt,
				rlen);
		pci_epc_unmap_addr(epf->epc, epf->func_no, epf->vfunc_no, wphys, wvirt,
				wlen);
		pr_info("done\n");
	}
#else
	err = vringh_getdesc(wvrh, wiov, NULL, &whead);
	if (err <= 0) {
		pr_info("failed to get vring desc\n");
		return;
	}

	pr_info("succeeded: %ld\n", vringh_kiov_length(riov));

	wlen = wiov->iov[wiov->i].iov_len;
	wvirt = pci_epc_map_addr(epf->epc, epf->func_no, epf->vfunc_no,
				 (u64)wiov->iov[wiov->i].iov_base, &wphys,
				 wlen);
	if (IS_ERR(wvirt)) {
		pr_info("failed to map to access the rx data\n");
		return;
	}

	for(int i=0; i< wlen; i++) {
		pr_info("0x%x\n", ((u8*)wvirt)[i]);
	}
#endif
}

static int epf_vcon_device_setup(void *data)
{
	struct epf_vcon *vcon = data;
	struct pci_epf *epf = vcon->epf;
	const size_t vq_size = epf_vcon_get_vq_size();
	u16 __iomem *queue_notify = vcon->cfg_base + VIRTIO_PCI_QUEUE_NOTIFY;
	const u16 notify_default = EPF_VCON_NQUEUES;
	int err;
	int nqueues;
	struct epf_virtio_qinfo qinfo[EPF_VCON_NQUEUES];
	struct epf_vringh *vrh;

	nqueues = epf_virtio_negotiate_qinfo(vcon->cfg_base, qinfo,
					     EPF_VCON_NQUEUES);
	if (nqueues < 0) {
		pr_err("failed to negoticate configs with driver\n");
		return nqueues;
	}

	/* Polling phase is finished. This thread backs to normal priority. */
	sched_set_normal(vcon->device_setup_task, 19);

	while (!(epf_vcon_rhost_get_config8(vcon, VIRTIO_PCI_STATUS) &
		 VIRTIO_CONFIG_S_DRIVER_OK))
		;

	for (int i = 0; i < nqueues; ++i) {
		vrh = epf_virtio_alloc_vringh(epf, 0, qinfo[i].pci_addr,
					      vq_size);
		if (IS_ERR(vrh)) {
			err = PTR_ERR(vrh);
			goto err_free_epf_vringh;
		}

		switch (qinfo[i].sel) {
		case 0:
			vcon->rxvrh = vrh;
			break;
		case 1:
			vcon->txvrh = vrh;
			break;
		default:
			continue;
		}
	}

	vringh_kiov_init(&vcon->riov, NULL, 0);
	vringh_kiov_init(&vcon->wiov, NULL, 0);

	vcon->notify_monitor_task = epf_virtio_start_notify_monitor(
		queue_notify, notify_default, epf_vcon_notify_callback, vcon);
	if (IS_ERR(vcon->notify_monitor_task)) {
		pr_debug("Failed to create notify monitor thread\n");
		goto err_free_epf_vringh;
	}

	return 0;

err_free_epf_vringh:
	epf_virtio_free_vringh(epf, vcon->rxvrh);
	epf_virtio_free_vringh(epf, vcon->txvrh);

	return err;
}

static int epf_vcon_spawn_device_setup_task(struct epf_vcon *vcon)
{
	vcon->device_setup_task = kthread_create(epf_vcon_device_setup, vcon,
						 "pci-epf-vcon/cfg_negotiator");
	if (IS_ERR(vcon->device_setup_task))
		return PTR_ERR(vcon->device_setup_task);

	/* Change the thread priority to high for the polling. */
	sched_set_fifo(vcon->device_setup_task);
	wake_up_process(vcon->device_setup_task);

	return 0;
}

static int epf_vcon_rhost_setup(struct epf_vcon *vcon)
{
	struct pci_epf *epf = vcon->epf;
	int err;

	err = pci_epc_write_header(epf->epc, epf->func_no, epf->vfunc_no,
				   &epf_vcon_pci_header);
	if (err)
		return err;

	err = epf_vcon_setup_bar(vcon);
	if (err)
		return err;

	err = epf_vcon_spawn_device_setup_task(vcon);
	if (err)
		return err;

	return 0;
}

static int epf_vcon_bind(struct pci_epf *epf)
{
	int err;
	struct epf_vcon *vcon = epf_get_drvdata(epf);

	err = epf_vcon_rhost_setup(vcon);
	if (err)
		return err;

	return 0;
}

static void epf_vcon_unbind(struct pci_epf *epf)
{
}

static struct pci_epf_ops epf_vcon_ops = {
	.bind = epf_vcon_bind,
	.unbind = epf_vcon_unbind,
};

static const struct pci_epf_device_id epf_vcon_ids[] = {
	{ .name = "pci_epf_vcon" },
	{}
};

static int epf_vcon_probe(struct pci_epf *epf)
{
	struct epf_vcon *vcon;

	vcon = devm_kzalloc(&epf->dev, sizeof(*vcon), GFP_KERNEL);
	if (!vcon)
		return -ENOMEM;

	epf_set_drvdata(epf, vcon);
	vcon->epf = epf;

	return 0;
}

static struct pci_epf_driver epf_vcon_drv = {
	.driver.name = "pci_epf_vcon",
	.ops = &epf_vcon_ops,
	.id_table = epf_vcon_ids,
	.probe = epf_vcon_probe,
	.owner = THIS_MODULE,
};

static int __init epf_vcon_init(void)
{
	int err;

	err = pci_epf_register_driver(&epf_vcon_drv);
	if (err) {
		pr_err("Failed to regsiter epf virtio console function\n");
		return err;
	}

	return 0;
}
module_init(epf_vcon_init);

static void epf_vcon_exit(void)
{
}
module_exit(epf_vcon_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Shunsuke Mie <mie@igel.co.jp>");

