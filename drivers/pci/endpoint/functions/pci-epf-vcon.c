// SPDX-License-Identifier: GPL-2.0

#include <linux/module.h>
#include <linux/pci-epf.h>
#include <linux/vringh.h>
#include <linux/pci-epc.h>
#include <linux/virtio_console.h>
#include <linux/virtio_pci.h>
#include <linux/kthread.h>
#include <linux/virtio.h>
#include <linux/virtio_ring.h>

#include "pci-epf-virtio.h"

static void *epf_virtio_load_from_vrh(struct pci_epf *epf, struct vringh *vrh,
				      struct vringh_kiov *iov, size_t *len)
{
	int err;
	u16 head;
	size_t rlen;
	void __iomem *virt;
	phys_addr_t phys;
	void *buf;

	err = vringh_getdesc(vrh, iov, NULL, &head);
	if (err <= 0) {
		return ERR_PTR(err);
	}

	rlen = iov->iov[iov->i].iov_len;
	virt = pci_epc_map_addr(epf->epc, epf->func_no, epf->vfunc_no,
				(u64)iov->iov[iov->i].iov_base, &phys, rlen);
	if (IS_ERR(virt))
		return virt;

	buf = kmalloc(rlen, GFP_KERNEL);
	if (!buf) {
		buf = ERR_PTR(-ENOMEM);
		goto done;
	}

	memcpy_fromio(buf, virt, rlen);

	*len = rlen;

done:
	vringh_complete(vrh, head, rlen);
	pci_epc_unmap_addr(epf->epc, epf->func_no, epf->vfunc_no, phys, virt,
			   rlen);

	return buf;
}

static int virtio_store_to_vrh(struct vringh *vrh,
				   struct vringh_kiov *iov, const void *buf,
				   size_t len)
{
	int err;
	u16 head;
	size_t rlen;
	void __iomem *virt;

	err = vringh_getdesc(vrh, NULL, iov, &head);
	if (err <= 0)
		return err;

	rlen = iov->iov[iov->i].iov_len;
	if (len > rlen) {
		// Split transfer is not supported yet.
		return -EIO;
	}

	virt = phys_to_virt((u64)iov->iov[iov->i].iov_base);

	memcpy(virt, buf, len);

	vringh_complete(vrh, head, len);

	return 1;
}

static int epf_virtio_store_to_vrh(struct pci_epf *epf, struct vringh *vrh,
				   struct vringh_kiov *iov, const void *buf,
				   size_t len)
{
	int err;
	u16 head;
	size_t rlen;
	void __iomem *virt;
	phys_addr_t phys;

	err = vringh_getdesc(vrh, NULL, iov, &head);
	if (err < 0) {
		return err;
	} else if (!err) {
		pr_debug("disc doesn't remain\n");
		return 0;
	}

	rlen = iov->iov[iov->i].iov_len;
	if (len > rlen) {
		// Split transfer is not supported yet.
		pr_info("buffer is too small\n");
		return -EIO;
	}

	virt = pci_epc_map_addr(epf->epc, epf->func_no, epf->vfunc_no,
				(u64)iov->iov[iov->i].iov_base, &phys, len);
	if (IS_ERR(virt)) {
		pr_info("failed to map to access the rx data\n");
		return PTR_ERR(virt);
	}

	memcpy_toio(virt, buf, len);

	vringh_complete(vrh, head, len);
	pci_epc_unmap_addr(epf->epc, epf->func_no, epf->vfunc_no, phys, virt,
			   len);
	return 1;
}

struct epf_vcon {
	struct pci_epf *epf;
	struct virtio_console_config config;
	void __iomem *cfg_base;
	struct task_struct *device_setup_task, *notify_monitor_task;
	struct vringh_kiov tx_iov, rx_iov;
	struct epf_vringh *txvrh, *rxvrh;
	struct vringh_kiov riov, wiov;

	struct work_struct raise_irq_work;
	struct work_struct xmit_to_remote;

	struct virtio_device vdev;

	struct vringh lhost_vrhs[2];
	struct virtqueue *lhost_vqs[2];
	struct vringh_kiov lhost_iovs[2];
};

static inline struct epf_vcon *vdev_to_vcon(struct virtio_device *vdev)
{
	return container_of(vdev, struct epf_vcon, vdev);
}

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
	void *buf;
	size_t len;
	int err;

	buf = epf_virtio_load_from_vrh(vcon->epf, &vcon->txvrh->vrh,
				       &vcon->wiov, &len);
	if (IS_ERR(buf)) {
		pr_err("Failed to load\n");
		return;
	}

	// send to local
	err = virtio_store_to_vrh(&vcon->lhost_vrhs[0],
				&vcon->lhost_iovs[0], buf, len);
	if (err < 0) {
		pr_debug("Failed to store: %d\n", err);
		return;
	}

	vring_interrupt(0, vcon->lhost_vqs[0]);

	kfree(buf);
}

static int epf_vcon_device_setup(void *data)
{
	struct epf_vcon *vcon = data;
	struct pci_epf *epf = vcon->epf;
	const size_t vq_size = epf_vcon_get_vq_size();
	u16 __iomem *queue_notify = vcon->cfg_base + VIRTIO_PCI_QUEUE_NOTIFY;
	const u16 notify_default = EPF_VCON_NQUEUES;
	int err;
	int nqueues = EPF_VCON_NQUEUES;
	struct epf_virtio_qinfo qinfo[EPF_VCON_NQUEUES];
	struct epf_vringh *vrh;

	err = epf_virtio_negotiate_qinfo(vcon->cfg_base, qinfo,
					 EPF_VCON_NQUEUES);
	if (err < 0) {
		pr_err("failed to negoticate configs with driver\n");
		return err;
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

static void *virtio_load_from_vrh(struct vringh *vrh,
				      struct vringh_kiov *iov, size_t *len);
static void epf_vcon_xmit(struct work_struct *work)
{
	struct epf_vcon *vcon =
		container_of(work, struct epf_vcon, xmit_to_remote);
	size_t size;
	void *buf;
	int err;

	buf = virtio_load_from_vrh(&vcon->lhost_vrhs[1], &vcon->lhost_iovs[1], &size);
// 	buf = epf_virtio_load_from_vrh(vcon->epf, &vcon->lhost_vrhs[1], &vcon->lhost_iovs[1], &size);
	if (IS_ERR(buf)) {
		pr_info("failed to load: %ld\n", PTR_ERR(buf));
		return;
	}

	err = virtio_store_to_vrh(&vcon->lhost_vrhs[1], &vcon->lhost_iovs[1], " ", 1);
	if (err < 0) {
		pr_err("failed ack\n");
	}

	err = epf_virtio_store_to_vrh(vcon->epf, &vcon->rxvrh->vrh, &vcon->riov, buf, size);
	if (err < 0) {
		pr_info("failed to store: %d\n", err);
		return;
	}

	kfree(buf);

	if (!schedule_work(&vcon->raise_irq_work))
		pr_err("failed to enqueue irq work\n");

}

static void epf_vcon_raise_irq_handler(struct work_struct *work)
{
	struct epf_vcon *vcon =
		container_of(work, struct epf_vcon, raise_irq_work);
	struct pci_epf *epf = vcon->epf;

	pci_epc_raise_irq(epf->epc, epf->func_no, epf->vfunc_no,
			  PCI_EPC_IRQ_LEGACY, 0);
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

	INIT_WORK(&vcon->raise_irq_work, epf_vcon_raise_irq_handler);
	INIT_WORK(&vcon->xmit_to_remote, epf_vcon_xmit);

	return 0;
}

static u64 epf_vcon_vdev_get_features(struct virtio_device *vdev)
{
	return 0;
}

static int epf_vcon_vdev_finalize_features(struct virtio_device *vdev)
{
	return 0;
}

static void epf_vcon_vdev_get_config(struct virtio_device *vdev,
				     unsigned int offset, void *buf,
				     unsigned int len)
{
}

static void epf_vcon_vdev_set_config(struct virtio_device *vdev,
				     unsigned int offset, const void *buf,
				     unsigned int len)
{
}

static u8 epf_vcon_vdev_get_status(struct virtio_device *vdev)
{
	return 0;
}

static void epf_vcon_vdev_set_status(struct virtio_device *vdev, u8 status)
{
}

static void epf_vcon_vdev_reset(struct virtio_device *vdev)
{
}

static void *virtio_load_from_vrh(struct vringh *vrh,
				      struct vringh_kiov *iov, size_t *len)
{
	int err;
	u16 head;
	size_t rlen;
	void __iomem *virt;
	void *buf;

	err = vringh_getdesc(vrh, iov, NULL, &head);
	if (err <= 0) {
		return ERR_PTR(err);
	}

	rlen = iov->iov[iov->i].iov_len;
	virt = phys_to_virt((u64)iov->iov[iov->i].iov_base);
	if (IS_ERR(virt))
		return virt;

	buf = kmalloc(rlen, GFP_KERNEL);
	if (!buf) {
		buf = ERR_PTR(-ENOMEM);
		goto done;
	}

	memcpy_fromio(buf, virt, rlen);

	*len = rlen;

done:
	vringh_complete(vrh, head, rlen);
	return buf;
}

static bool epf_vcon_vdev_vq_notify(struct virtqueue *vq)
{
	struct epf_vcon *vcon = vdev_to_vcon(vq->vdev);
	void *buf;
	size_t size;
	int err;

	switch (vq->index) {
	case 0:
		break;
	case 1:
		buf = virtio_load_from_vrh(&vcon->lhost_vrhs[1], &vcon->lhost_iovs[1], &size);
		if (IS_ERR(buf)) {
			pr_info("failed to load: %ld\n", PTR_ERR(buf));
			return true;
		}
		// ack to local
		err = epf_virtio_store_to_vrh(vcon->epf, &vcon->lhost_vrhs[1], &vcon->lhost_iovs[1], " ", 1);
		if (err < 0) {
			pr_err("failed ack: %d\n", err);
			return true;
		}
		err = epf_virtio_store_to_vrh(vcon->epf, &vcon->rxvrh->vrh, &vcon->riov, buf, size);
		if (err < 0) {
			pr_info("failed to store: %d\n", err);
			return true;
		}

		kfree(buf);
		schedule_work(&vcon->raise_irq_work);

		break;
	default:
		return false;
	}

	return true;
}

static int epf_vcon_vdev_find_vqs(struct virtio_device *vdev, unsigned int nvqs,
				  struct virtqueue *vqs[],
				  vq_callback_t *callback[],
				  const char *const names[], const bool *ctx,
				  struct irq_affinity *desc)
{
#if 1
	struct epf_vcon *vcon = vdev_to_vcon(vdev);
	int err;
	int qidx, i;
	const size_t vq_size = epf_vcon_get_vq_size();

	if (nvqs > 2)
		return -EINVAL;

	for (qidx = 0, i = 0; i < nvqs; i++) {
		struct virtqueue *vq;
		struct vring *vring;
		// 		struct vringh *vrh;

		if (!names[i]) {
			vqs[i] = NULL;
			continue;
		}

		vq = vring_create_virtqueue(qidx++, vq_size,
					    VIRTIO_PCI_VRING_ALIGN, vdev, true,
					    false, ctx ? ctx[i] : false,
					    epf_vcon_vdev_vq_notify,
					    callback[i], names[i]);
		if (!vq) {
			err = -ENOMEM;
			goto err_del_vqs;
		}

		vqs[i] = vq;
		vcon->lhost_vqs[i] = vq;

		vring = virtqueue_get_vring(vq);
		err = vringh_init_kern(&vcon->lhost_vrhs[i], 0, vq_size, false,
				       GFP_KERNEL, vring->desc, vring->avail,
				       vring->used);
		if (err) {
			pr_err("failed to init vringh for vring %d\n", i);
			goto err_del_vqs;
		}

		vringh_kiov_init(&vcon->lhost_iovs[i], NULL, 0);
	}

#endif
	return 0;

err_del_vqs:
	for (; i >= 0; i--) {
		if (!names[i])
			continue;

		if (!vqs[i])
			continue;

		vring_del_virtqueue(vqs[i]);
	}
	return err;
}

static void epf_vcon_vdev_del_vqs(struct virtio_device *vdev)
{
}

static const struct virtio_config_ops epf_vcon_vdev_config_ops = {
	.get_features = epf_vcon_vdev_get_features,
	.finalize_features = epf_vcon_vdev_finalize_features,
	.get = epf_vcon_vdev_get_config,
	.set = epf_vcon_vdev_set_config,
	.get_status = epf_vcon_vdev_get_status,
	.set_status = epf_vcon_vdev_set_status,
	.reset = epf_vcon_vdev_reset,
	.find_vqs = epf_vcon_vdev_find_vqs,
	.del_vqs = epf_vcon_vdev_del_vqs,
};

static int epf_vcon_setup_lhost(struct virtio_device *vdev, struct device* parent)
{
	int err;

	vdev->dev.parent = parent;
	vdev->config = &epf_vcon_vdev_config_ops;
	vdev->id.vendor = PCI_VENDOR_ID_REDHAT_QUMRANET;
	vdev->id.device = VIRTIO_ID_CONSOLE;

	err = register_virtio_device(vdev);
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

	err = epf_vcon_setup_lhost(&vcon->vdev, vcon->epf->epc->dev.parent);
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

#if 1
	err = pci_epf_register_driver(&epf_vcon_drv);
	if (err) {
		pr_err("Failed to regsiter epf virtio console function\n");
		return err;
	}
#endif

	return 0;
}
module_init(epf_vcon_init);

static void epf_vcon_exit(void)
{
}
module_exit(epf_vcon_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Shunsuke Mie <mie@igel.co.jp>");
