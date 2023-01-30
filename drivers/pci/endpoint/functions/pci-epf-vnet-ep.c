// SPDX-License-Identifier: GPL-2.0
/*
 * Functions work for Endpoint(local) side using EPF framework
 */
#include <linux/pci-epc.h>
#include <linux/virtio_pci.h>
#include <linux/virtio_ring.h>

#include "pci-epf-vnet.h"

static inline struct epf_vnet *vdev_to_vnet(struct virtio_device *vdev)
{
	return container_of(vdev, struct epf_vnet, ep.vdev);
}

static void epf_vnet_ep_vdev_release(struct device *dev)
{
	pr_info("%s:%d\n", __func__, __LINE__);
}

static u64 epf_vnet_ep_vdev_get_features(struct virtio_device *vdev)
{
	struct epf_vnet *vnet = vdev_to_vnet(vdev);

	return vnet->virtio.features;
}

static int epf_vnet_ep_vdev_finalize_features(struct virtio_device *vdev)
{
	pr_info("%s:%d\n", __func__, __LINE__);
	//TODO check the guest(driver) features
	return 0;
}

static void epf_vnet_ep_vdev_get_config(struct virtio_device *vdev,
					unsigned int offset, void *buf,
					unsigned len)
{
	pr_info("%s:%d\n", __func__, __LINE__);
	//TODO return network configuration that includes mac address.
}

static void epf_vnet_ep_vdev_set_config(struct virtio_device *vdev,
					unsigned int offset, const void *buf,
					unsigned len)
{
	pr_info("%s:%d\n", __func__, __LINE__);
}

static u8 epf_vnet_ep_vdev_get_status(struct virtio_device *vdev)
{
	pr_info("%s:%d\n", __func__, __LINE__);
	return 0;
}

static void epf_vnet_ep_vdev_set_status(struct virtio_device *vdev, u8 status)
{
	pr_info("%s:%d %x\n", __func__, __LINE__, status);
}

static void epf_vnet_ep_vdev_reset(struct virtio_device *vdev)
{
	pr_info("%s:%d\n", __func__, __LINE__);
}

static bool epf_vnet_ep_vdev_vq_notify(struct virtqueue *vq)
{
	struct epf_vnet *vnet = vdev_to_vnet(vq->vdev);
	struct vringh *tx_vrh = &vnet->ep.txvrh->vrh;
	struct vringh *rx_vrh = &vnet->rc.rxvrh->vrh;
	struct vringh_kiov *tx_iov = &vnet->ep.tx_iov;
	struct vringh_kiov *rx_iov = &vnet->rc.rx_iov;

	// 	if (unlikely(!vnet->rc_init_done))
	// 		return true;

	if (vq->index == 1) {
		while (epf_vnet_transfer(vnet, tx_vrh, rx_vrh, tx_iov, rx_iov,
					 DMA_MEM_TO_DEV) > 0)
			;
	}

	return true;
}

static int epf_vnet_ep_vdev_find_vqs(struct virtio_device *vdev, unsigned nvqs,
				     struct virtqueue *vqs[],
				     vq_callback_t *callback[],
				     const char *const names[], const bool *ctx,
				     struct irq_affinity *desc)
{
	int i;
	int err;
	int qidx = 0;
	struct epf_vnet *vnet = vdev_to_vnet(vdev);

	for (i = 0; i < nvqs; i++) {
		struct virtqueue *vq;
		struct vring *vring;
		struct vringh *vrh;
		struct vringh_kiov *kiov;
		struct kvec *kvec;

		if (!names[i]) {
			vqs[i] = NULL;
			continue;
		}

		vq = vring_create_virtqueue(qidx++, epf_vnet_get_vq_size(),
					    VIRTIO_PCI_VRING_ALIGN, vdev, true,
					    false, ctx ? ctx[i] : false,
					    epf_vnet_ep_vdev_vq_notify,
					    callback[i], names[i]);
		if (!vq) {
			err = -ENOMEM;
			goto err_del_vqs;
		}

		vqs[i] = vq;
		// 		if (i == 0)
		// 			vnet->ep.rxvq = vq;

		vring = virtqueue_get_vring(vq);
		if (i == 0) {
			vrh = &vnet->ep.rxvrh->vrh;
			kiov = &vnet->ep.rx_iov;
		} else if (i == 1) {
			vrh = &vnet->ep.txvrh->vrh;
			kiov = &vnet->ep.tx_iov;
		} else {
			BUG_ON("founc unsuspected queue index\n");
		}

		err = vringh_init_kern(vrh, vnet->virtio.features,
				       epf_vnet_get_vq_size(), false,
				       GFP_KERNEL, vring->desc, vring->avail,
				       vring->used);
		if (err) {
			pr_err("failed to init vringh for vring %d\n", i);
			goto err_del_vqs;
		}

		kvec = kmalloc_array(epf_vnet_get_vq_size(), sizeof *kvec,
				     GFP_KERNEL);
		if (!kvec) {
			err = -ENOMEM;
			goto err_del_vqs;
		}
		vringh_kiov_init(kiov, kvec, epf_vnet_get_vq_size());
	}

	return 0;

err_del_vqs:
	//TODO delete created virtqueues
	return err;
}

static void epf_vnet_ep_vdev_del_vqs(struct virtio_device *vdev)
{
	pr_info("%s:%d\n", __func__, __LINE__);
}

static const char *epf_vnet_ep_vdev_bus_name(struct virtio_device *vdev)
{
	//TODO
	pr_info("%s:%d\n", __func__, __LINE__);
	return "dummy bus name";
}

static void epf_vnet_ep_vdev_sync_cbs(struct virtio_device *vdev)
{
	pr_info("%s:%d\n", __func__, __LINE__);
}

static const struct virtio_config_ops epf_vnet_ep_vdev_config_ops = {
	.get_features = epf_vnet_ep_vdev_get_features,
	.finalize_features = epf_vnet_ep_vdev_finalize_features,
	.get = epf_vnet_ep_vdev_get_config,
	.set = epf_vnet_ep_vdev_set_config,
	.get_status = epf_vnet_ep_vdev_get_status,
	.set_status = epf_vnet_ep_vdev_set_status,
	.reset = epf_vnet_ep_vdev_reset,
	.find_vqs = epf_vnet_ep_vdev_find_vqs,
	.del_vqs = epf_vnet_ep_vdev_del_vqs,
	.bus_name = epf_vnet_ep_vdev_bus_name,
	.synchronize_cbs = epf_vnet_ep_vdev_sync_cbs,
};

int epf_vnet_ep_setup(struct epf_vnet *vnet)
{
	int err;
	struct virtio_device *vdev = &vnet->ep.vdev;

	vdev->dev.parent = vnet->epf->epc->dev.parent;
	vdev->dev.release = epf_vnet_ep_vdev_release;
	vdev->config = &epf_vnet_ep_vdev_config_ops;
	vdev->id.vendor = PCI_VENDOR_ID_REDHAT_QUMRANET;
	vdev->id.device = VIRTIO_ID_NET;

	err = register_virtio_device(vdev);
	if (err)
		return err;

	return 0;
}
