// SPDX-License-Identifier: GPL-2.0
/*
 * Functions work for Endpoint(local) side using EPF framework
 */
#include <linux/pci-epc.h>
#include <linux/virtio_pci.h>
#include <linux/virtio_net.h>
#include <linux/virtio_ring.h>

#include "pci-epf-vnet.h"

static inline struct epf_vnet *vdev_to_vnet(struct virtio_device *vdev)
{
	return container_of(vdev, struct epf_vnet, ep.vdev);
}

static void epf_vnet_ep_set_status(struct epf_vnet *vnet, u16 status)
{
	vnet->ep.net_config_status |= status;
}

static void epf_vnet_ep_clear_status(struct epf_vnet *vnet, u16 status)
{
	vnet->ep.net_config_status &= ~status;
}

static void epf_vnet_ep_raise_config_irq(struct epf_vnet *vnet)
{
	virtio_config_changed(&vnet->ep.vdev);
}

int epf_vnet_ep_announce_linkup(struct epf_vnet *vnet)
{
	epf_vnet_ep_set_status(vnet,
			       VIRTIO_NET_S_LINK_UP | VIRTIO_NET_S_ANNOUNCE);
	epf_vnet_ep_raise_config_irq(vnet);

	return 0;
}

static int epf_vnet_ep_process_ctrlq_entry(struct epf_vnet *vnet)
{
	int err;
	u16 head;
	struct virtio_net_ctrl_hdr *hdr;
	size_t len;

	struct vringh *vrh = &vnet->ep.ctlvrh;
	struct vringh_kiov *wiov = &vnet->ep.ctl_iov;
	struct vringh_kiov riov;

	vringh_kiov_init(&riov,
			 kmalloc_array(epf_vnet_get_vq_size(),
				       sizeof(struct kvec), GFP_KERNEL),
			 epf_vnet_get_vq_size());

	err = vringh_getdesc(vrh, &riov, wiov, &head);
	if (err < 0) {
		return err;
	} else if (!err) {
		return 0;
	}

	// Should be vringh_kiov_length(iov) == iov->iov[iov->i].iov_len ?
	// If it is, we can check and use the command simply.

	len = vringh_kiov_length(&riov);
	// 	len = vringh_kiov_length(iov);
	if (len < sizeof(*hdr)) {
		pr_err("Invalid command: length is shoter than header: %ld\n",
		       len);
		goto done;
		return 0;
	}

	hdr = phys_to_virt((unsigned long)riov.iov[riov.i].iov_base);

	switch (hdr->class) {
	case VIRTIO_NET_CTRL_ANNOUNCE:
		if (hdr->cmd != VIRTIO_NET_CTRL_ANNOUNCE_ACK) {
			pr_err("Found invalid command: announce: %d\n",
			       hdr->cmd);
			goto done;
		}
		epf_vnet_ep_clear_status(vnet, VIRTIO_NET_S_ANNOUNCE);

		iowrite8(VIRTIO_NET_OK,
			 phys_to_virt(
				 (unsigned long)wiov->iov[wiov->i].iov_base));
		break;
	default:
		pr_err("Found not supported class: %d\n", hdr->class);
	}

done:
	vringh_complete(vrh, head, len);
	return 0;
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
	struct epf_vnet *vnet = vdev_to_vnet(vdev);
	unsigned copy_len;
	const unsigned mac_len = sizeof vnet->vnet_cfg.mac;
	const unsigned status_len = sizeof vnet->vnet_cfg.status;

	switch (offset) {
	case offsetof(struct virtio_net_config, mac):
		copy_len = len >= mac_len ? mac_len : len;
		// this EP function doesn't provide a VIRTIO_NET_F_MAC feature, so just
		// clear the buffer.
		memset(buf, 0x00, copy_len);
		len -= copy_len;
		buf += copy_len;
		fallthrough;
	case offsetof(struct virtio_net_config, status):
		copy_len = len >= status_len ? status_len : len;
		memcpy(buf, &vnet->ep.net_config_status, copy_len);
		len -= copy_len;
		buf += copy_len;
		fallthrough;
	default:
		if (offset > sizeof(vnet->vnet_cfg)) {
			memset(buf, 0x00, len);
			break;
		}
		memcpy(buf, (void *)&vnet->vnet_cfg + offset, len);
	}
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
	struct vringh *tx_vrh = &vnet->ep.txvrh;
	struct vringh *rx_vrh = &vnet->rc.rxvrh->vrh;
	struct vringh_kiov *tx_iov = &vnet->ep.tx_iov;
	struct vringh_kiov *rx_iov = &vnet->rc.rx_iov;

	/* Support only one queue pair */
	switch (vq->index) {
	case 0: // rx queue
		break;
	case 1: // tx queue
		while (epf_vnet_transfer(vnet, tx_vrh, rx_vrh, tx_iov, rx_iov,
					 DMA_MEM_TO_DEV) > 0)
			;
		break;
	case 2: // control queue
		epf_vnet_ep_process_ctrlq_entry(vnet);
		break;
	default:
		return false;
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
	const size_t vq_size = epf_vnet_get_vq_size();

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

		vq = vring_create_virtqueue(qidx++, vq_size,
					    VIRTIO_PCI_VRING_ALIGN, vdev, true,
					    false, ctx ? ctx[i] : false,
					    epf_vnet_ep_vdev_vq_notify,
					    callback[i], names[i]);
		if (!vq) {
			err = -ENOMEM;
			goto err_del_vqs;
		}

		vqs[i] = vq;
		vring = virtqueue_get_vring(vq);

		switch (i) {
		case 0: // rx
			vrh = &vnet->ep.rxvrh;
			kiov = &vnet->ep.rx_iov;
			break;
		case 1: // tx
			vrh = &vnet->ep.txvrh;
			kiov = &vnet->ep.tx_iov;
			break;
		case 2: // control
			vrh = &vnet->ep.ctlvrh;
			kiov = &vnet->ep.ctl_iov;
			break;
		default:
			BUG_ON("found unsuspected queue index\n");
		}

		// XXX: a argument named weak_barrier of vringh_init_kern should be
		// probably true. Please check it.
		err = vringh_init_kern(vrh, vnet->virtio.features, vq_size,
				       false, GFP_KERNEL, vring->desc,
				       vring->avail, vring->used);
		if (err) {
			pr_err("failed to init vringh for vring %d\n", i);
			goto err_del_vqs;
		}

		kvec = kmalloc_array(vq_size, sizeof *kvec, GFP_KERNEL);
		if (!kvec) {
			err = -ENOMEM;
			goto err_del_vqs;
		}
		vringh_kiov_init(kiov, kvec, vq_size);
	}

	epf_vnet_init_complete(vnet, EPF_VNET_INIT_COMPLETE_EP);
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
