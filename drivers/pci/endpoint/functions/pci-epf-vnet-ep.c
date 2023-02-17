// SPDX-License-Identifier: GPL-2.0
/*
 * Functions work for Endpoint side(local) using EPF framework
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

void epf_vnet_ep_announce_linkup(struct epf_vnet *vnet)
{
	epf_vnet_ep_set_status(vnet,
			       VIRTIO_NET_S_LINK_UP | VIRTIO_NET_S_ANNOUNCE);
	epf_vnet_ep_raise_config_irq(vnet);
}

void epf_vnet_ep_notify(struct epf_vnet *vnet, struct virtqueue *vq)
{
	vring_interrupt(0, vq);
}

static int epf_vnet_ep_process_ctrlq_entry(struct epf_vnet *vnet)
{
	struct vringh *vrh = &vnet->ep.ctlvrh;
	struct vringh_kiov *wiov = &vnet->ep.ctl_riov;
	struct vringh_kiov *riov = &vnet->ep.ctl_wiov;
	struct virtio_net_ctrl_hdr *hdr;
	virtio_net_ctrl_ack *ack;
	int err;
	u16 head;
	size_t len;
	struct virtio_rdma_ack_query_port *port;
	struct virtio_rdma_ack_query_device *device;
	struct virtio_rdma_cmd_add_gid *cmd_add_gid;

	err = vringh_getdesc(vrh, riov, wiov, &head);
	if (err <= 0)
		goto done;

	len = vringh_kiov_length(riov);
	if (len < sizeof(*hdr)) {
		pr_debug("Command is too short: %ld\n", len);
		err = -EIO;
		goto done;
	}

	if (vringh_kiov_length(wiov) < sizeof(*ack)) {
		pr_debug("Space for ack is not enough\n");
		err = -EIO;
		goto done;
	}

	hdr = phys_to_virt((unsigned long)riov->iov[riov->i].iov_base);
	ack = phys_to_virt((unsigned long)wiov->iov[wiov->i].iov_base);
	wiov->i++;
	riov->i++;

	switch (hdr->class) {
	case VIRTIO_NET_CTRL_ANNOUNCE:
		if (hdr->cmd != VIRTIO_NET_CTRL_ANNOUNCE_ACK) {
			pr_debug("Invalid command: announce: %d\n", hdr->cmd);
			goto done;
		}

		epf_vnet_ep_clear_status(vnet, VIRTIO_NET_S_ANNOUNCE);
		*ack = VIRTIO_NET_OK;
		break;
#if defined(CONFIG_PCI_EPF_VNET_ROCE)
	case VIRTIO_NET_CTRL_ROCE: {
		switch (hdr->cmd) {
		case VIRTIO_NET_CTRL_ROCE_QUERY_PORT:
			//TODO
			if (wiov->i >= wiov->used) {
				err = -EIO;
				break;
			}

			if (wiov->iov[wiov->i].iov_len < sizeof(*port)) {
				pr_err("invalid size of port query\n");
				err = -EIO;
				break;
			}
			port = phys_to_virt(
				(unsigned long)wiov->iov[wiov->i].iov_base);
			port->gid_tbl_len = EPF_VNET_ROCE_GID_TBL_LEN;
			port->max_msg_sz = 0x800000;
			*ack = VIRTIO_NET_OK;
			break;
		case VIRTIO_NET_CTRL_ROCE_QUERY_DEVICE:
			if (wiov->i >= wiov->used) {
				pr_err("");
				err = -EIO;
				break;
			}

			if (wiov->iov[wiov->i].iov_len < sizeof(*device)) {
				pr_err("");
				err = -EIO;
				break;
			}

			device = phys_to_virt(
				(unsigned long)wiov->iov[wiov->i].iov_base);

			device->device_cap_flags =
				vnet->roce_attr.device_cap_flags;
			device->max_mr_size = vnet->roce_attr.max_mr_size;
			device->page_size_cap = vnet->roce_attr.page_size_cap;
			device->hw_ver = vnet->roce_attr.hw_ver;
			device->max_qp_wr = vnet->roce_attr.max_qp_wr;
			device->max_send_sge = vnet->roce_attr.max_send_sge;
			device->max_recv_sge = vnet->roce_attr.max_recv_sge;
			device->max_sge_rd = vnet->roce_attr.max_sge_rd;
			device->max_cqe = vnet->roce_attr.max_cqe;
			device->max_mr = vnet->roce_attr.max_mr;
			device->max_pd = vnet->roce_attr.max_pd;
			device->max_qp_rd_atom = vnet->roce_attr.max_qp_rd_atom;
			device->max_qp_init_rd_atom =
				vnet->roce_attr.max_qp_init_rd_atom;
			device->max_ah = vnet->roce_attr.max_ah;

			*ack = VIRTIO_NET_OK;
			break;
		case VIRTIO_NET_CTRL_ROCE_ADD_GID:
			if (riov->i >= riov->used) {
				pr_err("");
				err = -EIO;
				break;
			}

			if (riov->iov[riov->i].iov_len < sizeof(*cmd_add_gid)) {
				pr_err("invalid size of port query\n");
				err = -EIO;
				break;
			}

			cmd_add_gid = phys_to_virt(
				(unsigned long)riov->iov[riov->i].iov_base);

			if (cmd_add_gid->index >= EPF_VNET_ROCE_GID_TBL_LEN) {
				err = -EINVAL;
				break;
			}

			memcpy(vnet->roce_gid_tbl[cmd_add_gid->index].raw,
			       cmd_add_gid->gid, sizeof(cmd_add_gid->gid));

			//TODO print gid for debuging

			*ack = VIRTIO_NET_OK;
			break;
		default:
			pr_debug("Found unknown roce command: %d\n", hdr->cmd);
			err = -EIO;
			break;
		}
		break;
	}
#endif // CONFIG_PCI_EPF_VNET_ROCE
	default:
		pr_debug("Found not supported class: %d\n", hdr->class);
		err = -EIO;
	}

done:
	vringh_complete(vrh, head, len);
	return err;
}

static u64 epf_vnet_ep_vdev_get_features(struct virtio_device *vdev)
{
	struct epf_vnet *vnet = vdev_to_vnet(vdev);

	return vnet->virtio_features;
}

static int epf_vnet_ep_vdev_finalize_features(struct virtio_device *vdev)
{
	struct epf_vnet *vnet = vdev_to_vnet(vdev);

	if (vdev->features != vnet->virtio_features)
		return -EINVAL;

	return 0;
}

static void epf_vnet_ep_vdev_get_config(struct virtio_device *vdev,
					unsigned int offset, void *buf,
					unsigned int len)
{
	struct epf_vnet *vnet = vdev_to_vnet(vdev);
	const unsigned int mac_len = sizeof(vnet->vnet_cfg.mac);
	const unsigned int status_len = sizeof(vnet->vnet_cfg.status);
	unsigned int copy_len;

	switch (offset) {
	case offsetof(struct virtio_net_config, mac):
		/* This PCIe EP function doesn't provide a VIRTIO_NET_F_MAC feature, so just
		 * clear the buffer.
		 */
		copy_len = len >= mac_len ? mac_len : len;
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
					unsigned int len)
{
	/* Do nothing, because all of virtio net config space is readonly. */
}

static u8 epf_vnet_ep_vdev_get_status(struct virtio_device *vdev)
{
	return 0;
}

static void epf_vnet_ep_vdev_set_status(struct virtio_device *vdev, u8 status)
{
	struct epf_vnet *vnet = vdev_to_vnet(vdev);

	if (status & VIRTIO_CONFIG_S_DRIVER_OK)
		epf_vnet_init_complete(vnet, EPF_VNET_INIT_COMPLETE_EP);
}

static void epf_vnet_ep_vdev_reset(struct virtio_device *vdev)
{
	pr_debug("doesn't support yet");
}

static bool epf_vnet_ep_vdev_vq_notify(struct virtqueue *vq)
{
	struct epf_vnet *vnet = vdev_to_vnet(vq->vdev);
	struct vringh *tx_vrh = &vnet->ep.txvrh;
	struct vringh *rx_vrh = &vnet->rc.rxvrh->vrh;
	struct vringh_kiov *tx_iov = &vnet->ep.tx_iov;
	struct vringh_kiov *rx_iov = &vnet->rc.rx_iov;
	int err;

	/* Support only one queue pair */
	switch (vq->index) {
	case 0: // rx queue
		break;
	case 1: // tx queue
		while ((err = epf_vnet_transfer(vnet, tx_vrh, rx_vrh, tx_iov,
						rx_iov, DMA_MEM_TO_DEV)) > 0)
			;
		if (err < 0)
			pr_debug("Failed to transmit: EP -> Host: %d\n", err);
		break;
	case 2: // control queue
		epf_vnet_ep_process_ctrlq_entry(vnet);
		break;
	default:
		return false;
	}

	return true;
}

static int epf_vnet_ep_vdev_find_vqs(struct virtio_device *vdev,
				     unsigned int nvqs, struct virtqueue *vqs[],
				     vq_callback_t *callback[],
				     const char *const names[], const bool *ctx,
				     struct irq_affinity *desc)
{
	struct epf_vnet *vnet = vdev_to_vnet(vdev);
	const size_t vq_size = epf_vnet_get_vq_size();
	int i;
	int err;
	int qidx;

	for (qidx = 0, i = 0; i < nvqs; i++) {
		struct virtqueue *vq;
		struct vring *vring;
		struct vringh *vrh;

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
			vnet->ep.rxvq = vq;
			break;
		case 1: // tx
			vrh = &vnet->ep.txvrh;
			vnet->ep.txvq = vq;
			break;
		case 2: // control
			vrh = &vnet->ep.ctlvrh;
			vnet->ep.ctlvq = vq;
			break;
		default:
			err = -EIO;
			goto err_del_vqs;
		}

		err = vringh_init_kern(vrh, vnet->virtio_features, vq_size,
				       true, GFP_KERNEL, vring->desc,
				       vring->avail, vring->used);
		if (err) {
			pr_err("failed to init vringh for vring %d\n", i);
			goto err_del_vqs;
		}
	}

	err = epf_vnet_init_kiov(&vnet->ep.tx_iov, vq_size);
	if (err)
		goto err_free_kiov;
	err = epf_vnet_init_kiov(&vnet->ep.rx_iov, vq_size);
	if (err)
		goto err_free_kiov;
	err = epf_vnet_init_kiov(&vnet->ep.ctl_riov, vq_size);
	if (err)
		goto err_free_kiov;
	err = epf_vnet_init_kiov(&vnet->ep.ctl_wiov, vq_size);
	if (err)
		goto err_free_kiov;

	return 0;

err_free_kiov:
	epf_vnet_deinit_kiov(&vnet->ep.tx_iov);
	epf_vnet_deinit_kiov(&vnet->ep.rx_iov);
	epf_vnet_deinit_kiov(&vnet->ep.ctl_riov);
	epf_vnet_deinit_kiov(&vnet->ep.ctl_wiov);

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

static void epf_vnet_ep_vdev_del_vqs(struct virtio_device *vdev)
{
	struct virtqueue *vq, *n;
	struct epf_vnet *vnet = vdev_to_vnet(vdev);

	list_for_each_entry_safe(vq, n, &vdev->vqs, list)
		vring_del_virtqueue(vq);

	epf_vnet_deinit_kiov(&vnet->ep.tx_iov);
	epf_vnet_deinit_kiov(&vnet->ep.rx_iov);
	epf_vnet_deinit_kiov(&vnet->ep.ctl_riov);
	epf_vnet_deinit_kiov(&vnet->ep.ctl_wiov);
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
};

void epf_vnet_ep_cleanup(struct epf_vnet *vnet)
{
	unregister_virtio_device(&vnet->ep.vdev);
}

int epf_vnet_ep_setup(struct epf_vnet *vnet)
{
	int err;
	struct virtio_device *vdev = &vnet->ep.vdev;

	vdev->dev.parent = vnet->epf->epc->dev.parent;
	vdev->config = &epf_vnet_ep_vdev_config_ops;
	vdev->id.vendor = PCI_VENDOR_ID_REDHAT_QUMRANET;
	vdev->id.device = VIRTIO_ID_NET;

	err = register_virtio_device(vdev);
	if (err)
		return err;

	return 0;
}
