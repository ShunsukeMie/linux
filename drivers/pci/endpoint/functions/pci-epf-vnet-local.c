#include <linux/module.h>
#include <linux/virtio_config.h>
#include <linux/virtio_ring.h>
#include <linux/virtio_pci.h>

#include "pci-epf-vnet.h"

static struct epf_vnet *vdev_to_vnet(struct virtio_device *vdev)
{
	return container_of(vdev, struct epf_vnet, vdev);
}

static void epf_vnet_vdev_release(struct device *dev)
{
	pr_info("%s:%d\n", __func__, __LINE__);
}

static u64 epf_vnet_vdev_get_features(struct virtio_device *vdev)
{
	struct epf_vnet *vnet = vdev_to_vnet(vdev);

	return vnet->features;
}

static int epf_vnet_vdev_finalize_features(struct virtio_device *vdev)
{
	pr_info("%s:%d\n", __func__, __LINE__);
	//TODO check the guest(driver) features
	return 0;
}

static void epf_vnet_vdev_get_config(struct virtio_device *vdev,
				     unsigned int offset, void *buf,
				     unsigned len)
{
	pr_info("%s:%d\n", __func__, __LINE__);
	//TODO return network configuration that includes mac address.
}

static void epf_vnet_vdev_set_config(struct virtio_device *vdev,
				     unsigned int offset, const void *buf,
				     unsigned len)
{
	pr_info("%s:%d\n", __func__, __LINE__);
}

static u8 epf_vnet_vdev_get_status(struct virtio_device *vdev)
{
	pr_info("%s:%d\n", __func__, __LINE__);
	return 0;
}

static void epf_vnet_vdev_set_status(struct virtio_device *vdev, u8 status)
{
	pr_info("%s:%d %x\n", __func__, __LINE__, status);
}

static void epf_vnet_vdev_reset(struct virtio_device *vdev)
{
	pr_info("%s:%d\n", __func__, __LINE__);
}

static bool epf_vnet_vdev_vq_notify(struct virtqueue *vq)
{
	struct epf_vnet *vnet = vdev_to_vnet(vq->vdev);

	if (unlikely(!vnet->rc_init_done))
		return true;

	if (vq->index == 1)
		queue_work(vnet->ep.tx_wq, &vnet->ep.tx_work);

	return true;
}

static int epf_vnet_vdev_find_vqs(struct virtio_device *vdev, unsigned nvqs,
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

		vq = vring_create_virtqueue(qidx++, epf_vnet_virtqueue_size(),
					    VIRTIO_PCI_VRING_ALIGN, vdev, true,
					    false, ctx ? ctx[i] : false,
					    epf_vnet_vdev_vq_notify,
					    callback[i], names[i]);
		if (!vq) {
			err = -ENOMEM;
			goto err_del_vqs;
		}

		vqs[i] = vq;
		if (i == 0)
			vnet->ep.rxvq = vq;

		vring = virtqueue_get_vring(vq);
		if (i == 0) {
			vrh = &vnet->ep.rx_vrh;
			kiov = &vnet->ep.rxiov;
		} else if (i == 1) {
			vrh = &vnet->ep.tx_vrh;
			kiov = &vnet->ep.txiov;
		} else {
			BUG_ON("founc unsuspected queue index\n");
		}

		err = vringh_init_kern(vrh, vnet->features,
				       epf_vnet_virtqueue_size(), false,
				       vring->desc, vring->avail, vring->used);
		if (err) {
			pr_err("failed to init vringh for vring %d\n", i);
			goto err_del_vqs;
		}

		kvec = kmalloc_array(epf_vnet_virtqueue_size(), sizeof *kvec,
				     GFP_KERNEL);
		if (!kvec) {
			err = -ENOMEM;
			goto err_del_vqs;
		}
		vringh_kiov_init(kiov, kvec, epf_vnet_virtqueue_size());
	}

	return 0;

err_del_vqs:
	//TODO delete created virtqueues
	return err;
}

static void epf_vnet_vdev_del_vqs(struct virtio_device *vdev)
{
	pr_info("%s:%d\n", __func__, __LINE__);
}

static const char *epf_vnet_vdev_bus_name(struct virtio_device *vdev)
{
	//TODO
	pr_info("%s:%d\n", __func__, __LINE__);
	return "dummy bus name";
}

static void epf_vnet_vdev_sync_cbs(struct virtio_device *vdev)
{
	pr_info("%s:%d\n", __func__, __LINE__);
}

static const struct virtio_config_ops epf_vnet_vdev_config_ops = {
	.get_features = epf_vnet_vdev_get_features,
	.finalize_features = epf_vnet_vdev_finalize_features,
	.get = epf_vnet_vdev_get_config,
	.set = epf_vnet_vdev_set_config,
	.get_status = epf_vnet_vdev_get_status,
	.set_status = epf_vnet_vdev_set_status,
	.reset = epf_vnet_vdev_reset,
	.find_vqs = epf_vnet_vdev_find_vqs,
	.del_vqs = epf_vnet_vdev_del_vqs,
	.bus_name = epf_vnet_vdev_bus_name,
	.synchronize_cbs = epf_vnet_vdev_sync_cbs,
};

static void tmp_callback(void *p)
{
	struct completion *txcmp = p;
	complete(txcmp);
}

static int _epf_vnet_ep_tx_handler(struct epf_vnet *vnet)
{
	int err;

	struct vringh_kiov *tiov = &vnet->ep.txiov;
	struct vringh_kiov *riov = &vnet->rc.rxiov;
	struct vringh *tvrh = &vnet->ep.tx_vrh;
	struct vringh *rvrh = &vnet->rc.rx_vrh;
	size_t total_tx_len;
	u16 lhead, rhead;
	struct device *dma_dev = vnet->vdev.dev.parent;

	err = vringh_getdesc_kern(tvrh, tiov, NULL, &lhead, GFP_KERNEL);
	if (err < 0) {
		pr_err("failed to get tx descs\n");
		return err;
	} else if (!err) {
		// No data to transport
		return 0;
	}

	total_tx_len = vringh_kiov_length(tiov);

	err = vringh_getdesc_iomem(rvrh, NULL, riov, &rhead, GFP_KERNEL);
	if (err < 0) {
		pr_err("failed to get rx descs\n");
		goto err_abandon_tx;
	} else if (!err) {
		pr_info("rx desc is full at rc\n");
		goto err_abandon_tx;
	}

	//TODO check desc using vringh_kiov_length();

	for (; tiov->i < tiov->used; tiov->i++, riov->i++) {
		size_t llen, rlen;
		u64 lbase, rbase;

		llen = tiov->iov[tiov->i].iov_len;
		lbase = (u64)tiov->iov[tiov->i].iov_base;

		rlen = riov->iov[riov->i].iov_len;
		rbase = (u64)riov->iov[riov->i].iov_base;

		if (riov->i >= riov->used) {
			pr_err("not enough descriptors\n");
			err = -ENOSPC;
			goto err_abandon_rx;
		}

		if (llen > rlen) {
			pr_err("descriptor is not enought: 0x%lx > 0x%lx\n",
			       llen, rlen);
			err = -ENOSPC;
			goto err_abandon_rx;
		}

		dma_sync_single_for_device(dma_dev, lbase, llen,
					   DMA_MEM_TO_DEV);

		{
			struct completion tx_complete;
			init_completion(&tx_complete);
			err = epf_vnet_dma_single(vnet, rbase, lbase, llen,
						  tmp_callback, &tx_complete,
						  DMA_MEM_TO_DEV);
			if (err) {
				pr_err("failed to request a dma\n");
				err = -EIO;
				goto err_abandon_rx;
			}

			err = wait_for_completion_interruptible(&tx_complete);
			if (err < 0) {
				pr_err("error at waiting completion: %d", err);
				goto err_abandon_rx;
			}
		}
	}

	vringh_complete_kern(tvrh, lhead, total_tx_len);
	vringh_complete_iomem(rvrh, rhead, total_tx_len);

	queue_work(vnet->irq_wq, &vnet->raise_irq_work);

	return 1;

err_abandon_rx:
	vringh_abandon_iomem(rvrh, 1);
err_abandon_tx:
	vringh_abandon_iomem(tvrh, 1);

	return err;
}

static void epf_vnet_ep_tx_handler(struct work_struct *work)
{
	struct _ep *ep = container_of(work, struct _ep, tx_work);
	struct epf_vnet *vnet = container_of(ep, struct epf_vnet, ep);

	while (_epf_vnet_ep_tx_handler(vnet) > 0)
		;
}

int epf_vnet_setup_local(struct epf_vnet *vnet, struct device *parent)
{
	int err;
	struct virtio_device *vdev = &vnet->vdev;

	vnet->ep.tx_wq = alloc_workqueue(
		"epf-vnet/tx-wq", WQ_MEM_RECLAIM | WQ_HIGHPRI | WQ_UNBOUND, 0);
	if (!vnet->ep.tx_wq) {
		pr_err("failed to create workqueue\n");
		return -ENOMEM;
	}

	INIT_WORK(&vnet->ep.tx_work, epf_vnet_ep_tx_handler);

	vdev->dev.parent = parent;
	vdev->dev.release = epf_vnet_vdev_release;
	vdev->config = &epf_vnet_vdev_config_ops;
	vdev->id.vendor = epf_vnet_pci_header.subsys_vendor_id;
	vdev->id.device = epf_vnet_pci_header.subsys_id;

	err = register_virtio_device(vdev);
	if (err) {
		pr_err("Failed to register a virtio net device");
		goto err_out;
	}

	return 0;

err_out:
	return err;
}
