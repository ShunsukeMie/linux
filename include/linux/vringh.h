/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Linux host-side vring helpers; for when the kernel needs to access
 * someone else's vring.
 *
 * Copyright IBM Corporation, 2013.
 * Parts taken from drivers/vhost/vhost.c Copyright 2009 Red Hat, Inc.
 *
 * Written by: Rusty Russell <rusty@rustcorp.com.au>
 */
#ifndef _LINUX_VRINGH_H
#define _LINUX_VRINGH_H
#include <uapi/linux/virtio_ring.h>
#include <linux/virtio_byteorder.h>
#include <linux/uio.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#if IS_REACHABLE(CONFIG_VHOST_IOTLB)
#include <linux/dma-direction.h>
#include <linux/vhost_iotlb.h>
#endif
#include <asm/barrier.h>

struct vringh;
struct vringh_range;

/**
 * struct vringh_ops - ops for accessing a vring and checking to access range.
 * @getu16: read u16 value from pointer
 * @putu16: write u16 value to pointer
 * @xfer_from: copy memory range from specified address to local virtual address
 * @xfer_tio: copy memory range from local virtual address to specified address
 * @putused: update vring used descriptor
 * @copydesc: copy desiptor from target to local virtual address
 * @range_check: check if the region is accessible
 * @getrange: return a range that vring can access
 */
struct vringh_ops {
	int (*getu16)(const struct vringh *vrh, u16 *val, const __virtio16 *p);
	int (*putu16)(const struct vringh *vrh, __virtio16 *p, u16 val);
	int (*xfer_from)(const struct vringh *vrh, void *src, void *dst,
			 size_t len);
	int (*xfer_to)(const struct vringh *vrh, void *dst, void *src,
		       size_t len);
	int (*putused)(const struct vringh *vrh, struct vring_used_elem *dst,
		       const struct vring_used_elem *src, unsigned int num);
	int (*copydesc)(const struct vringh *vrh, void *dst, const void *src,
			size_t len);
	bool (*range_check)(struct vringh *vrh, u64 addr, size_t *len,
			    struct vringh_range *range);
	bool (*getrange)(struct vringh *vrh, u64 addr, struct vringh_range *r);
};

/* virtio_ring with information needed for host access. */
struct vringh {
	/* Everything is little endian */
	bool little_endian;

	/* Guest publishes used event idx (note: we always do). */
	bool event_indices;

	/* Can we get away with weak barriers? */
	bool weak_barriers;

	/* Last available index we saw (ie. where we're up to). */
	u16 last_avail_idx;

	/* Last index we used. */
	u16 last_used_idx;

	/* How many descriptors we've completed since last need_notify(). */
	u32 completed;

	/* The vring (note: it may contain user pointers!) */
	struct vring vring;

	/* IOTLB for this vring */
	struct vhost_iotlb *iotlb;

	/* spinlock to synchronize IOTLB accesses */
	spinlock_t *iotlb_lock;

	/* The function to call to notify the guest about added buffers */
	void (*notify)(struct vringh *);

	struct vringh_ops ops;

	gfp_t desc_gfp;
};

/**
 * struct vringh_config_ops - ops for creating a host vring from a virtio driver
 * @find_vrhs: find the host vrings and instantiate them
 *	vdev: the virtio_device
 *	nhvrs: the number of host vrings to find
 *	hvrs: on success, includes new host vrings
 *	callbacks: array of driver callbacks, for each host vring
 *		include a NULL entry for vqs that do not need a callback
 *	Returns 0 on success or error status
 * @del_vrhs: free the host vrings found by find_vrhs().
 */
struct virtio_device;
typedef void vrh_callback_t(struct virtio_device *, struct vringh *);
struct vringh_config_ops {
	int (*find_vrhs)(struct virtio_device *vdev, unsigned nhvrs,
			 struct vringh *vrhs[], vrh_callback_t *callbacks[]);
	void (*del_vrhs)(struct virtio_device *vdev);
};

/* The memory the vring can access, and what offset to apply. */
struct vringh_range {
	u64 start, end_incl;
	u64 offset;
};

/**
 * struct vringh_iov - iovec mangler.
 *
 * Mangles iovec in place, and restores it.
 * Remaining data is iov + i, of used - i elements.
 */
struct vringh_iov {
	struct iovec *iov;
	size_t consumed; /* Within iov[i] */
	unsigned i, used, max_num;
};

/**
 * struct vringh_kiov - kvec mangler.
 *
 * Mangles kvec in place, and restores it.
 * Remaining data is iov + i, of used - i elements.
 */
struct vringh_kiov {
	struct kvec *iov;
	size_t consumed; /* Within iov[i] */
	unsigned i, used, max_num;
};

/* Flag on max_num to indicate we're kmalloced. */
#define VRINGH_IOV_ALLOCATED 0x8000000

/* Helpers for userspace vrings. */
int vringh_init_user(struct vringh *vrh, u64 features,
		     unsigned int num, bool weak_barriers,
		     vring_desc_t __user *desc,
		     vring_avail_t __user *avail,
		     vring_used_t __user *used,
			 bool (*getrange)(struct vringh *vrh, u64 addr, struct vringh_range *r));

static inline void vringh_iov_init(struct vringh_iov *iov,
				   struct iovec *iovec, unsigned num)
{
	iov->used = iov->i = 0;
	iov->consumed = 0;
	iov->max_num = num;
	iov->iov = iovec;
}

static inline void vringh_iov_reset(struct vringh_iov *iov)
{
	iov->iov[iov->i].iov_len += iov->consumed;
	iov->iov[iov->i].iov_base -= iov->consumed;
	iov->consumed = 0;
	iov->i = 0;
}

static inline void vringh_iov_cleanup(struct vringh_iov *iov)
{
	if (iov->max_num & VRINGH_IOV_ALLOCATED)
		kfree(iov->iov);
	iov->max_num = iov->used = iov->i = iov->consumed = 0;
	iov->iov = NULL;
}

/* Convert a descriptor into iovecs. */
int vringh_getdesc(struct vringh *vrh,
			struct vringh_kiov *riov,
			struct vringh_kiov *wiov,
			u16 *head);

/* Copy bytes from readable vsg, consuming it (and incrementing wiov->i). */
ssize_t vringh_iov_pull(struct vringh *vrh, struct vringh_kiov *riov, void *dst, size_t len);

/* Copy bytes into writable vsg, consuming it (and incrementing wiov->i). */
ssize_t vringh_iov_push(struct vringh *vrh, struct vringh_kiov *wiov,
			     const void *src, size_t len);

/* Mark a descriptor as used. */
int vringh_complete(struct vringh *vrh, u16 head, u32 len);
int vringh_complete_multi(struct vringh *vrh,
			       const struct vring_used_elem used[],
			       unsigned num_used);

/* Pretend we've never seen descriptor (for easy error handling). */
void vringh_abandon(struct vringh *vrh, unsigned int num);

/* Do we need to fire the eventfd to notify the other side? */
int vringh_need_notify(struct vringh *vrh);

bool vringh_notify_enable(struct vringh *vrh);
void vringh_notify_disable(struct vringh *vrh);

/* Helpers for kernelspace vrings. */
int vringh_init_kern(struct vringh *vrh, u64 features,
		     unsigned int num, bool weak_barriers, gfp_t gfp,
		     struct vring_desc *desc,
		     struct vring_avail *avail,
		     struct vring_used *used);

static inline void vringh_kiov_init(struct vringh_kiov *kiov,
				    struct kvec *kvec, unsigned num)
{
	kiov->used = kiov->i = 0;
	kiov->consumed = 0;
	kiov->max_num = num;
	kiov->iov = kvec;
}

static inline void vringh_kiov_reset(struct vringh_kiov *kiov)
{
	kiov->iov[kiov->i].iov_len += kiov->consumed;
	kiov->iov[kiov->i].iov_base -= kiov->consumed;
	kiov->consumed = 0;
	kiov->i = 0;
}

static inline void vringh_kiov_cleanup(struct vringh_kiov *kiov)
{
	if (kiov->max_num & VRINGH_IOV_ALLOCATED)
		kfree(kiov->iov);
	kiov->max_num = kiov->used = kiov->i = kiov->consumed = 0;
	kiov->iov = NULL;
}

static inline size_t vringh_kiov_length(struct vringh_kiov *kiov)
{
	size_t len = 0;
	int i;

	for (i = kiov->i; i < kiov->used; i++)
		len += kiov->iov[i].iov_len;

	return len;
}

void vringh_kiov_advance(struct vringh_kiov *kiov, size_t len);

/* Notify the guest about buffers added to the used ring */
static inline void vringh_notify(struct vringh *vrh)
{
	if (vrh->notify)
		vrh->notify(vrh);
}

static inline bool vringh_is_little_endian(const struct vringh *vrh)
{
	return vrh->little_endian ||
		virtio_legacy_is_little_endian();
}

static inline u16 vringh16_to_cpu(const struct vringh *vrh, __virtio16 val)
{
	return __virtio16_to_cpu(vringh_is_little_endian(vrh), val);
}

static inline __virtio16 cpu_to_vringh16(const struct vringh *vrh, u16 val)
{
	return __cpu_to_virtio16(vringh_is_little_endian(vrh), val);
}

static inline u32 vringh32_to_cpu(const struct vringh *vrh, __virtio32 val)
{
	return __virtio32_to_cpu(vringh_is_little_endian(vrh), val);
}

static inline __virtio32 cpu_to_vringh32(const struct vringh *vrh, u32 val)
{
	return __cpu_to_virtio32(vringh_is_little_endian(vrh), val);
}

static inline u64 vringh64_to_cpu(const struct vringh *vrh, __virtio64 val)
{
	return __virtio64_to_cpu(vringh_is_little_endian(vrh), val);
}

static inline __virtio64 cpu_to_vringh64(const struct vringh *vrh, u64 val)
{
	return __cpu_to_virtio64(vringh_is_little_endian(vrh), val);
}

#if IS_REACHABLE(CONFIG_VHOST_IOTLB)

void vringh_set_iotlb(struct vringh *vrh, struct vhost_iotlb *iotlb,
		      spinlock_t *iotlb_lock);

int vringh_init_iotlb(struct vringh *vrh, u64 features,
		      unsigned int num, bool weak_barriers, gfp_t gfp,
		      struct vring_desc *desc,
		      struct vring_avail *avail,
		      struct vring_used *used);

#endif /* CONFIG_VHOST_IOTLB */

#if IS_REACHABLE(CONFIG_VHOST_IOMEM)

int vringh_init_iomem(struct vringh *vrh, u64 features, unsigned int num,
		      bool weak_barriers, gfp_t gfp, struct vring_desc *desc,
		      struct vring_avail *avail, struct vring_used *used);

#endif /* CONFIG_VHOST_IOMEM */

#endif /* _LINUX_VRINGH_H */
