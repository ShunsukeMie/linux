/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _PCI_EPF_VNET_H
#define _PCI_EPF_VNET_H

#include <linux/pci-epf.h>
#include <linux/pci-epf-virtio.h>
#include <linux/virtio_net.h>
#include <linux/dmaengine.h>
#include <linux/virtio.h>

#if defined(CONFIG_PCI_EPF_VNET_ROCE)
#include <rdma/ib_verbs.h>

#define EPF_VNET_ROCE_GID_TBL_LEN 512

struct epf_vnet_roce_dev_attr {
	u64 max_mr_size;
	u64 page_size_cap;
	u32 hw_ver;
	u32 max_qp_wr;
	u64 device_cap_flags;
	u32 max_send_sge;
	u32 max_recv_sge;
	u32 max_sge_rd;
	u32 max_cqe;
	u32 max_mr;
	u32 max_mw;
	u32 max_pd;
	u32 max_qp_rd_atom;
	u32 max_qp_init_rd_atom;
	u32 max_ah;
	u32 max_fast_reg_page_list_len;
	u8 local_ca_ack_delay;
};
#endif // CONFIG_PCI_EPF_VNET_ROCE

struct epf_vnet {
	//TODO Should this variable be placed here?
	struct pci_epf *epf;
	struct virtio_net_config vnet_cfg;
	u64 virtio_features;

	// dma channels for local to remote(lr) and remote to local(rl)
	struct dma_chan *lr_dma_chan, *rl_dma_chan;

	struct {
		void __iomem *cfg_base;
		struct task_struct *device_setup_task;
		struct task_struct *notify_monitor_task;
		struct workqueue_struct *tx_wq, *irq_wq, *ctl_wq;
		struct work_struct tx_work, raise_irq_work, ctl_work;
		struct pci_epf_vringh *txvrh, *rxvrh, *ctlvrh;
		struct vringh_kiov tx_iov, rx_iov, ctl_riov, ctl_wiov;
	} rc;

	struct {
		struct virtqueue *rxvq, *txvq, *ctlvq;
		struct vringh txvrh, rxvrh, ctlvrh;
		struct vringh_kiov tx_iov, rx_iov, ctl_riov, ctl_wiov;
		struct virtio_device vdev;
		u16 net_config_status;
	} ep;

#define EPF_VNET_INIT_COMPLETE_EP BIT(0)
#define EPF_VNET_INIT_COMPLETE_RC BIT(1)
	u8 init_complete;

#if defined(CONFIG_PCI_EPF_VNET_ROCE)
	struct epf_vnet_roce_dev_attr roce_attr;
	union ib_gid roce_gid_tbl[EPF_VNET_ROCE_GID_TBL_LEN];

#endif // CONFIG_PCI_EPF_VNET_ROCE
};

int epf_vnet_rc_setup(struct epf_vnet *vnet);
void epf_vnet_rc_cleanup(struct epf_vnet *vnet);
int epf_vnet_ep_setup(struct epf_vnet *vnet);
void epf_vnet_ep_cleanup(struct epf_vnet *vnet);

int epf_vnet_get_vq_size(void);
int epf_vnet_init_kiov(struct vringh_kiov *kiov, const size_t vq_size);
void epf_vnet_deinit_kiov(struct vringh_kiov *kiov);
int epf_vnet_transfer(struct epf_vnet *vnet, struct vringh *tx_vrh,
		      struct vringh *rx_vrh, struct vringh_kiov *tx_iov,
		      struct vringh_kiov *rx_iov,
		      enum dma_transfer_direction dir);
void epf_vnet_rc_notify(struct epf_vnet *vnet);
void epf_vnet_ep_notify(struct epf_vnet *vnet, struct virtqueue *vq);

void epf_vnet_init_complete(struct epf_vnet *vnet, u8 from);
void epf_vnet_ep_announce_linkup(struct epf_vnet *vnet);
void epf_vnet_rc_announce_linkup(struct epf_vnet *vnet);

#endif // _PCI_EPF_VNET_H
