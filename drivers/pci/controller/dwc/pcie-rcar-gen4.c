// SPDX-License-Identifier: GPL-2.0
/*
 * PCIe host/endpoint controller driver for Renesas R-Car Gen4 Series SoCs
 * Copyright (C) 2022 Renesas Electronics Corporation
 */

#include <linux/io.h>
#include <linux/of_device.h>
#include <linux/pci.h>
#include <linux/pm_runtime.h>
#include <linux/reset.h>

#include "pcie-rcar-gen4.h"
#include "pcie-designware.h"

/* Renesas-specific */
#define PCIERSTCTRL1		0x0014
#define  APP_HOLD_PHY_RST	BIT(16)
#define  APP_LTSSM_ENABLE	BIT(0)

#define DWC_VERSION		0x520a

static void rcar_gen4_pcie_ltssm_enable(struct rcar_gen4_pcie *rcar,
					bool enable)
{
	u32 val;

	val = readl(rcar->base + PCIERSTCTRL1);
	if (enable) {
		val |= APP_LTSSM_ENABLE;
		val &= ~APP_HOLD_PHY_RST;
	} else {
		val &= ~APP_LTSSM_ENABLE;
		val |= APP_HOLD_PHY_RST;
	}
	writel(val, rcar->base + PCIERSTCTRL1);
}

static int rcar_gen4_pcie_link_up(struct dw_pcie *dw)
{
	struct rcar_gen4_pcie *rcar = to_rcar_gen4_pcie(dw);
	u32 val, mask;

	val = readl(rcar->base + PCIEINTSTS0);
	mask = RDLH_LINK_UP | SMLH_LINK_UP;

	return (val & mask) == mask;
}

static int rcar_gen4_pcie_start_link(struct dw_pcie *dw)
{
	struct rcar_gen4_pcie *rcar = to_rcar_gen4_pcie(dw);

	rcar_gen4_pcie_ltssm_enable(rcar, true);

	return 0;
}

static void rcar_gen4_pcie_stop_link(struct dw_pcie *dw)
{
	struct rcar_gen4_pcie *rcar = to_rcar_gen4_pcie(dw);

	rcar_gen4_pcie_ltssm_enable(rcar, false);
}

void rcar_gen4_pcie_set_device_type(struct rcar_gen4_pcie *rcar, bool rc,
				    int num_lanes)
{
	u32 val;

	val = readl(rcar->base + PCIEMSR0);
	if (rc)
		val |= DEVICE_TYPE_RC;
	else
		val |= DEVICE_TYPE_EP;
	if (num_lanes < 4)
		val |= BIFUR_MOD_SET_ON;
	writel(val, rcar->base + PCIEMSR0);
}

void rcar_gen4_pcie_disable_bar(struct dw_pcie *dw, u32 bar_mask_reg)
{
	dw_pcie_writel_dbi(dw, SHADOW_REG(bar_mask_reg), 0x0);
}

void rcar_gen4_pcie_set_max_link_width(struct dw_pcie *dw, int num_lanes)
{
	u32 val = dw_pcie_readl_dbi(dw, EXPCAP(PCI_EXP_LNKCAP));

	val &= ~PCI_EXP_LNKCAP_MLW;
	switch (num_lanes) {
	case 1:
		val |= PCI_EXP_LNKCAP_MLW_X1;
		break;
	case 2:
		val |= PCI_EXP_LNKCAP_MLW_X2;
		break;
	case 4:
		val |= PCI_EXP_LNKCAP_MLW_X4;
		break;
	default:
		dev_info(dw->dev, "invalid num-lanes %d\n", num_lanes);
		val |= PCI_EXP_LNKCAP_MLW_X1;
		break;
	}
	dw_pcie_writel_dbi(dw, EXPCAP(PCI_EXP_LNKCAP), val);
}

int rcar_gen4_pcie_prepare(struct rcar_gen4_pcie *rcar)
{
	struct device *dev = rcar->dw.dev;
	int err;

	pm_runtime_enable(dev);
	err = pm_runtime_resume_and_get(dev);
	if (err < 0) {
		dev_err(dev, "%s: failed to resume/get Runtime PM\n", __func__);
		goto err_resume_and_get;
	}

	err = reset_control_deassert(rcar->rst);
	if (err < 0) {
		dev_err(dev, "%s: failed to deassert reset_control\n", __func__);
		goto err_deassert;
	}

	writel(PCIEDMAINTSTSEN_INIT, rcar->base + PCIEDMAINTSTSEN);

	return 0;

err_deassert:
	pm_runtime_put(dev);

err_resume_and_get:
	pm_runtime_disable(dev);

	return err;
}

void rcar_gen4_pcie_unprepare(struct rcar_gen4_pcie *rcar)
{
	struct device *dev = rcar->dw.dev;

	writel(0, rcar->base + PCIEDMAINTSTSEN);
	reset_control_assert(rcar->rst);
	pm_runtime_put(dev);
	pm_runtime_disable(dev);
}

int rcar_gen4_pcie_devm_reset_get(struct rcar_gen4_pcie *rcar,
				  struct device *dev)
{
	rcar->rst = devm_reset_control_get(dev, NULL);
	if (IS_ERR(rcar->rst)) {
		dev_err(dev, "failed to get Cold-reset\n");
		return PTR_ERR(rcar->rst);
	}

	return 0;
}

static const struct dw_pcie_ops dw_pcie_ops = {
	.start_link = rcar_gen4_pcie_start_link,
	.stop_link = rcar_gen4_pcie_stop_link,
	.link_up = rcar_gen4_pcie_link_up,
};

struct rcar_gen4_pcie *rcar_gen4_pcie_devm_alloc(struct device *dev)
{
	struct rcar_gen4_pcie *rcar;

	rcar = devm_kzalloc(dev, sizeof(*rcar), GFP_KERNEL);
	if (!rcar)
		return NULL;

	rcar->dw.dev = dev;
	rcar->dw.ops = &dw_pcie_ops;
	rcar->dw.version = DWC_VERSION;

	return rcar;
}
