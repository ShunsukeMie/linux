// SPDX-License-Identifier: GPL-2.0-only
/*
 * PCIe host/endpoint controller driver for Renesas R-Car Gen4 Series SoCs
 * Copyright (C) 2022-2023 Renesas Electronics Corporation
 */

#include <linux/delay.h>
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

#define RETRAIN_MAX_RETRY	10

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

static bool rcar_gen4_pcie_check_retrain_link(struct dw_pcie *dw)
{
	u8 offset = dw_pcie_find_capability(dw, PCI_CAP_ID_EXP);
	u32 lnkcap = dw_pcie_readl_dbi(dw, offset + PCI_EXP_LNKCAP);
	u32 lnkctl = dw_pcie_readl_dbi(dw, offset + PCI_EXP_LNKCTL);
	u16 lnksta = dw_pcie_readw_dbi(dw, offset + PCI_EXP_LNKSTA);
	int i;

	if ((lnksta & PCI_EXP_LNKSTA_CLS) == (lnkcap & PCI_EXP_LNKCAP_SLS))
		return true;

	lnkctl |= PCI_EXP_LNKCTL_RL;
	dw_pcie_writel_dbi(dw, offset + PCI_EXP_LNKCTL, lnkctl);

	for (i = 0; i < RETRAIN_MAX_RETRY; i++) {
		lnksta = dw_pcie_readw_dbi(dw, offset + PCI_EXP_LNKSTA);
		if (lnksta & PCI_EXP_LNKSTA_LT)
			return true;
		usleep_range(1000, 1100);
	}

	return false;
}

static int rcar_gen4_pcie_link_up(struct dw_pcie *dw)
{
	struct rcar_gen4_pcie *rcar = to_rcar_gen4_pcie(dw);
	u32 val, mask;

	/* Require retraining here. Otherwise RDLH_LINK_UP may not be set */
	if (rcar->needs_retrain && !rcar_gen4_pcie_check_retrain_link(dw))
		return 0;

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

int rcar_gen4_pcie_set_device_type(struct rcar_gen4_pcie *rcar, bool rc,
				   int num_lanes)
{
	u32 val;

	/* Note: Assume the reset is asserted here */
	val = readl(rcar->base + PCIEMSR0);
	if (rc)
		val |= DEVICE_TYPE_RC;
	else
		val |= DEVICE_TYPE_EP;
	if (num_lanes < 4)
		val |= BIFUR_MOD_SET_ON;
	writel(val, rcar->base + PCIEMSR0);

	return reset_control_deassert(rcar->rst);
}

void rcar_gen4_pcie_disable_bar(struct dw_pcie *dw, u32 bar_mask_reg)
{
	dw_pcie_writel_dbi2(dw, bar_mask_reg, 0x0);
}

int rcar_gen4_pcie_prepare(struct rcar_gen4_pcie *rcar)
{
	struct device *dev = rcar->dw.dev;
	int err;

	pm_runtime_enable(dev);
	err = pm_runtime_resume_and_get(dev);
	if (err < 0) {
		dev_err(dev, "Failed to resume/get Runtime PM\n");
		pm_runtime_disable(dev);
	}

	return err;
}

void rcar_gen4_pcie_unprepare(struct rcar_gen4_pcie *rcar)
{
	struct device *dev = rcar->dw.dev;

	if (!reset_control_status(rcar->rst))
		reset_control_assert(rcar->rst);
	pm_runtime_put(dev);
	pm_runtime_disable(dev);
}

static int rcar_gen4_pcie_devm_reset_get(struct rcar_gen4_pcie *rcar,
				  struct device *dev)
{
	rcar->rst = devm_reset_control_get(dev, NULL);
	if (IS_ERR(rcar->rst)) {
		dev_err(dev, "Failed to get Cold-reset\n");
		return PTR_ERR(rcar->rst);
	}

	return 0;
}

int rcar_gen4_pcie_get_resources(struct rcar_gen4_pcie *rcar,
				 struct platform_device *pdev)
{
	struct dw_pcie *dw = &rcar->dw;

	/* Renesas-specific registers */
	rcar->base = devm_platform_ioremap_resource_byname(pdev, "app");
	if (IS_ERR(rcar->base))
		return PTR_ERR(rcar->base);

	return rcar_gen4_pcie_devm_reset_get(rcar, dw->dev);
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
	dw_pcie_cap_set(&rcar->dw, EDMA_UNROLL);

	return rcar;
}
