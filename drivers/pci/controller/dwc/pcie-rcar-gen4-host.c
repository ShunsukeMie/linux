// SPDX-License-Identifier: GPL-2.0
/*
 * PCIe host controller driver for Renesas R-Car Gen4 Series SoCs
 * Copyright (C) 2022 Renesas Electronics Corporation
 */

#include <linux/interrupt.h>
#include <linux/module.h>
#include <linux/of_device.h>
#include <linux/pci.h>
#include <linux/platform_device.h>

#include "pcie-rcar-gen4.h"
#include "pcie-designware.h"

static int rcar_gen4_pcie_host_init(struct dw_pcie_rp *pp)
{
	struct dw_pcie *dw = to_dw_pcie_from_pp(pp);
	struct rcar_gen4_pcie *rcar = to_rcar_gen4_pcie(dw);
	int ret;
	u32 val;

	rcar_gen4_pcie_set_device_type(rcar, true, dw->num_lanes);

	dw_pcie_dbi_ro_wr_en(dw);

	/* Enable L1 Substates */
	val = dw_pcie_readl_dbi(dw, L1PSCAP(PCI_L1SS_CTL1));
	val &= ~PCI_L1SS_CTL1_L1SS_MASK;
	val |= PCI_L1SS_CTL1_PCIPM_L1_2 | PCI_L1SS_CTL1_PCIPM_L1_1 |
	       PCI_L1SS_CTL1_ASPM_L1_2 | PCI_L1SS_CTL1_ASPM_L1_1;
	dw_pcie_writel_dbi(dw, L1PSCAP(PCI_L1SS_CTL1), val);

	rcar_gen4_pcie_disable_bar(dw, BAR0MASKF);
	rcar_gen4_pcie_disable_bar(dw, BAR1MASKF);

	/* Set Root Control */
	val = dw_pcie_readl_dbi(dw, EXPCAP(PCI_EXP_RTCTL));
	val |= PCI_EXP_RTCTL_SECEE | PCI_EXP_RTCTL_SENFEE |
	       PCI_EXP_RTCTL_SEFEE | PCI_EXP_RTCTL_PMEIE |
	       PCI_EXP_RTCTL_CRSSVE;
	dw_pcie_writel_dbi(dw, EXPCAP(PCI_EXP_RTCTL), val);

	/* Set Interrupt Disable, SERR# Enable, Parity Error Response */
	val = dw_pcie_readl_dbi(dw, PCI_COMMAND);
	val |= PCI_COMMAND_PARITY | PCI_COMMAND_SERR |
	       PCI_COMMAND_INTX_DISABLE;
	dw_pcie_writel_dbi(dw, PCI_COMMAND, val);

	/* Enable SERR */
	val = dw_pcie_readb_dbi(dw, PCI_BRIDGE_CONTROL);
	val |= PCI_BRIDGE_CTL_SERR;
	dw_pcie_writeb_dbi(dw, PCI_BRIDGE_CONTROL, val);

	/* Device control */
	val = dw_pcie_readl_dbi(dw, EXPCAP(PCI_EXP_DEVCTL));
	val |= PCI_EXP_DEVCTL_CERE | PCI_EXP_DEVCTL_NFERE |
	       PCI_EXP_DEVCTL_FERE | PCI_EXP_DEVCTL_URRE;
	dw_pcie_writel_dbi(dw, EXPCAP(PCI_EXP_DEVCTL), val);

	dw_pcie_dbi_ro_wr_dis(dw);

	if (IS_ENABLED(CONFIG_PCI_MSI)) {
		/* Enable MSI interrupt signal */
		val = readl(rcar->base + PCIEINTSTS0EN);
		val |= MSI_CTRL_INT;
		writel(val, rcar->base + PCIEINTSTS0EN);
	}

	dw_pcie_setup_rc(pp);

	dw_pcie_dbi_ro_wr_en(dw);
	rcar_gen4_pcie_set_max_link_width(dw, dw->num_lanes);
	dw_pcie_dbi_ro_wr_dis(dw);

	if (!dw_pcie_link_up(dw)) {
		ret = dw->ops->start_link(dw);
		if (ret)
			return ret;
	}

	/* Ignore errors, the link may come up later */
	if (dw_pcie_wait_for_link(dw))
		dev_info(dw->dev, "PCIe link down\n");

	return 0;
}

static const struct dw_pcie_host_ops rcar_gen4_pcie_host_ops = {
	.host_init = rcar_gen4_pcie_host_init,
};

static int rcar_gen4_add_dw_pcie_rp(struct rcar_gen4_pcie *rcar,
				   struct platform_device *pdev)
{
	struct dw_pcie *dw = &rcar->dw;
	struct dw_pcie_rp *pp = &dw->pp;
	int ret;

	if (IS_ENABLED(CONFIG_PCI_MSI)) {
		pp->msi_irq = platform_get_irq_byname(pdev, "others");
		if (pp->msi_irq < 0)
			return pp->msi_irq;
	}

	pp->ops = &rcar_gen4_pcie_host_ops;

	ret = dw_pcie_host_init(pp);
	if (ret) {
		dev_err(&pdev->dev, "Failed to initialize host\n");
		return ret;
	}

	return 0;
}

static void rcar_gen4_remove_dw_pcie_rp(struct rcar_gen4_pcie *rcar)
{
	dw_pcie_host_deinit(&rcar->dw.pp);
}

static int rcar_gen4_pcie_get_resources(struct rcar_gen4_pcie *rcar,
					struct platform_device *pdev)
{
	struct dw_pcie *dw = &rcar->dw;

	/* Renesas-specific registers */
	rcar->base = devm_platform_ioremap_resource_byname(pdev, "app");
	if (IS_ERR(rcar->base))
		return PTR_ERR(rcar->base);

	return rcar_gen4_pcie_devm_reset_get(rcar, dw->dev);
}

static int rcar_gen4_pcie_probe(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct rcar_gen4_pcie *rcar;
	int err;

	rcar = rcar_gen4_pcie_devm_alloc(dev);
	if (!rcar)
		return -ENOMEM;

	err = rcar_gen4_pcie_get_resources(rcar, pdev);
	if (err < 0) {
		dev_err(dev, "failed to request resource: %d\n", err);
		return err;
	}

	platform_set_drvdata(pdev, rcar);

	err = rcar_gen4_pcie_prepare(rcar);
	if (err < 0)
		return err;

	err = rcar_gen4_add_dw_pcie_rp(rcar, pdev);
	if (err < 0)
		goto err_add;

	return 0;

err_add:
	rcar_gen4_pcie_unprepare(rcar);

	return err;
}

static int rcar_gen4_pcie_remove(struct platform_device *pdev)
{
	struct rcar_gen4_pcie *rcar = platform_get_drvdata(pdev);

	rcar_gen4_remove_dw_pcie_rp(rcar);
	rcar_gen4_pcie_unprepare(rcar);

	return 0;
}

static const struct of_device_id rcar_gen4_pcie_of_match[] = {
	{ .compatible = "renesas,rcar-gen4-pcie", },
	{},
};

static struct platform_driver rcar_gen4_pcie_driver = {
	.driver = {
		.name = "pcie-rcar-gen4",
		.of_match_table = rcar_gen4_pcie_of_match,
	},
	.probe = rcar_gen4_pcie_probe,
	.remove = rcar_gen4_pcie_remove,
};
module_platform_driver(rcar_gen4_pcie_driver);

MODULE_DESCRIPTION("Renesas R-Car Gen4 PCIe host controller driver");
MODULE_LICENSE("GPL");
