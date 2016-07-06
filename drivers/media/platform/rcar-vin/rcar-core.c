/*
 * Driver for Renesas R-Car VIN
 *
 * Copyright (C) 2016 Renesas Electronics Corp.
 * Copyright (C) 2011-2013 Renesas Solutions Corp.
 * Copyright (C) 2013 Cogent Embedded, Inc., <source@cogentembedded.com>
 * Copyright (C) 2008 Magnus Damm
 *
 * Based on the soc-camera rcar_vin driver
 *
 * This program is free software; you can redistribute  it and/or modify it
 * under  the terms of  the GNU General  Public License as published by the
 * Free Software Foundation;  either version 2 of the  License, or (at your
 * option) any later version.
 */

#include <linux/module.h>
#include <linux/of.h>
#include <linux/of_device.h>
#include <linux/of_graph.h>
#include <linux/platform_device.h>
#include <linux/pm_runtime.h>

#include <media/v4l2-of.h>

#include "rcar-vin.h"

/* -----------------------------------------------------------------------------
 * Subdevice group helpers
 */

static unsigned int rvin_pad_idx(struct v4l2_subdev *sd, int direction)
{
	unsigned int pad_idx;

	for (pad_idx = 0; pad_idx < sd->entity.num_pads; pad_idx++)
		if (sd->entity.pads[pad_idx].flags == direction)
			return pad_idx;

	return 0;
}

int rvin_subdev_get(struct rvin_dev *vin)
{
	strncpy(vin->inputs[0].name, "Digital", RVIN_INPUT_NAME_SIZE);
	vin->inputs[0].sink_idx =
		rvin_pad_idx(vin->digital.subdev, MEDIA_PAD_FL_SINK);
	vin->inputs[0].source_idx =
		rvin_pad_idx(vin->digital.subdev, MEDIA_PAD_FL_SOURCE);

	vin->current_input = 0;

	return 0;
}

int rvin_subdev_put(struct rvin_dev *vin)
{
	vin->current_input = 0;

	return 0;
}

int rvin_subdev_set_input(struct rvin_dev *vin, struct rvin_input_item *item)
{
	if (vin->digital.subdev)
		return 0;

	return -EBUSY;
}

int rvin_subdev_get_code(struct rvin_dev *vin, u32 *code)
{
	*code = vin->digital.code;
	return 0;
}

int rvin_subdev_get_mbus_cfg(struct rvin_dev *vin,
			     struct v4l2_mbus_config *mbus_cfg)
{
	*mbus_cfg = vin->digital.mbus_cfg;
	return 0;
}

struct v4l2_subdev_pad_config*
rvin_subdev_alloc_pad_config(struct rvin_dev *vin)
{
	return v4l2_subdev_alloc_pad_config(vin->digital.subdev);
}

int rvin_subdev_ctrl_add_handler(struct rvin_dev *vin)
{
	int ret;

	v4l2_ctrl_handler_free(&vin->ctrl_handler);

	ret = v4l2_ctrl_handler_init(&vin->ctrl_handler, 16);
	if (ret < 0)
		return ret;

	return v4l2_ctrl_add_handler(&vin->ctrl_handler,
				     vin->digital.subdev->ctrl_handler, NULL);
}

/* -----------------------------------------------------------------------------
 * Async notifier
 */

#define notifier_to_vin(n) container_of(n, struct rvin_dev, notifier)

static bool rvin_mbus_supported(struct rvin_graph_entity *entity)
{
	struct v4l2_subdev *sd = entity->subdev;
	struct v4l2_subdev_mbus_code_enum code = {
		.which = V4L2_SUBDEV_FORMAT_ACTIVE,
	};
	bool found;

	code.index = 0;
	while (!v4l2_subdev_call(sd, pad, enum_mbus_code, NULL, &code)) {
		code.index++;
		switch (code.code) {
		case MEDIA_BUS_FMT_YUYV8_1X16:
		case MEDIA_BUS_FMT_UYVY8_2X8:
		case MEDIA_BUS_FMT_UYVY10_2X10:
		case MEDIA_BUS_FMT_RGB888_1X24:
			entity->code = code.code;
			return true;
		default:
			break;
		}
	}

	/*
	 * Older versions where looking for the wrong media bus format.
	 * It where looking for a YUVY format but then treated it as a
	 * UYVY format. This was not noticed since atlest one subdevice
	 * used for testing (adv7180) reported a YUVY media bus format
	 * but provided UYVY data. There might be other unknown subdevices
	 * which also do this, to not break compatibility try to use them
	 * in legacy mode.
	 */
	found = false;
	code.index = 0;
	while (!v4l2_subdev_call(sd, pad, enum_mbus_code, NULL, &code)) {
		code.index++;
		switch (code.code) {
		case MEDIA_BUS_FMT_YUYV8_2X8:
			vin->source.code = MEDIA_BUS_FMT_UYVY8_2X8;
			found = true;
			break;
		case MEDIA_BUS_FMT_YUYV10_2X10:
			vin->source.code = MEDIA_BUS_FMT_UYVY10_2X10;
			found = true;
			break;
		default:
			break;
		}

		if (found) {
			vin_err(vin,
				"media bus %d not supported, trying legacy mode %d\n",
				code.code, vin->source.code);
			return true;
		}
	}

	return false;
}

static int rvin_digital_notify_complete(struct v4l2_async_notifier *notifier)
{
	struct rvin_dev *vin = notifier_to_vin(notifier);
	int ret;

	/* Verify subdevices mbus format */
	if (!rvin_mbus_supported(&vin->digital)) {
		vin_err(vin, "Unsupported media bus format for %s\n",
			vin->digital.subdev->name);
		return -EINVAL;
	}

	vin_dbg(vin, "Found media bus format for %s: %d\n",
		vin->digital.subdev->name, vin->digital.code);

	ret = v4l2_device_register_subdev_nodes(&vin->v4l2_dev);
	if (ret < 0) {
		vin_err(vin, "Failed to register subdev nodes\n");
		return ret;
	}

	return 0;
}

static void rvin_digital_notify_unbind(struct v4l2_async_notifier *notifier,
				       struct v4l2_subdev *subdev,
				       struct v4l2_async_subdev *asd)
{
	struct rvin_dev *vin = notifier_to_vin(notifier);

	if (vin->digital.subdev == subdev) {
		vin_dbg(vin, "unbind digital subdev %s\n", subdev->name);
		vin->digital.subdev = NULL;
		return;
	}

	vin_err(vin, "no entity for subdev %s to unbind\n", subdev->name);
}

static int rvin_digital_notify_bound(struct v4l2_async_notifier *notifier,
				     struct v4l2_subdev *subdev,
				     struct v4l2_async_subdev *asd)
{
	struct rvin_dev *vin = notifier_to_vin(notifier);

	v4l2_set_subdev_hostdata(subdev, vin);

	if (vin->digital.asd.match.of.node == subdev->dev->of_node) {
		vin_dbg(vin, "bound digital subdev %s\n", subdev->name);
		vin->digital.subdev = subdev;
		return 0;
	}

	vin_err(vin, "no entity for subdev %s to bind\n", subdev->name);
	return -EINVAL;
}

static int rvin_digitial_parse_v4l2(struct rvin_dev *vin,
				    struct device_node *ep,
				    struct v4l2_mbus_config *mbus_cfg)
{
	struct v4l2_of_endpoint v4l2_ep;
	int ret;

	ret = v4l2_of_parse_endpoint(ep, &v4l2_ep);
	if (ret) {
		vin_err(vin, "Could not parse v4l2 endpoint\n");
		return -EINVAL;
	}

	mbus_cfg->type = v4l2_ep.bus_type;

	switch (mbus_cfg->type) {
	case V4L2_MBUS_PARALLEL:
		vin_dbg(vin, "Found PARALLEL media bus\n");
		mbus_cfg->flags = v4l2_ep.bus.parallel.flags;
		break;
	case V4L2_MBUS_BT656:
		vin_dbg(vin, "Found BT656 media bus\n");
		mbus_cfg->flags = 0;
		break;
	default:
		vin_err(vin, "Unknown media bus type\n");
		return -EINVAL;
	}

	return 0;
}

static int rvin_digital_graph_parse(struct rvin_dev *vin)
{
	struct device_node *ep, *np;
	int ret;

	vin->digital.asd.match.of.node = NULL;
	vin->digital.subdev = NULL;

	/*
	 * Port 0 id 0 is local digital input, try to get it.
	 * Not all instances can or will have this, that is OK
	 */
	ep = of_graph_get_endpoint_by_regs(vin->dev->of_node, 0, 0);
	if (!ep)
		return 0;

	np = of_graph_get_remote_port_parent(ep);
	if (!np) {
		vin_err(vin, "No remote parent for digital input\n");
		of_node_put(ep);
		return -EINVAL;
	}
	of_node_put(np);

	ret = rvin_digitial_parse_v4l2(vin, ep, &vin->digital.mbus_cfg);
	of_node_put(ep);
	if (ret)
		return ret;

	vin->digital.asd.match.of.node = np;
	vin->digital.asd.match_type = V4L2_ASYNC_MATCH_OF;

	return 0;
}

static int rvin_digital_graph_init(struct rvin_dev *vin)
{
	struct v4l2_async_subdev **subdevs = NULL;
	int ret;

	ret = rvin_digital_graph_parse(vin);
	if (ret)
		return ret;

	if (!vin->digital.asd.match.of.node) {
		vin_dbg(vin, "No digital subdevice found\n");
		return -ENODEV;
	}

	/* Register the subdevices notifier. */
	subdevs = devm_kzalloc(vin->dev, sizeof(*subdevs), GFP_KERNEL);
	if (subdevs == NULL)
		return -ENOMEM;

	subdevs[0] = &vin->digital.asd;

	vin_dbg(vin, "Found digital subdevice %s\n",
		of_node_full_name(subdevs[0]->match.of.node));

	vin->notifier.num_subdevs = 1;
	vin->notifier.subdevs = subdevs;
	vin->notifier.bound = rvin_digital_notify_bound;
	vin->notifier.unbind = rvin_digital_notify_unbind;
	vin->notifier.complete = rvin_digital_notify_complete;

	ret = v4l2_async_notifier_register(&vin->v4l2_dev, &vin->notifier);
	if (ret < 0) {
		vin_err(vin, "Notifier registration failed\n");
		return ret;
	}

	return 0;
}

/* -----------------------------------------------------------------------------
 * Platform Device Driver
 */

static const struct of_device_id rvin_of_id_table[] = {
	{ .compatible = "renesas,vin-r8a7794", .data = (void *)RCAR_GEN2 },
	{ .compatible = "renesas,vin-r8a7793", .data = (void *)RCAR_GEN2 },
	{ .compatible = "renesas,vin-r8a7791", .data = (void *)RCAR_GEN2 },
	{ .compatible = "renesas,vin-r8a7790", .data = (void *)RCAR_GEN2 },
	{ .compatible = "renesas,vin-r8a7779", .data = (void *)RCAR_H1 },
	{ .compatible = "renesas,vin-r8a7778", .data = (void *)RCAR_M1 },
	{ },
};
MODULE_DEVICE_TABLE(of, rvin_of_id_table);

static int rvin_probe_channel(struct platform_device *pdev,
			      struct rvin_dev *vin)
{
	struct resource *mem;
	int irq, ret;

	mem = platform_get_resource(pdev, IORESOURCE_MEM, 0);
	if (mem == NULL)
		return -EINVAL;

	vin->base = devm_ioremap_resource(vin->dev, mem);
	if (IS_ERR(vin->base))
		return PTR_ERR(vin->base);

	irq = platform_get_irq(pdev, 0);
	if (irq <= 0)
		return irq;

	ret = rvin_dma_probe(vin, irq);
	if (ret)
		return ret;

	return 0;
}

static int rcar_vin_probe(struct platform_device *pdev)
{
	const struct of_device_id *match;
	struct rvin_dev *vin;
	int ret;

	vin = devm_kzalloc(&pdev->dev, sizeof(*vin), GFP_KERNEL);
	if (!vin)
		return -ENOMEM;

	match = of_match_device(of_match_ptr(rvin_of_id_table), &pdev->dev);
	if (!match)
		return -ENODEV;

	vin->dev = &pdev->dev;
	vin->chip = (enum chip_id)match->data;

	/* Initialize the top-level structure */
	ret = v4l2_device_register(vin->dev, &vin->v4l2_dev);
	if (ret)
		return ret;

	ret = rvin_probe_channel(pdev, vin);
	if (ret)
		goto err_register;

	ret = rvin_digital_graph_init(vin);
	if (ret < 0)
		goto err_dma;

	ret = rvin_v4l2_probe(vin);
	if (ret)
		goto err_dma;

	platform_set_drvdata(pdev, vin);

	pm_suspend_ignore_children(&pdev->dev, true);
	pm_runtime_enable(&pdev->dev);

	return 0;

err_dma:
	rvin_dma_remove(vin);
err_register:
	v4l2_device_unregister(&vin->v4l2_dev);

	return ret;
}

static int rcar_vin_remove(struct platform_device *pdev)
{
	struct rvin_dev *vin = platform_get_drvdata(pdev);

	pm_runtime_disable(&pdev->dev);

	rvin_v4l2_remove(vin);

	v4l2_async_notifier_unregister(&vin->notifier);

	rvin_dma_remove(vin);

	v4l2_device_unregister(&vin->v4l2_dev);

	return 0;
}

static struct platform_driver rcar_vin_driver = {
	.driver = {
		.name = "rcar-vin",
		.of_match_table = rvin_of_id_table,
	},
	.probe = rcar_vin_probe,
	.remove = rcar_vin_remove,
};

module_platform_driver(rcar_vin_driver);

MODULE_AUTHOR("Niklas Söderlund <niklas.soderlund@ragnatech.se>");
MODULE_DESCRIPTION("Renesas R-Car VIN camera host driver");
MODULE_LICENSE("GPL v2");
