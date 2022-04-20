// SPDX-License-Identifier: (GPL-2.0 OR BSD-3-Clause)
/*
 * Wave5 series multi-standard codec IP - platform driver
 *
 * Copyright (C) 2021 CHIPS&MEDIA INC
 */
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/platform_device.h>
#include <linux/clk.h>
#include <linux/io.h>
#include <linux/firmware.h>
#include <linux/interrupt.h>
#include <linux/pci.h>
#include <linux/delay.h>
#include "wave5-vpu-hpi.h"
#include "wave5-regdefine.h"
#include "wave5-vpuconfig.h"
#include "wave5-hpi.h"

#define VPU_PLATFORM_DEVICE_NAME "vdec"
#define VPU_CLK_NAME "vcodec"

#define WAVE5_IS_ENC BIT(0)
#define WAVE5_IS_DEC BIT(1)

#define PCI_VENDOR_ID_WAVE5 0xCEDA
#define PCI_DEVICE_ID_WAVE5 0x4311
#define REGISTER_FILE_SIZE_WAVE5 0x2000

struct wave5_match_data {
	int flags;
	const char *fw_name;
};

#if 0
static int interrupt_poller_func(void *arg)
{
	struct vpu_device *dev = (struct vpu_device *)arg;
	unsigned int irq_status;

	while (true) {
		if (kthread_should_stop())
			break;
		if (wave5_vdi_readl(dev, W5_VPU_VPU_INT_STS)) {
			irq_status = wave5_vdi_readl(dev, W5_VPU_VINT_REASON);
			wave5_vdi_write_register(dev, W5_VPU_VINT_REASON_CLR, irq_status);
			wave5_vdi_write_register(dev, W5_VPU_VINT_CLEAR, 0x1);

			kfifo_in(&dev->irq_status, &irq_status, sizeof(int));
		}
		msleep_interruptible(10);
	}

	return 0;
}
#endif // #if 0

static int interrupt_poller_func(void *arg)
{
	struct vpu_device *dev = (struct vpu_device *)arg;
	unsigned int irq_status, val;
	struct vpu_instance *inst;

	while (true) {
		if (kthread_should_stop())
			break;
		mutex_lock(&dev->hw_lock);
		if (wave5_vdi_readl(dev, W5_VPU_VPU_INT_STS)) {
			irq_status = wave5_vdi_readl(dev, W5_VPU_VINT_REASON);
			wave5_vdi_write_register(dev, W5_VPU_VINT_REASON_CLR, irq_status);
			wave5_vdi_write_register(dev, W5_VPU_VINT_CLEAR, 0x1);

			kfifo_in(&dev->irq_status, &irq_status, sizeof(int));

			if (irq_status) {
				dev_info(dev->dev, "irq_status: 0x%x\n", irq_status);
				inst = v4l2_m2m_get_curr_priv(dev->v4l2_m2m_dev);
				if (inst) {
					dev_info(dev->dev, "inst not null\n");
					inst->ops->finish_process(inst);
				} else {
					val = wave5_vdi_readl(dev, W5_VPU_VINT_REASON_USR);
					val &= ~irq_status;
					wave5_vdi_write_register(dev, W5_VPU_VINT_REASON_USR, val);
					complete(&dev->irq_done);
				
				}
			}
		} 
		mutex_unlock(&dev->hw_lock);
		msleep_interruptible(10);
	}

	return 0;
}

int wave5_vpu_wait_interrupt(struct vpu_instance *inst, unsigned int timeout)
{
	int ret;

	dev_dbg(inst->dev->dev, "wait start\n");
	ret = wait_for_completion_timeout(&inst->dev->irq_done,
					  msecs_to_jiffies(timeout));
	dev_dbg(inst->dev->dev, "wait end\n");
	if (!ret)
		return -ETIMEDOUT;

	reinit_completion(&inst->dev->irq_done);

	return 0;
}

/* static irqreturn_t wave5_vpu_irq(int irq, void *dev_id) */
/* { */
/* 	struct vpu_device *dev = dev_id; */
/* 	unsigned int irq_status; */

/* 	if (wave5_vdi_readl(dev, W5_VPU_VPU_INT_STS)) { */
/* 		irq_status = wave5_vdi_readl(dev, W5_VPU_VINT_REASON); */
/* 		wave5_vdi_write_register(dev, W5_VPU_VINT_REASON_CLR, irq_status); */
/* 		wave5_vdi_write_register(dev, W5_VPU_VINT_CLEAR, 0x1); */

/* 		kfifo_in(&dev->irq_status, &irq_status, sizeof(int)); */

/* 		return IRQ_WAKE_THREAD; */
/* 	} */

/* 	return IRQ_HANDLED; */
/* } */

/* static irqreturn_t wave5_vpu_irq_thread(int irq, void *dev_id) */
/* { */
/* 	struct vpu_device *dev = dev_id; */
/* 	struct vpu_instance *inst; */
/* 	unsigned int irq_status, val; */
/* 	int ret; */

/* 	while (kfifo_len(&dev->irq_status)) { */
/* 		inst = v4l2_m2m_get_curr_priv(dev->v4l2_m2m_dev); */
/* 		if (inst) { */
/* 			inst->ops->finish_process(inst); */
/* 		} else { */
/* 			ret = kfifo_out(&dev->irq_status, &irq_status, sizeof(int)); */
/* 			if (!ret) */
/* 				break; */
/* 			dev_dbg(dev->dev, "irq_status: 0x%x\n", irq_status); */
/* 			val = wave5_vdi_readl(dev, W5_VPU_VINT_REASON_USR); */
/* 			val &= ~irq_status; */
/* 			wave5_vdi_write_register(dev, W5_VPU_VINT_REASON_USR, val); */
/* 			complete(&dev->irq_done); */
/* 		} */
/* 	} */

/* 	return IRQ_HANDLED; */
/* } */


static void wave5_vpu_device_run(void *priv)
{
	struct vpu_instance *inst = priv;

	dev_dbg(inst->dev->dev, "inst type=%d state=%d\n",
		inst->type, inst->state);

	inst->ops->start_process(inst);
}

static int wave5_vpu_job_ready(void *priv)
{
	struct vpu_instance *inst = priv;

	dev_dbg(inst->dev->dev, "inst type=%d state=%d\n",
		inst->type, inst->state);

	if (inst->state == VPU_INST_STATE_STOP)
		return 0;

	return 1;
}

static void wave5_vpu_job_abort(void *priv)
{
	struct vpu_instance *inst = priv;

	dev_dbg(inst->dev->dev, "inst type=%d state=%d\n",
		inst->type, inst->state);

	inst->ops->stop_process(inst);
}

static const struct v4l2_m2m_ops wave5_vpu_m2m_ops = {
	.device_run = wave5_vpu_device_run,
	.job_ready = wave5_vpu_job_ready,
	.job_abort = wave5_vpu_job_abort,
};

static int wave5_vpu_load_firmware(struct device *dev, const char *fw_name)
{
	const struct firmware *fw;
	int ret;
	u32 version;
	u32 revision;
	u32 product_id;

	ret = request_firmware(&fw, fw_name, dev);
	if (ret) {
		dev_err(dev, "request_firmware fail\n");
		return ret;
	}

	ret = wave5_vpu_init_with_bitcode(dev, (u8 *)fw->data, fw->size);
	if (ret) {
		dev_err(dev, "vpu_init_with_bitcode fail\n");
		goto release_fw;
	}
	release_firmware(fw);

	/* ret = wave5_vpu_get_version_info(dev, &version, &revision, &product_id); */
	/* if (ret) { */
	/* 	dev_err(dev, "vpu_get_version_info fail\n"); */
	/* 	goto release_fw; */
	/* } */

	/* dev_err(dev, "enum product_id : %08x\n", product_id); */
	/* dev_err(dev, "fw_version : %08x(r%d)\n", version, revision); */

	return 0;

release_fw:
	release_firmware(fw);
	return ret;
}

static int wave5_vpu_probe(struct pci_dev *pdev, const struct pci_device_id *id)
{
	int ret;
	int i;
	struct vpu_device *dev;
	/* struct resource *res; */
	unsigned long register_file_base;

	ret = pcim_enable_device(pdev);
	if (ret) {
		dev_err(&pdev->dev, "%s(): failed to enable pci device.\n", __func__);
	}


	/* physical addresses limited to 32 bits */
	dma_set_mask(&pdev->dev, DMA_BIT_MASK(32));
	dma_set_coherent_mask(&pdev->dev, DMA_BIT_MASK(32));

	dev = devm_kzalloc(&pdev->dev, sizeof(*dev), GFP_KERNEL);
	if (!dev)
		return -ENOMEM;

	for (i = 0; i < 6; ++i) {
		if ((pci_resource_flags(pdev, i) & IORESOURCE_MEM)) {
			/* physical address */
			dev->bar = i;
			break;
		}
	}

	ret = pci_request_region(pdev, dev->bar, "wave5");
	if (ret) {
		dev_err(&pdev->dev, "%s(): failed to request region.\n", __func__);
	}

	register_file_base = pci_resource_start(pdev, dev->bar);
	if (!register_file_base) {
		dev_err(&pdev->dev, "HPI controller has no memory regions defined.\n");
		return -EINVAL;
	} else {
		dev_info(&pdev->dev, "Physical address: 0x%08lx\n", register_file_base);
	}

	dev->vdb_register = devm_ioremap(&pdev->dev, register_file_base, REGISTER_FILE_SIZE_WAVE5);
	if (IS_ERR(dev->vdb_register))
		return PTR_ERR(dev->vdb_register);

	ida_init(&dev->inst_ida);

	mutex_init(&dev->dev_lock);
	mutex_init(&dev->hw_lock);
	mutex_init(&dev->vdi_lock);
	init_completion(&dev->irq_done);
	dev_set_drvdata(&pdev->dev, dev);
	dev->dev = &pdev->dev;

	dev->product_code = wave5_vdi_readl(dev, VPU_PRODUCT_CODE_REGISTER);
	dev_info(&pdev->dev, "product code is : 0x%04x\n", dev->product_code);
	ret = wave5_vdi_init(&pdev->dev);
	if (ret < 0) {
		dev_err(&pdev->dev, "failed to init vdi: %d\n", ret);
		goto err_clk_dis;
	}

	/* fpga init */
	/* vdi_init_fpga */

	ret = wave5_vdi_readl(dev, W5_VCPU_CUR_PC);
	dev_err(&pdev->dev, "v4l2 readl: %d\n", ret);

	dev->product = wave_vpu_get_product_id(dev); 
	dev_err(&pdev->dev, "code: %x\n", dev->product);

	ret = v4l2_device_register(&pdev->dev, &dev->v4l2_dev);
	if (ret) {
		dev_err(&pdev->dev, "v4l2_device_register fail: %d\n", ret);
		goto err_vdi_release;
	}

	dev->v4l2_m2m_dev = v4l2_m2m_init(&wave5_vpu_m2m_ops);
	if (IS_ERR(dev->v4l2_m2m_dev)) {
		ret = PTR_ERR(dev->v4l2_m2m_dev);
		dev_err(&pdev->dev, "v4l2_m2m_init fail: %d\n", ret);
		goto err_v4l2_unregister;
	}

	/* if (match_data->flags & WAVE5_IS_DEC) { */
		ret = wave5_vpu_dec_register_device(dev);
		if (ret) {
			dev_err(&pdev->dev, "wave5_vpu_dec_register_device fail: %d\n", ret);
			goto err_m2m_release;
		}
	/* } */
	/* if (match_data->flags & WAVE5_IS_ENC) { */
		ret = wave5_vpu_enc_register_device(dev);
		if (ret) {
			dev_err(&pdev->dev, "wave5_vpu_enc_register_device fail: %d\n", ret);
			goto err_dec_unreg;
		}
	/* } */

	/* res = platform_get_resource(pdev, IORESOURCE_IRQ, 0); */
	/* if (!res) { */
	/* 	dev_err(&pdev->dev, "failed to get irq resource\n"); */
	/* 	ret = -ENXIO; */
	/* 	goto err_enc_unreg; */
	/* } */
	/* dev->irq = res->start; */

	if (kfifo_alloc(&dev->irq_status, 16 * sizeof(int), GFP_KERNEL)) {
		dev_err(&pdev->dev, "failed to allocate fifo\n");
		goto err_enc_unreg;
	}

	/* ret = wave5_vpu_load_firmware(&pdev->dev, match_data->fw_name); */
	ret = wave5_vpu_load_firmware(&pdev->dev, "chagall.bin");
	if (ret) {
		dev_err(&pdev->dev, "failed to wave5_vpu_load_firmware: %d\n", ret);
		goto err_kfifo_free;
	}
	dev_info(&pdev->dev, "wave5 loading OK\n");

	/* ret = devm_request_threaded_irq(&pdev->dev, dev->irq, wave5_vpu_irq, */
	/* 				wave5_vpu_irq_thread, 0, "vpu_irq", dev); */
	/* if (ret) { */
	/* 	dev_err(&pdev->dev, "fail to register interrupt handler: %d\n", ret); */
	/* 	goto err_kfifo_free; */
	/* } */

	dev->irq_poller_thread = kthread_run(interrupt_poller_func, dev, "wave5_irq_thread");
	if (!dev->irq_poller_thread) {
		dev_err(&pdev->dev, "irq poller thread create fail\n");
		goto err_kfifo_free;
	}

	/* dev_dbg(&pdev->dev, "Added wave driver with caps %s %s and product code 0x%x\n", */
	/* 	match_data->flags & WAVE5_IS_ENC ? "'ENCODE'" : "", */
	/* 	match_data->flags & WAVE5_IS_DEC ? "'DECODE'" : "", */
	/* 	dev->product_code); */
	return 0;

err_irq_poller_free:
	if (dev->irq_poller_thread) {
		kthread_stop(dev->irq_poller_thread);
		dev->irq_poller_thread = NULL;
	}
err_kfifo_free:
	kfifo_free(&dev->irq_status);
err_enc_unreg:
	/* if (match_data->flags & WAVE5_IS_ENC) */
		wave5_vpu_enc_unregister_device(dev);
err_dec_unreg:
	/* if (match_data->flags & WAVE5_IS_DEC) */
		wave5_vpu_dec_unregister_device(dev);
err_m2m_release:
	v4l2_m2m_release(dev->v4l2_m2m_dev);
err_v4l2_unregister:
	v4l2_device_unregister(&dev->v4l2_dev);
err_vdi_release:
	wave5_vdi_release(&pdev->dev);
err_clk_dis:
	/* clk_bulk_disable_unprepare(dev->num_clks, dev->clks); */

	return ret;
}

static void wave5_vpu_remove(struct pci_dev *pdev)
{
	struct vpu_device *dev = dev_get_drvdata(&pdev->dev);

	if (dev->irq_poller_thread) {
		kthread_stop(dev->irq_poller_thread);
		dev->irq_poller_thread = NULL;
	}

	pci_release_region(pdev, dev->bar);

	/* clk_bulk_disable_unprepare(dev->num_clks, dev->clks); */
	wave5_vpu_enc_unregister_device(dev);
	wave5_vpu_dec_unregister_device(dev);
	v4l2_m2m_release(dev->v4l2_m2m_dev);
	v4l2_device_unregister(&dev->v4l2_dev);
	kfifo_free(&dev->irq_status);
	wave5_vdi_release(&pdev->dev);
}

static const struct wave5_match_data wave511_data = {
	.flags = WAVE5_IS_DEC,
	.fw_name = "wave511_dec_fw.bin",
};

static const struct wave5_match_data wave521_data = {
	.flags = WAVE5_IS_ENC,
	.fw_name = "wave521_enc_fw.bin",
};

static const struct wave5_match_data wave521c_data = {
	.flags = WAVE5_IS_ENC | WAVE5_IS_DEC,
	.fw_name = "wave521c_codec_fw.bin",
};

static const struct wave5_match_data default_match_data = {
	.flags = WAVE5_IS_ENC | WAVE5_IS_DEC,
	.fw_name = "chagall.bin",
};

static const struct pci_device_id wave5_pci_id = {
	.vendor = PCI_VENDOR_ID_WAVE5,
	.device =  PCI_DEVICE_ID_WAVE5,
};

static struct pci_device_id wave5_vpu_pci_tbl[] = {
	{ PCI_VENDOR_ID_WAVE5, PCI_DEVICE_ID_WAVE5,
	  PCI_ANY_ID, PCI_ANY_ID, 0, 0, 0 },
	{ 0, }
};
MODULE_DEVICE_TABLE(pci, wave5_vpu_pci_tbl);

static struct pci_driver wave5_vpu_driver = {
	.name = KBUILD_MODNAME,
	.id_table = wave5_vpu_pci_tbl,
	.probe = wave5_vpu_probe,
	.remove = wave5_vpu_remove,
};

static int __init wave5_vpu_init(void)
{
	return pci_register_driver(&wave5_vpu_driver);
}

static void __exit wave5_vpu_cleanup(void)
{
	pci_unregister_driver(&wave5_vpu_driver);
}

module_init(wave5_vpu_init);
module_exit(wave5_vpu_cleanup);

//module_platform_driver(wave5_vpu_driver);
MODULE_DESCRIPTION("chips&media VPU V4L2 driver");
MODULE_LICENSE("Dual BSD/GPL");
