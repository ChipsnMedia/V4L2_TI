// SPDX-License-Identifier: (GPL-2.0 OR BSD-3-Clause)
/*
 * Wave5 series multi-standard codec IP - low level access functions
 *
 * Copyright (C) 2021 CHIPS&MEDIA INC
 */

#include <linux/bug.h>
#include <linux/delay.h>
#include <linux/iopoll.h>
#include "wave5-vdi-hpi.h"
#include "wave5-vpu-hpi.h"
#include "wave5-regdefine.h"

#define VDI_SRAM_BASE_ADDR 0x00

#define VDI_SYSTEM_ENDIAN VDI_BIG_ENDIAN
#define VDI_128BIT_BUS_SYSTEM_ENDIAN VDI_128BIT_BIG_ENDIAN

#define VPU_BIT_REG_BASE            0x80000000
#define VPU_INIT_VIDEO_MEMORY_SIZE_IN_BYTE (2*1024*1024*1024UL)
#define VPU_DRAM_PHYSICAL_BASE  0x80000000
#define HPI_MAX_BUS_LENGTH      16
#if defined(CODA960) || defined(CODA980)
#define HPI_BUS_LENGTH          8
#else
#define HPI_BUS_LENGTH          16
#endif
/*------------------------------------------------------------------------
ChipsnMedia HPI register definitions
------------------------------------------------------------------------*/
#define HPI_CHECK_STATUS			1
#define HPI_WAIT_TIME				0x100000
#define HPI_WAIT_TIMEOUT            1000
#define HPI_BASE					0x20030000
#define HPI_ADDR_CMD				(0x00<<2)
#define HPI_ADDR_STATUS				(0x01<<2)
#define HPI_ADDR_ADDR_H				(0x02<<2)
#define HPI_ADDR_ADDR_L				(0x03<<2)
#define HPI_ADDR_ADDR_M				(0x06<<2)
#define HPI_ADDR_DATA				(0x80<<2)

#define HPI_MAX_PKSIZE 256

#define	DEVICE0_ADDR_COMMAND		0x75
#define DEVICE0_ADDR_PARAM0			0x76
#define	DEVICE0_ADDR_PARAM1			0x77
#define	DEVICE1_ADDR_COMMAND		0x78
#define DEVICE1_ADDR_PARAM0			0x79
#define	DEVICE1_ADDR_PARAM1			0x7a
#define DEVICE_ADDR_SW_RESET		0x7b

#define	DEVICE2_ADDR_COMMAND		0x7c
#define DEVICE2_ADDR_PARAM0			0x7d
#define	DEVICE2_ADDR_PARAM1			0x7e
#define	DEVICE3_ADDR_COMMAND		0x7f
#define DEVICE3_ADDR_PARAM0			0x60
#define	DEVICE3_ADDR_PARAM1			0x61
#define	DEVICE4_ADDR_COMMAND		0x62
#define DEVICE4_ADDR_PARAM0			0x63
#define	DEVICE4_ADDR_PARAM1			0x64
#define	DEVICE5_ADDR_COMMAND		0x65
#define DEVICE5_ADDR_PARAM0			0x66
#define	DEVICE5_ADDR_PARAM1			0x67
#define	DEVICE6_ADDR_COMMAND		0x68    /*!<< used for change clocks */
#define DEVICE6_ADDR_PARAM0			0x69
#define	DEVICE6_ADDR_PARAM1			0x6a
#define	DEVICE7_ADDR_COMMAND		0x6b
#define DEVICE7_ADDR_PARAM0			0x6c
#define	DEVICE7_ADDR_PARAM1			0x6d
#define CLOCK_MUX_REG			    0x6e        /*!<< BEFORE CHANGING CLOCKS SET VALUE TO 0x1F */
#define TOTAL_CLOCK_NUMBER          8

static struct _clock_gen_reg_struct {
    u32 command;
    u32 param0;
    u32 param1;
} s_clock_gen_reg[TOTAL_CLOCK_NUMBER] = {
    { DEVICE0_ADDR_COMMAND, DEVICE0_ADDR_PARAM0, DEVICE0_ADDR_PARAM1 },
    { DEVICE1_ADDR_COMMAND, DEVICE1_ADDR_PARAM0, DEVICE1_ADDR_PARAM1 },
    { DEVICE2_ADDR_COMMAND, DEVICE2_ADDR_PARAM0, DEVICE2_ADDR_PARAM1 },
    { DEVICE3_ADDR_COMMAND, DEVICE3_ADDR_PARAM0, DEVICE3_ADDR_PARAM1 },
    { DEVICE4_ADDR_COMMAND, DEVICE4_ADDR_PARAM0, DEVICE4_ADDR_PARAM1 },
    { DEVICE5_ADDR_COMMAND, DEVICE5_ADDR_PARAM0, DEVICE5_ADDR_PARAM1 },
    { DEVICE6_ADDR_COMMAND, DEVICE6_ADDR_PARAM0, DEVICE6_ADDR_PARAM1 },
    { DEVICE7_ADDR_COMMAND, DEVICE7_ADDR_PARAM0, DEVICE7_ADDR_PARAM1 },
};

#define CLOCK_GEN_COMMAND(_device_no)   s_clock_gen_reg[_device_no].command
#define CLOCK_GEN_PARAM0(_device_no)    s_clock_gen_reg[_device_no].param0
#define CLOCK_GEN_PARAM1(_device_no)    s_clock_gen_reg[_device_no].param1

#define ACLK_MAX                     50
#define ACLK_MIN                     5
#define CCLK_MAX                     50
#define CCLK_MIN                     5

#define CLOCK_ID_ACLK                0
#define CLOCK_ID_CCLK                1
#define CLOCK_ID_VCLK                2
#define CLOCK_ID_BCLK                3
#define CLOCK_ID_MCLK                4
#define CLOCK_MASK_ALL               0x1f

#define HPI_SET_TIMING_MAX           1000

static int wave5_vdi_allocate_common_memory(struct device *dev)
{
	struct vpu_device *vpu_dev = dev_get_drvdata(dev);

	vpu_dev->common_mem.size = WAVE5_SIZE_COMMON;
	vpu_dev->common_mem.daddr = vpu_dev->fpga_memory.daddr;

	return 0;
}

static void pci_write_reg(struct vpu_device *dev, unsigned int addr, unsigned int data);

static int hpi_hw_reset(struct vpu_device *vpu_dev)
{
	pci_write_reg(vpu_dev, DEVICE_ADDR_SW_RESET << 2, 1);
	msleep_interruptible(1000);

	return 0;
}

static int wave5_vdi_set_clock_gate(int enable)
{
	return 0;
}

static int wave5_vdi_fpga_init(struct vpu_device *dev);

int wave5_vdi_init(struct device *dev)
{
	struct vpu_device *vpu_dev = dev_get_drvdata(dev);
	int i;
	int ret;

	vpu_dev->fpga_memory.daddr = VPU_DRAM_PHYSICAL_BASE;
	vpu_dev->fpga_memory.vaddr = vpu_dev->vdb_register;
	vpu_dev->fpga_memory.size = VPU_INIT_VIDEO_MEMORY_SIZE_IN_BYTE;

	//memset(vpu_dev->buffer_pool, 0x00, sizeof(vpu_dev->buffer_pool[0]) * MAX_VPU_BUFFER_POOL);

	ret = wave5_vdi_allocate_common_memory(dev);
	if (ret < 0) {
		dev_err(dev, "[VDI] fail to get vpu common buffer from driver\n");
		return ret;
	}

	if (vmem_init(&vpu_dev->vmem, vpu_dev->fpga_memory.daddr
		      + vpu_dev->common_mem.size,
		      vpu_dev->fpga_memory.size - vpu_dev->common_mem.size)) {
		dev_err(dev, "[VDI] fail to initialize fpga memory allocator\n");
		return -1;
	}

	/* if (PRODUCT_CODE_W_SERIES(vpu_dev->product_code)) { */
		// if BIT processor is not running.
		if (wave5_vdi_readl(vpu_dev, W5_VCPU_CUR_PC) == 0) {
			for (i = 0; i < 64; i++)
				wave5_vdi_write_register(vpu_dev, (i * 4) + 0x100, 0x0);
		}
	/* } else { */
	/* 	/\* WARN_ONCE(1, "unsupported product code 0x%x\n", vpu_dev->product_code); *\/ */
	/* 	dev_err(dev, "unsupported product code 0x%x\n", vpu_dev->product_code); */
	/* } */

	/* hpi init */

	hpi_hw_reset(vpu_dev);
	wave5_vdi_fpga_init(vpu_dev);

	dev_dbg(dev, "[VDI] success to init driver\n");

	return 0;
}

static int hpi_ics307m_set_clock_freq(struct vpu_device *dev, int domain, int freq_mhz)
{
	int vdw, rdw, od, sdw;
	int min_clk;
	int max_clk;
	int ret;

	if (!domain) {
		min_clk = ACLK_MIN;
		max_clk = ACLK_MAX;
	} else {
		min_clk = CCLK_MIN;
		max_clk = CCLK_MAX;
	}

	if (freq_mhz < min_clk || freq_mhz > max_clk)
		return 0;

	if (freq_mhz >= min_clk && freq_mhz < 14) {
		vdw = (freq_mhz - 4) * 2;
		rdw = 2;
		od = 10;
	} else  {
		vdw = freq_mhz - 8;
		rdw = 3;
		od = 4;
	}

	switch (od) {
	case 0:
	case 1:
		sdw = 0;
		break;
	case 2:
		sdw = 1;
		break;
	case 3:
		sdw = 6;
		break;
	case 4:
		sdw = 3;
		break;
	case 5:
		sdw = 4;
		break;
	case 6:
		sdw = 7;
		break;
	case 7:
		sdw = 4;
		break;
	case 8:
		sdw = 2;
		break;
	default:
		sdw = 0;
	}

	ret = mutex_lock_interruptible(&dev->vdi_lock);
	if (ret) {
		dev_err(dev->dev, "%s(): unable to acquire vdi_lock\n", __func__);
		return false;
	}

        pci_write_reg(dev, CLOCK_GEN_PARAM0(domain) << 2, 0x20 | sdw);
        pci_write_reg(dev, CLOCK_GEN_PARAM1(domain) << 2, ((vdw << 7) & 0xff80) | rdw);
	pci_write_reg(dev, CLOCK_GEN_COMMAND(domain) << 2, 1);
	pci_write_reg(dev, CLOCK_GEN_COMMAND(domain) << 2, 0);

	mutex_unlock(&dev->vdi_lock);

	return 0;
}

static int wave5_vdi_set_clock_freq(struct vpu_device *dev, int domain, int freq_mhz)
{
	if (domain == CLOCK_ID_ACLK)
		dev->clk.aclk = freq_mhz;
	else if (domain == CLOCK_ID_CCLK)
		dev->clk.cclk = freq_mhz;
	else if (domain == CLOCK_ID_BCLK)
		dev->clk.bclk = freq_mhz;
	else if (domain == CLOCK_ID_MCLK)
		dev->clk.mclk = freq_mhz;
	else if (domain == CLOCK_ID_VCLK)
		dev->clk.vclk = freq_mhz;

	return hpi_ics307m_set_clock_freq(dev, domain, freq_mhz);
}

static bool hpi_write_reg_test(struct vpu_device *vpu_dev, unsigned int addr, unsigned int data);
static bool hpi_read_reg_test(struct vpu_device *vpu_dev, unsigned int addr, unsigned int *data);

int wave5_vdi_set_timing_opt(struct vpu_device *dev)
{
	int i;
	int j;
	unsigned int addr;
	unsigned int r_data;
	unsigned int w_data;
	bool test_fail;
	
	unsigned int start_addr;
	unsigned int end_addr;

	r_data = wave5_vdi_readl(dev, 0x1044);

	start_addr = W5_BS_RD_PTR;
	end_addr = W5_BS_WR_PTR;

	i = 2;

	/* lock */
	pci_write_reg(dev, 0x70 << 2, 25);
	pci_write_reg(dev, 0x71 << 2, 25);
	pci_write_reg(dev, 0x72 << 2, 6);

	/* unlock */

	addr = start_addr;
	r_data = 0x12345678;
	test_fail = 0;

	for (j = 0; j < 10000; j++) {
		if (!hpi_write_reg_test(dev, j, r_data)) {
			test_fail = true;
			break;
		}
		if (!hpi_read_reg_test(dev, j, &w_data)) {
			test_fail = true;
			break;
		}
		if (r_data != w_data) {
			test_fail = true;
			break;
		} else {
			if (!hpi_write_reg_test(dev, addr, 0)) {
				test_fail = true;
				break;
			}
		}
	}
	addr += 4;
	if (addr == end_addr)
		addr = start_addr;
	r_data++;

	if (test_fail) {
		while (test_fail && i < HPI_SET_TIMING_MAX) {
			i++;
			addr = start_addr;
			r_data = 0x12345678;
			test_fail = false;

			pci_write_reg(dev, 0x70 << 2, i);
			pci_write_reg(dev, 0x71 << 2, i);

			if (i < 15)
				pci_write_reg(dev, 0x72 << 2, 0);
			else
				pci_write_reg(dev, 0x72 << 2, i * 20 / 100);

			for (j = 0; j < 10000; j++) {
				if (!hpi_write_reg_test(dev, addr, r_data)) {
					test_fail = true;
					break;
				}
				if (!hpi_read_reg_test(dev, addr, &w_data)) {
					test_fail = true;
					break;
				}
				if (r_data != w_data) {
					test_fail = true;
					break;
				} else {
					if (!hpi_write_reg_test(dev, addr, 0)) {
						test_fail = true;
						break;
					}
				}
				addr += 4;
				if (addr == end_addr)
					addr = start_addr;
				r_data++;
			}
		}
		/* hw lock */

		pci_write_reg(dev, 0x70 << 2, i);
		pci_write_reg(dev, 0x71 << 2, i + i * 40 / 100);
		pci_write_reg(dev, 0x72 << 2, i * 20 / 100);

		/* hw unlock */

		dev_info(dev->dev, "timing value changed\n");

		hpi_hw_reset(dev);
	}

	/* hw lock */
	pci_write_reg(dev, 0x70 << 2, 25);
	pci_write_reg(dev, 0x71 << 2, 25);
	pci_write_reg(dev, 0x72 << 2, 6);
	/* hw unlock */

	return 0;
}

static int wave5_vdi_fpga_init(struct vpu_device *dev)
{
	u32 aclk_freq = 20;
	u32 bclk_freq = 20;
	u32 cclk_freq = 20;
	u32 mclk_freq = 20;
	u32 vclk_freq = 20;

	hpi_hw_reset(dev);

	/* Get ready to change clock */
	pci_write_reg(dev, CLOCK_MUX_REG << 2, CLOCK_MASK_ALL);

	wave5_vdi_set_clock_freq(dev, 5, 20);
	wave5_vdi_set_clock_freq(dev, 0, aclk_freq);
	dev_info(dev->dev, "set default ACLK to %d\n", aclk_freq);
	wave5_vdi_set_clock_freq(dev, 1, cclk_freq);
	dev_info(dev->dev, "set default CCLK to %d\n", cclk_freq);
	wave5_vdi_set_clock_freq(dev, 2, vclk_freq);
	dev_info(dev->dev, "set default VCLK to %d\n", vclk_freq);
	wave5_vdi_set_clock_freq(dev, 3, bclk_freq);
	dev_info(dev->dev, "set default BCLK to %d\n", bclk_freq);
	wave5_vdi_set_clock_freq(dev, 4, mclk_freq);
	dev_info(dev->dev, "set default MCLK to %d\n", mclk_freq);

	/* Finish changing clock */
	pci_write_reg(dev, CLOCK_MUX_REG << 2, 0);

	wave5_vdi_set_timing_opt(dev);

	wave5_vdi_write_register(dev, 0x01000000, 0);
	wave5_vdi_write_register(dev, 0x01000004, 0);

	hpi_hw_reset(dev);

	msleep_interruptible(1000);

	return 0;
}

int wave5_vdi_release(struct device *dev)
{
	struct vpu_device *vpu_dev = dev_get_drvdata(dev);

	vpu_dev->vdb_register = NULL;
	//wave5_vdi_free_dma_memory(vpu_dev, &vpu_dev->common_mem);

	return 0;
}

static void pci_write_reg(struct vpu_device *dev, unsigned int addr, unsigned int data)
{
	unsigned long *reg_addr = (unsigned long *)(dev->vdb_register + addr);
	*(volatile unsigned int *)reg_addr = data;
}

static unsigned int pci_read_reg(struct vpu_device *dev, unsigned int addr)
{
	unsigned long *reg_addr = (unsigned long *)(dev->vdb_register + addr);
	return *(volatile unsigned int *)reg_addr;
}

static int pci_read_memory(struct vpu_device *dev, unsigned int addr, unsigned char *buf, int size)
{
	int status;
	int i, j, k;
	int data = 0, cnt;
	int ret;

	dev_dbg(dev->dev, "%s(): reading from %lu\n", __func__, addr);

	i = j = k = 0;
	for (i = 0; i < size / HPI_MAX_PKSIZE; i++) {
		ret = mutex_lock_interruptible(&dev->vdi_lock);
		if (ret) {
			dev_err(dev->dev, "%s(): unable to acquire vdi_lock\n", __func__);
			return -1;
		}

		pci_write_reg(dev, HPI_ADDR_ADDR_H, (addr >> 16));
		pci_write_reg(dev, HPI_ADDR_ADDR_L, (addr & 0xffff));

		pci_write_reg(dev, HPI_ADDR_CMD, ((HPI_MAX_PKSIZE) << 4) + 1);

		cnt = 0;
		do {
			status = pci_read_reg(dev, HPI_ADDR_STATUS);
			status = status & 1;
			cnt++;
		} while (!status && cnt < HPI_WAIT_TIMEOUT);

		if (cnt == HPI_WAIT_TIMEOUT) {
			mutex_unlock(&dev->vdi_lock);
			return -200;
		}

		for (j = 0; j < HPI_MAX_PKSIZE / 2; j++) {
			data = pci_read_reg(dev, HPI_ADDR_DATA + j * 4);
			buf[k] = (data >> 8) & 0xff;
			buf[k+1] = data & 0xff;
			k += 2;
		}
		mutex_unlock(&dev->vdi_lock);

		addr += HPI_MAX_PKSIZE;
	}
	size = size % HPI_MAX_PKSIZE;

	if (((addr + size) & 0xffffff00) != (addr & 0xffffff00))
		size = size;

	if (size) {

		ret = mutex_lock_interruptible(&dev->vdi_lock);
		if (ret) {
			dev_err(dev->dev, "unable to acquire vdi_lock\n");
		return -1;
	}
		pci_write_reg(dev, HPI_ADDR_ADDR_H, (addr >> 16));
		pci_write_reg(dev, HPI_ADDR_ADDR_L, (addr & 0xffff));

		pci_write_reg(dev, HPI_ADDR_CMD, (size << 4) + 1);

		do {
			status = pci_read_reg(dev, HPI_ADDR_STATUS);
			status &= 1;
		} while (!status);

		for (j = 0; j < size / 2; j++) {
			data = pci_read_reg(dev, HPI_ADDR_DATA + j * 4);
			buf[k] = (data >> 8) & 0xff;
			buf[k+1] = data & 0xff;
			k = k + 2;
		}
		mutex_unlock(&dev->vdi_lock);
	}

	return 1;
}

static int pci_write_memory(struct vpu_device *dev, unsigned int addr, unsigned char *buf, int size)
{
	int status;
	int i, j, k;
	int data = 0;
	int cnt;
	int ret;

	i = j = k = 0;

	dev_dbg(dev->dev, "%s(): writing to %lu\n", __func__, addr);

	for (i = 0; i < size/HPI_MAX_PKSIZE; i++)
	{
		ret = mutex_lock_interruptible(&dev->vdi_lock);
		if (ret) {
			dev_err(dev->dev, "unable to acquire vdi_lock\n");
			return -1;
		}

		pci_write_reg(dev, HPI_ADDR_ADDR_H, (addr >> 16));
		pci_write_reg(dev, HPI_ADDR_ADDR_L, (addr & 0xffff));

		for (j = 0; j < HPI_MAX_PKSIZE/2; j++)
		{
			data = (buf[k] << 8) | buf[k+1];
			pci_write_reg(dev, HPI_ADDR_DATA + j * 4, data);
			k = k + 2;
		}
#ifdef CNM_FPGA_VU19P_INTERFACE
		pci_write_reg(dev, HPI_ADDR_CMD, (((HPI_MAX_PKSIZE) << 4) + 2 + 8));
#else
		pci_write_reg(dev, HPI_ADDR_CMD, (((HPI_MAX_PKSIZE) << 4) + 2));
#endif
		cnt = 0;
		do {
			status = pci_read_reg(dev, HPI_ADDR_STATUS);
			status = (status >> 1) & 1;
			cnt++;
		} while (status == 0 && cnt < 10000);

		if (cnt == 10000) {
			mutex_unlock(&dev->vdi_lock);
			return -200;
		}

		mutex_unlock(&dev->vdi_lock);
		addr += HPI_MAX_PKSIZE;
	}

	size = size % HPI_MAX_PKSIZE;

	if (size)
	{
		ret = mutex_lock_interruptible(&dev->vdi_lock);
		if (ret) {
			dev_err(dev->dev, "unable to acquire vdi_lock\n");
			return -1;
		}

		pci_write_reg(dev, HPI_ADDR_ADDR_H, (addr >> 16));
		pci_write_reg(dev, HPI_ADDR_ADDR_L, (addr & 0xffff));

		for (j = 0; j < size / 2; j++)
		{
			data = (buf[k] << 8) | buf[k+1];
			pci_write_reg(dev, HPI_ADDR_DATA + j * 4, data);
			k = k + 2;
		}
#ifdef CNM_FPGA_VU19P_INTERFACE
		pci_write_reg(dev, HPI_ADDR_CMD, ((size << 4) + 2 + 8));
#else
		pci_write_reg(dev, HPI_ADDR_CMD, ((size << 4) + 2));
#endif
		do {
			status = pci_read_reg(dev, HPI_ADDR_STATUS);
			status = (status >> 1) & 1;
		} while (status == 0);

		mutex_unlock(&dev->vdi_lock);
	}
	return 1;
}

static void pci_write_cmd(struct vpu_device *dev)
{
	pci_write_reg(dev, HPI_ADDR_CMD, (16<<4)|2);
}

static void pci_read_cmd(struct vpu_device *dev)
{
	pci_write_reg(dev, HPI_ADDR_CMD, (16<<4)|1);
}

static void wave5_swap_endian(struct vpu_device *vpu_dev, u8 *data, int len, int endian);

static int hpi_write_memory(struct vpu_device *vpu_dev, u32 bus_len, unsigned int addr, unsigned char *data, int len, int endian)
{
	unsigned int next_4k_addr;
	int size_to_write, remaining_size;
	unsigned char *pbuf;
	/* TODO: allocate on heap */
	unsigned char ls_buf[HPI_MAX_BUS_LENGTH];
	unsigned int align_size = bus_len;
	unsigned int align_mask = bus_len-1;
	unsigned int aligned_addr;
	unsigned int offset;

	if (addr < vpu_dev->fpga_memory.daddr)
		return 0;

	addr = addr - vpu_dev->fpga_memory.daddr;
//	s_hpi_base = base;
	// ASSERT: base = vdb_register.virt_addr

	aligned_addr = addr & ~align_mask;
	offset = addr - aligned_addr;
	pbuf = kmalloc((len + offset + align_mask) & ~align_mask, GFP_KERNEL);
	if (pbuf) {
		/* error */
	}

	if (offset) {
		pci_read_memory(vpu_dev, aligned_addr, ls_buf, (offset + align_mask) & ~align_mask);
		wave5_swap_endian(vpu_dev, ls_buf, align_size, endian);
		memcpy(pbuf, ls_buf, offset);
	}

	addr = aligned_addr;
	remaining_size = len;
	next_4k_addr = (addr + 0xfff) & ~0xfff;
	if (addr != next_4k_addr && (addr + len) > next_4k_addr) {
		size_to_write = next_4k_addr - addr - offset;
		memcpy(pbuf + offset, data, size_to_write);
		wave5_swap_endian(vpu_dev, pbuf, (size_to_write + offset + align_mask) & ~align_mask, endian);
		pci_write_memory(vpu_dev, addr, (unsigned char *)pbuf, (size_to_write + offset + align_mask) & ~align_mask);

		data += size_to_write;
		remaining_size -= size_to_write;
		addr = next_4k_addr;
		offset = 0;
	}

	size_to_write = remaining_size + offset;
	memcpy(pbuf + offset, data, remaining_size);
	wave5_swap_endian(vpu_dev, pbuf, (size_to_write + align_mask) & ~align_mask, endian);
	pci_write_memory(vpu_dev, addr, pbuf, (size_to_write + align_mask) & ~align_mask);

	kfree(pbuf);

	//io_unlock(core_idx);

	return len;
}

static int hpi_read_memory(struct vpu_device *vpu_dev, u32 bus_len, unsigned int addr, unsigned char *data, int len, int endian)
{
	unsigned int num_4k_blocks;
	unsigned int next_4k_addr;
	int size_to_read, remaining_size;
	unsigned char *pbuf;
	unsigned char *alloc_buf;
	unsigned int align_size = bus_len;
	unsigned int align_mask = bus_len - 1;
	unsigned int aligned_addr;
	unsigned int offset;

	if (addr < vpu_dev->fpga_memory.daddr)
		return 0;

	addr = addr - vpu_dev->fpga_memory.daddr;

	num_4k_blocks = ((len + 0xfff) & ~0xfff) >> 12;
	
	aligned_addr = addr & ~align_mask;
	offset = addr - aligned_addr;
	alloc_buf = kmalloc((len + offset + align_mask) & ~align_mask, GFP_KERNEL);
	if (!alloc_buf) {
		dev_err(vpu_dev->dev, "failed to allocate memory");
		return 0;
	}

	pbuf = alloc_buf;

	addr = aligned_addr;
	remaining_size = len + offset;
	next_4k_addr = (addr + 0xfff) & ~0xfff;
	if (addr != next_4k_addr && (addr + len) > next_4k_addr) {
		size_to_read = next_4k_addr - addr;
		pci_read_memory(vpu_dev, addr, (unsigned char *)pbuf,
				(size_to_read + align_mask) & ~align_mask);
		wave5_swap_endian(vpu_dev, pbuf,
				  (size_to_read + offset + align_mask) & ~align_mask,
				  endian);
		memcpy(data, pbuf + offset, size_to_read - offset);

		data += size_to_read - offset;
		remaining_size -= size_to_read;
		addr = next_4k_addr;
		offset = 0;
	}

	if (num_4k_blocks) {
		pci_read_memory(vpu_dev, addr, pbuf,
				(remaining_size + align_mask) & ~align_mask);
		wave5_swap_endian(vpu_dev, (unsigned char *)pbuf,
				  (remaining_size + align_mask) & ~align_mask,
				  endian);
		memcpy(data, pbuf + offset, remaining_size - offset);
	}	

	kfree(pbuf);

	return len;

}

void wave5_vdi_write_register(struct vpu_device *vpu_dev, unsigned int addr, unsigned int data)
{
	int status;
	int cnt = 0;
	int ret;

	ret = mutex_lock_interruptible(&vpu_dev->vdi_lock);
	if (ret) {
		dev_err(vpu_dev->dev, "%s(): unable to acquire vdi_lock\n", __func__);
		return;
	}

	addr += VPU_BIT_REG_BASE;

	pci_write_reg(vpu_dev, HPI_ADDR_ADDR_H, (addr >> 16));
	pci_write_reg(vpu_dev, HPI_ADDR_ADDR_L, (addr & 0xffff));


	pci_write_reg(vpu_dev, HPI_ADDR_DATA, ((data >> 16) & 0xffff));
	pci_write_reg(vpu_dev, HPI_ADDR_DATA + 4, (data & 0xFFFF));

	pci_write_cmd(vpu_dev);

	ret = read_poll_timeout(pci_read_reg, status, (status & 0x2), 0,
			  HPI_WAIT_TIMEOUT*1000, false, vpu_dev, HPI_ADDR_STATUS);
	mutex_unlock(&vpu_dev->vdi_lock);

	if (ret) {
		dev_err(vpu_dev->dev, "wave_vdi_write_register timeout\n");
	}
}

unsigned int wave5_vdi_readl(struct vpu_device *vpu_dev, u32 addr)
{
	int status;
	int cnt = 0;
	unsigned int data = 0;
	int ret;

	ret = mutex_lock_interruptible(&vpu_dev->vdi_lock);
	if (ret) {
		dev_err(vpu_dev->dev, "%s(): unable to acquire vdi_lock\n", __func__);
		return -1;
	}

	addr += VPU_BIT_REG_BASE;

	pci_write_reg(vpu_dev, HPI_ADDR_ADDR_H, ((addr >> 16) & 0xffff));
	pci_write_reg(vpu_dev, HPI_ADDR_ADDR_L, (addr & 0xffff));

	pci_read_cmd(vpu_dev);

	ret = read_poll_timeout(pci_read_reg, status, (status & 0x1), 0,
				HPI_WAIT_TIMEOUT*1000, false, vpu_dev, HPI_ADDR_STATUS);

	if (ret) {
		dev_err(vpu_dev->dev, "wave5_vdi_readl timeout.\n");
	}

	data = pci_read_reg(vpu_dev, HPI_ADDR_DATA) << 16;
	data |= pci_read_reg(vpu_dev, HPI_ADDR_DATA + 4);

	mutex_unlock(&vpu_dev->vdi_lock);

	return data;
}

static bool hpi_write_reg_test(struct vpu_device *vpu_dev, unsigned int addr, unsigned int data) {
	int status;
	int i;
	int ret;

	ret = mutex_lock_interruptible(&vpu_dev->vdi_lock);
	if (ret) {
		dev_err(vpu_dev->dev, "%s(): unable to acquire vdi_lock\n", __func__);
		return false;
	}

	pci_write_reg(vpu_dev, HPI_ADDR_ADDR_H, (addr >> 16));
	pci_write_reg(vpu_dev, HPI_ADDR_ADDR_L, (addr & 0xffff));
	       
	pci_write_reg(vpu_dev, HPI_ADDR_DATA, ((data >> 16) & 0xffff));
	pci_write_reg(vpu_dev, HPI_ADDR_DATA + 4, data & 0xffff);

	pci_write_cmd(vpu_dev);

	i = 0;
	do {
		status = pci_read_reg(vpu_dev, HPI_ADDR_STATUS);
		status = (status >> 1) & 1;
		if (i++ > 10000) {
			mutex_unlock(&vpu_dev->vdi_lock);
			return false;
		}
	} while (!status);

	mutex_unlock(&vpu_dev->vdi_lock);

	return true;
}

static bool hpi_read_reg_test(struct vpu_device *vpu_dev, unsigned int addr, unsigned int *data)
{
	int status;
	int i;
	int ret;

	ret = mutex_lock_interruptible(&vpu_dev->vdi_lock);
	if (ret) {
		dev_err(vpu_dev->dev, "%s(): unable to acquire vdi_lock\n", __func__);
		return false;
	}

	pci_write_reg(vpu_dev, HPI_ADDR_ADDR_H, ((addr >> 16) & 0xffff));
	pci_write_reg(vpu_dev, HPI_ADDR_ADDR_L, (addr & 0xffff));

	pci_read_cmd(vpu_dev);

	i = 0;
	do {
		status = pci_read_reg(vpu_dev, HPI_ADDR_STATUS);
		status = status & 1;
		if (i++ > 10000) {
			mutex_unlock(&vpu_dev->vdi_lock);
			return false;
		}
	} while (!status);

	*data = pci_read_reg(vpu_dev, HPI_ADDR_DATA) << 16;
	*data |= pci_read_reg(vpu_dev, HPI_ADDR_DATA + 4);

	mutex_unlock(&vpu_dev->vdi_lock);

	return true;
}

int wave5_vdi_clear_memory(struct vpu_device *vpu_dev, struct vpu_buf *vb)
{
	/* TODO: do foreign memory clear */
	return vb->size;
}


int wave5_vdi_write_memory(struct vpu_device *vpu_dev, struct vpu_buf *vb, size_t offset,
			   u8 *data, int len, int endian)
{
	if (!vb || !vb->daddr) {
		dev_err(vpu_dev->dev, "%s(): unable to write to unmapped buffer\n", __func__);
		return -EINVAL;
	}

	if (offset > vb->size || len > vb->size || offset + len > vb->size) {
		dev_err(vpu_dev->dev, "%s(): buffer too small\n", __func__);
		return -ENOSPC;
	}

	/* wave5_swap_endian(vpu_dev, data, len, endian); */
	//memcpy(vb->vaddr + offset, data, len);

	/* for (i = 0; i < MAX_VPU_BUFFER_POOL; i++) { */
	/* 	if (vpu_dev->buffer_pool[i].inuse == 1) { */
	/* 		vdb = vpu_dev->buffer_pool[i].vdb; */
	/* 		if (offset >= vdb.faddr && offset < (vdb.faddr * vdb.size)) */
	/* 			break; */
	/* 	} */
	/* } */

	if (!vb->size) {
		dev_err(vpu_dev->dev, "%s(): address 0x%08x is not mapped address\n", __func__, (unsigned int)offset);
		return -1;
	}

	return hpi_write_memory(vpu_dev, HPI_BUS_LENGTH, vb->daddr + offset, data, len, endian);
}

int wave5_vdi_read_memory(struct vpu_device *vpu_dev, struct vpu_buf *vb, size_t offset,
			  u8 *data, int len, int endian)
{
	if (!vb || !vb->daddr) {
		dev_err(vpu_dev->dev, "%s(): unable to write to unmapped buffer\n", __func__);
		return -EINVAL;
	}

	if (offset > vb->size || len > vb->size || offset + len > vb->size) {
		dev_err(vpu_dev->dev, "%s(): buffer too small\n", __func__);
		return -ENOSPC;
	}

	if (!vb->size) {
		dev_err(vpu_dev->dev, "%s(); address 0x%08x is not mapped address\n"
			, __func__, (unsigned int)offset);
		return -1;
	}

	return hpi_read_memory(vpu_dev, HPI_BUS_LENGTH, vb->daddr + offset, data, len, endian);
}

int wave5_vdi_allocate_dma_memory(struct vpu_device *vpu_dev, struct vpu_buf *vb)
{
	unsigned long daddr;
	daddr = vmem_alloc(&vpu_dev->vmem, vb->size, 0);
	if ((unsigned long)-1 == daddr) {
		return -ENOMEM;
	}

	vb->daddr = daddr;
	++vpu_dev->num_buffer;

	return 0;
}

void wave5_vdi_free_dma_memory(struct vpu_device *vpu_dev, struct vpu_buf *vb)
{
	int ret;
	ret = vmem_free(&vpu_dev->vmem, vb->daddr, 0);
	if (ret == -1) {
		dev_err(vpu_dev->dev, "%s(): failed to free vmem buffer\n", __func__);
		return;
	}
	
	--vpu_dev->num_buffer;
	memset(vb, 0, sizeof(*vb));
}

int wave5_vdi_convert_endian(struct vpu_device *vpu_dev, unsigned int endian)
{
	if (PRODUCT_CODE_W_SERIES(vpu_dev->product_code)) {
		switch (endian) {
		case VDI_LITTLE_ENDIAN:
			endian = 0x00;
			break;
		case VDI_BIG_ENDIAN:
			endian = 0x0f;
			break;
		case VDI_32BIT_LITTLE_ENDIAN:
			endian = 0x04;
			break;
		case VDI_32BIT_BIG_ENDIAN:
			endian = 0x03;
			break;
		}
	}

	return (endian & 0x0f);
}

static void byte_swap(unsigned char *data, int len)
{
	u8 temp;
	int i;

	for (i = 0; i < len; i += 2) {
		temp = data[i];
		data[i] = data[i + 1];
		data[i + 1] = temp;
	}
}

static void word_swap(unsigned char *data, int len)
{
	u16 temp;
	u16 *ptr = (u16 *)data;
	int i;
	s32 size = len / sizeof(uint16_t);

	for (i = 0; i < size; i += 2) {
		temp = ptr[i];
		ptr[i] = ptr[i + 1];
		ptr[i + 1] = temp;
	}
}

static void dword_swap(unsigned char *data, int len)
{
	u32 temp;
	u32 *ptr = (u32 *)data;
	s32 size = len / sizeof(uint32_t);
	int i;

	for (i = 0; i < size; i += 2) {
		temp = ptr[i];
		ptr[i] = ptr[i + 1];
		ptr[i + 1] = temp;
	}
}

static void lword_swap(unsigned char *data, int len)
{
	u64 temp;
	u64 *ptr = (u64 *)data;
	s32 size = len / sizeof(uint64_t);
	int i;

	for (i = 0; i < size; i += 2) {
		temp = ptr[i];
		ptr[i] = ptr[i + 1];
		ptr[i + 1] = temp;
	}
}

static void wave5_swap_endian(struct vpu_device *vpu_dev, u8 *data, int len, int endian)
{
	int changes;
	int sys_endian;
	bool byte_change, word_change, dword_change, lword_change;

#if 0
	if (PRODUCT_CODE_W_SERIES(vpu_dev->product_code)) {
		sys_endian = VDI_128BIT_BUS_SYSTEM_ENDIAN;
	} else {
		dev_err(vpu_dev->dev, "unknown product id : %08x\n", vpu_dev->product_code);
		return;
	}
#endif
	sys_endian = VDI_128BIT_BUS_SYSTEM_ENDIAN;

	endian = wave5_vdi_convert_endian(vpu_dev, endian);
	sys_endian = wave5_vdi_convert_endian(vpu_dev, sys_endian);
	if (endian == sys_endian)
		return;

	changes = endian ^ sys_endian;
	byte_change = changes & 0x01;
	word_change = ((changes & 0x02) == 0x02);
	dword_change = ((changes & 0x04) == 0x04);
	lword_change = ((changes & 0x08) == 0x08);

	if (byte_change)
		byte_swap(data, len);
	if (word_change)
		word_swap(data, len);
	if (dword_change)
		dword_swap(data, len);
	if (lword_change)
		lword_swap(data, len);
}

