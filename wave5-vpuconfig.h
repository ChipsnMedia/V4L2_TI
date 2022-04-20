/* SPDX-License-Identifier: (GPL-2.0 OR BSD-3-Clause) */
/*
 * Wave5 series multi-standard codec IP - product config definitions
 *
 * Copyright (C) 2021 CHIPS&MEDIA INC
 */

#ifndef _VPU_CONFIG_H_
#define _VPU_CONFIG_H_

#define WAVE517_CODE                    0x5170
#define WAVE537_CODE                    0x5370
#define WAVE511_CODE                    0x5110
#define WAVE521_CODE                    0x5210
#define WAVE521C_CODE                   0x521c
#define WAVE521C_DUAL_CODE              0x521d  // wave521 dual core
#define WAVE521E1_CODE                  0x5211
#define WAVE627_CODE                    0x6270
#define WAVE637_CODE                    0x6370
#define WAVE663_CODE                    0x6630
#define WAVE677_CODE                    0x6770

#define PRODUCT_CODE_W_SERIES(x) ({					\
		int c = x;						\
		((c) == WAVE517_CODE ||	(c) == WAVE537_CODE ||		\
		 (c) == WAVE511_CODE || (c) == WAVE521_CODE ||		\
		 (c) == WAVE521E1_CODE || (c) == WAVE521C_CODE ||	\
		 (c) == WAVE521C_DUAL_CODE || (c) == WAVE627_CODE ||	\
		 (c) == WAVE637_CODE || (c) == WAVE663_CODE ||          \
		 (c) == WAVE677_CODE);                                  \
})

#define PRODUCT_CODE_W5_SERIES(x) ({                                    \
		int c = x;						\
		((c) == WAVE517_CODE ||	(c) == WAVE537_CODE ||		\
		 (c) == WAVE511_CODE || (c) == WAVE521_CODE ||		\
		 (c) == WAVE521E1_CODE || (c) == WAVE521C_CODE ||	\
		 (c) == WAVE521C_DUAL_CODE);                       	\
})

#define PRODUCT_CODE_W6_SERIES(x) ({					\
		int c = x;						\
		((c) == WAVE627_CODE ||	(c) == WAVE637_CODE ||          \
                 (c) == WAVE663_CODE || (c) == WAVE677_CODE);           \
})

#define WAVE627ENC_WORKBUF_SIZE         (132*1024)
#define WAVE637DEC_WORKBUF_SIZE         (4096*1024)
#define WAVE517_WORKBUF_SIZE            (2 * 1024 * 1024)
#define WAVE521ENC_WORKBUF_SIZE         (128 * 1024)      //HEVC 128K, AVC 40K
#define WAVE521DEC_WORKBUF_SIZE         (1784 * 1024)

#define MAX_NUM_INSTANCE                32

#define W5_MIN_ENC_PIC_WIDTH            256
#define W5_MIN_ENC_PIC_HEIGHT           128
#define W5_MAX_ENC_PIC_WIDTH            8192
#define W5_MAX_ENC_PIC_HEIGHT           8192

//  application specific configuration
#define VPU_ENC_TIMEOUT                 60000
#define VPU_DEC_TIMEOUT                 60000

#define HOST_ENDIAN                     VDI_128BIT_LITTLE_ENDIAN
#define VPU_FRAME_ENDIAN                HOST_ENDIAN
#define VPU_STREAM_ENDIAN               HOST_ENDIAN
#define VPU_USER_DATA_ENDIAN            HOST_ENDIAN
#define VPU_SOURCE_ENDIAN               HOST_ENDIAN

// for WAVE encoder
#define USE_SRC_PRP_AXI         0
#define USE_SRC_PRI_AXI         1
#define DEFAULT_SRC_AXI         USE_SRC_PRP_AXI

/************************************************************************/
/* VPU COMMON MEMORY                                                    */
/************************************************************************/
#define VLC_BUF_NUM                     (3)

#define COMMAND_QUEUE_DEPTH             (4)

#define W_REMAP_INDEX0                 0
#define W_REMAP_INDEX1                 1
#define W_REMAP_MAX_SIZE               (1024 * 1024)

#define WAVE5_MAX_CODE_BUF_SIZE         (2 * 1024 * 1024)
#define WAVE5_TEMPBUF_OFFSET            WAVE5_MAX_CODE_BUF_SIZE
#define WAVE5_TEMPBUF_SIZE              (1024 * 1024)

#define WAVE6_MAX_CODE_BUF_SIZE         (1*1024*1024)
#define WAVE6_TEMPBUF_OFFSET            WAVE6_MAX_CODE_BUF_SIZE
#define WAVE6_TEMPBUF_SIZE              (2*1024*1024)

#define WAVE5_SIZE_COMMON               (WAVE5_MAX_CODE_BUF_SIZE + WAVE5_TEMPBUF_SIZE)
#define WAVE6_SIZE_COMMON               (WAVE6_MAX_CODE_BUF_SIZE + WAVE6_TEMPBUF_SIZE)

//=====4. VPU REPORT MEMORY  ======================//

#define WAVE_UPPER_PROC_AXI_ID     0x0

#define WAVE5_PROC_AXI_ID           0x0
#define WAVE5_PRP_AXI_ID            0x0
#define WAVE5_FBD_Y_AXI_ID          0x0
#define WAVE5_FBC_Y_AXI_ID          0x0
#define WAVE5_FBD_C_AXI_ID          0x0
#define WAVE5_FBC_C_AXI_ID          0x0
#define WAVE5_SEC_AXI_ID            0x0
#define WAVE5_PRI_AXI_ID            0x0

#define WAVE5_PROC_AXI_AXPROT       0x0
#define WAVE5_PROC_AXI_AXCACHE      0x0
#define WAVE5_PROC_AXI_EXT_ADDR     0x0
#define WAVE5_SEC_AXI_AXPROT        0x0
#define WAVE5_SEC_AXI_AXCACHE       0x0
#define WAVE5_SEC_AXI_EXT_ADDR      0x0

#define PROC_AXI_EXT_BASE           0x0
#define VCPU_EXT_ADDR               0x0
#define FBC_FBC_EXT_ADDR            0x0
#define SRC_BWB_EXT_ADDR            0x0
#define GDMA0_EXT_ADDR              0x0
#define GDMA1_EXT_ADDR              0x0
#define SDMA_EXT_ADDR               0x0
#define RDO_COL_EXT_ADDR            0x0
#define RDO_NB_EXT_ADDR            0x0
#define LF_NB_EXT_ADDR            0x0

#endif  /* _VPU_CONFIG_H_ */

