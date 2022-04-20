# SPDX-License-Identifier: GPL-2.0
#

obj-m := wave5.o
wave5-y := \
	wave5-vpu-hpi.o \
	wave5-vdi-hpi.o \
	wave5-vpuapi.o \
	wave5-vpu-dec.o \
	wave5-vpu-enc.o \
	wave5-hw.o \
	vmm.o


KDIR ?= /lib/modules/`uname -r`/build

all:
	make -C $(KDIR) M=$(PWD) modules

debug:
	make -C $(KDIR) M=$(PWD) modules EXTRA_CFLAGS="-g -DDEBUG"

clean:
	make -C $(KDIR) M=$(PWD) clean
