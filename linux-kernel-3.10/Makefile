#
# Author: (C) 2012 Michail Flouris <michail.flouris@onapp.com>

# Add heavy debugging??
#DFLAGS = -g -g3 -ggdb
#EXTRA_CFLAGS += $(DFLAGS)

# Directory for Module installation
KERNEL_VERSION ?= $(shell uname -r)
BASEKERNDIR := 
MODDIR := /lib/modules/$(KERNEL_VERSION)/kernel/drivers/block/

#DMOBJS = nbd.o
KMODNAME = nbd

TESTS= qhash_test nbd_print_debug nbd_set_timeout nbd_conn_info nbd_server_cmd

obj-m += $(KMODNAME).o
#nbd-objs += $(DMOBJS)

# We were called directly from the command line; invoke the kernel build system.
ifeq ($(KERNELRELEASE),)
	#KERNELDIR ?= $(BASEKERNDIR)/lib/modules/$(shell uname -r)/build
	KERNELDIR ?= $(BASEKERNDIR)/lib/modules/$(KERNEL_VERSION)/build
	#PWD := $(shell pwd)

default: all
endif

# Need special flags for Centos7 (el7) patchset 328 onwards, kernel code is different from el6
KERN_RH_PATCHSET := $(shell echo '$(KERNEL_VERSION)' | cut -d '-' -f 2 | cut -d '.' -f 1)
RHP_MIN_VER_328 := $(shell echo '$(KERN_RH_PATCHSET) >= 328 ' | bc )

ifeq ($(shell echo '$(KERNEL_VERSION)' | grep el7 | wc -l), 1)
	ifeq ($(shell echo '$(RHP_MIN_VER_328)'), 1)
		EXTRA_CFLAGS += -DEL7_VER_328
	endif
endif

.PHONY: all nbd_mod ins lsm rmm install clean wc
all: nbd_mod $(TESTS)

nbd_mod:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) modules

qhash_test.o: qhash_test.c nbd.h
nbd_print_debug.o: nbd_print_debug.c nbd.h
nbd_set_timeout.o: nbd_set_timeout.c nbd.h
nbd_conn_info.o: nbd_conn_info.c nbd.h
nbd_server_cmd.o: nbd_server_cmd.c nbd.h

ins:
	/sbin/insmod $(KMODNAME).ko
	@/sbin/lsmod | grep $(KMODNAME)

lsm:
	@/sbin/lsmod | grep $(KMODNAME)

rmm:
	/sbin/rmmod $(KMODNAME).ko

install:
	install -m 744 $(KMODNAME).ko $(MODDIR)
	/sbin/depmod -a $(KERNEL_VERSION)
	install -m 755 nbd_set_timeout /usr/bin
	install -m 755 nbd_conn_info /usr/bin
	install -m 755 nbd_server_cmd /usr/bin

clean:
	\rm -rf *.o .*.o.d .depend *.ko .*.cmd *.mod.c .tmp* Module.markers Module.symvers modules.order
	\rm -f types.vim tags $(TESTS)

wc:
	@echo -n "Code lines (excl. blank lines): "
	@cat *.[ch] | grep -v "^$$" | grep -v "^[ 	]*$$" | wc -l

nbd.o: nbd.h nbd.c

tags:: *.[ch]
	@\rm -f tags
	@ctags -R --languages=c

types.vim: *.[ch]
	@echo "==> Updating tags !"
	@\rm -f $@
	@ctags -R --c-types=+gstu -o- *.[ch] | awk '{printf("%s\n", $$1)}' | uniq | sort | \
	awk 'BEGIN{printf("syntax keyword myTypes\t")} {printf("%s ", $$1)} END{print ""}' > $@
	@ctags -R --c-types=+cd -o- *.[ch] | awk '{printf("%s\n", $$1)}' | uniq | sort | \
	awk 'BEGIN{printf("syntax keyword myDefines\t")} {printf("%s ", $$1)} END{print ""}' >> $@
	@ctags -R --c-types=+v-gstucd -o- *.[ch] | awk '{printf("%s\n", $$1)}' | uniq | sort | \
	awk 'BEGIN{printf("syntax keyword myVariables\t")} {printf("%s ", $$1)} END{print ""}' >> $@

