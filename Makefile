#
# Author: (C) 2012 Michail Flouris <michail.flouris@onapp.com>

# Add heavy debugging??
#DFLAGS = -g -g3 -ggdb
#EXTRA_CFLAGS += $(DFLAGS)

# try to detect the Linux distro type
ifneq ($(wildcard /etc/redhat-release),) 
    LINUX_TYPE := Redhat
else 
	ifneq ($(wildcard /etc/debian_version),) 
	    LINUX_TYPE := Debian
		ifneq ($(wildcard /etc/lsb-release),) 
		    LINUX_TYPE = Ubuntu
		else 
		    LINUX_TYPE := Unknown
		endif
	else 
		ifneq ($(wildcard /etc/SuSE-release),) 
		    LINUX_TYPE := SuSE
		else
			LINUX_TYPE := Unknown
		endif
	endif
endif

KERNEL_VERSION ?= $(shell uname -r)
KERN_MAJOR_VER := $(shell echo '$(KERNEL_VERSION)' | cut -d '.' -f 1)
KERN_MINOR_VER := $(shell echo '$(KERNEL_VERSION)' | cut -d '.' -f 2)

# 0 or 1 if we compile on 64-bit architecture
IS_64_ARCH := $(shell uname -m | grep 64 | wc -l )

# Directory for building module
BUILDDIR :=

ifeq ($(LINUX_TYPE),Redhat)
CENTOS_VERSION := $(shell cat /etc/redhat-release | grep 'CentOS' | cut -c 16 )

# Check which version of centos to build on... 
ifeq ($(CENTOS_VERSION),)
	BUILDDIR := $(error CentOS not found! Current makefiles support only CentOS. Aborting!)
endif
ifeq ($(CENTOS_VERSION),5)
	BUILDDIR := "centos5_kernel-2.6.18"
	#BUILDDIR := "centos5_kernel-2.6.18-threaded"
endif
ifeq ($(CENTOS_VERSION),6)
	ifeq ($(KERN_MAJOR_VER),3)
		BUILDDIR := "linux-kernel-3.8"
	else
		BUILDDIR := "centos6_kernel-2.6.32"
	endif
endif
else
	# we go by kernel version number in here...
	ifeq ($(LINUX_TYPE),Ubuntu)
		ifeq ($(KERN_MAJOR_VER),3)
			MIN_VER_12 := $(shell echo '$(KERN_MINOR_VER) >= 1 && $(KERN_MINOR_VER) <= 2' | bc )
			MIN_VER_34 := $(shell echo '$(KERN_MINOR_VER) >= 3 && $(KERN_MINOR_VER) <= 4' | bc )
			ifeq ($(MIN_VER_12),1)
				BUILDDIR := "linux-kernel-3.1.5"
			else
			ifeq ($(MIN_VER_34),1)
				BUILDDIR := "linux-kernel-3.4.6"
			endif
			endif
		else
			BUILDDIR := $(error Ubuntu Kernel version < 3! Change into a 2.x kernel version subdir and 'make' in there!)
		endif
	else
		BUILDDIR := $(error Unsupported linux distro! Change into a kernel version subdir and 'make' in there!)
	endif
endif

# Do we support the build on the current Linux distro & kernel version?
ifeq ($(BUILDDIR),)
	BUILDDIR := $(error NBD built not supported on current distro/kernel version! Aborting!)
endif

BINS= qhash_test nbd_print_debug

.PHONY: all ins lsm rmm test install clean wc
all:
	@echo Detected LINUX_TYPE=\"${LINUX_TYPE}\"
	@echo Building on CENTOS_VERSION=\"$(CENTOS_VERSION)\"
	@echo BUILDDIR= $(BUILDDIR)
	(cd $(BUILDDIR) ; $(MAKE))

ins:
	(cd $(BUILDDIR) ; $(MAKE) $@)

lsm:
	(cd $(BUILDDIR) ; $(MAKE) $@)

rmm:
	(cd $(BUILDDIR) ; $(MAKE) $@)

test:
	(cd $(BUILDDIR) ; $(MAKE) $@)

install:
	(cd $(BUILDDIR) ; $(MAKE) $@)

clean:
	(cd $(BUILDDIR) ; $(MAKE) $@)
	\rm -rf *.o .*.o.d .depend *.ko .*.cmd *.mod.c .tmp*
	\rm -f types.vim tags $(BINS)

wc:
	(cd $(BUILDDIR) ; $(MAKE) $@)
	@echo -n "Code lines (excl. blank lines): "
	@cat *.[ch] | grep -v "^$$" | grep -v "^[ 	]*$$" | wc -l

tags:: *.[ch]
	(cd $(BUILDDIR) ; $(MAKE) $@)
	@\rm -f tags
	@ctags -R --languages=c

types.vim: *.[ch]
	(cd $(BUILDDIR) ; $(MAKE) $@)
	@echo "==> Updating tags !"
	@\rm -f $@
	@ctags -R --c-types=+gstu -o- *.[ch] | awk '{printf("%s\n", $$1)}' | uniq | sort | \
	awk 'BEGIN{printf("syntax keyword myTypes\t")} {printf("%s ", $$1)} END{print ""}' > $@
	@ctags -R --c-types=+cd -o- *.[ch] | awk '{printf("%s\n", $$1)}' | uniq | sort | \
	awk 'BEGIN{printf("syntax keyword myDefines\t")} {printf("%s ", $$1)} END{print ""}' >> $@
	@ctags -R --c-types=+v-gstucd -o- *.[ch] | awk '{printf("%s\n", $$1)}' | uniq | sort | \
	awk 'BEGIN{printf("syntax keyword myVariables\t")} {printf("%s ", $$1)} END{print ""}' >> $@

