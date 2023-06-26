# SPDX-License-Identifier: GPL-2.0
#
# Copyright (C) 2020 Dave Voutila <dave@sisu.io>. All rights reserved.

KERNELRELEASE ?= $(shell uname -r)
KERNELDIR ?= /lib/modules/$(KERNELRELEASE)/build
DEPMOD ?= depmod
PWD := $(shell pwd)
NGTCP2_FILES = quic.c ngtcp2/

all: module
debug: module-debug

authors.h:
	> $@
	git shortlog -sne $(NGTCP2_FILES) |  cut -f 2- | while read a; do \
		echo "MODULE_AUTHOR(\"$$a\");" >> $@; \
	done

module: authors.h
	@$(MAKE) -C $(KERNELDIR) M=$(PWD) modules

module-debug:
	@$(MAKE) -C $(KERNELDIR) M=$(PWD) CONFIG_VMMCI_DEBUG=y modules

clean:
	@$(MAKE) -C $(KERNELDIR) M=$(PWD) clean
	@$(MAKE) -C tests clean
	rm -f authors.h

install:
	@$(MAKE) -C $(KERNELDIR) M=$(PWD) modules_install
	@$(DEPMOD) -A $(KERNELRELEASE)

test:
	@$(MAKE) -C tests

.PHONY: all debug module module-debug clean install test
