# SPDX-License-Identifier: GPL-2.0
#
# Copyright (C) 2020 Dave Voutila <dave@sisu.io>. All rights reserved.

KERNELRELEASE ?= $(shell uname -r)
KERNEL_MAJOR ?= $(shell uname -r | cut -d. -f1)
KERNEL_MINOR ?= $(shell uname -r | cut -d. -f2)
KERNELDIR ?= /lib/modules/$(KERNELRELEASE)/build
DEPMOD ?= depmod
PWD := $(shell pwd)
NGTCP2_FILES = quic.c ngtcp2/

WOLFSSL_REPO = https://github.com/wolfSSL/wolfssl
WOLFSSL_VERSION = v5.6.3-stable

all: module
debug: module-debug

authors.h:
	> $@
	git shortlog -sne $(NGTCP2_FILES) |  cut -f 2- | while read a; do \
		echo "MODULE_AUTHOR(\"$$a\");" >> $@; \
	done

module: authors.h
	@if ! [ $(KERNEL_MAJOR) -ge 6 -a $(KERNEL_MINOR) -ge 2 ]; then \
	    $(MAKE) -C $(KERNELDIR) M=$(PWD)/compat/linux modules; \
	fi
	@$(MAKE) -C $(KERNELDIR) M=$(PWD) modules

module-debug:
	@if ! [ $(KERNEL_MAJOR) -ge 6 -a $(KERNEL_MINOR) -ge 2 ]; then \
	    $(MAKE) -C $(KERNELDIR) M=$(PWD)/compat/linux modules; \
	fi
	@$(MAKE) -C $(KERNELDIR) M=$(PWD) CONFIG_INET_QUIC_DEBUG=y modules

clean:
	@if ! [ $(KERNEL_MAJOR) -ge 6 -a $(KERNEL_MINOR) -ge 2 ]; then \
	    $(MAKE) -C $(KERNELDIR) M=$(PWD)/compat/linux clean; \
	fi
	@$(MAKE) -C $(KERNELDIR) M=$(PWD) clean
	@$(MAKE) -C tests clean
	rm -f authors.h

install:
	@$(MAKE) -C $(KERNELDIR) M=$(PWD) modules_install
	@$(DEPMOD) -A $(KERNELRELEASE)

test:
	@$(MAKE) -C tests

wolfssl:
	git clone --depth 1 -b $(WOLFSSL_VERSION) $(WOLFSSL_REPO)

wolfssl/configure: wolfssl
	cd wolfssl && autoreconf -i

wolfssl/Makefile: wolfssl/configure
	cd wolfssl && \
	./configure --enable-linuxkm --enable-cryptonly --enable-tls13 \
	    --enable-hkdf --with-linux-source=$(KERNELDIR)

wolfssl/linuxkm/libwolfssl.ko: wolfssl/Makefile
	sudo make -C wolfssl


.PHONY: all debug module module-debug clean install test
