# SPDX-License-Identifier: GPL-2.0
#
# Copyright (C) 2020 Dave Voutila <dave@sisu.io>. All rights reserved.

KERNELRELEASE ?= $(shell uname -r)
KERNEL_MAJOR ?= $(shell uname -r | cut -d. -f1)
KERNEL_MINOR ?= $(shell uname -r | cut -d. -f2)
KERNELDIR ?= /lib/modules/$(KERNELRELEASE)/build
MODDIR ?= /lib/modules/$(KERNELRELEASE)/kernel
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

module: kquic.ko

kquic.ko: authors.h compat/linux/aesgcm.ko *.c *.h
	@$(MAKE) -C $(KERNELDIR) M=$(PWD) modules

module-debug:
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

compat/linux/aesgcm.ko:
	@if ! [ $(KERNEL_MAJOR) -ge 6 -a $(KERNEL_MINOR) -ge 2 ]; then \
	    $(MAKE) -C $(KERNELDIR) M=$(PWD)/compat/linux modules; \
	else \
		touch compat/linux/aesgcm.ko; \
	fi

wolfssl:
	git clone --depth 1 -b $(WOLFSSL_VERSION) $(WOLFSSL_REPO)

wolfssl/configure: wolfssl/configure.ac
	cd wolfssl && autoreconf -i

wolfssl/Makefile: wolfssl/configure
	cd wolfssl && \
	./configure --enable-linuxkm --enable-cryptonly --enable-tls13 \
	    --enable-hkdf --with-linux-source=$(KERNELDIR)

wolfssl/linuxkm/libwolfssl.ko: wolfssl/Makefile
	sudo make -C wolfssl || true

load: wolfssl/linuxkm/libwolfssl.ko compat/linux/aesgcm.ko
	@if ! [ $(KERNEL_MAJOR) -ge 6 -a $(KERNEL_MINOR) -ge 2 ]; then \
	    if ! /usr/sbin/lsmod | grep -q gf128mul; then \
	        echo /usr/sbin/insmod $(MODDIR)/crypto/gf128mul.ko; \
	        /usr/sbin/insmod $(MODDIR)/crypto/gf128mul.ko; \
	    fi; \
	    if ! /usr/sbin/lsmod | grep -q aesgcm; then \
		echo /usr/sbin/insmod compat/linux/aesgcm.ko; \
		/usr/sbin/insmod compat/linux/aesgcm.ko; \
	    fi; \
	fi
	@if ! /usr/sbin/lsmod | grep -q libwolfssl; then \
		echo /usr/sbin/insmod wolfssl/linuxkm/libwolfssl.ko; \
		/usr/sbin/insmod wolfssl/linuxkm/libwolfssl.ko; \
	fi
	/usr/sbin/insmod kquic.ko

unload:
	/usr/sbin/rmmod kquic.ko

reload: | unload load

.PHONY: all debug module module-debug clean install test load unload reload
