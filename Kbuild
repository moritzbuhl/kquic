# SPDX-License-Identifier: GPL-2.0
#
# Copyright (C) 2020 Dave Voutila <dave@sisu.io>. All rights reserved.

KBUILD_EXTRA_SYMBOLS := $(PWD)/wolfssl/linuxkm/Module.symvers
KBUILD_EXTRA_SYMBOLS += $(PWD)/compat/linux/Module.symvers

ccflags-y := -O3 -Wall -I$(PWD) -I$(PWD)/wolfssl \
	-DHAVE_CONFIG_H -DNGTCP2_USE_GENERIC_SOCKADDR \
	-DWOLFSSL_LINUXKM -DHAVE_HKDF
ccflags-$(CONFIG_INET_QUIC_DEBUG) += -DDEBUG -g

obj-m :=	kquic.o
kquic-y :=	quic.o crypto.o ngtcp2.o
kquic-y +=	ngtcp2/crypto/shared.o \
	ngtcp2/ngtcp2_acktr.o ngtcp2/ngtcp2_buf.o \
	ngtcp2/ngtcp2_conversion.o ngtcp2/ngtcp2_ksl.o ngtcp2/ngtcp2_opl.o \
	ngtcp2/ngtcp2_pq.o ngtcp2/ngtcp2_rob.o ngtcp2/ngtcp2_unreachable.o \
	ngtcp2/ngtcp2_addr.o ngtcp2/ngtcp2_cc.o ngtcp2/ngtcp2_crypto.o \
	ngtcp2/ngtcp2_log.o ngtcp2/ngtcp2_path.o ngtcp2/ngtcp2_pv.o \
	ngtcp2/ngtcp2_rst.o ngtcp2/ngtcp2_vec.o ngtcp2/ngtcp2_balloc.o \
	ngtcp2/ngtcp2_cid.o ngtcp2/ngtcp2_err.o ngtcp2/ngtcp2_map.o \
	ngtcp2/ngtcp2_pkt.o ngtcp2/ngtcp2_qlog.o ngtcp2/ngtcp2_rtb.o \
	ngtcp2/ngtcp2_version.o ngtcp2/ngtcp2_bbr2.o ngtcp2/ngtcp2_conn.o \
	ngtcp2/ngtcp2_gaptr.o ngtcp2/ngtcp2_mem.o ngtcp2/ngtcp2_pmtud.o \
	ngtcp2/ngtcp2_range.o ngtcp2/ngtcp2_str.o \
	ngtcp2/ngtcp2_window_filter.o ngtcp2/ngtcp2_bbr.o \
	ngtcp2/ngtcp2_conv.o ngtcp2/ngtcp2_idtr.o ngtcp2/ngtcp2_objalloc.o \
	ngtcp2/ngtcp2_ppe.o ngtcp2/ngtcp2_ringbuf.o ngtcp2/ngtcp2_strm.o
