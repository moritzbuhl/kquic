# SPDX-License-Identifier: GPL-2.0
#
# Copyright (C) 2020 Dave Voutila <dave@sisu.io>. All rights reserved.

ccflags-y := -O3 -Wall
ccflags-$(CONFIG_INET_QUIC_DEBUG) += -DDEBUG -g

obj-m +=	quic.o
#obj-m +=	ngtcp2/
