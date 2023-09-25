# SPDX-License-Identifier: MIT
#
# Copyright (C) 2023 Moritz Buhl <m.buhl@tum.de>. All rights reserved.

all: test-tcp test-quic test-quic-server test-quic-client
	@$(shell dirname $(realpath $(firstword $(MAKEFILE_LIST))))/test-tcp
	@$(shell dirname $(realpath $(firstword $(MAKEFILE_LIST))))/test-quic

test-tcp: test.c
	${CC} ${CFLAGS} -DDO_TCP test.c -o $@

test-quic: test.c
	${CC} ${CFLAGS} test.c -o $@

test-quic-server: test.c
	${CC} ${CFLAGS} -DDO_SERVER test.c -o $@

test-quic-client: test.c
	${CC} ${CFLAGS} -DDO_CLIENT test.c -o $@

clean:
	rm -f test-tcp test-quic

.PHONY: all clean
