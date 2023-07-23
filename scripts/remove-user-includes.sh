#!/bin/sh

set -eux

for h in inttypes.h stdarg.h stddef.h sys/types.h ngtcp2/version.h assert.h \
	errno.h stdio.h string.h stdlib.h netinet/in.h sys/socket.h
do
	find ngtcp2 -name '*.[ch]' -exec sed -i -e \
		"s,^#[ 	]*include[ 	]*<$h>,,g" {} \;
done
