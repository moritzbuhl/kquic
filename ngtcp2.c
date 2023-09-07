/*
 * ngtcp2.c
 *
 * Copyright (c) 2023 Moritz Buhl <m.buhl@tum.de>
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
 * LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
 * OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
 * WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

#include <linux/random.h>

#include "config.h"
#include "ngtcp2/ngtcp2/ngtcp2.h"

#define NGTCP2_LOG_BUFLEN	4096
void ngtcp_log(void *user_data, const char *fmt, ...) {
	va_list args;
	int rc;
	char buf[NGTCP2_LOG_BUFLEN];

	va_start(args, fmt);
	rc = vsnprintf(buf, sizeof(buf), fmt, args);
	va_end(args);

	if (rc < 0 || (size_t)rc >= sizeof(buf)) {
		return;
	}

	printk(buf);
}

int get_new_connection_id_cb(ngtcp2_conn *conn, ngtcp2_cid *cid,
		uint8_t *token, size_t cidlen,
		void *user_data) {

	get_random_bytes(cid->data, cidlen);

	cid->datalen = cidlen;

	get_random_bytes(token, NGTCP2_STATELESS_RESET_TOKENLEN);

	return 0;
}

void rand_cb(uint8_t *dest, size_t destlen, const ngtcp2_rand_ctx *rand_ctx) {
	get_random_bytes(dest, destlen);
}
