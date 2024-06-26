/*
 * ngtcp2
 *
 * Copyright (c) 2022 ngtcp2 contributors
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

#ifndef _PTLS_H
#define _PTLS_H

#define NGTCP2_MIN_CIDLEN	1
#define NGTCP2_MAX_CIDLEN	20

struct ngtcp2_cid {
	size_t	datalen;
	uint8_t	data[NGTCP2_MAX_CIDLEN];
};

struct nl_msg;

void qked_set_tls_alert(struct nl_msg *, uint8_t);
int qked_tls_early_data_rejected(struct nl_msg *);
int qked_submit_crypto_data(struct nl_msg *, uint8_t, uint8_t *, size_t);
void qked_tls_handshake_completed(struct nl_msg *);
int qked_crypto_derive_and_install_tx_key(struct nl_msg *, uint8_t,
	const void *, size_t);
int qked_crypto_derive_and_install_rx_key(struct nl_msg *, uint8_t,
	const void *, size_t);
int qked_conn_decode_and_set_remote_transport_params(struct nl_msg *,
	uint8_t *, size_t);

int ptls_read_write_crypto_data(struct nl_msg *, struct ngtcp2_cid *,
	uint8_t, const uint8_t *, size_t, uint8_t *, size_t, int);

#endif /* _PTLS_H */
