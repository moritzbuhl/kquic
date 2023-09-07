/*
 * ngtcp2.h
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

#ifndef _NGTCP2_H
#define _NGTCP2_H

#include "ngtcp2/crypto/shared.h"

void ngtcp_log(void *, const char *, ...);
int get_new_connection_id_cb(ngtcp2_conn *, ngtcp2_cid *, uint8_t *,
	size_t cidlen, void *);
void rand_cb(uint8_t *, size_t, const ngtcp2_rand_ctx *);

ngtcp2_callbacks ngtcp2_cbs = {
	.client_initial = ngtcp2_crypto_client_initial_cb,
	.recv_client_initial = NULL,
	.recv_crypto_data = ngtcp2_crypto_recv_crypto_data_cb,
	.handshake_completed = NULL,
	.recv_version_negotiation = NULL,
	.encrypt = ngtcp2_crypto_encrypt_cb,
	.decrypt = ngtcp2_crypto_decrypt_cb,
	.hp_mask = ngtcp2_crypto_hp_mask_cb,
	.recv_stream_data = NULL,
	.acked_stream_data_offset = NULL,
	.stream_open = NULL,
	.stream_close = NULL,
	.recv_stateless_reset = NULL,
	.recv_retry = ngtcp2_crypto_recv_retry_cb,
	.extend_max_local_streams_bidi = NULL,
	.extend_max_local_streams_uni = NULL,
	.rand = rand_cb,
	.get_new_connection_id = get_new_connection_id_cb,
	.remove_connection_id = NULL,
	.update_key = ngtcp2_crypto_update_key_cb,
	.path_validation = NULL,
	.select_preferred_addr = NULL,
	.stream_reset = NULL,
	.extend_max_remote_streams_bidi = NULL,
	.extend_max_remote_streams_uni = NULL,
	.extend_max_stream_data = NULL,
	.dcid_status = NULL,
	.handshake_confirmed = NULL,
	.recv_new_token = NULL,
	.delete_crypto_aead_ctx = ngtcp2_crypto_delete_crypto_aead_ctx_cb,
	.delete_crypto_cipher_ctx = ngtcp2_crypto_delete_crypto_cipher_ctx_cb,
	.recv_datagram = NULL,
	.ack_datagram = NULL,
	.lost_datagram = NULL,
	.get_path_challenge_data = ngtcp2_crypto_get_path_challenge_data_cb,
	.stream_stop_sending = NULL,
	.version_negotiation = ngtcp2_crypto_version_negotiation_cb,
	.recv_rx_key = NULL,
	.recv_tx_key = NULL,
	.tls_early_data_rejected = NULL, /* XXX: requires more message exchanges in qked */
};

#endif /* _NGTCP2_H */
