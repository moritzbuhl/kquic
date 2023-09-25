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

#include <err.h>
#include <stdint.h>
#include <string.h>

#include <tree.h>

#include <picotls.h>
#include <picotls/openssl.h>

#include "ngtcp_picotls.h"

#define MINIMUM(a,b)	(((a)<(b))?(a):(b))

#define NGTCP2_TLSEXT_QUIC_TRANSPORT_PARAMETERS_V1 0x39u

enum ngtcp2_encryption_level {
	NGTCP2_ENCRYPTION_LEVEL_INITIAL,
	NGTCP2_ENCRYPTION_LEVEL_HANDSHAKE,
	NGTCP2_ENCRYPTION_LEVEL_1RTT,
	NGTCP2_ENCRYPTION_LEVEL_0RTT
};

static const uint8_t H3_ALPN_V1[] = "h3";
static const uint8_t HQ_ALPN_V1[] = "hq-interop";


struct ptls_ctx {
	ptls_t 				*ptls;
	ptls_context_t			 ctx;
	ptls_handshake_properties_t	 handshake_properties;
	RB_ENTRY(ptls_ctx)		 ctx_node;
	struct ngtcp2_cid		 dcid, scid;
};

static int
set_additional_extensions(ptls_handshake_properties_t *hsprops,
	uint8_t *buf, size_t nwrite)
{
	ptls_raw_extension_t *exts;

	warnx("%s", __func__);

	if ((exts = malloc(sizeof(ptls_raw_extension_t) * 2)) == NULL)
		err(1, "malloc");
	exts[1].type = UINT16_MAX;
	hsprops->additional_extensions = exts;

	exts[0].type = NGTCP2_TLSEXT_QUIC_TRANSPORT_PARAMETERS_V1;
	exts[0].data.base = buf;
	exts[0].data.len = nwrite;

	return 0;
}

int
ngtcp2_crypto_picotls_collect_extension(ptls_t *ptls,
	struct st_ptls_handshake_properties_t *properties, uint16_t type)
{
	warnx("%s", __func__);
	return type == NGTCP2_TLSEXT_QUIC_TRANSPORT_PARAMETERS_V1;
}

int
ngtcp2_crypto_picotls_collected_extensions(ptls_t *ptls,
	struct st_ptls_handshake_properties_t *properties,
	ptls_raw_extension_t *extensions)
{
	warnx("XXX NEED IMPLEMENTATION! %s", __func__);

	for (; extensions->type != UINT16_MAX; ++extensions) {
		if (extensions->type !=
		    NGTCP2_TLSEXT_QUIC_TRANSPORT_PARAMETERS_V1)
			continue;
warnx("%s: need ngtcp2_conn_decode_and_set_remote_transport_params", __func__);
/* XXXXXXXXXXXXXXXXX
 * write msg with flags to call the following (at right order!)
 * on kernel side.

		rv = ngtcp2_conn_decode_and_set_remote_transport_params(
			conn, extensions->data.base, extensions->data.len);
		if (rv != 0) {
			ngtcp2_conn_set_tls_error(conn, rv);
			return -1;
		}

		return 0;
	}
*/
	}

	return 0;
}

int
ngtcp2_crypto_picotls_configure_client_session(struct ptls_ctx *cptls,
	uint8_t *tx_data, size_t tx_datalen)
{
	ptls_handshake_properties_t *hsprops = &cptls->handshake_properties;
	ptls_iovec_t *alpn;

	warnx("%s", __func__);

	hsprops->client.max_early_data_size = calloc(1, sizeof(uint32_t));
	if (hsprops->client.max_early_data_size == NULL) {
		return -1;
	}

	if (set_additional_extensions(hsprops, tx_data, tx_datalen) != 0) {
		free(hsprops->client.max_early_data_size);
		hsprops->client.max_early_data_size = NULL;
		return -1;
	}

	hsprops->collect_extension = ngtcp2_crypto_picotls_collect_extension;
	hsprops->collected_extensions = ngtcp2_crypto_picotls_collected_extensions;

	if ((alpn = malloc(sizeof(ptls_iovec_t))) == NULL)
		err(1, "malloc");

	alpn->base = H3_ALPN_V1;
	alpn->len = sizeof(H3_ALPN_V1) - 1; // XXX

	hsprops->client.negotiated_protocols.list = alpn;
	hsprops->client.negotiated_protocols.count = 1;

	return 0;
}

static int
ptls_ctx_cmp(struct ptls_ctx *a, struct ptls_ctx *b)
{
	int rc;

	rc = memcmp(a->dcid.data, b->dcid.data,
		MINIMUM(a->dcid.datalen, b->dcid.datalen));
	if (rc == 0)
		rc = memcmp(a->scid.data, b->scid.data,
			MINIMUM(a->scid.datalen, b->scid.datalen));
	return rc;
}

RB_HEAD(ptls_conns, ptls_ctx) connections = RB_INITIALIZER(&connections);

RB_PROTOTYPE(ptls_conns, ptls_ctx, ctx_node, ptls_ctx_cmp);
RB_GENERATE(ptls_conns, ptls_ctx, ctx_node, ptls_ctx_cmp);

static size_t
ptls_convert_encryption_level(uint8_t encryption_level)
{
	switch (encryption_level) {
	case NGTCP2_ENCRYPTION_LEVEL_INITIAL: return 0;
	case NGTCP2_ENCRYPTION_LEVEL_0RTT: return 1;
	case NGTCP2_ENCRYPTION_LEVEL_HANDSHAKE: return 2;
	case NGTCP2_ENCRYPTION_LEVEL_1RTT: return 3;
	default:
		assert(0);
		abort();
	}
}

uint8_t
ngtcp2_crypto_picotls_from_epoch(size_t epoch)
{
	switch (epoch) {
	case 0: return NGTCP2_ENCRYPTION_LEVEL_INITIAL;
	case 1: return NGTCP2_ENCRYPTION_LEVEL_0RTT;
	case 2: return NGTCP2_ENCRYPTION_LEVEL_HANDSHAKE;
	case 3: return NGTCP2_ENCRYPTION_LEVEL_1RTT;
	default:
		assert(0);
		abort();
	}
}

void
ngtcp2_crypto_picotls_ctx_init(struct ptls_ctx *cptls)
{
	cptls->ptls = NULL;
	memset(&cptls->handshake_properties, 0, sizeof(cptls->handshake_properties));
	memset(&cptls->ctx, 0, sizeof(cptls->ctx));
}

static int
update_traffic_key_cb(ptls_update_traffic_key_t *self, ptls_t *ptls,
	int is_enc, size_t epoch, const void *secret)
{
	warnx("%s !!!!", __func__);
/*
	ngtcp2_crypto_conn_ref *conn_ref = *ptls_get_data_ptr(ptls);
	ngtcp2_conn *conn = conn_ref->get_conn(conn_ref);
	ngtcp2_encryption_level level = ngtcp2_crypto_picotls_from_epoch(epoch);
	ptls_cipher_suite_t *cipher = ptls_get_cipher(ptls);
	size_t secretlen = cipher->hash->digest_size;

	(void)self;

	if (is_enc) {
		if (ngtcp2_crypto_derive_and_install_tx_key(conn, NULL, NULL, NULL, level,
		    secret, secretlen) != 0) {
			return -1;
		}

		return 0;
	}

	if (ngtcp2_crypto_derive_and_install_rx_key(conn, NULL, NULL, NULL,
	    level, secret, secretlen) != 0) {
		return -1;
	}
*/
	return 0;
}

static ptls_update_traffic_key_t update_traffic_key = {update_traffic_key_cb};

ptls_key_exchange_algorithm_t *key_exchanges[] = { /* XXX */
	&ptls_openssl_x25519,
	&ptls_openssl_secp256r1,
	&ptls_openssl_secp384r1,
	&ptls_openssl_secp521r1,
	NULL,
};

ptls_cipher_suite_t *cipher_suites[] = {
	&ptls_openssl_aes128gcmsha256,
	&ptls_openssl_aes256gcmsha384, /* XXX */
	&ptls_openssl_chacha20poly1305sha256, /* XXX */
	NULL,
};

int
ngtcp2_crypto_picotls_configure_client_context(ptls_context_t *ctx)
{
	ctx->omit_end_of_early_data = 1;
	ctx->update_traffic_key = &update_traffic_key;

	ctx->random_bytes = ptls_openssl_random_bytes,
	ctx->get_time = &ptls_get_time;
	ctx->key_exchanges = key_exchanges;
	ctx->cipher_suites = cipher_suites;
	ctx->require_dhe_on_psk = 1;

	return 0;
}

static struct ptls_ctx *
ptls_get_ctx(struct ngtcp2_cid *dcid, struct ngtcp2_cid *scid)
{

	struct ptls_ctx find, *res;
	memcpy(&find.dcid.data, dcid->data, dcid->datalen);
	find.dcid.datalen = dcid->datalen;
	memcpy(&find.scid.data, scid->data, scid->datalen);
	find.scid.datalen = scid->datalen;

	if ((res = RB_FIND(ptls_conns, &connections, &find)) == NULL) {
		if ((res = malloc(sizeof(struct ptls_ctx))) == NULL)
			err(1, "malloc");
		memcpy(res->dcid.data, dcid->data, dcid->datalen);
		res->dcid.datalen = dcid->datalen;
		memcpy(res->scid.data, scid->data, scid->datalen);
		res->scid.datalen = scid->datalen;
		ngtcp2_crypto_picotls_ctx_init(res);
		ngtcp2_crypto_picotls_configure_client_context(&res->ctx);
		res->ptls = ptls_client_new(&res->ctx);
		ptls_set_server_name(res->ptls, "localhost", strlen("localhost")); // XXX

		RB_INSERT(ptls_conns, &connections, res);
	}
	return res;
}

int
ptls_read_write_crypto_data(struct nl_msg *msg, struct ngtcp2_cid *dcid, struct ngtcp2_cid *scid,
	uint8_t encryption_level, const uint8_t *data, size_t datalen,
	uint8_t *tx_data, size_t tx_datalen, int is_server)
{
	struct ptls_ctx *cptls = ptls_get_ctx(dcid, scid);
	ptls_buffer_t sendbuf;
	size_t epoch_offsets[5] = {0};
	size_t epoch = ptls_convert_encryption_level(encryption_level);
	size_t epoch_datalen;
	size_t i;
	int rv;

	warnx("%s", __func__);

	if (tx_data != NULL)
		ngtcp2_crypto_picotls_configure_client_session(cptls, tx_data, tx_datalen);

	ptls_buffer_init(&sendbuf, (void *)"", 0);

	assert(epoch == ptls_get_read_epoch(cptls->ptls));

	rv = ptls_handle_message(cptls->ptls, &sendbuf, epoch_offsets, epoch, data, datalen, &cptls->handshake_properties);

	if (rv != 0 && rv != PTLS_ERROR_IN_PROGRESS) {
		if (PTLS_ERROR_GET_CLASS(rv) == PTLS_ERROR_CLASS_SELF_ALERT) {
			qked_set_tls_alert(msg, (uint8_t)PTLS_ERROR_TO_ALERT(rv));
		}

		rv = -1;
		goto fin;
	}

	if (is_server &&
	    cptls->handshake_properties.client.early_data_acceptance ==
	    PTLS_EARLY_DATA_REJECTED) {
		rv = -1;
		rv = qked_tls_early_data_rejected(msg);
		if (rv != 0) {
			rv = -1;
			goto fin;
		}
	}

	for (i = 0; i < 4; ++i) {
		epoch_datalen = epoch_offsets[i + 1] - epoch_offsets[i];
		if (epoch_datalen == 0) {
			continue;
		}

		assert(i != 1);

		if (qked_submit_crypto_data(msg,
		    ngtcp2_crypto_picotls_from_epoch(i), sendbuf.base +
		    epoch_offsets[i], epoch_datalen) != 0) {
			rv = -1;
			goto fin;
		}
	}

	if (rv == 0) {
		qked_tls_handshake_completed(msg);
	}

	rv = 0;

 fin:
	ptls_buffer_dispose(&sendbuf);

	return rv;
}
