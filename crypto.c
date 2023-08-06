/*
 * crypto.c
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

/* do not use the wolfcrypt AES implementation, use the kernel one instead. */
#define NO_AES

#include <crypto/aead.h>
#include <crypto/gcm.h>

#include <wolfssl/wolfcrypt/hmac.h>

#include "config.h"
#include "ngtcp2/ngtcp2/ngtcp2.h"
#include "ngtcp2/crypto/shared.h"

#if LINUX_VERSION_CODE < KERNEL_VERSION(6,2,0)
# include "compat/linux/aesgcm.h"
#endif


int ngtcp2_crypto_hkdf_expand(uint8_t *dest, size_t destlen,
		const ngtcp2_crypto_md *md, const uint8_t *secret,
		size_t secretlen, const uint8_t *info,
		size_t infolen) {
	pr_info("%s\n", __func__);
	if (destlen > UINT_MAX || secretlen > UINT_MAX || infolen > UINT_MAX)
		return -1;

	return wc_HKDF_Expand(WC_SHA256, secret, secretlen, info, infolen, dest,
			destlen);
}

int ngtcp2_crypto_hkdf_extract(uint8_t *dest, const ngtcp2_crypto_md *md,
		const uint8_t *secret, size_t secretlen,
		const uint8_t *salt, size_t saltlen) {
	pr_info("%s\n", __func__);

	if (saltlen > UINT_MAX || secretlen > UINT_MAX)
		return -1;

	return wc_HKDF_Extract(WC_SHA256, salt, saltlen, secret, secretlen, dest);
}

int ngtcp2_crypto_hkdf(uint8_t *dest, size_t destlen,
		const ngtcp2_crypto_md *md, const uint8_t *secret,
		size_t secretlen, const uint8_t *salt, size_t saltlen,
		const uint8_t *info, size_t infolen) {
	pr_info("%s\n", __func__);

	if (destlen > UINT_MAX || infolen > UINT_MAX || saltlen > UINT_MAX ||
			secretlen > UINT_MAX)
		return -1;

	return wc_HKDF(WC_SHA256, secret, secretlen, salt, saltlen, info,
		infolen, dest, destlen);
}

int ngtcp2_crypto_aead_ctx_decrypt_init(ngtcp2_crypto_aead_ctx *aead_ctx,
		const ngtcp2_crypto_aead *aead,
		const uint8_t *key, size_t noncelen) {
	struct aesgcm_ctx *hd;
	unsigned int keylen;

	pr_info("%s\n", __func__);

	if ((hd = kmalloc(sizeof(struct crypto_aes_ctx), GFP_KERNEL)) == NULL)
		return -1;

	keylen = ngtcp2_crypto_aead_keylen(aead);
	if (aesgcm_expandkey(hd, key, keylen, noncelen) != 0)
		return -1;

	aead_ctx->native_handle = hd;
	return 0;
}

int ngtcp2_crypto_aead_ctx_encrypt_init(ngtcp2_crypto_aead_ctx *aead_ctx,
		const ngtcp2_crypto_aead *aead,
		const uint8_t *key, size_t noncelen) {
	pr_info("%s\n", __func__);
	return ngtcp2_crypto_aead_ctx_decrypt_init(aead_ctx, aead, key,
		noncelen);
}

int ngtcp2_crypto_decrypt(uint8_t *dest, const ngtcp2_crypto_aead *aead,
		const ngtcp2_crypto_aead_ctx *aead_ctx,
		const uint8_t *ciphertext, size_t ciphertextlen,
		const uint8_t *nonce, size_t noncelen,
		const uint8_t *aad, size_t aadlen) {
	uint8_t *auth_tag = dest + ciphertextlen;
	pr_info("%s\n", __func__);

	if (!aesgcm_decrypt(aead_ctx->native_handle, dest, ciphertext,
                    ciphertextlen, aad, aadlen, nonce, auth_tag))
		return -1;
	return 0;
}

int ngtcp2_crypto_encrypt(uint8_t *dest, const ngtcp2_crypto_aead *aead,
		const ngtcp2_crypto_aead_ctx *aead_ctx,
		const uint8_t *plaintext, size_t plaintextlen,
		const uint8_t *nonce, size_t noncelen,
		const uint8_t *aad, size_t aadlen) {
	uint8_t *auth_dest = dest + plaintextlen;
	pr_info("%s\n", __func__);

	aesgcm_encrypt(aead_ctx->native_handle, dest, plaintext,
                    plaintextlen, aad, aadlen, nonce, auth_dest);
	return 0;
}

ngtcp2_crypto_aead *ngtcp2_crypto_aead_init(ngtcp2_crypto_aead *aead,
		void *aead_native_handle) {
	pr_info("%s\n", __func__);
	aead->native_handle = aead_native_handle;
	aead->max_overhead = GCM_AES_IV_SIZE;
	return aead;
}

ngtcp2_crypto_aead *ngtcp2_crypto_aead_retry(ngtcp2_crypto_aead *aead) {
	pr_info("%s\n", __func__);
	return ngtcp2_crypto_aead_init(aead, NULL);
}

size_t ngtcp2_crypto_md_hashlen(const ngtcp2_crypto_md *md) {
	pr_info("%s\n", __func__);
	return 0;
}

void ngtcp2_crypto_aead_ctx_free(ngtcp2_crypto_aead_ctx *aead_ctx) {
	pr_info("%s\n", __func__);
	if (aead_ctx->native_handle)
		kfree(aead_ctx->native_handle);
}

int ngtcp2_crypto_set_remote_transport_params(ngtcp2_conn *conn, void *tls) {
	pr_info("%s\n", __func__);
	return 0;
}

size_t ngtcp2_crypto_aead_noncelen(const ngtcp2_crypto_aead *aead) {
	pr_info("%s\n", __func__);
	return ((struct aesgcm_ctx *)aead->native_handle)->authsize;
}


ngtcp2_crypto_ctx *ngtcp2_crypto_ctx_initial(ngtcp2_crypto_ctx *ctx) {
	pr_info("%s\n", __func__);
	return NULL;
}

ngtcp2_crypto_ctx *ngtcp2_crypto_ctx_tls(ngtcp2_crypto_ctx *ctx,
		void *tls_native_handle) {
	pr_info("%s\n", __func__);
	return NULL;
}
 
size_t ngtcp2_crypto_aead_keylen(const ngtcp2_crypto_aead *aead) {
	/* only aes_128_gcm */
	pr_info("%s\n", __func__);
	return 16;
}

ngtcp2_crypto_ctx *ngtcp2_crypto_ctx_tls_early(ngtcp2_crypto_ctx *ctx,
		void *tls_native_handle) {
	pr_info("%s\n", __func__);
	return ngtcp2_crypto_ctx_tls(ctx, tls_native_handle);
}

int ngtcp2_crypto_read_write_crypto_data( ngtcp2_conn *conn,
		ngtcp2_encryption_level encryption_level,
		const uint8_t *data, size_t datalen) {
	pr_info("%s\n", __func__);
	return -1;
}

int ngtcp2_crypto_hp_mask(uint8_t *dest, const ngtcp2_crypto_cipher *hp,
		const ngtcp2_crypto_cipher_ctx *hp_ctx, const uint8_t *sample) {
	pr_info("%s\n", __func__);
	return 0;
}

int ngtcp2_crypto_random(uint8_t *data, size_t datalen) {
	pr_info("%s\n", __func__);
	get_random_bytes(data, datalen);
	return 0;
}

int ngtcp2_crypto_get_path_challenge_data_cb(ngtcp2_conn *conn, uint8_t *data,
		void *user_data) {
	pr_info("%s\n", __func__);
	get_random_bytes(data, NGTCP2_PATH_CHALLENGE_DATALEN);
	return 0;
}

int ngtcp2_crypto_cipher_ctx_encrypt_init(ngtcp2_crypto_cipher_ctx *cipher_ctx,
		const ngtcp2_crypto_cipher *cipher, const uint8_t *key) {
	pr_info("%s\n", __func__);
	return 0;
}

int ngtcp2_crypto_set_local_transport_params(void *tls, const uint8_t *buf,
		size_t len) {
	pr_info("%s\n", __func__);
	return 0;
}

void ngtcp2_crypto_cipher_ctx_free(ngtcp2_crypto_cipher_ctx *cipher_ctx) {
	pr_info("%s\n", __func__);
	return;
}

ngtcp2_crypto_md *ngtcp2_crypto_md_sha256(ngtcp2_crypto_md *md) {
	pr_info("%s\n", __func__);
	return md;
}

ngtcp2_crypto_aead *ngtcp2_crypto_aead_aes_128_gcm(ngtcp2_crypto_aead *aead) {
	pr_info("%s\n", __func__);
	return ngtcp2_crypto_aead_init(aead, NULL);
}
