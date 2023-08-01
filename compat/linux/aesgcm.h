#ifndef _COMPAT_AESGCM_H
#define _COMPAT_AESGCM_H

#include <crypto/gcm.h>
#include <crypto/aes.h>
#include <crypto/gf128mul.h>

struct aesgcm_ctx {
	be128			ghash_key;
	struct crypto_aes_ctx	aes_ctx;
	unsigned int		authsize;
};

int aesgcm_expandkey(struct aesgcm_ctx *ctx, const u8 *key,
		     unsigned int keysize, unsigned int authsize);

void aesgcm_encrypt(const struct aesgcm_ctx *ctx, u8 *dst, const u8 *src,
		    int crypt_len, const u8 *assoc, int assoc_len,
		    const u8 iv[GCM_AES_IV_SIZE], u8 *authtag);

bool __must_check aesgcm_decrypt(const struct aesgcm_ctx *ctx, u8 *dst,
				 const u8 *src, int crypt_len, const u8 *assoc,
				 int assoc_len, const u8 iv[GCM_AES_IV_SIZE],
				 const u8 *authtag);

#endif
