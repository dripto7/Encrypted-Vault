// SPDX-License-Identifier: GPL-2.0
/* kv_crypto.c - AES-256-GCM through the kernel crypto API. */
#define pr_fmt(fmt) "kvault: " fmt

#include <linux/module.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <crypto/aead.h>
#include <crypto/hash.h>
#include <crypto/algapi.h>
#include <linux/scatterlist.h>

#include "kv_internal.h"

static struct crypto_aead *kv_aead;
static struct crypto_shash *kv_shash;

int kv_crypto_init(void)
{
	kv_aead = crypto_alloc_aead("gcm(aes)", 0, 0);
	if (IS_ERR(kv_aead)) {
		pr_err("cannot allocate gcm(aes): %ld\n", PTR_ERR(kv_aead));
		return PTR_ERR(kv_aead);
	}
	if (crypto_aead_setauthsize(kv_aead, KV_TAG_LEN)) {
		crypto_free_aead(kv_aead);
		kv_aead = NULL;
		return -EINVAL;
	}

	kv_shash = crypto_alloc_shash("sha256", 0, 0);
	if (IS_ERR(kv_shash)) {
		crypto_free_aead(kv_aead);
		kv_aead = NULL;
		return PTR_ERR(kv_shash);
	}

	pr_info("crypto: %s (driver %s)\n",
		crypto_tfm_alg_name(crypto_aead_tfm(kv_aead)),
		crypto_tfm_alg_driver_name(crypto_aead_tfm(kv_aead)));
	return 0;
}

void kv_crypto_exit(void)
{
	if (kv_shash && !IS_ERR(kv_shash))
		crypto_free_shash(kv_shash);
	if (kv_aead && !IS_ERR(kv_aead))
		crypto_free_aead(kv_aead);
	kv_shash = NULL;
	kv_aead = NULL;
}

/* The driver name of the gcm(aes) implementation the kernel selected for us.
 * Reported in STATUS and in /proc/kvault/stats so the benchmark in the test
 * report can say which code path it measured. */
const char *kv_crypto_driver_name(void)
{
	if (!kv_aead || IS_ERR(kv_aead))
		return "none";
	return crypto_tfm_alg_driver_name(crypto_aead_tfm(kv_aead));
}

bool kv_crypto_accelerated(void)
{
	static const char * const accel[] = { "aesni", "vaes", "aes-ce",
					      "ccp", "padlock" };
	const char *drv = kv_crypto_driver_name();
	size_t i;

	for (i = 0; i < ARRAY_SIZE(accel); i++)
		if (strstr(drv, accel[i]))
			return true;
	return false;
}

/* The key-check value lets UNSEAL tell a wrong passphrase from a right one
 * without keeping anything that could reconstruct the key: it is a hash of
 * the derived key, compared in constant time. */
int kv_crypto_kcv(const u8 *key, u8 *kcv_out)
{
	SHASH_DESC_ON_STACK(desc, kv_shash);
	int ret;

	if (!kv_shash || IS_ERR(kv_shash))
		return -ENODEV;

	desc->tfm = kv_shash;
	ret = crypto_shash_digest(desc, key, KV_KEY_LEN, kcv_out);
	shash_desc_zero(desc);
	return ret;
}

static int kv_gcm(const u8 *key, const u8 *nonce,
		  const u8 *aad, u32 aad_len,
		  const u8 *in, u32 in_len,
		  u8 *out, u8 *tag, bool encrypt)
{
	struct aead_request *req;
	struct scatterlist sg;
	DECLARE_CRYPTO_WAIT(wait);
	u8 *scratch;
	u32 scratch_len;
	u8 iv[KV_NONCE_LEN];
	int ret;

	if (!kv_aead || IS_ERR(kv_aead))
		return -ENODEV;

	scratch_len = aad_len + in_len + KV_TAG_LEN;
	scratch = kzalloc(scratch_len, GFP_KERNEL);
	if (!scratch)
		return -ENOMEM;

	req = aead_request_alloc(kv_aead, GFP_KERNEL);
	if (!req) {
		kfree_sensitive(scratch);
		return -ENOMEM;
	}

	ret = crypto_aead_setkey(kv_aead, key, KV_KEY_LEN);
	if (ret)
		goto out;

	memcpy(scratch, aad, aad_len);
	memcpy(scratch + aad_len, in, in_len);
	if (!encrypt)
		/* Decrypt reads the tag from the end of the payload. */
		memcpy(scratch + aad_len + in_len, tag, KV_TAG_LEN);

	/* The IV must be a copy: the AEAD code may write to the iv buffer, and
	 * the caller's nonce is stored state we must not disturb. */
	memcpy(iv, nonce, sizeof(iv));

	sg_init_one(&sg, scratch, scratch_len);
	aead_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG,
				  crypto_req_done, &wait);
	aead_request_set_ad(req, aad_len);
	aead_request_set_crypt(req, &sg, &sg,
			       encrypt ? in_len : in_len + KV_TAG_LEN, iv);

	if (encrypt)
		ret = crypto_wait_req(crypto_aead_encrypt(req), &wait);
	else
		ret = crypto_wait_req(crypto_aead_decrypt(req), &wait);
	if (ret)
		/* -EBADMSG here is the tamper detection working: either the
		 * ciphertext, the tag or the name was altered. */
		goto out;

	memcpy(out, scratch + aad_len, in_len);
	if (encrypt)
		memcpy(tag, scratch + aad_len + in_len, KV_TAG_LEN);

out:
	memzero_explicit(iv, sizeof(iv));
	aead_request_free(req);
	kfree_sensitive(scratch);
	return ret;
}

int kv_crypto_encrypt(const u8 *key, const u8 *nonce,
		      const u8 *aad, u32 aad_len,
		      const u8 *pt, u32 pt_len, u8 *ct, u8 *tag)
{
	return kv_gcm(key, nonce, aad, aad_len, pt, pt_len, ct, tag, true);
}

int kv_crypto_decrypt(const u8 *key, const u8 *nonce,
		      const u8 *aad, u32 aad_len,
		      const u8 *ct, u32 ct_len, const u8 *tag, u8 *pt)
{
	return kv_gcm(key, nonce, aad, aad_len, ct, ct_len, pt, (u8 *)tag,
		      false);
}

bool kv_crypto_kcv_matches(const u8 *key, const u8 *stored_kcv)
{
	u8 kcv[KV_KCV_LEN];
	bool match;

	if (kv_crypto_kcv(key, kcv))
		return false;
	match = !crypto_memneq(kcv, stored_kcv, KV_KCV_LEN);
	memzero_explicit(kcv, sizeof(kcv));
	return match;
}
