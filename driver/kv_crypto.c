// SPDX-License-Identifier: GPL-2.0
/*
 * kv_crypto.c - AES-256-GCM through the kernel crypto API.
 *
 * The module never implements a cipher itself: it allocates "gcm(aes)" and
 * lets the kernel pick the best implementation available, which on a CPU with
 * the aes flag means the AES-NI driver.
 *
 * GCM rather than CBC because an encrypt-then-MAC construction is needed for
 * tamper detection; with GCM the authentication tag comes from the same pass
 * and a flipped byte in the vault file fails the tag check on import.
 */
#define pr_fmt(fmt) "kvault: " fmt

#include <linux/module.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <crypto/aead.h>
#include <crypto/hash.h>

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

/* Whether the active gcm(aes) implementation is the hardware-accelerated one.
 * Reported in STATUS and used by the benchmark in the test report. */
bool kv_crypto_has_aesni(void)
{
	const char *drv;

	if (!kv_aead || IS_ERR(kv_aead))
		return false;
	drv = crypto_tfm_alg_driver_name(crypto_aead_tfm(kv_aead));
	return drv && strstr(drv, "aesni") != NULL;
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

int kv_crypto_encrypt(const u8 *key, const u8 *nonce, const u8 *pt, u32 pt_len,
		      u8 *ct, u8 *tag)
{
	/* Filled in at the v0.4 milestone (PUT/GET with AES-GCM). */
	return -ENOSYS;
}

int kv_crypto_decrypt(const u8 *key, const u8 *nonce, const u8 *ct, u32 ct_len,
		      const u8 *tag, u8 *pt)
{
	return -ENOSYS;
}
