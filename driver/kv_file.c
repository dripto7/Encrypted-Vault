// SPDX-License-Identifier: GPL-2.0
/*
 * kv_file.c - serialise the vault to a sealed blob and back.
 *
 * The blob is what user space writes to disk. It contains ciphertext, nonces,
 * tags, ACLs and the KDF parameters: everything needed to reconstruct the vault
 * given the right passphrase, and nothing that helps without it.
 *
 * Two rules govern this file:
 *
 * 1. Every multi-byte field is written little-endian with the cpu_to_le*
 *    helpers, even though the development machine is already little-endian.
 *    A format whose byte order is "whatever the writer happened to use" is not
 *    a format, and the bug only ever shows up on someone else's hardware.
 *
 * 2. Everything parsed in kv_import() is untrusted. The blob may have been
 *    edited by anyone who could reach the file, so every length is bounds-
 *    checked against what remains of the buffer before it is used, and the
 *    arithmetic is done in a way that cannot wrap.
 *
 * Callers must hold kv_vault.lock.
 */
#define pr_fmt(fmt) "kvault: " fmt

#include <linux/module.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <asm/byteorder.h>
#include <crypto/algapi.h>

#include "kv_internal.h"

/* Size the blob will occupy. Returns 0 if it would exceed KV_BLOB_MAX. */
u32 kv_export_size(void)
{
	struct kv_secret *s;
	u64 total = sizeof(struct kv_file_header);
	int i;

	for (i = 0; i < (1 << KV_HASH_BITS); i++) {
		hlist_for_each_entry(s, &kv_vault.secrets[i], node) {
			total += sizeof(struct kv_file_entry);
			total += (u64)s->acl_count * sizeof(struct kv_file_acl);
			total += s->ct_len;
			if (total > KV_BLOB_MAX)
				return 0;
		}
	}
	return (u32)total;
}

int kv_export(u8 *buf, u32 cap, u32 *out_len)
{
	struct kv_file_header hdr;
	struct kv_secret *s;
	u32 need = kv_export_size();
	u32 off = 0;
	int i;
	u32 j;

	if (!need)
		return -E2BIG;
	if (cap < need) {
		*out_len = need;
		return -ENOSPC;
	}

	memset(&hdr, 0, sizeof(hdr));
	hdr.magic          = cpu_to_le32(KV_FILE_MAGIC);
	hdr.version        = cpu_to_le32(KV_FILE_VERSION);
	hdr.kdf_iterations = cpu_to_le32(kv_vault.kdf_iterations);
	hdr.entry_count    = cpu_to_le32(kv_vault.secret_count);
	memcpy(hdr.salt, kv_vault.salt, KV_SALT_LEN);
	memcpy(hdr.kcv, kv_vault.kcv, KV_KCV_LEN);

	memcpy(buf, &hdr, sizeof(hdr));
	off = sizeof(hdr);

	for (i = 0; i < (1 << KV_HASH_BITS); i++) {
		hlist_for_each_entry(s, &kv_vault.secrets[i], node) {
			struct kv_file_entry e;

			memset(&e, 0, sizeof(e));
			strscpy(e.name, s->name, sizeof(e.name));
			e.owner_uid  = cpu_to_le32(from_kuid(&init_user_ns,
							     s->owner));
			e.version    = cpu_to_le32(s->version);
			e.created_ms = cpu_to_le64(s->created_ms);
			e.modified_ms = cpu_to_le64(s->modified_ms);
			e.ct_len     = cpu_to_le32(s->ct_len);
			e.acl_count  = cpu_to_le32(s->acl_count);
			memcpy(e.nonce, s->nonce, KV_NONCE_LEN);
			memcpy(e.tag, s->tag, KV_TAG_LEN);

			memcpy(buf + off, &e, sizeof(e));
			off += sizeof(e);

			for (j = 0; j < s->acl_count; j++) {
				struct kv_file_acl a;

				a.subject_kind = cpu_to_le32(s->acl[j].subject_kind);
				a.subject_id   = cpu_to_le32(s->acl[j].subject_id);
				a.perms        = cpu_to_le32(s->acl[j].perms);
				a._pad         = 0;
				memcpy(buf + off, &a, sizeof(a));
				off += sizeof(a);
			}

			memcpy(buf + off, s->ct, s->ct_len);
			off += s->ct_len;
		}
	}

	*out_len = off;
	return 0;
}

/*
 * Verify one entry's ciphertext without keeping the plaintext.
 *
 * This is the whole tamper story: GCM's tag covers the ciphertext and the
 * associated data, which here is the secret's name, so a single flipped bit
 * anywhere in either makes crypto_aead_decrypt return -EBADMSG. Import checks
 * every entry before it commits any of them, so a damaged file does not get
 * half-loaded.
 */
static int kv_verify_entry(const char *name, const u8 *nonce, const u8 *ct,
			   u32 ct_len, const u8 *tag)
{
	u8 *pt;
	int ret;

	pt = kzalloc(ct_len, GFP_KERNEL);
	if (!pt)
		return -ENOMEM;

	ret = kv_crypto_decrypt(kv_vault.key, nonce, (const u8 *)name,
				KV_NAME_MAX, ct, ct_len, tag, pt);
	kfree_sensitive(pt);
	return ret;
}

int kv_import(const u8 *buf, u32 len)
{
	struct kv_file_header hdr;
	u32 entry_count;
	u32 pass;
	int ret = 0;

	if (len < sizeof(hdr))
		return -EINVAL;

	memcpy(&hdr, buf, sizeof(hdr));
	if (le32_to_cpu(hdr.magic) != KV_FILE_MAGIC)
		return -EINVAL;
	if (le32_to_cpu(hdr.version) != KV_FILE_VERSION)
		return -EPROTO;

	/* The key currently loaded must be the key this file was sealed with.
	 * Checking the key-check value first turns "every entry failed its tag"
	 * into a single clear answer: wrong passphrase, not a corrupt file. */
	if (crypto_memneq(hdr.kcv, kv_vault.kcv, KV_KCV_LEN))
		return -EACCES;

	entry_count = le32_to_cpu(hdr.entry_count);

	/*
	 * Two passes. The first validates and authenticates everything against
	 * the untrusted buffer; only if that succeeds does the second pass
	 * mutate the store. An import that fails leaves the running vault
	 * exactly as it was.
	 */
	for (pass = 0; pass < 2; pass++) {
		u32 off = sizeof(hdr);
		u32 n;

		if (pass == 1)
			kv_store_clear();

		for (n = 0; n < entry_count; n++) {
			struct kv_file_entry e;
			struct kv_secret *s;
			const u8 *ct;
			u32 acl_count, ct_len, j;

			/* Bounds are checked by subtracting from what remains,
			 * never by adding to the offset: off + need could wrap
			 * and pass a comparison it should fail. */
			if (len - off < sizeof(e))
				return -EINVAL;
			memcpy(&e, buf + off, sizeof(e));
			off += sizeof(e);

			e.name[KV_NAME_MAX - 1] = '\0';
			if (strnlen(e.name, KV_NAME_MAX) == 0)
				return -EINVAL;

			acl_count = le32_to_cpu(e.acl_count);
			ct_len    = le32_to_cpu(e.ct_len);
			if (acl_count > KV_ACL_MAX)
				return -EINVAL;
			if (ct_len == 0 || ct_len > KV_SECRET_MAX)
				return -EINVAL;
			if (len - off < acl_count * sizeof(struct kv_file_acl))
				return -EINVAL;

			if (pass == 0) {
				/* Skip the ACLs; pass 1 reads them. */
				const u32 acl_bytes =
					acl_count * sizeof(struct kv_file_acl);

				if (len - off - acl_bytes < ct_len)
					return -EINVAL;
				ct = buf + off + acl_bytes;
				ret = kv_verify_entry(e.name, e.nonce, ct,
						      ct_len, e.tag);
				if (ret) {
					pr_warn("import: entry '%s' failed authentication (%d)\n",
						e.name, ret);
					return ret == -EBADMSG ? -EBADMSG : ret;
				}
				off += acl_bytes + ct_len;
				continue;
			}

			s = kv_store_insert(e.name,
					    make_kuid(&init_user_ns,
						      le32_to_cpu(e.owner_uid)));
			if (!s)
				return -ENOMEM;

			s->version     = le32_to_cpu(e.version);
			s->created_ms  = le64_to_cpu(e.created_ms);
			s->modified_ms = le64_to_cpu(e.modified_ms);
			memcpy(s->nonce, e.nonce, KV_NONCE_LEN);
			memcpy(s->tag, e.tag, KV_TAG_LEN);

			for (j = 0; j < acl_count; j++) {
				struct kv_file_acl a;

				memcpy(&a, buf + off, sizeof(a));
				off += sizeof(a);
				s->acl[j].subject_kind =
					le32_to_cpu(a.subject_kind);
				s->acl[j].subject_id = le32_to_cpu(a.subject_id);
				s->acl[j].perms      = le32_to_cpu(a.perms);
			}
			s->acl_count = acl_count;

			if (len - off < ct_len)
				return -EINVAL;
			s->ct = kzalloc(ct_len, GFP_KERNEL);
			if (!s->ct)
				return -ENOMEM;
			memcpy(s->ct, buf + off, ct_len);
			s->ct_len = ct_len;
			off += ct_len;
		}
	}

	pr_info("imported %u secrets\n", entry_count);
	return 0;
}
