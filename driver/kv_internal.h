/* SPDX-License-Identifier: GPL-2.0 */
/*
 * kv_internal.h - definitions private to the kvault module.
 *
 * Nothing here crosses the syscall boundary; the user-space ABI lives in
 * include/kvault_ioctl.h.
 */
#ifndef _KV_INTERNAL_H
#define _KV_INTERNAL_H

#include <linux/types.h>
#include <linux/list.h>
#include <linux/mutex.h>
#include <linux/timer.h>
#include <linux/wait.h>
#include <linux/cred.h>
#include <linux/fs.h>
#include <linux/poll.h>
#include "../include/kvault_ioctl.h"

#define KV_HASH_BITS        8     /* 256 buckets of secrets */
#define KV_AUDIT_RING_SIZE  1024  /* must be a power of two */
#define KV_UID_MAP_MAX      64    /* uid -> role bindings */

/* One stored secret. The plaintext is never a member: only ciphertext plus
 * the nonce and tag needed to recover it live here. */
struct kv_secret {
	struct hlist_node node;
	char              name[KV_NAME_MAX];
	kuid_t            owner;
	u32               version;
	u64               created_ms;
	u64               modified_ms;
	u8                nonce[KV_NONCE_LEN];
	u8                tag[KV_TAG_LEN];
	u8               *ct;
	u32               ct_len;
	struct kv_acl_entry {
		u32 subject_kind;
		u32 subject_id;
		u32 perms;
	} acl[KV_ACL_MAX];
	u32               acl_count;
};

/* Per-open state. Kept in file->private_data so each fd carries the identity
 * of whoever opened it, captured at open() time. */
struct kv_session {
	kuid_t uid;
	pid_t  pid;
	u64    opened_ms;
	u64    op_count;
	u64    audit_cursor;   /* audit minor: next sequence number to deliver */
};

/* A uid -> role binding. */
struct kv_uid_role {
	u32 uid;
	u32 role_id;
	bool used;
};

/* The whole vault. A single global instance: the device represents one vault,
 * the way a TPM represents one chip. */
struct kv_vault {
	struct mutex       lock;          /* guards everything below */
	u32                state;         /* KV_STATE_* */
	u8                 key[KV_KEY_LEN];
	bool               key_present;
	u8                 kcv[KV_KCV_LEN];
	bool               kcv_present;
	u8                 salt[KV_SALT_LEN];
	u32                kdf_iterations;
	u32                failed_attempts;
	u64                lockout_until_ms;
	u64                last_activity_ms;
	struct hlist_head  secrets[1 << KV_HASH_BITS];
	u32                secret_count;
	struct kv_uid_role uid_roles[KV_UID_MAP_MAX];
	struct timer_list  autolock_timer;
};

extern struct kv_vault kv_vault;

/* Module parameters, defined in kv_main.c. */
extern unsigned int kv_autolock_secs;
extern unsigned int kv_max_attempts;
extern unsigned int kv_lockout_secs;

/* Wall-clock milliseconds, used for timestamps and lockout deadlines. */
static inline u64 kv_now_ms(void)
{
	return ktime_get_real_ns() / NSEC_PER_MSEC;
}

/* kv_store.c */
int  kv_store_init(void);
void kv_store_teardown(void);
struct kv_secret *kv_store_find(const char *name);
struct kv_secret *kv_store_insert(const char *name, kuid_t owner);
void kv_store_remove(struct kv_secret *s);
void kv_store_clear(void);

/* kv_crypto.c */
int  kv_crypto_init(void);
void kv_crypto_exit(void);
int  kv_crypto_encrypt(const u8 *key, const u8 *nonce, const u8 *pt, u32 pt_len,
		       u8 *ct, u8 *tag);
int  kv_crypto_decrypt(const u8 *key, const u8 *nonce, const u8 *ct, u32 ct_len,
		       const u8 *tag, u8 *pt);
int  kv_crypto_kcv(const u8 *key, u8 *kcv_out);
bool kv_crypto_has_aesni(void);

/* kv_acl.c */
u32  kv_role_of(kuid_t uid);
bool kv_is_admin(kuid_t uid);
bool kv_acl_check(const struct kv_secret *s, kuid_t uid, u32 want);
int  kv_acl_set(struct kv_secret *s, u32 kind, u32 id, u32 perms);
int  kv_acl_revoke(struct kv_secret *s, u32 kind, u32 id);
int  kv_role_bind(u32 uid, u32 role_id);

/* kv_audit.c */
int  kv_audit_init(void);
void kv_audit_exit(void);
void kv_audit_log(kuid_t uid, pid_t pid, u32 op, const char *name,
		  u32 result, int err);
ssize_t kv_audit_read(struct kv_session *sess, char __user *buf, size_t count);
__poll_t kv_audit_poll(struct file *filp, struct kv_session *sess,
		       struct poll_table_struct *wait);
u64  kv_audit_seq(void);
u64  kv_audit_dropped_count(void);

/* kv_proc.c */
int  kv_proc_init(void);
void kv_proc_exit(void);

#endif /* _KV_INTERNAL_H */
