/* SPDX-License-Identifier: GPL-2.0 */
/*
 * kvault_ioctl.h - shared ABI between the kvault kernel module and user space.
 *
 * This header is included by both the driver (kernel C) and the user-space
 * tools (C++17), so it must stay free of anything specific to either side.
 * Every field uses a fixed-width type and the structures are explicitly
 * padded, because the on-disk vault format and the ioctl ABI must not change
 * meaning between compilers or ABIs.
 */
#ifndef _KVAULT_IOCTL_H
#define _KVAULT_IOCTL_H

#ifdef __KERNEL__
#include <linux/types.h>
#include <linux/ioctl.h>
#else
/* linux/types.h gives user space the same __uXX spelling the kernel uses, so
 * the struct definitions below are literally the same text on both sides of
 * the syscall boundary. Defining the typedefs by hand instead would clash
 * with any other header that pulls in linux/types.h. */
#include <linux/types.h>
#include <stdint.h>
#include <sys/ioctl.h>
#endif

#define KV_DEVICE_NAME      "kvault"
#define KV_AUDIT_NAME       "kvault_audit"
#define KV_MINOR_CTL        0
#define KV_MINOR_AUDIT      1
#define KV_MINOR_COUNT      2

/* ABI version. Bumped whenever a struct below changes shape. */
#define KV_ABI_VERSION      1u

/* Sizes. All limits are hard-capped in the kernel; user space must not assume
 * the kernel will accept anything larger just because the buffer is bigger. */
#define KV_NAME_MAX         64u    /* includes the NUL terminator */
#define KV_SECRET_MAX       4096u  /* plaintext bytes per secret */
#define KV_KEY_LEN          32u    /* AES-256 */
#define KV_NONCE_LEN        12u    /* GCM standard nonce */
#define KV_TAG_LEN          16u    /* GCM auth tag */
#define KV_SALT_LEN         16u    /* PBKDF2 salt */
#define KV_KCV_LEN          32u    /* key-check value */
#define KV_ROLE_NAME_MAX    32u
#define KV_ACL_MAX          16u    /* ACL entries per secret */
#define KV_LIST_MAX         64u    /* names returned by one LIST call */

/* Permission bits in an ACL entry. */
#define KV_PERM_READ        (1u << 0)
#define KV_PERM_WRITE       (1u << 1)
#define KV_PERM_DELETE      (1u << 2)
#define KV_PERM_GRANT       (1u << 3)
#define KV_PERM_ALL         (KV_PERM_READ | KV_PERM_WRITE | \
                             KV_PERM_DELETE | KV_PERM_GRANT)

/* An ACL subject is either a concrete UID or a role. One bit of the subject
 * kind keeps the two namespaces from colliding. */
#define KV_SUBJ_UID         0u
#define KV_SUBJ_ROLE        1u

/* Built-in role ids. Roles are fixed at build time: adding roles at runtime
 * would mean a second policy surface in the kernel for no security gain. */
#define KV_ROLE_NONE        0u
#define KV_ROLE_ADMIN       1u
#define KV_ROLE_DEVELOPER   2u
#define KV_ROLE_AUDITOR     3u
#define KV_ROLE_GUEST       4u
#define KV_ROLE_COUNT       5u

/* Vault lifecycle states (see docs/03-design.md state machine). */
#define KV_STATE_SEALED     0u
#define KV_STATE_UNSEALED   1u
#define KV_STATE_AUTO_LOCKED 2u
#define KV_STATE_LOCKED_OUT 3u

/* Operations, as recorded in the audit log. Values are part of the ABI. */
#define KV_OP_UNSEAL        1u
#define KV_OP_SEAL          2u
#define KV_OP_PUT           3u
#define KV_OP_GET           4u
#define KV_OP_DELETE        5u
#define KV_OP_LIST          6u
#define KV_OP_ROTATE        7u
#define KV_OP_GRANT         8u
#define KV_OP_REVOKE        9u
#define KV_OP_SET_ROLE      10u
#define KV_OP_EXPORT        11u
#define KV_OP_IMPORT        12u
#define KV_OP_AUTO_LOCK     13u
#define KV_OP_LOCKOUT       14u

#define KV_RESULT_ALLOW     0u
#define KV_RESULT_DENY      1u

/* --- ioctl payloads ---------------------------------------------------- */

/* UNSEAL: user space derives the key with PBKDF2 and hands it over once. */
struct kv_unseal_arg {
	__u8  key[KV_KEY_LEN];
	__u32 abi_version;
	__u32 _pad;
};

/* PUT / GET: @data is plaintext in both directions. On GET the caller sets
 * @len to the capacity of @data and the kernel writes back the real length. */
struct kv_secret_arg {
	char  name[KV_NAME_MAX];
	__u32 len;
	__u32 _pad;
	__u8  data[KV_SECRET_MAX];
};

/* DELETE / ROTATE and anything else that only needs to name a secret. */
struct kv_name_arg {
	char  name[KV_NAME_MAX];
};

/* LIST: the kernel fills @names with the secrets this caller may READ and
 * sets @count. Secrets the caller cannot read are omitted rather than
 * reported as denied, so LIST does not leak the namespace. */
struct kv_list_arg {
	__u32 count;
	__u32 _pad;
	char  names[KV_LIST_MAX][KV_NAME_MAX];
};

/* GRANT / REVOKE: @perms is a KV_PERM_* mask. */
struct kv_grant_arg {
	char  name[KV_NAME_MAX];
	__u32 subject_kind;   /* KV_SUBJ_UID or KV_SUBJ_ROLE */
	__u32 subject_id;     /* uid, or KV_ROLE_* */
	__u32 perms;
	__u32 _pad;
};

/* SET_ROLE: bind a UID to a role. Admin only. */
struct kv_setrole_arg {
	__u32 uid;
	__u32 role_id;
};

/* STATUS: never contains key material or plaintext. */
struct kv_status_arg {
	__u32 abi_version;
	__u32 state;              /* KV_STATE_* */
	__u32 secret_count;
	__u32 failed_attempts;
	__u32 max_attempts;
	__u32 auto_lock_secs;
	__u64 lockout_until_ms;   /* 0 when not locked out */
	__u64 last_activity_ms;
	__u32 caller_uid;
	__u32 caller_role;
	__u32 has_aesni;
	__u32 _pad;
};

/* EXPORT / IMPORT move the sealed blob across the boundary. The kernel never
 * touches the filesystem itself: user space owns persistence, and what it
 * gets handed is ciphertext, nonces and tags only.
 *
 * A sealed vault can reach a megabyte, which does not fit in an ioctl command
 * number (_IOC_SIZEBITS is 14 bits, so the largest struct an _IOW/_IOR code
 * can describe is 16383 bytes). The argument is therefore a small descriptor
 * carrying a user-space pointer, and the driver copies the blob through that
 * pointer in a second step. __u64 rather than a real pointer keeps the struct
 * the same size for 32- and 64-bit callers. */
#define KV_BLOB_MAX         (1u << 20)   /* 1 MiB of sealed vault */

struct kv_blob_arg {
	__u64 buf;      /* user-space address of the blob buffer */
	__u32 len;      /* in: capacity (EXPORT) or blob size (IMPORT); out: size written */
	__u32 _pad;
};

/* --- audit records ----------------------------------------------------- */

/* Read from /dev/kvault_audit as a stream of fixed-size records. Fixed size
 * means a short read can never split a record in a way the reader has to
 * reassemble. */
struct kv_audit_rec {
	__u64 seq;
	__u64 timestamp_ms;
	__u32 uid;
	__u32 pid;
	__u32 op;           /* KV_OP_* */
	__u32 result;       /* KV_RESULT_ALLOW / KV_RESULT_DENY */
	__s32 err;          /* 0 or -errno */
	__u32 role;
	char  name[KV_NAME_MAX];
};

/* --- on-disk sealed vault format -------------------------------------- */

#define KV_FILE_MAGIC       0x4B56414Cu   /* "KVAL" */
#define KV_FILE_VERSION     1u

/* All multi-byte fields in the file are little-endian: the format is written
 * by one architecture and may be read by another, so the byte order is
 * pinned rather than left to the host. */
struct kv_file_header {
	__u32 magic;
	__u32 version;
	__u32 kdf_iterations;
	__u32 entry_count;
	__u8  salt[KV_SALT_LEN];
	__u8  kcv[KV_KCV_LEN];
};

struct kv_file_entry {
	char  name[KV_NAME_MAX];
	__u32 owner_uid;
	__u32 version;
	__u64 created_ms;
	__u64 modified_ms;
	__u32 ct_len;
	__u32 acl_count;
	__u8  nonce[KV_NONCE_LEN];
	__u8  tag[KV_TAG_LEN];
	/* followed by acl_count * struct kv_file_acl, then ct_len ciphertext bytes */
};

struct kv_file_acl {
	__u32 subject_kind;
	__u32 subject_id;
	__u32 perms;
	__u32 _pad;
};

/* --- ioctl codes ------------------------------------------------------- */

#define KV_IOC_MAGIC        'K'

/* Vault state */
#define KVAULT_UNSEAL       _IOW(KV_IOC_MAGIC,  1, struct kv_unseal_arg)
#define KVAULT_SEAL         _IO(KV_IOC_MAGIC,   2)
#define KVAULT_STATUS       _IOR(KV_IOC_MAGIC,  3, struct kv_status_arg)
/* Secrets */
#define KVAULT_PUT          _IOW(KV_IOC_MAGIC, 10, struct kv_secret_arg)
#define KVAULT_GET          _IOWR(KV_IOC_MAGIC, 11, struct kv_secret_arg)
#define KVAULT_DELETE       _IOW(KV_IOC_MAGIC, 12, struct kv_name_arg)
#define KVAULT_LIST         _IOR(KV_IOC_MAGIC, 13, struct kv_list_arg)
#define KVAULT_ROTATE       _IOW(KV_IOC_MAGIC, 14, struct kv_name_arg)
/* Access control */
#define KVAULT_GRANT        _IOW(KV_IOC_MAGIC, 20, struct kv_grant_arg)
#define KVAULT_REVOKE       _IOW(KV_IOC_MAGIC, 21, struct kv_grant_arg)
#define KVAULT_SET_ROLE     _IOW(KV_IOC_MAGIC, 22, struct kv_setrole_arg)
/* Persistence */
#define KVAULT_EXPORT       _IOWR(KV_IOC_MAGIC, 30, struct kv_blob_arg)
#define KVAULT_IMPORT       _IOW(KV_IOC_MAGIC, 31, struct kv_blob_arg)

#endif /* _KVAULT_IOCTL_H */
