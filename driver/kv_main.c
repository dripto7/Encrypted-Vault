// SPDX-License-Identifier: GPL-2.0
/* kv_main.c - character device, per-open sessions and ioctl dispatch. */
#define pr_fmt(fmt) "kvault: " fmt

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/capability.h>
#include <linux/random.h>

#include "kv_internal.h"

struct kv_vault kv_vault;

unsigned int kv_autolock_secs = 300;
unsigned int kv_max_attempts  = 3;
unsigned int kv_lockout_secs  = 60;
unsigned int kv_max_secrets   = 1024;

module_param_named(autolock_secs, kv_autolock_secs, uint, 0644);
MODULE_PARM_DESC(autolock_secs, "Seconds of inactivity before the vault auto-locks (0 disables)");
module_param_named(max_attempts, kv_max_attempts, uint, 0644);
MODULE_PARM_DESC(max_attempts, "Failed unseal attempts before lockout");
module_param_named(lockout_secs, kv_lockout_secs, uint, 0644);
MODULE_PARM_DESC(lockout_secs, "Lockout duration in seconds after too many failed unseals");
module_param_named(max_secrets, kv_max_secrets, uint, 0644);
MODULE_PARM_DESC(max_secrets, "Maximum number of secrets the vault will hold");

static dev_t kv_devt;
static struct cdev kv_cdev;
static struct class *kv_class;

/* --- lifecycle helpers ------------------------------------------------- */

/* Drop the master key. Called on seal, auto-lock and module unload.
 * memzero_explicit, not memset: the compiler is allowed to delete a memset
 * whose result is never read, and that is exactly the case here. */
static void kv_wipe_key(void)
{
	memzero_explicit(kv_vault.key, sizeof(kv_vault.key));
	kv_vault.key_present = false;
}

/* Caller must hold kv_vault.lock. */
static void kv_do_seal(u32 new_state)
{
	kv_wipe_key();
	kv_vault.state = new_state;
	timer_delete(&kv_vault.autolock_timer);
}

static void kv_touch_locked(void)
{
	kv_vault.last_activity_ms = kv_now_ms();
	if (kv_vault.state == KV_STATE_UNSEALED && kv_autolock_secs)
		mod_timer(&kv_vault.autolock_timer,
			  jiffies + kv_autolock_secs * HZ);
}

/* Timer context: no sleeping, so take the lock without blocking and simply
 * re-arm if somebody else is mid-operation. */
static void kv_autolock_fn(struct timer_list *t)
{
	if (!mutex_trylock(&kv_vault.lock)) {
		mod_timer(&kv_vault.autolock_timer, jiffies + HZ);
		return;
	}
	if (kv_vault.state == KV_STATE_UNSEALED) {
		kv_do_seal(KV_STATE_AUTO_LOCKED);
		pr_info("auto-locked after %u s of inactivity\n", kv_autolock_secs);
		kv_audit_log(GLOBAL_ROOT_UID, 0, KV_OP_AUTO_LOCK, "", KV_RESULT_ALLOW, 0);
	}
	mutex_unlock(&kv_vault.lock);
}

/* --- file operations --------------------------------------------------- */

static int kv_open(struct inode *inode, struct file *filp)
{
	struct kv_session *sess;

	sess = kzalloc(sizeof(*sess), GFP_KERNEL);
	if (!sess)
		return -ENOMEM;

	sess->uid       = current_uid();
	sess->pid       = current->pid;
	sess->opened_ms = kv_now_ms();
	/* An audit reader starts at the current end of the log: it streams what
	 * happens from now on rather than replaying history on every open. */
	sess->audit_cursor = kv_audit_seq();

	filp->private_data = sess;
	return 0;
}

static int kv_release(struct inode *inode, struct file *filp)
{
	kfree_sensitive(filp->private_data);
	filp->private_data = NULL;
	return 0;
}

static ssize_t kv_read(struct file *filp, char __user *buf, size_t count,
		       loff_t *ppos)
{
	if (iminor(file_inode(filp)) != KV_MINOR_AUDIT)
		return -EINVAL;
	return kv_audit_read(filp->private_data, buf, count);
}

static __poll_t kv_poll(struct file *filp, struct poll_table_struct *wait)
{
	if (iminor(file_inode(filp)) != KV_MINOR_AUDIT)
		return 0;
	return kv_audit_poll(filp, filp->private_data, wait);
}

/* --- request validation ------------------------------------------------ */

static int kv_check_name(char *name)
{
	size_t len;
	size_t i;

	/* Force termination rather than trusting the caller to have done it:
	 * everything downstream treats this as a C string. */
	name[KV_NAME_MAX - 1] = '\0';
	len = strnlen(name, KV_NAME_MAX);
	if (len == 0 || len >= KV_NAME_MAX)
		return -EINVAL;

	for (i = 0; i < len; i++) {
		const char c = name[i];

		if (!(c >= 'a' && c <= 'z') && !(c >= 'A' && c <= 'Z') &&
		    !(c >= '0' && c <= '9') && c != '_' && c != '-' && c != '.')
			return -EINVAL;
	}
	return 0;
}

/* Must hold the lock. Resolves the lockout deadline before anything else looks
 * at the state, so an expired lockout does not keep the vault shut. */
static void kv_expire_lockout(void)
{
	if (kv_vault.state == KV_STATE_LOCKED_OUT &&
	    kv_now_ms() >= kv_vault.lockout_until_ms) {
		kv_vault.state = KV_STATE_SEALED;
		kv_vault.failed_attempts = 0;
		kv_vault.lockout_until_ms = 0;
	}
}

/* --- vault lifecycle --------------------------------------------------- */

static int kv_ioctl_unseal(struct kv_session *sess, void __user *uarg)
{
	struct kv_unseal_arg *arg;
	int ret;

	/* Unsealing is administrative: it is the operation that makes every
	 * other operation possible. */
	if (!kv_is_admin(sess->uid)) {
		kv_audit_log(sess->uid, sess->pid, KV_OP_UNSEAL, "",
			     KV_RESULT_DENY, -EACCES);
		return -EACCES;
	}

	arg = kzalloc(sizeof(*arg), GFP_KERNEL);
	if (!arg)
		return -ENOMEM;

	if (copy_from_user(arg, uarg, sizeof(*arg))) {
		ret = -EFAULT;
		goto out;
	}
	if (arg->abi_version != KV_ABI_VERSION || arg->kdf_iterations == 0) {
		ret = -EINVAL;
		goto out;
	}

	mutex_lock(&kv_vault.lock);
	kv_expire_lockout();

	if (kv_vault.state == KV_STATE_LOCKED_OUT) {
		/* Refused without the key-check being performed at all: a
		 * locked-out attacker learns nothing about the passphrase, not
		 * even how long checking it took. */
		ret = -EAGAIN;
		goto unlock;
	}
	if (kv_vault.state == KV_STATE_UNSEALED) {
		ret = -EALREADY;
		goto unlock;
	}

	if (!kv_vault.kcv_present) {
		/* First unseal of an empty vault: adopt this passphrase. There
		 * is nothing to check it against, and refusing would leave the
		 * vault permanently unusable. */
		ret = kv_crypto_kcv(arg->key, kv_vault.kcv);
		if (ret)
			goto unlock;
		kv_vault.kcv_present = true;
		memcpy(kv_vault.salt, arg->salt, KV_SALT_LEN);
		kv_vault.kdf_iterations = arg->kdf_iterations;
		pr_info("vault initialized by uid %u\n",
			from_kuid(&init_user_ns, sess->uid));
	} else if (!kv_crypto_kcv_matches(arg->key, kv_vault.kcv)) {
		kv_vault.failed_attempts++;
		if (kv_vault.failed_attempts >= kv_max_attempts) {
			kv_vault.state = KV_STATE_LOCKED_OUT;
			kv_vault.lockout_until_ms =
				kv_now_ms() + (u64)kv_lockout_secs * 1000;
			kv_audit_log(sess->uid, sess->pid, KV_OP_LOCKOUT, "",
				     KV_RESULT_DENY, -EAGAIN);
			pr_warn("locked out after %u failed unseal attempts\n",
				kv_vault.failed_attempts);
		}
		kv_audit_log(sess->uid, sess->pid, KV_OP_UNSEAL, "",
			     KV_RESULT_DENY, -EACCES);
		ret = -EACCES;
		goto unlock;
	}

	memcpy(kv_vault.key, arg->key, KV_KEY_LEN);
	kv_vault.key_present = true;
	kv_vault.state = KV_STATE_UNSEALED;
	kv_vault.failed_attempts = 0;
	kv_touch_locked();
	kv_audit_log(sess->uid, sess->pid, KV_OP_UNSEAL, "",
		     KV_RESULT_ALLOW, 0);
	ret = 0;

unlock:
	mutex_unlock(&kv_vault.lock);
out:
	/* The caller's key is gone from kernel memory whichever way this went:
	 * a rejected key is as worth wiping as an accepted one. */
	kfree_sensitive(arg);
	return ret;
}

static int kv_ioctl_seal(struct kv_session *sess)
{
	if (!kv_is_admin(sess->uid)) {
		kv_audit_log(sess->uid, sess->pid, KV_OP_SEAL, "",
			     KV_RESULT_DENY, -EACCES);
		return -EACCES;
	}

	mutex_lock(&kv_vault.lock);
	kv_do_seal(KV_STATE_SEALED);
	kv_audit_log(sess->uid, sess->pid, KV_OP_SEAL, "", KV_RESULT_ALLOW, 0);
	mutex_unlock(&kv_vault.lock);
	return 0;
}

/* --- secrets ----------------------------------------------------------- */

static int kv_ioctl_put(struct kv_session *sess, void __user *uarg)
{
	struct kv_secret_arg *arg;
	struct kv_secret *s;
	u8 *ct = NULL;
	u8 nonce[KV_NONCE_LEN];
	u8 tag[KV_TAG_LEN];
	bool created = false;
	int ret;

	/* 4 KiB of payload has no business on the kernel stack. */
	arg = kzalloc(sizeof(*arg), GFP_KERNEL);
	if (!arg)
		return -ENOMEM;

	if (copy_from_user(arg, uarg, sizeof(*arg))) {
		ret = -EFAULT;
		goto out_free;
	}
	ret = kv_check_name(arg->name);
	if (ret)
		goto out_free;
	if (arg->len == 0 || arg->len > KV_SECRET_MAX) {
		ret = -EINVAL;
		goto out_free;
	}

	mutex_lock(&kv_vault.lock);
	if (kv_vault.state != KV_STATE_UNSEALED) {
		ret = -EPERM;
		goto out_audit;
	}

	s = kv_store_find(arg->name);
	if (s) {
		if (!kv_acl_check(s, sess->uid, KV_PERM_WRITE)) {
			ret = -EACCES;
			goto out_audit;
		}
	} else {
		/* Creating a name is its own authorisation question: there is no
		 * object yet whose ACL could answer it. See kv_role_may_create. */
		if (!kv_role_may_create(kv_role_of(sess->uid))) {
			ret = -EACCES;
			goto out_audit;
		}
		if (kv_vault.secret_count >= kv_max_secrets) {
			ret = -ENOSPC;
			goto out_audit;
		}
	}

	get_random_bytes(nonce, sizeof(nonce));

	ct = kzalloc(arg->len, GFP_KERNEL);
	if (!ct) {
		ret = -ENOMEM;
		goto out_audit;
	}

	ret = kv_crypto_encrypt(kv_vault.key, nonce,
				(const u8 *)arg->name, KV_NAME_MAX,
				arg->data, arg->len, ct, tag);
	if (ret)
		goto out_audit;

	if (!s) {
		s = kv_store_insert(arg->name, sess->uid);
		if (!s) {
			ret = -ENOMEM;
			goto out_audit;
		}
		created = true;
	}

	/* Only now, with the new ciphertext in hand, is the old one discarded:
	 * a failure above leaves the existing secret intact. */
	kfree_sensitive(s->ct);
	s->ct = ct;
	ct = NULL;
	s->ct_len = arg->len;
	memcpy(s->nonce, nonce, sizeof(s->nonce));
	memcpy(s->tag, tag, sizeof(s->tag));
	s->modified_ms = kv_now_ms();
	if (!created)
		s->version++;

	kv_touch_locked();
	ret = 0;

out_audit:
	kv_audit_log(sess->uid, sess->pid, KV_OP_PUT, arg->name,
		     ret ? KV_RESULT_DENY : KV_RESULT_ALLOW, ret);
	mutex_unlock(&kv_vault.lock);
	kfree_sensitive(ct);
out_free:
	/* The plaintext the caller handed us does not outlive the call. */
	kfree_sensitive(arg);
	return ret;
}

static int kv_ioctl_get(struct kv_session *sess, void __user *uarg)
{
	struct kv_secret_arg *arg;
	struct kv_secret *s;
	int ret;

	arg = kzalloc(sizeof(*arg), GFP_KERNEL);
	if (!arg)
		return -ENOMEM;

	if (copy_from_user(arg, uarg, sizeof(*arg))) {
		ret = -EFAULT;
		goto out_free;
	}
	ret = kv_check_name(arg->name);
	if (ret)
		goto out_free;

	mutex_lock(&kv_vault.lock);
	if (kv_vault.state != KV_STATE_UNSEALED) {
		ret = -EPERM;
		goto out_audit;
	}

	s = kv_store_find(arg->name);
	if (!s) {
		ret = -ENOENT;
		goto out_audit;
	}

	/* The reference monitor. Everything above this point is parsing;
	 * everything below it has been authorised. */
	if (!kv_acl_check(s, sess->uid, KV_PERM_READ)) {
		ret = -EACCES;
		goto out_audit;
	}
	if (s->ct_len > arg->len) {
		ret = -ENOSPC;
		goto out_audit;
	}

	ret = kv_crypto_decrypt(kv_vault.key, s->nonce,
				(const u8 *)s->name, KV_NAME_MAX,
				s->ct, s->ct_len, s->tag, arg->data);
	if (ret)
		goto out_audit;

	arg->len = s->ct_len;
	kv_touch_locked();

out_audit:
	kv_audit_log(sess->uid, sess->pid, KV_OP_GET, arg->name,
		     ret ? KV_RESULT_DENY : KV_RESULT_ALLOW, ret);
	mutex_unlock(&kv_vault.lock);

	/* A denied or failed GET copies nothing back - not even the zeroed
	 * buffer - so there is no path where a caller receives a partial
	 * result and has to decide whether to trust it. */
	if (!ret && copy_to_user(uarg, arg, sizeof(*arg)))
		ret = -EFAULT;

out_free:
	kfree_sensitive(arg);
	return ret;
}

static int kv_ioctl_delete(struct kv_session *sess, void __user *uarg)
{
	struct kv_name_arg arg;
	struct kv_secret *s;
	int ret;

	if (copy_from_user(&arg, uarg, sizeof(arg)))
		return -EFAULT;
	ret = kv_check_name(arg.name);
	if (ret)
		return ret;

	mutex_lock(&kv_vault.lock);
	if (kv_vault.state != KV_STATE_UNSEALED) {
		ret = -EPERM;
		goto out;
	}

	s = kv_store_find(arg.name);
	if (!s) {
		ret = -ENOENT;
		goto out;
	}
	if (!kv_acl_check(s, sess->uid, KV_PERM_DELETE)) {
		ret = -EACCES;
		goto out;
	}

	kv_store_remove(s);
	kv_touch_locked();
	ret = 0;

out:
	kv_audit_log(sess->uid, sess->pid, KV_OP_DELETE, arg.name,
		     ret ? KV_RESULT_DENY : KV_RESULT_ALLOW, ret);
	mutex_unlock(&kv_vault.lock);
	return ret;
}

static int kv_ioctl_rotate(struct kv_session *sess, void __user *uarg)
{
	struct kv_name_arg arg;
	struct kv_secret *s;
	u8 *pt = NULL, *ct = NULL;
	u8 nonce[KV_NONCE_LEN];
	u8 tag[KV_TAG_LEN];
	int ret;

	if (copy_from_user(&arg, uarg, sizeof(arg)))
		return -EFAULT;
	ret = kv_check_name(arg.name);
	if (ret)
		return ret;

	mutex_lock(&kv_vault.lock);
	if (kv_vault.state != KV_STATE_UNSEALED) {
		ret = -EPERM;
		goto out;
	}

	s = kv_store_find(arg.name);
	if (!s) {
		ret = -ENOENT;
		goto out;
	}
	if (!kv_acl_check(s, sess->uid, KV_PERM_WRITE)) {
		ret = -EACCES;
		goto out;
	}

	pt = kzalloc(s->ct_len, GFP_KERNEL);
	ct = kzalloc(s->ct_len, GFP_KERNEL);
	if (!pt || !ct) {
		ret = -ENOMEM;
		goto out;
	}

	ret = kv_crypto_decrypt(kv_vault.key, s->nonce,
				(const u8 *)s->name, KV_NAME_MAX,
				s->ct, s->ct_len, s->tag, pt);
	if (ret)
		goto out;

	get_random_bytes(nonce, sizeof(nonce));
	ret = kv_crypto_encrypt(kv_vault.key, nonce,
				(const u8 *)s->name, KV_NAME_MAX,
				pt, s->ct_len, ct, tag);
	if (ret)
		goto out;

	kfree_sensitive(s->ct);
	s->ct = ct;
	ct = NULL;
	memcpy(s->nonce, nonce, sizeof(s->nonce));
	memcpy(s->tag, tag, sizeof(s->tag));
	s->version++;
	s->modified_ms = kv_now_ms();
	kv_touch_locked();

out:
	kv_audit_log(sess->uid, sess->pid, KV_OP_ROTATE, arg.name,
		     ret ? KV_RESULT_DENY : KV_RESULT_ALLOW, ret);
	mutex_unlock(&kv_vault.lock);
	kfree_sensitive(pt);
	kfree_sensitive(ct);
	return ret;
}

static int kv_ioctl_list(struct kv_session *sess, void __user *uarg)
{
	struct kv_list_arg *arg;
	struct kv_secret *s;
	int i, ret = 0;

	arg = kzalloc(sizeof(*arg), GFP_KERNEL);
	if (!arg)
		return -ENOMEM;

	mutex_lock(&kv_vault.lock);
	if (kv_vault.state != KV_STATE_UNSEALED) {
		ret = -EPERM;
		goto out;
	}

	for (i = 0; i < (1 << KV_HASH_BITS) && arg->count < KV_LIST_MAX; i++) {
		hlist_for_each_entry(s, &kv_vault.secrets[i], node) {
			if (arg->count >= KV_LIST_MAX)
				break;
			if (!kv_acl_check(s, sess->uid, KV_PERM_READ))
				continue;
			strscpy(arg->names[arg->count], s->name, KV_NAME_MAX);
			arg->count++;
		}
	}
	kv_touch_locked();

out:
	kv_audit_log(sess->uid, sess->pid, KV_OP_LIST, "",
		     ret ? KV_RESULT_DENY : KV_RESULT_ALLOW, ret);
	mutex_unlock(&kv_vault.lock);

	if (!ret && copy_to_user(uarg, arg, sizeof(*arg)))
		ret = -EFAULT;
	kfree(arg);
	return ret;
}

/* GRANT and REVOKE share everything but the final mutation. */
static int kv_ioctl_grant(struct kv_session *sess, void __user *uarg,
			  bool granting)
{
	struct kv_grant_arg arg;
	struct kv_secret *s;
	int ret;

	if (copy_from_user(&arg, uarg, sizeof(arg)))
		return -EFAULT;
	ret = kv_check_name(arg.name);
	if (ret)
		return ret;

	mutex_lock(&kv_vault.lock);
	if (kv_vault.state != KV_STATE_UNSEALED) {
		ret = -EPERM;
		goto out;
	}

	s = kv_store_find(arg.name);
	if (!s) {
		ret = -ENOENT;
		goto out;
	}
	/* Delegation is itself a permission: holding GRANT on a secret is what
	 * lets a principal widen access to it, and the owner and admin hold it
	 * implicitly. Without this, any reader could share what they can read. */
	if (!kv_acl_check(s, sess->uid, KV_PERM_GRANT)) {
		ret = -EACCES;
		goto out;
	}

	ret = granting ? kv_acl_set(s, arg.subject_kind, arg.subject_id,
				    arg.perms)
		       : kv_acl_revoke(s, arg.subject_kind, arg.subject_id);
	if (!ret) {
		s->modified_ms = kv_now_ms();
		kv_touch_locked();
	}

out:
	kv_audit_log(sess->uid, sess->pid,
		     granting ? KV_OP_GRANT : KV_OP_REVOKE, arg.name,
		     ret ? KV_RESULT_DENY : KV_RESULT_ALLOW, ret);
	mutex_unlock(&kv_vault.lock);
	return ret;
}

static int kv_ioctl_set_role(struct kv_session *sess, void __user *uarg)
{
	struct kv_setrole_arg arg;
	int ret;

	if (copy_from_user(&arg, uarg, sizeof(arg)))
		return -EFAULT;

	if (!kv_is_admin(sess->uid)) {
		kv_audit_log(sess->uid, sess->pid, KV_OP_SET_ROLE, "",
			     KV_RESULT_DENY, -EACCES);
		return -EACCES;
	}

	mutex_lock(&kv_vault.lock);
	ret = kv_role_bind(arg.uid, arg.role_id);
	kv_audit_log(sess->uid, sess->pid, KV_OP_SET_ROLE, "",
		     ret ? KV_RESULT_DENY : KV_RESULT_ALLOW, ret);
	mutex_unlock(&kv_vault.lock);
	return ret;
}

static int kv_ioctl_export(struct kv_session *sess, void __user *uarg)
{
	struct kv_blob_arg arg;
	u8 *blob = NULL;
	u32 len = 0;
	int ret;

	if (copy_from_user(&arg, uarg, sizeof(arg)))
		return -EFAULT;

	if (!kv_is_admin(sess->uid)) {
		kv_audit_log(sess->uid, sess->pid, KV_OP_EXPORT, "",
			     KV_RESULT_DENY, -EACCES);
		return -EACCES;
	}
	if (arg.len > KV_BLOB_MAX)
		return -EINVAL;

	mutex_lock(&kv_vault.lock);
	if (kv_vault.state != KV_STATE_UNSEALED) {
		ret = -EPERM;
		goto out;
	}

	blob = kvzalloc(KV_BLOB_MAX, GFP_KERNEL);
	if (!blob) {
		ret = -ENOMEM;
		goto out;
	}

	ret = kv_export(blob, arg.len, &len);

out:
	kv_audit_log(sess->uid, sess->pid, KV_OP_EXPORT, "",
		     ret ? KV_RESULT_DENY : KV_RESULT_ALLOW, ret);
	mutex_unlock(&kv_vault.lock);

	if (!ret) {
		if (copy_to_user((void __user *)(uintptr_t)arg.buf, blob, len))
			ret = -EFAULT;
		else {
			arg.len = len;
			if (copy_to_user(uarg, &arg, sizeof(arg)))
				ret = -EFAULT;
		}
	} else if (ret == -ENOSPC) {
		/* Tell the caller how much room it needed. */
		arg.len = len;
		if (copy_to_user(uarg, &arg, sizeof(arg)))
			ret = -EFAULT;
	}

	kvfree(blob);
	return ret;
}

static int kv_ioctl_import(struct kv_session *sess, void __user *uarg)
{
	struct kv_blob_arg arg;
	u8 *blob;
	int ret;

	if (copy_from_user(&arg, uarg, sizeof(arg)))
		return -EFAULT;

	if (!kv_is_admin(sess->uid)) {
		kv_audit_log(sess->uid, sess->pid, KV_OP_IMPORT, "",
			     KV_RESULT_DENY, -EACCES);
		return -EACCES;
	}
	if (arg.len == 0 || arg.len > KV_BLOB_MAX)
		return -EINVAL;

	blob = kvzalloc(arg.len, GFP_KERNEL);
	if (!blob)
		return -ENOMEM;

	if (copy_from_user(blob, (const void __user *)(uintptr_t)arg.buf,
			   arg.len)) {
		kvfree(blob);
		return -EFAULT;
	}

	mutex_lock(&kv_vault.lock);
	if (kv_vault.state != KV_STATE_UNSEALED)
		ret = -EPERM;
	else
		ret = kv_import(blob, arg.len);
	kv_audit_log(sess->uid, sess->pid, KV_OP_IMPORT, "",
		     ret ? KV_RESULT_DENY : KV_RESULT_ALLOW, ret);
	if (!ret)
		kv_touch_locked();
	mutex_unlock(&kv_vault.lock);

	kvfree(blob);
	return ret;
}

/* STATUS is deliberately readable by anyone: it reports lifecycle state and
 * counters only, never names, plaintext or key material. */
static int kv_ioctl_status(struct kv_session *sess, void __user *uarg)
{
	struct kv_status_arg st;

	memset(&st, 0, sizeof(st));
	mutex_lock(&kv_vault.lock);
	kv_expire_lockout();
	st.abi_version      = KV_ABI_VERSION;
	st.state            = kv_vault.state;
	st.secret_count     = kv_vault.secret_count;
	st.failed_attempts  = kv_vault.failed_attempts;
	st.max_attempts     = kv_max_attempts;
	st.auto_lock_secs   = kv_autolock_secs;
	st.lockout_until_ms = kv_vault.lockout_until_ms;
	st.last_activity_ms = kv_vault.last_activity_ms;
	st.caller_uid       = from_kuid(&init_user_ns, sess->uid);
	st.caller_role      = kv_role_of(sess->uid);
	st.initialized      = kv_vault.kcv_present ? 1 : 0;
	st.kdf_iterations   = kv_vault.kdf_iterations;
	memcpy(st.salt, kv_vault.salt, KV_SALT_LEN);
	mutex_unlock(&kv_vault.lock);
	st.accelerated = kv_crypto_accelerated() ? 1 : 0;
	strscpy(st.crypto_driver, kv_crypto_driver_name(),
		sizeof(st.crypto_driver));

	if (copy_to_user(uarg, &st, sizeof(st)))
		return -EFAULT;
	return 0;
}

static long kv_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	struct kv_session *sess = filp->private_data;
	void __user *uarg = (void __user *)arg;
	long ret;

	if (iminor(file_inode(filp)) != KV_MINOR_CTL)
		return -ENOTTY;
	if (_IOC_TYPE(cmd) != KV_IOC_MAGIC)
		return -ENOTTY;

	sess->op_count++;

	switch (cmd) {
	case KVAULT_STATUS:
		ret = kv_ioctl_status(sess, uarg);
		break;
	case KVAULT_UNSEAL:
		ret = kv_ioctl_unseal(sess, uarg);
		break;
	case KVAULT_SEAL:
		ret = kv_ioctl_seal(sess);
		break;
	case KVAULT_PUT:
		ret = kv_ioctl_put(sess, uarg);
		break;
	case KVAULT_GET:
		ret = kv_ioctl_get(sess, uarg);
		break;
	case KVAULT_DELETE:
		ret = kv_ioctl_delete(sess, uarg);
		break;
	case KVAULT_LIST:
		ret = kv_ioctl_list(sess, uarg);
		break;
	case KVAULT_ROTATE:
		ret = kv_ioctl_rotate(sess, uarg);
		break;
	case KVAULT_GRANT:
		ret = kv_ioctl_grant(sess, uarg, true);
		break;
	case KVAULT_REVOKE:
		ret = kv_ioctl_grant(sess, uarg, false);
		break;
	case KVAULT_SET_ROLE:
		ret = kv_ioctl_set_role(sess, uarg);
		break;
	case KVAULT_EXPORT:
		ret = kv_ioctl_export(sess, uarg);
		break;
	case KVAULT_IMPORT:
		ret = kv_ioctl_import(sess, uarg);
		break;
	default:
		ret = -ENOTTY;
		break;
	}

	return ret;
}

static const struct file_operations kv_fops = {
	.owner          = THIS_MODULE,
	.open           = kv_open,
	.release        = kv_release,
	.read           = kv_read,
	.poll           = kv_poll,
	.unlocked_ioctl = kv_ioctl,
	.compat_ioctl   = compat_ptr_ioctl,
	.llseek         = noop_llseek,
};

/* --- module init / exit ------------------------------------------------ */

static void kv_vault_init(void)
{
	int i;

	mutex_init(&kv_vault.lock);
	kv_vault.state = KV_STATE_SEALED;
	for (i = 0; i < (1 << KV_HASH_BITS); i++)
		INIT_HLIST_HEAD(&kv_vault.secrets[i]);
	timer_setup(&kv_vault.autolock_timer, kv_autolock_fn, 0);
	/* root is admin until a policy is loaded, so the vault is never
	 * unadministrable. */
	kv_role_bind(0, KV_ROLE_ADMIN);
}

static int __init kvault_init(void)
{
	struct device *dev;
	int ret;

	kv_vault_init();

	ret = kv_crypto_init();
	if (ret)
		return ret;
	ret = kv_store_init();
	if (ret)
		goto err_crypto;
	ret = kv_audit_init();
	if (ret)
		goto err_store;

	ret = alloc_chrdev_region(&kv_devt, 0, KV_MINOR_COUNT, KV_DEVICE_NAME);
	if (ret)
		goto err_audit;

	cdev_init(&kv_cdev, &kv_fops);
	kv_cdev.owner = THIS_MODULE;
	ret = cdev_add(&kv_cdev, kv_devt, KV_MINOR_COUNT);
	if (ret)
		goto err_region;

	kv_class = class_create(KV_DEVICE_NAME);
	if (IS_ERR(kv_class)) {
		ret = PTR_ERR(kv_class);
		goto err_cdev;
	}

	dev = device_create(kv_class, NULL, MKDEV(MAJOR(kv_devt), KV_MINOR_CTL),
			    NULL, KV_DEVICE_NAME);
	if (IS_ERR(dev)) {
		ret = PTR_ERR(dev);
		goto err_class;
	}
	dev = device_create(kv_class, NULL, MKDEV(MAJOR(kv_devt), KV_MINOR_AUDIT),
			    NULL, KV_AUDIT_NAME);
	if (IS_ERR(dev)) {
		ret = PTR_ERR(dev);
		goto err_dev0;
	}

	ret = kv_proc_init();
	if (ret)
		goto err_dev1;

	pr_info("loaded (major %d, crypto=%s accel=%d, autolock=%us, max_attempts=%u, max_secrets=%u)\n",
		MAJOR(kv_devt), kv_crypto_driver_name(),
		kv_crypto_accelerated(), kv_autolock_secs, kv_max_attempts,
		kv_max_secrets);
	return 0;

err_dev1:
	device_destroy(kv_class, MKDEV(MAJOR(kv_devt), KV_MINOR_AUDIT));
err_dev0:
	device_destroy(kv_class, MKDEV(MAJOR(kv_devt), KV_MINOR_CTL));
err_class:
	class_destroy(kv_class);
err_cdev:
	cdev_del(&kv_cdev);
err_region:
	unregister_chrdev_region(kv_devt, KV_MINOR_COUNT);
err_audit:
	kv_audit_exit();
err_store:
	kv_store_teardown();
err_crypto:
	kv_crypto_exit();
	return ret;
}

static void __exit kvault_exit(void)
{
	kv_proc_exit();
	device_destroy(kv_class, MKDEV(MAJOR(kv_devt), KV_MINOR_AUDIT));
	device_destroy(kv_class, MKDEV(MAJOR(kv_devt), KV_MINOR_CTL));
	class_destroy(kv_class);
	cdev_del(&kv_cdev);
	unregister_chrdev_region(kv_devt, KV_MINOR_COUNT);

	/* Unloading the module must not leave key material or plaintext
	 * recoverable from freed pages. */
	mutex_lock(&kv_vault.lock);
	kv_do_seal(KV_STATE_SEALED);
	kv_store_clear();
	mutex_unlock(&kv_vault.lock);
	timer_delete_sync(&kv_vault.autolock_timer);

	kv_audit_exit();
	kv_store_teardown();
	kv_crypto_exit();
	pr_info("unloaded, key wiped\n");
}

module_init(kvault_init);
module_exit(kvault_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("KVault project");
MODULE_DESCRIPTION("Kernel-backed encrypted secrets vault with UID-based RBAC and audit");
MODULE_VERSION("1.0");
