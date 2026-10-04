// SPDX-License-Identifier: GPL-2.0
/*
 * kv_main.c - character device, per-open sessions and ioctl dispatch.
 *
 * Two minors are registered under one cdev:
 *   minor 0 (/dev/kvault)       - the control/command interface (ioctl)
 *   minor 1 (/dev/kvault_audit) - a read-only audit stream (read + poll)
 *
 * Every entry point captures the caller's identity from the kernel's own
 * credentials rather than from anything user space passes in, which is the
 * whole point of putting the policy check down here.
 */
#define pr_fmt(fmt) "kvault: " fmt

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/capability.h>

#include "kv_internal.h"

struct kv_vault kv_vault;

unsigned int kv_autolock_secs = 300;
unsigned int kv_max_attempts  = 3;
unsigned int kv_lockout_secs  = 60;

module_param_named(autolock_secs, kv_autolock_secs, uint, 0644);
MODULE_PARM_DESC(autolock_secs, "Seconds of inactivity before the vault auto-locks (0 disables)");
module_param_named(max_attempts, kv_max_attempts, uint, 0644);
MODULE_PARM_DESC(max_attempts, "Failed unseal attempts before lockout");
module_param_named(lockout_secs, kv_lockout_secs, uint, 0644);
MODULE_PARM_DESC(lockout_secs, "Lockout duration in seconds after too many failed unseals");

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

static void __maybe_unused kv_touch_locked(void)
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

/* STATUS is deliberately readable by anyone: it reports lifecycle state and
 * counters only, never names, plaintext or key material. */
static int kv_ioctl_status(struct kv_session *sess, void __user *uarg)
{
	struct kv_status_arg st;

	memset(&st, 0, sizeof(st));
	mutex_lock(&kv_vault.lock);
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
	case KVAULT_SEAL:
	case KVAULT_PUT:
	case KVAULT_GET:
	case KVAULT_DELETE:
	case KVAULT_LIST:
	case KVAULT_ROTATE:
	case KVAULT_GRANT:
	case KVAULT_REVOKE:
	case KVAULT_SET_ROLE:
	case KVAULT_EXPORT:
	case KVAULT_IMPORT:
		/* Implemented in the v0.4/v0.5 driver milestones. */
		ret = -ENOSYS;
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

	pr_info("loaded (major %d, crypto=%s accel=%d, autolock=%us, max_attempts=%u)\n",
		MAJOR(kv_devt), kv_crypto_driver_name(),
		kv_crypto_accelerated(), kv_autolock_secs, kv_max_attempts);
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
MODULE_VERSION("0.1");
