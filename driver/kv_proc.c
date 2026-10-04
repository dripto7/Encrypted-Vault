// SPDX-License-Identifier: GPL-2.0
/*
 * kv_proc.c - /proc/kvault/{status,stats}
 *
 * These files exist so the vault's lifecycle can be inspected without opening
 * the device. They are world-readable, which constrains what they may contain:
 * lifecycle state and counters, never secret names, plaintext or key material.
 */
#define pr_fmt(fmt) "kvault: " fmt

#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>

#include "kv_internal.h"


static struct proc_dir_entry *kv_proc_dir;

static const char *kv_state_name(u32 state)
{
	switch (state) {
	case KV_STATE_SEALED:      return "SEALED";
	case KV_STATE_UNSEALED:    return "UNSEALED";
	case KV_STATE_AUTO_LOCKED: return "AUTO_LOCKED";
	case KV_STATE_LOCKED_OUT:  return "LOCKED_OUT";
	default:                   return "UNKNOWN";
	}
}

static int kv_status_show(struct seq_file *m, void *v)
{
	u64 now = kv_now_ms();

	mutex_lock(&kv_vault.lock);
	seq_printf(m, "state:            %s\n", kv_state_name(kv_vault.state));
	seq_printf(m, "secrets:          %u\n", kv_vault.secret_count);
	seq_printf(m, "key_loaded:       %s\n", kv_vault.key_present ? "yes" : "no");
	seq_printf(m, "failed_attempts:  %u/%u\n", kv_vault.failed_attempts,
		   kv_max_attempts);
	if (kv_vault.lockout_until_ms > now)
		seq_printf(m, "lockout_remaining: %llu ms\n",
			   kv_vault.lockout_until_ms - now);
	if (kv_vault.last_activity_ms)
		seq_printf(m, "idle:             %llu ms\n",
			   now - kv_vault.last_activity_ms);
	mutex_unlock(&kv_vault.lock);

	seq_printf(m, "autolock_secs:    %u\n", kv_autolock_secs);
	seq_printf(m, "abi_version:      %u\n", KV_ABI_VERSION);
	return 0;
}

static int kv_stats_show(struct seq_file *m, void *v)
{
	seq_printf(m, "audit_records:    %llu\n", kv_audit_seq());
	seq_printf(m, "audit_dropped:    %llu\n", kv_audit_dropped_count());
	seq_printf(m, "audit_ring_size:  %u\n", KV_AUDIT_RING_SIZE);
	seq_printf(m, "crypto_driver:    %s\n", kv_crypto_driver_name());
	seq_printf(m, "accelerated:      %s\n",
		   kv_crypto_accelerated() ? "yes" : "no");
	seq_printf(m, "secret_max_bytes: %u\n", KV_SECRET_MAX);
	return 0;
}

int kv_proc_init(void)
{
	kv_proc_dir = proc_mkdir(KV_DEVICE_NAME, NULL);
	if (!kv_proc_dir)
		return -ENOMEM;

	if (!proc_create_single("status", 0444, kv_proc_dir, kv_status_show))
		goto err;
	if (!proc_create_single("stats", 0444, kv_proc_dir, kv_stats_show))
		goto err;
	return 0;

err:
	remove_proc_subtree(KV_DEVICE_NAME, NULL);
	kv_proc_dir = NULL;
	return -ENOMEM;
}

void kv_proc_exit(void)
{
	if (kv_proc_dir) {
		remove_proc_subtree(KV_DEVICE_NAME, NULL);
		kv_proc_dir = NULL;
	}
}
