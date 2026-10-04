// SPDX-License-Identifier: GPL-2.0
/* kv_audit.c - append-only audit ring buffer with a blocking reader. */
#define pr_fmt(fmt) "kvault: " fmt

#include <linux/module.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/uaccess.h>
#include <linux/wait.h>
#include <linux/sched.h>

#include "kv_internal.h"

static struct kv_audit_rec *kv_ring;
static DEFINE_SPINLOCK(kv_audit_lock);
static DECLARE_WAIT_QUEUE_HEAD(kv_audit_wq);

/* Monotonically increasing count of records ever written. Readers hold a
 * cursor into this sequence, so each reader is independent and a slow reader
 * cannot block a writer. */
static u64 kv_audit_next;
static u64 kv_audit_dropped;

int kv_audit_init(void)
{
	BUILD_BUG_ON(KV_AUDIT_RING_SIZE & (KV_AUDIT_RING_SIZE - 1));

	kv_ring = kcalloc(KV_AUDIT_RING_SIZE, sizeof(*kv_ring), GFP_KERNEL);
	if (!kv_ring)
		return -ENOMEM;
	return 0;
}

void kv_audit_exit(void)
{
	kfree(kv_ring);
	kv_ring = NULL;
}

u64 kv_audit_seq(void)
{
	u64 seq;
	unsigned long flags;

	spin_lock_irqsave(&kv_audit_lock, flags);
	seq = kv_audit_next;
	spin_unlock_irqrestore(&kv_audit_lock, flags);
	return seq;
}

u64 kv_audit_dropped_count(void)
{
	return kv_audit_dropped;
}

/* Safe to call with kv_vault.lock held: this takes only a spinlock and never
 * sleeps, so logging a decision cannot deadlock against the operation that
 * produced it. */
void kv_audit_log(kuid_t uid, pid_t pid, u32 op, const char *name,
		  u32 result, int err)
{
	struct kv_audit_rec *rec;
	unsigned long flags;

	if (!kv_ring)
		return;

	spin_lock_irqsave(&kv_audit_lock, flags);
	rec = &kv_ring[kv_audit_next & (KV_AUDIT_RING_SIZE - 1)];
	memset(rec, 0, sizeof(*rec));
	rec->seq          = kv_audit_next;
	rec->timestamp_ms = kv_now_ms();
	rec->uid          = from_kuid(&init_user_ns, uid);
	rec->pid          = pid;
	rec->op           = op;
	rec->result       = result;
	rec->err          = err;
	rec->role         = kv_role_of(uid);
	if (name)
		strscpy(rec->name, name, sizeof(rec->name));

	if (kv_audit_next >= KV_AUDIT_RING_SIZE)
		kv_audit_dropped++;
	kv_audit_next++;
	spin_unlock_irqrestore(&kv_audit_lock, flags);

	wake_up_interruptible(&kv_audit_wq);
}

/* Copy whole records only. A caller whose buffer cannot hold one record gets
 * -EINVAL rather than a truncated record it would have to reassemble. */
ssize_t kv_audit_read(struct kv_session *sess, char __user *buf, size_t count)
{
	struct kv_audit_rec rec;
	size_t copied = 0;
	unsigned long flags;
	bool have;
	int ret;

	if (!sess)
		return -EBADF;
	if (count < sizeof(rec))
		return -EINVAL;

	for (;;) {
		spin_lock_irqsave(&kv_audit_lock, flags);
		/* A reader that fell more than a ring behind has lost records;
		 * fast-forward it to the oldest record still present. */
		if (kv_audit_next > KV_AUDIT_RING_SIZE &&
		    sess->audit_cursor < kv_audit_next - KV_AUDIT_RING_SIZE)
			sess->audit_cursor = kv_audit_next - KV_AUDIT_RING_SIZE;

		have = sess->audit_cursor < kv_audit_next;
		if (have) {
			rec = kv_ring[sess->audit_cursor &
				      (KV_AUDIT_RING_SIZE - 1)];
			sess->audit_cursor++;
		}
		spin_unlock_irqrestore(&kv_audit_lock, flags);

		if (!have)
			break;

		if (copy_to_user(buf + copied, &rec, sizeof(rec)))
			return copied ? (ssize_t)copied : -EFAULT;
		copied += sizeof(rec);
		if (copied + sizeof(rec) > count)
			return copied;
	}

	if (copied)
		return copied;

	/* Nothing buffered: block until a writer appends. */
	ret = wait_event_interruptible(kv_audit_wq,
				       sess->audit_cursor < kv_audit_seq());
	if (ret)
		return ret;
	return kv_audit_read(sess, buf, count);
}

__poll_t kv_audit_poll(struct file *filp, struct kv_session *sess,
		       struct poll_table_struct *wait)
{
	poll_wait(filp, &kv_audit_wq, wait);
	if (sess && sess->audit_cursor < kv_audit_seq())
		return EPOLLIN | EPOLLRDNORM;
	return 0;
}
