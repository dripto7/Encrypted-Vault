// SPDX-License-Identifier: GPL-2.0
/* kv_acl.c - the reference monitor: roles, ACL evaluation, admin checks. */
#define pr_fmt(fmt) "kvault: " fmt

#include <linux/module.h>
#include <linux/capability.h>
#include <linux/cred.h>

#include "kv_internal.h"

/* Default permissions per role, applied when no ACL entry matches. */
static const u32 kv_role_defaults[KV_ROLE_COUNT] = {
	[KV_ROLE_NONE]      = 0,
	[KV_ROLE_ADMIN]     = KV_PERM_ALL,
	[KV_ROLE_DEVELOPER] = 0,  /* developers get access per secret, not globally */
	[KV_ROLE_AUDITOR]   = 0,  /* the audit stream only: never secret contents */
	[KV_ROLE_GUEST]     = 0,
};

u32 kv_role_of(kuid_t uid)
{
	u32 raw = from_kuid(&init_user_ns, uid);
	int i;

	for (i = 0; i < KV_UID_MAP_MAX; i++)
		if (kv_vault.uid_roles[i].used &&
		    kv_vault.uid_roles[i].uid == raw)
			return kv_vault.uid_roles[i].role_id;
	return KV_ROLE_GUEST;
}

int kv_role_bind(u32 uid, u32 role_id)
{
	int i, free_slot = -1;

	if (role_id >= KV_ROLE_COUNT)
		return -EINVAL;

	for (i = 0; i < KV_UID_MAP_MAX; i++) {
		if (kv_vault.uid_roles[i].used) {
			if (kv_vault.uid_roles[i].uid == uid) {
				kv_vault.uid_roles[i].role_id = role_id;
				return 0;
			}
		} else if (free_slot < 0) {
			free_slot = i;
		}
	}
	if (free_slot < 0)
		return -ENOSPC;

	kv_vault.uid_roles[free_slot].uid     = uid;
	kv_vault.uid_roles[free_slot].role_id = role_id;
	kv_vault.uid_roles[free_slot].used    = true;
	return 0;
}

bool kv_role_may_create(u32 role)
{
	return role == KV_ROLE_ADMIN || role == KV_ROLE_DEVELOPER;
}

/* Administrative operations need both the admin role and CAP_SYS_ADMIN: the
 * role is vault policy, the capability is the kernel's own notion of
 * privilege, and requiring both means neither alone is enough. */
bool kv_is_admin(kuid_t uid)
{
	return kv_role_of(uid) == KV_ROLE_ADMIN && capable(CAP_SYS_ADMIN);
}

bool kv_acl_check(const struct kv_secret *s, kuid_t uid, u32 want)
{
	u32 raw  = from_kuid(&init_user_ns, uid);
	u32 role = kv_role_of(uid);
	u32 i;

	/* The owner always retains full control of their own secret. */
	if (uid_eq(s->owner, uid))
		return true;
	if (role == KV_ROLE_ADMIN)
		return true;

	for (i = 0; i < s->acl_count; i++) {
		const struct kv_acl_entry *e = &s->acl[i];

		if (e->subject_kind == KV_SUBJ_UID && e->subject_id == raw)
			return (e->perms & want) == want;
		if (e->subject_kind == KV_SUBJ_ROLE && e->subject_id == role)
			return (e->perms & want) == want;
	}

	return (kv_role_defaults[role < KV_ROLE_COUNT ? role : KV_ROLE_NONE]
		& want) == want;
}

int kv_acl_set(struct kv_secret *s, u32 kind, u32 id, u32 perms)
{
	u32 i;

	if (kind != KV_SUBJ_UID && kind != KV_SUBJ_ROLE)
		return -EINVAL;
	if (perms & ~KV_PERM_ALL)
		return -EINVAL;

	for (i = 0; i < s->acl_count; i++) {
		if (s->acl[i].subject_kind == kind &&
		    s->acl[i].subject_id == id) {
			s->acl[i].perms = perms;
			return 0;
		}
	}
	if (s->acl_count >= KV_ACL_MAX)
		return -ENOSPC;

	s->acl[s->acl_count].subject_kind = kind;
	s->acl[s->acl_count].subject_id   = id;
	s->acl[s->acl_count].perms        = perms;
	s->acl_count++;
	return 0;
}

int kv_acl_revoke(struct kv_secret *s, u32 kind, u32 id)
{
	u32 i;

	for (i = 0; i < s->acl_count; i++) {
		if (s->acl[i].subject_kind == kind &&
		    s->acl[i].subject_id == id) {
			s->acl[i] = s->acl[s->acl_count - 1];
			s->acl_count--;
			return 0;
		}
	}
	return -ENOENT;
}
