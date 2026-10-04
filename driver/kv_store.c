// SPDX-License-Identifier: GPL-2.0
/* kv_store.c - the in-kernel secret table. */
#define pr_fmt(fmt) "kvault: " fmt

#include <linux/module.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/stringhash.h>

#include "kv_internal.h"

static inline u32 kv_bucket(const char *name)
{
	return full_name_hash(NULL, name, strnlen(name, KV_NAME_MAX - 1))
	       & ((1 << KV_HASH_BITS) - 1);
}

int kv_store_init(void)
{
	return 0;
}

void kv_store_teardown(void)
{
}

struct kv_secret *kv_store_find(const char *name)
{
	struct kv_secret *s;

	hlist_for_each_entry(s, &kv_vault.secrets[kv_bucket(name)], node) {
		if (!strncmp(s->name, name, KV_NAME_MAX - 1))
			return s;
	}
	return NULL;
}

struct kv_secret *kv_store_insert(const char *name, kuid_t owner)
{
	struct kv_secret *s;

	s = kzalloc(sizeof(*s), GFP_KERNEL);
	if (!s)
		return NULL;

	strscpy(s->name, name, sizeof(s->name));
	s->owner       = owner;
	s->version     = 1;
	s->created_ms  = kv_now_ms();
	s->modified_ms = s->created_ms;

	hlist_add_head(&s->node, &kv_vault.secrets[kv_bucket(name)]);
	kv_vault.secret_count++;
	return s;
}

void kv_store_remove(struct kv_secret *s)
{
	hlist_del(&s->node);
	kv_vault.secret_count--;
	/* kfree_sensitive zeroes before freeing: the ciphertext is not secret
	 * on its own, but the entry is small and wiping it costs nothing. */
	kfree_sensitive(s->ct);
	kfree_sensitive(s);
}

void kv_store_clear(void)
{
	struct kv_secret *s;
	struct hlist_node *tmp;
	int i;

	for (i = 0; i < (1 << KV_HASH_BITS); i++)
		hlist_for_each_entry_safe(s, tmp, &kv_vault.secrets[i], node)
			kv_store_remove(s);
}
