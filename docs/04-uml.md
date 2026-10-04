# 4. UML models

PlantUML sources are in `uml/*.puml`; the PNGs beside them are generated. To
re-render after an edit:

```bash
plantuml -tpng docs/uml/*.puml
```

## 4.1 Architecture

![Architecture](uml/01-architecture.png)

The syscall boundary is the security boundary, and the diagram is arranged
around it. Note what crosses: commands and plaintext go down through
`/dev/kvault`, audit records come up through `/dev/kvault_audit`, and the
sealed blob crosses in both directions — but the key crosses exactly once, at
unseal, and never comes back.

## 4.2 Class diagram — user space

![User-space classes](uml/02-class-userspace.png)

Three things in this diagram are load-bearing rather than decorative:

**`VaultClient` is move-only.** It owns a file descriptor. Copying it would
give two objects the same descriptor and a double `close()` at destruction;
deleting the copy operations makes that a compile error instead of a runtime
one.

**`SecureBuffer` is non-copyable** for a different reason: every copy is another
place holding key material that would have to be wiped. Forbidding copies means
there is exactly one place to get the wipe right.

**`SimUser` is the only inheritance hierarchy in the project.** The subclasses
differ in the steps they are given and how an outcome is interpreted, not in
how they talk to the kernel — so `run()` is the single virtual method and
everything else is shared. An auditor who cannot even open the control device
is handled in the base class, because "refused at `open()`" is a legitimate
result to record rather than a special case.

## 4.3 Class diagram — kernel structures

![Kernel structures](uml/03-class-kernel.png)

Shown as a separate package because these are C structs, not classes: no
inheritance, no methods, and the operations on them are free functions. The
composition arrows to `kv_file_*` show the serialisation mapping — note that
`kv_uid_role` has no on-disk counterpart, which is the deliberate split
described in §3.8.

## 4.4 Sequence — unseal, then an authorised GET

![Unseal and GET](uml/04-seq-unseal-get.png)

The passphrase exists in user space for the length of one function call. The
derived key exists in an `mlock`ed buffer until the ioctl returns, then is
wiped by `~SecureBuffer`. From that point the only copy is in kernel memory.

The KDF parameters come from the *file*, not from the kernel. A freshly loaded
module knows no salt, so deriving from a new one produces a key that cannot
authenticate anything in an existing vault — this is not hypothetical, it is
the bug recorded in §5 of the test report.

## 4.5 Sequence — an unauthorised GET

![Denied GET](uml/05-seq-denied-get.png)

The most important diagram in the set, because it shows the three things that
distinguish KVault from a config file:

1. The decision is taken from `current_uid()`, which eve cannot influence.
2. Nothing is decrypted and nothing is copied back — not even a zeroed buffer.
3. The record is written **by the same code path that refused her, before the
   error is returned**. There is no window in which the access is refused but
   unrecorded, and nothing eve can do suppresses it.

The auditor's thread is asleep on a wait queue, not polling. The kernel wakes
it. That is why `poll` and a wait queue are in the driver at all.

## 4.6 Sequence — GRANT changes the outcome

![Grant](uml/06-seq-grant.png)

The same binary, the same arguments, the same process credentials — different
answer, because vault state changed. No restart, no reload, no cache to
invalidate: the decision is taken fresh on every call.

Step 2 is worth reading closely. `GRANT` itself requires the `GRANT` permission
on that secret. Without that check, any principal who could read a secret could
share it with everyone, and the ACL would describe a lower bound on access
rather than an upper one.

## 4.7 State machine — the vault

![Vault states](uml/07-state-vault.png)

Four states, and every edge leaving `UNSEALED` destroys the key. Two edges
deserve attention:

- `UNSEALED → AUTO_LOCKED` is taken by a kernel timer with **no user-space
  process involved**. Nothing has to be running for the vault to protect
  itself.
- `LOCKED_OUT → LOCKED_OUT` on `UNSEAL` returns `EAGAIN` *without performing
  the key check*, so the correct passphrase is refused during the cooldown too.

## 4.8 State machine — a secret

![Secret states](uml/08-state-secret.png)

`REVOKED` is a view rather than a stored flag: a secret's state is its ACL, and
"revoked" means no entry currently grants the principal in question. Modelling
it as stored state would create the possibility of the flag and the ACL
disagreeing.
