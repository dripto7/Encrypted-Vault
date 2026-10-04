# 3. Design

## 3.1 Architecture

![Architecture](uml/01-architecture.png)

Three things live in the kernel and nothing else does: the master key, the
authorisation decision, and the audit record. Everything that can live in user
space does — the CLI, the key derivation, the file I/O, the simulator — because
code in the kernel is code that can panic the machine, and the privilege
boundary is worth crossing only for things that need it.

The module registers one character device with two minors:

| Node | Minor | Interface | Audience |
|---|---|---|---|
| `/dev/kvault` | 0 | `ioctl` | processes that issue commands |
| `/dev/kvault_audit` | 1 | `read`, `poll` | processes that observe |

Two minors rather than one, because the two audiences are different and file
permissions should be able to say so. `kv_carol`, the auditor, is in the
`kvaudit` group and not in `kvault`: she can follow the log and cannot open the
control device at all. That is the outer layer of defence — the kernel's RBAC
check would refuse her anyway, but there is no reason to let her get that far.

## 3.2 Threat model

Stating what is *not* defended is as important as what is.

**The adversary** is a local, unprivileged or differently-privileged process:
another service account on the same host, a compromised application, a
curious developer. It may open the device, issue any ioctl with any argument,
read every world-readable file, and read the vault file if permissions allow.

**Defended:**

| Attack | Defence |
|---|---|
| Read another principal's secret | Reference monitor, on every operation, keyed on `current_uid()` |
| Claim to be another principal | Impossible: the UID comes from the kernel's own credentials, not the request |
| Read the key out of the vault process | There is no vault process; the key is in kernel memory, unreachable from ring 3 |
| Read secrets from the vault file | Ciphertext only; the key is not in the file |
| Edit the vault file | GCM tag covers ciphertext *and* the secret's name; import rejects the whole file |
| Move one secret's ciphertext under another's name | The name is authenticated as associated data, so the tag fails |
| Guess the passphrase online | Lockout after `max_attempts`, which refuses even the correct passphrase during the cooldown |
| Learn the key from comparison timing | `crypto_memneq`, which reads both buffers whole |
| Recover the key from swap | `mlock` on the user-space buffer; kernel memory is not swappable |
| Squat a name an application will use | Creation is authorised by role; guests and auditors cannot create |
| Exhaust kernel memory with secrets | `max_secrets` bound |
| Act without being recorded | The audit record is written by the same code path that takes the decision, before the result is returned |

**Not defended, deliberately:**

- **Root.** Root can load a module, read `/dev/kmem` where configured, patch
  the running kernel, or simply `rmmod` and substitute its own. Any claim to
  resist a hostile administrator would be false. KVault raises the bar from
  "any process of the same user" to "ring 0", which is the honest claim.
- **A weak passphrase.** 200 000 PBKDF2 iterations make an offline attack on an
  exported vault expensive, not impossible. A four-character passphrase is
  recoverable and no amount of design fixes that.
- **Side channels beyond comparison timing.** Cache-timing attacks against the
  AES implementation are the crypto driver's problem; KVault uses the kernel's
  and inherits whatever hardening it has.
- **Denial of service by an authorised principal.** A developer who may create
  secrets may create 1024 of them. The bound limits the damage; it does not
  identify the culprit beyond what the audit log already records.

## 3.3 Why the kernel, and not a daemon

A daemon could hold the key, authenticate clients over a Unix socket with
`SO_PEERCRED`, and write an audit log. That design is common and it works. The
difference is what an attacker must achieve:

- **The boundary is enforced by hardware, not by permissions.** Vault state
  lives in ring 0. A user-space process cannot `ptrace` it, cannot read its
  address space, cannot core-dump it — not because something forbids the access
  but because the CPU does not permit it. A daemon is a process like any other,
  and anything running as the same user can read its memory.
- **Identity needs no protocol.** `current_uid()` is not a claim the caller
  makes; it is what the kernel already knows about the process that entered the
  syscall. There is no handshake to implement incorrectly and no credential to
  replay.
- **There is nothing to go around.** A daemon can be bypassed by anyone who can
  read its backing store directly. Here the device is the only path to the
  ciphertext, and the key exists nowhere else.

The cost is real and should be stated: a bug in this code is a kernel bug. That
is why the module does as little as possible, validates every byte that crosses
the boundary, and keeps the parser for the untrusted on-disk format down to one
file with explicit bounds arithmetic.

## 3.4 The reference monitor

A reference monitor must be impossible to bypass, impossible to tamper with,
and small enough to verify. `kv_acl.c` is 150 lines and is consulted by every
operation that touches a secret.

The decision procedure, in order:

1. **Owner?** The creating UID retains full control of its own secret.
2. **Admin?** The admin role is granted everything.
3. **ACL match?** Entries are searched for the caller's UID, then the caller's
   role. The first match decides — and it decides fully, including denying, so
   a specific entry can be narrower than the role default.
4. **Role default.** `kv_role_defaults[]`, which is zero for everyone except
   admin. Least privilege: a principal nobody has said anything about gets
   nothing.

Creation is a separate question and is answered separately, by
`kv_role_may_create()`. An ACL attaches to an object, and when the caller is
creating one there is no object to consult. It cannot be folded into the role
defaults either, because those are the *fallback for existing secrets*: giving
the developer role a default `WRITE` so that it could create would grant it
write access to every secret in the vault. This distinction was not obvious
in advance — it was found when the simulator showed a guest successfully
creating a secret (see §5 of the test report).

Administrative operations require **both** the admin role and `CAP_SYS_ADMIN`.
The role is vault policy; the capability is the kernel's own notion of
privilege. Requiring both means a stale role binding inherited by a recycled
UID is not sufficient on its own.

## 3.5 Cryptography

**AES-256-GCM, through `crypto_alloc_aead("gcm(aes)")`.** The module implements
no cipher; the kernel selects the best registered implementation by priority.
On this hardware that is `generic-gcm-vaes-avx2`, not any of the `aesni`
drivers — a detail that matters, because a naive check for the string `aesni`
reports *no acceleration on the fastest available hardware*. `STATUS` and
`/proc/kvault/stats` therefore report the driver name.

**GCM rather than CBC** because tamper detection is a requirement, not an
extra. CBC provides confidentiality and nothing else; detecting modification
would mean bolting on a MAC and getting the composition order right. GCM
authenticates in the same pass, and the tag is what makes a flipped byte in the
vault file a rejected import rather than silent corruption.

**The secret's name is authenticated as associated data.** Without this, every
tag still verifies after an attacker swaps two entries' ciphertexts, and a
principal who may read `public_motd` could be served the contents of
`db_password`. Binding the name makes the swap fail.

**A fresh nonce per write**, from `get_random_bytes()`. Nonce reuse under one
key does not weaken GCM, it collapses it: the XOR of the two plaintexts leaks,
and so does the authentication key. A counter would be cheaper and is the wrong
answer — restoring a backup would rewind it.

**PBKDF2-HMAC-SHA256, 200 000 iterations, in user space** via OpenSSL. The
kernel never sees a passphrase, only a derived key. The KDF runs where a slow
operation is harmless.

**The key-check value** is SHA-256 of the derived key, compared with
`crypto_memneq`. It lets `UNSEAL` distinguish a right passphrase from a wrong
one without storing anything that could reconstruct the key. `memcmp` would
return at the first differing byte, leaking how many leading bytes were correct
— enough, over many attempts, to recover the value a byte at a time.

## 3.6 Data structures

![Kernel structures](uml/03-class-kernel.png)

`struct kv_vault` is a single global instance: the device represents one vault,
the way a TPM represents one chip. Secrets live in a 256-bucket `hlist` hash
table sized at compile time, because the expected population is small and a
resizable structure would add locking complexity for no benefit.

`struct kv_secret` has no plaintext member. It holds ciphertext, nonce, tag,
ownership, timestamps and up to 16 ACL entries — nothing that is useful without
the key.

`struct kv_session` is per-`open()`, held in `file->private_data`, and captures
the caller's UID at open time. For the audit minor it also holds that reader's
cursor, which is what makes readers independent: a slow reader cannot block a
writer, and each gets every record from the moment it opened.

## 3.7 The ioctl ABI

`include/kvault_ioctl.h` is compiled verbatim by both the C module and the C++
tools — one definition, no opportunity for the two sides to disagree. User
space takes `__u8`/`__u32` from `<linux/types.h>` rather than defining them,
which collided with OpenSSL's transitive includes when tried the other way.

Two constraints shaped it:

**`_IOC_SIZEBITS` is 14 bits**, so the largest struct an `_IOW`/`_IOR` command
number can describe is 16383 bytes. `KV_LIST_MAX` is therefore 64 names
(4104 bytes), and `EXPORT`/`IMPORT` pass a *descriptor* — a `__u64` holding a
user-space address plus a length — with the blob making a second trip through
that pointer. The `__u64` rather than a real pointer keeps the struct the same
size for 32- and 64-bit callers.

**Fixed-width, explicitly padded, little-endian on disk.** `cpu_to_le32()` is
used even though the development host is little-endian, because a format whose
byte order is "whatever the writer happened to use" is not a format, and the
bug would only ever appear on someone else's hardware.

## 3.8 Persistence

![Unseal and an authorised GET](uml/04-seq-unseal-get.png)

The kernel never touches the filesystem. `EXPORT` hands out ciphertext, nonces,
tags, ACLs and the KDF parameters; user space writes it; `IMPORT` takes it back.

`IMPORT` runs **two passes**: authenticate every entry, and only then touch the
store. A damaged file therefore cannot half-load — the running vault is exactly
as it was, which the tests confirm by reading a secret back after a rejected
import. Everything parsed is untrusted, so bounds are checked by subtracting
from what remains (`len - off < need`) rather than adding to the offset
(`off + need > len`), which could wrap and pass a comparison it should fail.

**What is in the file and what is not** is a deliberate split:

- **ACLs are vault content** and travel with it, including role-subject ones.
- **UID-to-role bindings are host configuration** and do not. They map local
  UIDs, which mean nothing on another machine, so they come from
  `configs/policy.conf` and are re-applied after a load. The test suite asserts
  both halves.

The file header is the one part user space parses, and it has to be: importing
needs the key, deriving the key needs the salt, and the salt is in the file.
The salt and iteration count are public KDF parameters — their job is to make
one precomputed table useless against many vaults, not to stay hidden.

`SealedStore::save()` writes a temporary file, `fsync`s it, renames it over the
target, then `fsync`s the *directory*. Skipping that last step is the usual
mistake: the contents are durable but the name still points at the old inode.

## 3.9 Concurrency

One mutex (`kv_vault.lock`) serialises all vault state. Coarse, and
appropriate: operations are short, contention is low, and a finer scheme would
buy throughput nobody needs at the cost of correctness arguments nobody wants
to make in kernel code. The shared AEAD tfm is a second reason — `setkey`
writes to it, so two concurrent operations would race on the key.

The audit ring uses a **spinlock**, not the mutex, because it is written from
timer context where sleeping is forbidden. `kv_audit_log()` never sleeps, so it
is safe to call with the vault mutex held — which is what lets a decision and
its record be written without a window between them.

The auto-lock timer runs in softirq context and therefore uses
`mutex_trylock()`, re-arming for one second if the lock is held rather than
blocking. A timer that blocked on a mutex would be a deadlock.

## 3.10 Lifecycle

![Vault states](uml/07-state-vault.png)

Every transition out of `UNSEALED` wipes the key with `memzero_explicit()` —
not `memset()`, which the compiler may delete entirely when it can prove the
result is never read, exactly the case here.

`LOCKED_OUT` refuses `UNSEAL` **without performing the key check at all**. The
correct passphrase is refused too. This is the point: an attacker who has
exhausted the attempt budget learns nothing further, not even how long a check
took. The deadline is evaluated lazily, on the next operation that inspects
state, so no timer is needed to leave the state.

![Secret states](uml/08-state-secret.png)

## 3.11 Trade-offs and rejected alternatives

| Decision | Alternative | Why |
|---|---|---|
| GCM in the kernel | GCM in user space with OpenSSL, kernel holds the key and enforces policy | The fallback was planned and not needed. The kernel AEAD path worked; handing plaintext back out to be encrypted would have put it in ring 3 on every write |
| One global vault | Multiple named vaults per device | One vault matches the TPM analogy and halves the state to reason about. Multiple vaults is a clean extension: the hash table and ACL code are unchanged |
| Fixed roles compiled in | Roles defined at runtime | Runtime roles would be a second policy surface in the kernel with no security gain — the roles are few and stable |
| Copy through one scratch buffer in `kv_gcm` | Scatter-gather across the caller's buffers | Buffers are at most 4 KiB. The copy is cheaper than getting sg bookkeeping subtly wrong, and the scratch is wiped in one place on every exit path |
| Audit ring drops oldest | Block the writer, or drop newest | Blocking makes a slow reader a denial of service. Dropping the newest would let a flood of denials hide the denial that follows them |
| `LIST` omits unreadable names | Report them as denied | A count would leak the shape of the namespace; names like `stripe_live_key` are informative on their own |
| Secrets capped at 4 KiB | Arbitrary length | Keeps every buffer a single allocation and bounds the worst-case time under the global mutex. Large blobs belong in a file encrypted *with* a key from the vault |
