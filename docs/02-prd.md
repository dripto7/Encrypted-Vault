# 2. Product requirements

Each requirement has an identifier, a statement, and the observable test that
decides whether it holds. A requirement that cannot be tested is not listed.

## 2.1 Functional requirements

### FR-1 — Seal and unseal

The vault starts sealed and holds no key. An administrator unseals it by
supplying a passphrase; user space derives a 256-bit key with PBKDF2-HMAC-SHA256
and passes it to the kernel once. The kernel verifies the key against a stored
key-check value and retains it. Sealing wipes the key.

- While sealed, every secret operation fails with `EPERM` and no plaintext is
  produced.
- A wrong passphrase is rejected without revealing how it differed; the
  key-check comparison is constant-time (`crypto_memneq`).
- After `SEAL`, the key bytes in kernel memory are zero.

### FR-2 — Create, read, update and delete secrets

`PUT`, `GET`, `DELETE`, `LIST` and `ROTATE` operate on secrets named by a
NUL-terminated string of at most 63 characters, with plaintext up to 4096 bytes.

- A secret stored and read back is byte-identical.
- `PUT` on an existing name creates a new version with a fresh nonce.
- `ROTATE` re-encrypts under a new nonce without changing the plaintext.
- `LIST` returns only the names the caller may read, so the namespace itself
  does not leak.
- Over-long names and over-long values are rejected with `EINVAL`/`E2BIG`
  rather than truncated.

### FR-3 — Access control enforced in the kernel

Every operation is authorised in the kernel against the caller's real UID,
obtained from `current_uid()`. The decision uses the secret's ACL, falling back
to the default permissions of the caller's role.

- The same binary run by two different users gets different answers.
- A denied operation returns `EACCES` and produces no plaintext, not even a
  partial buffer.
- Removing the user-space check entirely does not grant access: the enforcement
  point is the module, not the tool.

### FR-4 — Grant and revoke

An administrator may grant a permission bitmask (`READ`, `WRITE`, `DELETE`,
`GRANT`) on a secret to a UID or to a role, and revoke it again.

- A user denied before a grant succeeds after it, with no reload or restart.
- A user allowed before a revoke is denied after it.
- `GRANT` by a non-administrator fails with `EACCES`.
- Administrative operations require both the admin role and `CAP_SYS_ADMIN`.

### FR-5 — Audit log

Every attempt produces one record: sequence number, timestamp, UID, PID, role,
operation, secret name, result and errno. Records are readable from
`/dev/kvault_audit` as fixed-size structures, and a reader with nothing to read
blocks until there is.

- Both allowed and denied attempts appear.
- No record contains plaintext or key material.
- A reader blocked in `poll()` is woken by the next operation.
- When the ring wraps, the oldest records are lost and the drop count is
  reported in `/proc/kvault/stats`; new records are never dropped in favour of
  old ones.

### FR-6 — Automatic locking

After a configurable period of inactivity (`autolock_secs`, default 300) the
kernel wipes the key and moves the vault to `AUTO_LOCKED`.

- The vault locks itself with no user-space process involved.
- Any operation resets the timer.
- Setting `autolock_secs=0` disables the behaviour.

### FR-7 — Brute-force mitigation

After `max_attempts` (default 3) consecutive failed unseals, the vault enters
`LOCKED_OUT` for `lockout_secs` and refuses further attempts. A successful
unseal resets the counter.

- The *n*-th failure locks out; the attempt after it is refused without the
  key-check being performed at all.
- The failure counter is visible in `/proc/kvault/status` and in `STATUS`.
- Lockout survives closing and reopening the device: it is vault state, not
  session state.

### FR-8 — Persistence

`EXPORT` returns the sealed vault — ciphertext, nonces, tags, ACLs and the KDF
parameters. User space writes it to disk; `IMPORT` reloads it.

- A hex dump of the vault file contains no plaintext secret.
- Export, unload the module, reload, import: every secret reads back correctly.
- Flipping a single byte anywhere in the ciphertext or the tag makes `IMPORT`
  fail the GCM tag check, and no secret is loaded from the damaged entry.
- The file uses fixed-width little-endian fields, so it is portable between
  hosts of differing endianness.

### FR-9 — Multi-user simulator

`kvsim` forks one child per simulated principal, drops irreversibly to that
principal's UID with `setresuid()`, runs a scripted set of operations, and the
parent collects a results table comparing what happened to what the policy says
should happen.

- Each child's privilege drop is verified to be irreversible before it proceeds.
- Expected denials count as passes; an unexpected allow is a failure.
- The scenario demonstrates: an authorised read, an unauthorised read, a grant
  that changes the outcome, and an auditor who can read the log but no secret.

## 2.2 Non-functional requirements

### NFR-1 — No plaintext at rest

No file Encrypted Vault writes, and no file it causes to be written, contains a secret
in the clear. Verified by scanning the vault file for known plaintext after a
full session.

### NFR-2 — The key is never swapped or dumped

The kernel's copy is in kernel memory, which is not swappable. User space's
transient copy lives in an `mlock()`ed buffer that wipes itself on destruction
through a volatile pointer, so the wipe cannot be optimised away.

### NFR-3 — No kernel memory leaks

Loading and unloading the module leaves `kmemleak` clean and `dmesg` free of
warnings, after a workload that creates, rotates and deletes secrets.

### NFR-4 — Concurrency safety

All vault state is serialised by one mutex; the audit ring uses a spinlock
because it is written from timer context. Concurrent `GET`s from many processes
produce correct plaintext and no lockdep complaints.

### NFR-5 — Hardware acceleration where available

Encryption uses the kernel crypto API's best available `gcm(aes)`
implementation. Whether that is the AES-NI driver is reported in `STATUS` and
in `/proc/kvault/stats`, and the difference is measured in the test report.

### NFR-6 — Platform and language

Linux only, x86-64, kernel 6.x. The module is C with no external dependencies;
the tools are C++17 depending only on OpenSSL and pthreads.

### NFR-7 — Failure is closed

Any error path — allocation failure, crypto failure, a malformed request —
results in denial, not in access. Partial results are never returned: a `GET`
that fails authorisation does not write to the user's buffer at all.

## 2.3 Explicitly excluded

| Not provided | Why |
|---|---|
| Protection against root | Root can load modules and read kernel memory; claiming otherwise would be dishonest. The threat model is other local users. |
| Protection against a weak passphrase | PBKDF2 with 200 000 iterations raises the cost of an offline attack on an exported vault; it does not make a four-character passphrase safe. |
| New cryptographic primitives | Standard constructions only. |
| Networking | One host, one vault, no remote interface. |
| Side-channel hardening beyond constant-time comparison | Cache-timing attacks on the AES implementation are the crypto driver's concern, not the vault's. |
