# 1. Introduction

## 1.1 The problem

Applications need credentials at runtime: database passwords, API tokens, TLS
private keys. In practice these end up in one of three places, and all three
share the same two weaknesses.

| Where it goes | Who can read it | Who finds out |
|---|---|---|
| A config file next to the code | Any process running as that user; anyone who reads a backup or a git history | Nobody |
| An environment variable | Any process of that user, plus anything that can read `/proc/<pid>/environ`; it leaks into crash dumps, `ps` output and child processes | Nobody |
| A hardcoded constant | Anyone with the binary | Nobody |

The first weakness is **granularity**. The unit of protection is the Unix file
permission, so the smallest thing that can be protected is the whole file. If
two services run as the same user, each can read the other's credentials, and
nothing in the system expresses the intent that it should not.

The second is **accountability**. A `read()` on a config file is an ordinary
file read. Nothing distinguishes the application loading its own password from
a compromised process on the same box reading it for the first time, so there
is no record to consult after an incident.

Encrypting the file does not fix either one. The application still has to
decrypt it, so the key has to be somewhere the application can reach — which
means the problem has been moved, not solved.

## 1.2 What KVault does

KVault moves three things into the kernel:

1. **The key.** The master key is derived from a passphrase in user space,
   handed to the kernel once, and wiped from user space immediately. It lives
   in kernel memory, is never written to disk, and is destroyed when the vault
   is sealed, when the inactivity timer fires, or when the module is unloaded.

2. **The decision.** Every operation is checked against the vault's policy
   using the caller's real UID, read by the kernel from the calling process's
   own credentials. A process cannot claim to be someone else, because the only
   way to change that UID is a syscall the kernel itself authorised. This is a
   *reference monitor*: a single point every access must pass through, that
   cannot be bypassed and cannot be tampered with by the subjects it governs.

3. **The record.** Every attempt produces an audit record — the UID, the PID,
   the operation, the secret and the outcome — whether it was allowed or
   denied. Denials are the interesting half: a config file cannot tell you
   about an access that should not have happened, because it did not stop it.

The result is closer to a software TPM than to a password manager. The device
behaves like a piece of hardware that holds a key and will perform operations
with it on request, for callers it recognises, while logging what it was asked.

## 1.3 Why the kernel

The honest objection is that an ordinary daemon could do all of this. It could
hold the key in its own memory, check a client's identity over a Unix socket
with `SO_PEERCRED`, and write an audit log. That design is real and common.

The kernel version differs in what an attacker has to achieve:

- **The privilege boundary is hardware-enforced.** The vault's state lives in
  ring 0. A user-space process cannot read it with a debugger, cannot attach to
  it with `ptrace`, and cannot dump its address space — not because permissions
  forbid it but because the CPU does not permit the access at all. A daemon
  holding a key is a process like any other, and anything running as the same
  user (or as root) can read its memory.

- **The identity needs no protocol.** `current_uid()` is not a claim the caller
  makes; it is what the kernel already knows about the process that entered the
  syscall. There is no handshake to get wrong and no credential to replay.

- **There is nothing to bypass.** A daemon can be ignored: a process that can
  read the daemon's backing store does not need to ask it anything. The device
  is the only path to the ciphertext, and the key never exists outside it.

What this does *not* defend against is root. A sufficiently privileged user can
load a module, patch kernel memory or read the key out of the running kernel.
KVault's threat model is therefore explicit about it: the adversary is an
unprivileged or differently-privileged local process, not the machine's
administrator. Section 2 of the design document states this in full.

## 1.4 Scope

In scope:

- A loadable kernel module providing an encrypted secret store with
  UID-based role access control, an audit log and a lifecycle (seal, unseal,
  auto-lock, brute-force lockout).
- User-space tooling: a CLI (`vaultctl`) and a multi-user simulator (`kvsim`)
  that forks a child per principal, drops to that principal's UID, and reports
  what the kernel allowed and denied.
- Persistence of the encrypted store, and detection of tampering with it.

Out of scope, and deliberately so:

- New cryptography. KVault uses AES-256-GCM from the kernel crypto API and
  PBKDF2 from OpenSSL. The contribution is the system design.
- Defence against a malicious administrator, offline attacks on a weak
  passphrase, or side channels beyond the constant-time comparisons noted in
  the design.
- Networking, clustering or a distributed trust model. One machine, one vault.

## 1.5 How the rest of the documents fit together

| Document | Contents |
|---|---|
| `02-prd.md` | Functional and non-functional requirements, FR-1 … FR-9 |
| `03-design.md` | Architecture, data structures, the ioctl ABI, threat model |
| `04-uml.md` | Class diagram, sequence diagrams, state machines |
| `05-progress.md` | Development log and peer review notes |
| `06-test-report.md` | Test plan, results, the AES-NI benchmark, known limitations |
