# KVault — a kernel-backed encrypted secrets vault with role-based access control

KVault stores application secrets encrypted, keeps the master key in kernel
memory only, decides every access in the kernel from the caller's real Linux
UID, and records every attempt — allowed or denied — in an append-only audit
log.

The usual alternative is a config file or an environment variable. Both are
readable by any process running as the same user, and neither leaves a trace of
who read what. KVault moves the decision across the syscall boundary, where
user space cannot reach it.

## Layout

```
include/kvault_ioctl.h   the ABI shared by the module and the tools
driver/                  kvault.ko — char device, reference monitor, crypto, audit
src/client/              VaultClient, KeyDeriver, SecureBuffer (C++17)
src/cli/                 vaultctl
src/sim/                 kvsim — the multi-user access simulator
tests/                   unit, integration and system suites
configs/                 policy.conf (users → roles), simulation scenarios
docs/                    design documents, UML, diagrams, test report
```

## Build

Kernel headers for the *running* kernel are required, plus OpenSSL development
headers:

```bash
sudo apt install build-essential linux-headers-$(uname -r) libssl-dev
```

```bash
make            # module + user-space tools
make driver     # kvault.ko only
make user       # vaultctl + kvsim only
```

Secure Boot must be off, or an unsigned module will be refused at load time
(`mokutil --sb-state` to check).

## Run

```bash
sudo make load                 # insmod, then show the device nodes
cat /proc/kvault/status        # SEALED, and no secrets in sight
build/bin/vaultctl status
sudo make unload               # rmmod — the key is wiped on the way out
```

A session end to end:

```bash
sudo build/bin/vaultctl unseal            # first unseal adopts the passphrase
printf 's3cr3t' | sudo build/bin/vaultctl put db_password
sudo build/bin/vaultctl get db_password
sudo build/bin/vaultctl seal              # key wiped from kernel memory
```

For the multi-user simulation, create the test principals first:

```bash
sudo build/bin/kvsetup
sudo build/bin/kvsim
```

## Design in one paragraph

A single char device exposes two minors: `/dev/kvault` takes commands over
`ioctl`, and `/dev/kvault_audit` is a read-only stream that blocks on a wait
queue until there is something to report. Unsealing hands the kernel a
256-bit key derived in user space with PBKDF2; the kernel checks it against a
stored key-check value in constant time, keeps it, and user space wipes its
copy. Secrets are encrypted with AES-256-GCM through the kernel crypto API,
which selects the AES-NI implementation when the CPU has it. Persistence is
user space's job: `EXPORT` hands out ciphertext, nonces and tags, never
plaintext and never the key.

Full design, UML and the state machines are in [docs/](docs/).

## Status

| Milestone | Contents |
|-----------|----------|
| v0.1 | Repo, ABI header, char device with two minors, sessions, STATUS, audit ring with poll, procfs, user-space client and CLI skeleton |
| v0.2 | Product requirements |
| v0.3 | Design document and UML |
| v0.4 | Unseal/seal with a constant-time key check, PUT/GET with AES-256-GCM, brute-force lockout, `vaultctl` |
| v0.5 | RBAC, grant/revoke, auto-lock, lockout, export/import, simulator, test suites |
| v1.0 | Final report and demo |
