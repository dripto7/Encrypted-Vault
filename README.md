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

Full design, UML and the state machines are in [docs/](docs/):

| | |
|---|---|
| [01-introduction.md](docs/01-introduction.md) | The problem, and why the kernel |
| [02-prd.md](docs/02-prd.md) | Requirements, FR-1…FR-9 and NFR-1…NFR-7 |
| [03-design.md](docs/03-design.md) | Architecture, threat model, crypto, ABI, trade-offs |
| [04-uml.md](docs/04-uml.md) | Class, sequence and state diagrams |
| [05-progress.md](docs/05-progress.md) | Development log and review notes |
| [06-test-report.md](docs/06-test-report.md) | 90 test cases, benchmarks, defects found |
| [screenshots/](docs/screenshots/) | The seven-step demo, with the raw transcripts beside it |

**[EXPLANATION.md](EXPLANATION.md)** is the single document that covers all of
it: how every part works, what each diagram and screenshot shows, the full
command reference, the demo script, and interview questions with answers
([print-ready PDF](docs/KVault-explanation.pdf), 43 pages).
**[BRIEF.md](BRIEF.md)** is the two-page summary of the same material
([print-ready PDF](docs/KVault-panel-brief.pdf)).

## Demo

![Multi-user simulation](docs/screenshots/04-kvsim.png)

Four principals, each in a forked child that dropped to its own UID. `kv_alice`
and `kv_bob` hold the *same role* and get different answers, because the role
is not the decision — the ACL is. `kv_eve` is refused four times by the kernel,
and `kv_carol` is refused at `open()` by file permissions before the reference
monitor is even consulted.

The remaining six steps — load, lockout, grant/revoke, the live audit stream,
the vault file in hex with a flipped byte rejected, and auto-lock — are in
[docs/screenshots/](docs/screenshots/).

## Status

| Milestone | Contents |
|-----------|----------|
| v0.1 | Repo, ABI header, char device with two minors, sessions, STATUS, audit ring with poll, procfs, user-space client and CLI skeleton |
| v0.2 | Product requirements |
| v0.3 | Design document and UML |
| v0.4 | Unseal/seal with a constant-time key check, PUT/GET with AES-256-GCM, brute-force lockout, `vaultctl` |
| v0.5 | RBAC, grant/revoke, auto-lock, lockout, export/import, simulator, test suites |
| v1.0 | Documentation complete, fresh-clone build verified |

## Testing

```bash
make test                      # unit tier; integration and system report as skipped
sudo make load && make test    # adds the integration tier
sudo make test                 # all three tiers
make -C tests bench            # GET throughput and the crypto driver in use
```

98 cases pass: 33 unit, 19 integration, 4 system, 16 simulator steps and a
26-check RBAC/persistence session. See [docs/06-test-report.md](docs/06-test-report.md).
