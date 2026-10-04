# 6. Test report

All results below were produced against `kvault.ko` loaded on
**Linux 7.1.5+kali-amd64, x86-64**, with four real system users.

## 6.1 Summary

| Suite | Cases | Result |
|---|---|---|
| `unit/crypto-helpers` | 7 | 7 passed, 0 skipped, 0 failed |
| `unit/policy` | 7 | 7 passed, 0 skipped, 0 failed |
| `unit/scenario` | 8 | 8 passed, 0 skipped, 0 failed |
| `unit/sealedstore` | 11 | 11 passed, 0 skipped, 0 failed |
| `integration/ioctl` | 19 | 19 passed, 0 skipped, 0 failed |
| `system/lifecycle` | 5 | 5 passed, 0 skipped, 0 failed |
| `kvsim` multi-user scenario | 16 steps | 16/16 as policy specifies |
| RBAC + persistence session | 26 checks | 26 passed |
| **Total** | **99** | **99 passed, 0 failed** |

Kernel health after every run: no `WARNING`, `BUG`, lockdep or KASAN output;
`rmmod` clean each time.

Seven steps of the demo are captured in `screenshots/`.

## 6.2 How the suites are split

Three tiers, because they need different things from the environment:

| Tier | Needs | Runs with |
|---|---|---|
| unit | nothing | `make test` |
| integration | module loaded, device openable | `sudo make load && make test` |
| system | root, test users; changes vault state | `sudo make test` |

A case that cannot run reports `SKIP` and is counted separately. It is never
reported as a pass — a suite trusted for coverage it does not have is worse
than no suite, and §6.6 records the run where exactly that happened.

## 6.3 Requirements coverage

| Req | Evidence |
|---|---|
| FR-1 seal/unseal | `system/lifecycle`; wrong passphrase rejected on import; lockout after three failures |
| FR-2 CRUD | `integration/ioctl`: round trip at 1 byte and 4096 bytes, embedded NULs, overwrite, rotate, delete, list |
| FR-3 kernel-enforced RBAC | `kvsim` 16/16; alice allowed and bob allowed for *different reasons* under the same role |
| FR-4 grant/revoke | Identical request denied → granted → allowed → revoked → denied (`docs/screenshots/03-rbac.png`) |
| FR-5 audit | 14 records for the `kvsim` run, 7 of them denials; `AuditViewer` woken by the kernel |
| FR-6 auto-lock | `system/lifecycle`: vault reaches `AUTO_LOCKED` with no user-space process involved |
| FR-7 lockout | `v04` session: `1/3 → 2/3 → LOCKED_OUT`, correct passphrase then refused |
| FR-8 persistence | Export, reload module, unseal against the file, both secrets read back; one flipped byte rejected |
| FR-9 simulator | 4 principals, fork + irreversible `setresuid`, results table, driven by `configs/scenario-default.conf` |
| NFR-1 no plaintext at rest | `strings` over the vault file finds neither secret; names *are* present, by design |
| NFR-2 key not swapped | `mlock` in `SecureBuffer`; kernel memory not swappable; wipe test at `-O2` |
| NFR-3 no leaks | `dmesg` clean across load/unload cycles including the fuzz |
| NFR-4 concurrency | 8 processes × 50 reads; 6 threads × 40 interleaved put/get/list; zero mismatches |
| NFR-5 acceleration | `generic-gcm-vaes-avx2` reported and benchmarked (§6.5) |
| NFR-6 C/C++ only | `git ls-files` lists no interpreted source of any kind |
| NFR-7 fail closed | Every denial path returns before any `copy_to_user`; fuzz found no undocumented errno |

## 6.4 Negative and boundary testing

The integration suite spends more effort on inputs a correct caller would never
send than on the happy path.

| Input | Result |
|---|---|
| Unknown ioctl, correct magic | `ENOTTY` |
| Foreign magic (`'Z'`) | `ENOTTY` |
| Empty name / space / slash / tab | `EINVAL` |
| Name ≥ 64 bytes | `ENAMETOOLONG` |
| Zero-length value | `EINVAL` |
| Value of 4097 bytes | `E2BIG` |
| Value of exactly 4096 bytes | accepted, exact round trip |
| Value containing NUL bytes | preserved — secrets are bytes, not strings |
| `GET` with capacity below the stored length | `ENOSPC` |
| Permission bits outside `KV_PERM_ALL` | `EINVAL` |
| Subject kind other than UID/ROLE | `EINVAL` |
| Role ID beyond `KV_ROLE_COUNT` | `EINVAL` |
| Import of empty / 3-byte / 512 bytes of `0xAA` | `EINVAL` |
| Import with one bit flipped | `EBADMSG`, running vault untouched |
| Operations while sealed | `EPERM` |
| Read of fewer bytes than one audit record | `EINVAL` |
| `ioctl` on the audit minor | `ENOTTY` |

**Fuzz.** 400 iterations of random names (0–71 bytes, arbitrary byte values)
and random lengths (0–4159 bytes), fixed seed so a failure reproduces. Every
refusal carried a documented errno; nothing undocumented, no crash, `dmesg`
clean. Anything the kernel *accepted* was read back and compared, so a lenient
validator cannot pass by accident.

## 6.5 Performance

Full `GET` round trip — ioctl, reference monitor, decrypt, copy out — averaged
over 3000 operations after a 100-operation warm-up:

| Secret size | µs/op | MB/s |
|---|---|---|
| 16 B | 1.27 | 12.0 |
| 256 B | 0.94 | 258.9 |
| 1 KiB | 1.02 | 959.0 |
| 4 KiB | 1.35 | 2897.8 |

Driver selected: `generic-gcm-vaes-avx2` (hardware-accelerated).

Read these carefully. At 16 bytes the cost is almost entirely the syscall and
the policy check — the cipher is noise, and the apparent 12 MB/s says nothing
about AES. Throughput only becomes meaningful at 4 KiB, where it reaches
2.9 GB/s. The sub-microsecond figure at 256 B against 1.27 µs at 16 B is
measurement noise at this resolution, not a real inversion.

**On AES-NI detection.** This CPU reports `aes` *and* `vaes`, so the kernel
registers three `gcm(aes)` implementations and selects by priority:
`generic-gcm-vaes-avx2` (600) over `generic-gcm-aesni-avx` (500) over
`generic-gcm-aesni` (400). The first version of this code tested the driver
name for the substring `aesni` and therefore reported *no acceleration on the
fastest hardware available*. It now matches the accelerated families and
reports the driver name so the measurement says which path it measured.

**Software-path comparison: not obtained.** It requires removing the
accelerated driver (`modprobe -r aesni_intel`) and reloading the module so it
re-allocates its tfm. `aesni_intel` is in use on this host and `rmmod` refuses.
`tests/system/bench_crypto.cpp` documents the procedure for a machine where it
can be done. Reporting an un-run comparison as a result would be worse than
reporting its absence.

## 6.6 Defects found, and what found them

Six defects, and the distribution is the interesting part: **none** were found
by reading the code.

| # | Defect | Found by | Fix |
|---|---|---|---|
| 1 | AES-NI reported absent on a CPU that has it | Loading the module and reading `/proc/kvault/stats` | Match accelerated driver families; report the driver name |
| 2 | Persistence broken across a module reload — `IMPORT` failed `EACCES` and the vault looked corrupt when it was fine | The RBAC/persistence session | The file header is the authority on KDF parameters; `unseal <file>` reads them before deriving |
| 3 | `kvsim`'s privilege drop changed only the UID, so children kept root's supplementary groups | Reasoning about why group permissions would be meaningless, while writing the group setup | `initgroups` → `setresgid` → `setresuid`, in that order |
| 4 | `SimUser::run()` opened its client before any step, so an auditor who cannot open the control device crashed the forked child | First run with carol in `kvaudit` only | Opening is part of what the step tests; refusal is recorded |
| 5 | **A guest could create a secret.** `PUT` checked `WRITE` on an existing secret; nothing authorised creating a new name | `kvsim` — the step expected a denial and got an allow | `kv_role_may_create()`; plus a `max_secrets` bound |
| 7 | **A descriptor kept the privileges it was opened with.** Authorisation used the UID captured at `open()`, so a process could open the device as root, drop to an unprivileged user, and still read any secret | A proof of concept written while preparing for questions about `open()` | Authorise against `current_uid()` at operation time; the session UID is now diagnostics only |
| 6 | A skipped test case printed `ok` | Reading a run in which the auto-lock case reported green without executing | Harness reports `SKIP` and counts it; system suite restructured so nothing skips |

Defect 5 is the one that matters. A guest with no permissions at all could
bring a name into existence and become its owner — and owners have full
control. An attacker could squat a name an application expects to own, after
which the application's own writes are refused (denial of service) or, worse,
the squatter reads what something else later stores there. The hole existed
because creation is a question ACLs cannot answer: they attach to an object,
and at creation time there is none. It was invisible to inspection precisely
because every individual check in `PUT` was correct — the missing one had no
obvious place to be.

Defect 6 is a reminder that the tests are code too. The harness had a comment
saying a skipped case must not look like a pass, and then did exactly that.

## 6.7 Static analysis

`cppcheck --enable=warning,style --std=c++17` over `src/` is clean apart from
`uninitMemberVarNoCtor` on the ABI structs in `kvault_ioctl.h`. Those must
remain POD to be valid C, and every use site brace-initialises (`kv_secret_arg
arg{}`), which zeroes them. The one finding that was not an ABI struct —
`PolicyLoader::Binding` — was fixed with default member initialisers.

The module builds warning-free with `-Wall` under the kernel build system, as
do all user-space targets with `-Wall -Wextra -Wpedantic`.

## 6.8 Known limitations

1. **Root is not an adversary.** Stated in §3.2 and worth repeating: root can
   unload the module or read kernel memory. The claim is ring 0, not magic.
2. **The software-path benchmark was not run** (§6.5).
3. **`valgrind` was not run against the privileged paths.** It works on the
   unit suite; the integration and system tiers need root and a device, and a
   leak report dominated by the kernel interaction would not be informative.
   The user-space allocation surface is small and RAII-managed.
4. **`kmemleak` was not enabled** — it needs a boot parameter and a reboot.
   `dmesg` is clean across repeated load/unload cycles, which is weaker
   evidence.
5. **Recycled UIDs inherit role bindings.** Deleting `kv_alice` and creating a
   new account that reuses UID 997 gives it the developer role. This is
   inherent to identifying principals by UID; the mitigation is that
   administrative operations also require `CAP_SYS_ADMIN`.
6. **The audit log does not survive a reboot.** It is a kernel ring buffer. A
   persistent log would mean the kernel writing to a filesystem, which is
   exactly what `EXPORT` exists to avoid.
7. **One vault per machine**, 4 KiB per secret, 1024 secrets, 64 names per
   `LIST` call.
