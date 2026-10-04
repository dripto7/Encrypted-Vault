# 5. Progress log and review notes

## 5.1 Development log

| Tag | Contents |
|---|---|
| `v0.1` | Repo skeleton; `kvault_ioctl.h` (full ABI and on-disk format); char device with two minors, per-open sessions, `STATUS`; ACL evaluation; audit ring with wait queue and `poll`; procfs; auto-lock timer; `VaultClient`, `KeyDeriver`, `SecureBuffer`; `vaultctl status`/`watch`; `kvsim` skeleton; docs 01–02 |
| `v0.2` | Product requirements (FR-1…FR-9, NFR-1…NFR-7). Tagged at the same commit as `v0.1`: the PRD was written in the first sitting rather than the second, so there was never a separate state of the tree to tag |
| `v0.3` | Design document, UML sources and rendered diagrams, this log |
| `v0.4` | AES-256-GCM through the kernel crypto API; `UNSEAL`/`SEAL` with a constant-time key check; `PUT`/`GET`; brute-force lockout; the shell setup script rewritten as `kvsetup.cpp` |
| `v0.5` | Every remaining ioctl; `kv_file.c` serialisation with two-pass authenticated import; `SealedStore`, `PolicyLoader`, `AuditViewer`; finished simulator; three test tiers |
| `v1.0` | Documentation complete, demo captured, scenario file wired to the simulator, fresh-clone build verified |

Two things did not go according to the plan, both worth recording.

**The ABI was wrong on first contact with the compiler.** `_IOC_SIZEBITS` caps
an ioctl struct at 16383 bytes; `kv_list_arg` was 16392 and `kv_blob_arg` was a
megabyte. Both were designed on paper and neither could exist. The fix —
shrinking `LIST` and passing a descriptor with a user pointer for the blob — is
now the most-referenced paragraph in the design document.

**The build and the run disagreed about which kernel.** The module compiled
cleanly against the only headers installed (6.18.9) while the machine ran
7.1.5, so the first `.ko` could not be loaded at all. Worth remembering: a
module that builds is not a module that loads.

## 5.2 Schedule versus reality

The plan allocated Saturday to design and the driver, Sunday to RBAC, the
simulator and testing. What actually happened is that the driver skeleton,
audit ring and procfs landed in the first sitting, and the design document was
written *last* — against code that existed and had been run.

That inversion was accidental but turned out better. Six defects were found by
running the system (§6.6 of the test report), and three of them changed the
design: the KDF-parameter split between kernel and file, the host-configuration
versus vault-content distinction for role bindings, and the separation of
"may create" from every other permission. A design document written on
Saturday would have confidently described a system that did not work, and would
then have had to be rewritten anyway.

## 5.3 Review notes

Points raised in review, and what was done:

**"Why is `GRANT` a permission rather than an admin-only operation?"** Because
delegation needs to be delegable. If only admins could grant, every access
change would queue behind one principal. Making it a permission means the owner
of a secret can share it without being able to touch anything else — and
crucially, a principal who merely *reads* a secret cannot share it, because
`READ` does not imply `GRANT`. Had it been admin-only, the ACL would have
described a lower bound on who can access a secret rather than an upper one.

**"The auditor can't open the control device — isn't the kernel check enough?"**
The kernel check is enough. The group separation is defence in depth, and it
makes a statement the RBAC check cannot: the auditor has no business holding a
descriptor to the command channel at all. It also demonstrates the two layers
independently, which the simulator output shows — carol is refused at `open()`,
eve is refused by the reference monitor.

**"Is one global mutex going to be a bottleneck?"** Measured rather than
argued: 8 processes × 50 concurrent reads and 6 threads × 40 interleaved
operations, with a full `GET` at 1.3 µs. Contention is not the limit at this
scale, and the shared AEAD tfm would need its own serialisation regardless
because `setkey` writes to it.

**"`LIST` silently omitting entries could confuse an operator."** Accepted and
kept. An operator who cannot read a secret has no need to know it exists, and
names leak intent — `stripe_live_key` tells an attacker what the system does.
The audit log records the `LIST` call, so the operator's view is reconstructible
by someone who *is* authorised.

**"Why cap secrets at 4 KiB?"** It keeps every buffer a single allocation and
bounds the worst case under the global mutex. A large blob should be encrypted
with a key *from* the vault rather than stored *in* it — which is how a vault
is normally used in practice.

## 5.4 What I would do differently

- **Write the ABI header against the compiler, not against a diagram.** Both
  ABI defects would have surfaced in minutes.
- **Install headers for the running kernel before writing a line.** The first
  build was against the wrong tree and proved less than it appeared to.
- **Write the simulator earlier.** It found the only genuine security hole in
  the project, and it found it the first time it ran with a complete scenario.
  A denial that should have happened and did not is invisible to inspection —
  every individual check in `PUT` was correct, and the missing one had no
  obvious place to be.
- **Treat the test harness as code under test.** It reported a skipped case as
  a pass, in direct contradiction of its own comment saying it must not.
