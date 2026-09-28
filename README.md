# Feed Authority

Feed Authority is the electrical feed serving authority for the Data Center Control
Plane (DCCP), Tranche 3: Electrical Infrastructure Control. It answers one question,
and refuses to answer any other:

> **Which feed may serve this load now, under which mode, redundancy, maintenance,
> failure and policy constraints, and exactly why must an alternate feed be allowed,
> denied or left indeterminate?**

It is an authority and eligibility layer. It does not own the electrical topology, it
does not switch anything, and it does not prove that anything happened.

## Systems boundary

Feed Authority owns **which electrical feeds are permitted to serve which loads under
which operating conditions**. It is authoritative over admissibility, its reasons and
its durable grants. Everything else belongs to another system:

| Owned here | Owned elsewhere |
| --- | --- |
| Eligibility of a load/feed pair, with reasons per candidate | The electrical topology itself, its revisions and its provenance |
| The precedence ladder that decides a pair | Switching, actuation, breaker and transfer control |
| Protected-load obligations as admissibility constraints | PDU, UPS and generator control |
| Maintenance and operating-mode restrictions as admissibility constraints | Aggregate Power Control Plane state |
| Durable, revocable, generation-bound grants of serving eligibility | Power capacity computation and headroom |
| The authority epoch, decision generation and audit history | Load shedding and energy accounting |
| Revalidation of recovered authority against current inputs | Physical effect, metering and verification |

An authorization issued here grants **only feed-serving eligibility under its stated
conditions**. It does not close a breaker, transfer a load, prove available capacity or
prove physical effect. A grant is refused the moment the inputs it was bound to are
superseded, the evidence behind it stops supporting it, or the session that validated
it ends.

## The core question, answered with a candidate set

An evaluation returns every candidate with an outcome, never a single winner:

* **Allow** — an explicit permit rule matched through a named authority path, every
  higher-precedence class stayed silent, and the evidence the rule depends on is fresh.
* **Deny** — a rule or obligation denied the pair, a structural fact excludes it (no
  declared path, a feed that cannot serve), or no permit rule matched at all.
  Admissibility is closed by default: there is no implicit adjacency and no implicit
  permission.
* **Indeterminate** — the runtime cannot establish the answer from current evidence:
  stale, unknown, unsupported, unavailable, contradictory or future-dated evidence, an
  unresolved rule that could change the outcome, or two rules of equal precedence that
  contradict each other.

Admissibility is never mixed with preference. If a policy defines a ranking, the
eligible set is returned in that order and the first entry is reported as preferred; if
it does not, the eligible set is returned with
`selection_deferred_to_controller = true`. Choosing among admissible feeds is
switching, and switching is not this runtime's boundary.

## Architecture

```
include/feed_authority/   public headers: ids, generations, evidence, model, policy,
                          obligations, inputs, decision, grant, emergency,
                          idempotency, store, authority, render, scenario, diff
src/                      the library
  detail/                 canonical text codec, SHA-256, store format and path checks,
                          OS file lock, durable I/O, the eligibility engine
tools/                    feed-authority: the inspection and administration tool
examples/                 six runnable lifecycle and failure examples
bench/                    the completed-operation benchmark
tests/                    the proof obligations, one executable per obligation family
downstream/consumer/      an independent out-of-tree find_package consumer
docs/artifact-format.md   every byte-level format, bound and commit point
VALIDATION.md             what was validated, on what, and what was not
```

The library is C++20 with no third-party dependency. It is single-threaded by design:
one `FeedAuthority` value is confined to one thread, holds no internal mutex, starts no
thread nor process, and reaches the operating system only for durable file
replacement, advisory file locking and directory listing. Cross-process authority is
enforced by an operating-system lock plus generation fencing, so two processes cannot
publish over each other and a writer whose state was superseded refuses to mutate
rather than merging it.

## Authority, generations and fencing

Every value a caller can act on carries strongly typed identifiers that never collapse
into a generic integer:

| Type | Meaning |
| --- | --- |
| `TopologyRevision`, `PolicyRevision`, `ControlRevision`, `EvidenceRevision` | Externally supplied source generations |
| `StoreSequence` | Internal publication sequence, monotonic across restarts |
| `DecisionGeneration` | Internal monotonic generation of eligibility decisions |
| `AuthorityEpoch` | The writer session's epoch, advanced once per session |
| `Incarnation` | The identity of one writer session |
| `GrantId`, `EmergencyAuthorizationId` | Dense, deterministic authorization identities |
| `AttemptId` | Caller-supplied idempotency identity |

A mutation states the binding it was planned against and is refused when that binding
is no longer current: `StaleAuthority` for an epoch mismatch and
`StaleSourceGeneration` for a topology, policy, control or evidence revision mismatch.
Nothing is merged silently.

A grant binds the authority epoch, the four source revisions, the decision generation
and the decision fingerprint that authorized it. It authorizes nothing when it is
revoked, expired, superseded, recovered without revalidation, or no longer supported by
current evidence — and those are five distinguishable answers, not one failure code.

## State semantics

* **Identity is not metadata.** A feed is an opaque reference to a record another
  registry owns; Feed Authority never interprets its text.
* **Observation is not authority.** Evidence carries a declaration, an observation
  instant, a validity window and a source. Freshness is derived at an explicit instant
  and is never stored. Missing evidence resolves to Unknown, a future-dated observation
  to FutureDated, and two fresh observations that disagree to Contradictory — never to
  a value.
* **Planning is not permission.** Eligibility is computed from the adopted inputs;
  permission is a durable grant; neither is an actuation.
* **Recovered is not current.** State read from disk is adopted whole, but grants it
  contains are marked as needing revalidation, and no input generation becomes current
  merely because it was persisted.
* **Unknown, unavailable, unsupported, stale, denied and unsafe are all distinct**, and
  none of them is zero or "safe". A refusal always names its reason.

## Persistence and recovery

Authority state is stored in a directory with an explicit, integrity-checked format
documented in `docs/artifact-format.md`: a lock file, a fixed-size head marker with a
self digest and a previous-head digest chain, fixed-size generation files with a magic,
a format version, explicit sizes, an endianness check and a SHA-256 payload digest, and
a staging directory that is never authoritative.

Publication is transactional: reserve the sequence, write and flush the staging
generation, read it back and verify it byte for byte and structurally, publish it by
atomic rename, write and verify the new head marker, then atomically replace the head
marker. **The commit point is the atomic replacement of the head marker.** Before it,
the previous head is the whole state; after it, the new generation is. A crash in
between leaves staging or an orphan generation, both of which are residue: recovery
ignores them, reports them, and the next publication retires them.

Recovery adopts exactly one whole verified state or refuses. A store whose head is
older than the generations present (beyond a single orphan), whose generation digest
does not match, whose framing is truncated or whose payload is not canonical is
refused rather than repaired. Callers may additionally require a minimum sequence and
epoch, which fences a whole-store rollback to an older but internally valid state.

## Idempotency and replay

Every mutation carries a caller-supplied attempt identity. A retry of an accepted
attempt returns the prior accepted result **before any generation check runs**, so a
lost response can be retried even after another process moved the store on. Reusing an
attempt with different content is refused with `AttemptConflict`. The retained window
is bounded by `Limits::max_replay_entries` and evicts oldest first; once an attempt
falls out of the window, a retry behaves exactly like a new mutation and is judged
against current generations. The window is persisted, so replay survives a restart.

## Command line

```sh
feed-authority store create   --store DIR
feed-authority inputs adopt   --store DIR --scenario FILE
feed-authority evaluate       --store DIR --load L1 --scenario FILE --now 1735689600
feed-authority explain        --store DIR --load L1 --feeds F1,F2
feed-authority grant issue    --store DIR --load L1 --feed F1 --validity 300s
feed-authority grant check    --store DIR --id 1 --scenario FILE
feed-authority grant revalidate --store DIR --id 1 --scenario FILE --check
feed-authority grant revoke   --store DIR --id 1 --authorizer OPERATOR-1 --reason "..."
feed-authority emergency authorize --store DIR --authorizer INCIDENT-COMMANDER \
                              --justification "..." --loads L1 --classes maintenance_restriction \
                              --validity 600s --attempt e1
feed-authority store audit    --store DIR
feed-authority store verify   --store DIR
feed-authority store history  --store DIR --limit 20
feed-authority diff policy    --store DIR --from 4 --to 5
feed-authority evaluate       --store DIR --load L1 --scenario FILE --json
```

Exit codes: `0` success, `1` a refusal or a failure (a denied candidate, a revoked
grant, a corrupt store), `2` an unrecognized command or option. Every answer comes
from the library; the tool decides nothing on its own and never enables fault
injection.

## Examples

`examples/` contains six runnable programs, each registered as a test so that an
example that stops working is a defect rather than a stale document:

| Example | What it shows |
| --- | --- |
| `primary_secondary` | Normal operation: two admissible feeds, no ranking in policy, selection deferred |
| `maintenance_restriction` | A maintenance withdrawal that outranks an ordinary permit |
| `degraded_failover` | A failover-scoped permit and a faulted feed that policy cannot rescue |
| `emergency_authority` | An explicit, recorded override with its audit trail |
| `contradictory_evidence` | Disputed and stale evidence that never becomes permission |
| `stale_grant_refusal` | A superseded grant, revalidation, and revocation that is final |

## Consuming the package

```cmake
find_package(FeedAuthority 1.0 REQUIRED)
target_link_libraries(your_target PRIVATE FeedAuthority::feed_authority)
```

`downstream/consumer/` is an independent out-of-tree project that consumes the
installed package through `find_package` and runs a full lifecycle: create a store,
adopt a facility, evaluate, issue a grant, close, reopen, revalidate, verify and audit.
It is built and run by `cmake/RunDownstreamCheck.cmake`, which fails with the exact
reason when no toolchain or no installed package can be reached.

## Validation

`VALIDATION.md` records exactly what was validated. In summary, on Windows x64 with
MSVC 19.44: a Release and a Debug build with `/W4 /WX /permissive-`; 21 CTest entries —
15 proof-obligation suites plus 6 examples — running 129 test cases and 1 568 individual
checks with zero failures; a seeded randomized state machine checked against an
independent reference model; real multiprocess tests proving exclusion, release on
process death, stale-writer fencing and concurrent mutation; crash-injection tests that
kill a real process at each durable stage of the publication protocol; adversarial store
and path tests; and an out-of-tree `find_package` consumer built and run against a clean
install prefix.

## Benchmark

`bench/fa_bench_authority` measures **completed operations only** — nothing is timed
at submission, because this runtime has no queue. Every measured operation includes all
the work that makes it complete: validation, canonical encoding, staging write, required
flush, read-back verification, atomic publish and head commit for anything durable.

Workload: a synthetic facility with 32 feeds, 8 protected loads, 256 declared paths, 64
permit rules and one diversity obligation, adopted into a scratch store on local
storage. The workload is **SYNTHETIC**: no electrical equipment is involved. The
timings are **REAL** measurements of this process on this host.

Measured in Release with MSVC 19.44 on Windows x64 (one run, one process; the store is
removed afterwards):

| Operation | Scale | Per operation | Throughput |
| --- | --- | --- | --- |
| `adopt_inputs` (one full publication) | 1 | ~19 ms | ~53/s |
| `evaluate` (32 candidates, full ladder) | 20 000 | ~160-200 us | ~5 000-6 200/s |
| `issue_grant` (full durable publication) | 200 | ~25-33 ms | ~30-40/s |
| `authorize` (usability plus evidence re-evaluation) | 20 000 | ~150-370 us | ~2 700-6 800/s |
| `store_audit` (every retained generation) | 20 | ~40 ms | ~25/s |

The durable operations are dominated by the platform's flush and atomic-replace cost,
which is the price of the transactional publication described above; the read paths
(evaluation and authorization) never take a store lock and never write.

## Concurrency model and lock order

* One `FeedAuthority` value belongs to one thread. The library holds no internal
  mutex, starts no thread and runs no callback while holding a lock.
* Mutations acquire exactly one lock: the operating-system advisory lock on the store's
  lock file, held only for the duration of one publication. Nothing else is acquired
  while it is held, so there is no nested lock order to invert, and no callback or user
  code runs under it.
* Evaluation and authorization never take the lock: they read the adopted value
  snapshot.
* A writer whose in-memory state is older than the committed head is refused with
  `StaleAuthority`; `Reload()` adopts the newer head explicitly.
* The lock is released by the operating system when a process dies, which is why an
  abruptly terminated writer cannot wedge a store.

## Genuine limitations

* Validated on Windows x64 with MSVC only. The POSIX branches for file locking, durable
  writes, atomic replacement and directory listing are implemented and compile-checked
  by inspection, but they were not built or exercised on this host.
* AddressSanitizer is not available in the installed toolchain: the Visual Studio
  installation has no ASan runtime (`clang_rt.asan_*` is absent, and linking with
  `/fsanitize=address` fails with `LNK1104`). Debug builds with iterator debugging and
  runtime checks, plus MSVC static analysis, were used instead; they are not equivalent
  to a sanitizer.
* The reparse-point refusal is implemented and unit-tested through the path validator,
  but this host could not create a junction or symlink for the end-to-end case, so that
  specific scenario is reported as unexercised rather than proven.
* Evidence freshness is judged at the instant the caller supplies. The library reads a
  clock only when a caller does not supply one (`OpenOptions::opened_at` and the tool's
  `--now`), and it never reads one implicitly during evaluation.
* Evaluation is linear in the candidate set and the rule set; there is no incremental
  re-derivation and no cached partial order.
* Grants are bounded per store (`Limits::max_grants`) and are refused rather than
  evicted when the bound is reached, because a grant is an auditable record.
* The idempotency window is bounded and evicts oldest first. An attempt that has been
  evicted is no longer replayable; a retry then behaves like a new mutation.

## License

Apache License 2.0. Copyright 2026 Summon Software Labs. No telemetry transmission.
