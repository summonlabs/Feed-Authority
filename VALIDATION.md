# Validation report

This report describes what was actually executed and observed for Feed Authority
1.0.0. It contains no claims about platforms, toolchains or hardware that were not
exercised on this host.

## Host and toolchain

| Item | Value |
| --- | --- |
| Operating system | Windows 11 x64 |
| Compiler | Microsoft Visual C++ 19.44.35209 (Visual Studio 2022 Community, toolset 14.44.35207) |
| CMake | 4.3.2 |
| Generator | Ninja 1.13.2 |
| Build type | Release (`/O2 /MD`) and Debug (`/MDd /RTC1`, iterator debugging) |
| Warning policy | `/W4 /permissive- /utf-8 /Zc:__cplusplus /EHsc /WX` on every first-party target |

## Build results

| Configuration | Result |
| --- | --- |
| Release, `/W4 /WX` | Clean build of the library, the tool, six examples, the benchmark and twenty-one test executables; `ctest` reports "100% tests passed, 0 tests failed out of 21" |
| Debug, `/W4 /WX` | Clean build; `ctest` reports "100% tests passed, 0 tests failed out of 21" |
| Release with `FEED_AUTHORITY_ENABLE_MSVC_ANALYZE=ON` (`/analyze /analyze:external-`) | Clean rebuild of all 86 targets with zero warnings and zero errors; see the static analysis section below |

No warning is suppressed globally. Every warning that appeared during development was
fixed at its cause.

## Sanitizer status: unavailable, with the exact blocker

AddressSanitizer was requested and is **not available** in this installation:

```
cl /nologo /std:c++20 /EHsc /fsanitize=address /Zi t.cpp
LINK : fatal error LNK1104: cannot open file 'clang_rt.asan_static_runtime_thunk-x86_64.lib'
```

The Visual Studio installation contains `asan_compat.lib` but none of the
`clang_rt.asan_*` runtime libraries or the dynamic ASan runtime DLL, which the "C++
AddressSanitizer" optional component provides. No ASan result is claimed.

The strongest technically valid substitutes were used instead:

* **Debug builds** with the MSVC runtime checks (`/RTC1`), secure CRT and debug
  iterators (`_ITERATOR_DEBUG_LEVEL=2`), which catch out-of-range indexing, stack
  corruption and iterator misuse on every path the suite exercises.
* **MSVC static analysis** (`/analyze` with external-header warnings disabled) over
  every first-party target.
* **Adversarial input tests** that feed malformed, truncated, oversized,
  wrong-version, wrong-endian, non-canonical and path-manipulated artifacts to the
  readers, and real process-death tests at each durable stage.

These are not equivalent to a sanitizer and are not reported as if they were.

## Static analysis

`/analyze` was run over the library, the tool, the examples, the benchmark and the test
targets in Release, with the same `/W4 /WX` policy, and the complete build log was
captured:

```sh
cmake -S . -B build/analyze -G Ninja -DCMAKE_BUILD_TYPE=Release \
      -DFEED_AUTHORITY_ENABLE_MSVC_ANALYZE=ON -DFEED_AUTHORITY_BUILD_TESTS=ON \
      -DFEED_AUTHORITY_BUILD_TOOLS=ON -DFEED_AUTHORITY_BUILD_EXAMPLES=ON \
      -DFEED_AUTHORITY_BUILD_BENCHMARKS=ON
cmake --build build/analyze --clean-first > build/analyze-log.txt 2>&1
```

Observed result over all 86 targets:

```
BUILD_EXIT=0
warnings: 0
errors:   0
```

A clean rebuild was used so that every translation unit really was analyzed; the log
was searched for the word `warning` and none was found.

## Test suite

Twenty-one CTest entries — fifteen proof-obligation suites plus the six examples — run to
completion with no timeout of any kind: no CTest `TIMEOUT`, no timeout wrapper, no
watchdog and no process limit. A hang would be a defect to diagnose.

The fifteen suites contain **129 test cases** and execute **1 568 individual checks**;
the observed aggregate over a full run is `checks=1568 failed_checks=0`, and `ctest`
reports `100% tests passed, 0 tests failed out of 21`.

| Executable | Proof obligations it covers |
| --- | --- |
| `fa_test_ids_limits` | Identity validation and typing, checked counters, exact time parsing, bound consistency |
| `fa_test_evidence` | Evidence states as distinct, resolution determinism, contradiction, obstruction precedence, bounds |
| `fa_test_policy` | Policy invariants, permit-path requirement, interlock rules, deterministic primary error, canonical form |
| `fa_test_evaluation` | Default deny, precedence ladder, equal-precedence conflict, obligations over preference, evidence gating, insertion-order independence, ranking neutrality |
| `fa_test_grants` | Grant binding, supersession, expiry, revocation, revalidation, evidence withdrawal, bounds |
| `fa_test_emergency` | Explicit authority only, scope and class validation, audit trail, expiry, revocation, supersession, non-overridable denials |
| `fa_test_idempotency` | Replay before generation checks, attempt conflicts, bounded window and eviction, restart survival |
| `fa_test_persistence` | Transactional publication, reopen, read-only mode, audit, verification, rollback fences, residue, retention, diff history |
| `fa_test_adversarial` | Malformed framing, truncation, oversize, wrong version, wrong endianness, non-canonical payloads, duplicate identities, dangling references, path attacks, malformed scenarios, bounds |
| `fa_test_scenario` | Grammar strictness, defaults, order independence, declaration forms, malformed values with line references |
| `fa_test_diff_history` | History ordering and bounds, optional decision events, policy and input diffs, verification |
| `fa_test_property` | Seeded randomized state machine against an independent reference model, randomized store round trips, canonical order independence |
| `fa_test_process_authority` | Lock observation, cross-process exclusion, release on process death, stale-writer fencing, epoch handoff, sequential mutation, concurrent racers |
| `fa_test_crash_recovery` | Process death at each durable stage of the publication protocol, and what recovery adopts afterwards |
| `fa_test_cli` | The tool's full lifecycle, usage versus refusal exit codes, emergency override visibility, session-scoped authorization |

The six example executables (`fa_example_*`) are registered as tests as well, so an
example that stops working is a defect rather than a stale document.

### Deterministic randomized testing

`fa_test_property` drives 40 generated facilities through the engine and compares every
candidate outcome and reason against an independent reference model of the documented
ladder, then round-trips 31 randomized generations through the store, and checks
canonical order independence for 41 more. Seeds are fixed and printed, so a failure
reproduces exactly.

### Real multiprocess and crash testing

`fa_test_process_authority` starts real operating-system processes through
`CreateProcessW` with output redirected to files (never through a pipe) and proves:

* a second process is refused with `LockConflict` while another holds authority, with a
  bounded acquisition budget rather than an unbounded wait;
* terminating the holder with `TerminateProcess` releases authority to the next writer
  and leaves a store that still verifies;
* a writer whose state was superseded is refused with `StaleAuthority` and can reload
  and continue;
* four processes mutating the same store at once leave exactly one whole verified state,
  with distinct monotonic sequences for the committed racers and specific refusals for
  the rest.

`fa_test_crash_recovery` kills a real process at `after_staging_write`,
`after_staging_readback`, `after_generation_publish`, `after_head_staging_write` and
`after_head_commit` while it is adopting an input generation, then proves that the store
reopens as exactly one whole verified state: the adoption is part of no state before the
commit point and is the whole state after it, residue is reported and retired, and the
store keeps working afterwards. The termination is
`TerminateProcess(GetCurrentProcess(), 3)` in the probe process: non-interactive, with no
CRT abort path and no error-reporting dialog.

### Install, export and downstream consumption

```sh
cmake --install build/release --prefix build/prefix
cmake -DFA_SOURCE_DIR=... -DFA_BINARY_DIR=build/downstream -DFA_PREFIX=build/prefix \
      -DFA_GENERATOR=Ninja -DFA_CONFIG=Release -P cmake/RunDownstreamCheck.cmake
```

The out-of-tree consumer in `downstream/consumer/` configures against the installed
package with `find_package(FeedAuthority 1.0 REQUIRED)`, links
`FeedAuthority::feed_authority`, and runs a full lifecycle: create a store, adopt a
facility, evaluate, issue a grant, close, reopen (the grant is recovered but refused
until revalidated), re-adopt, revalidate, verify and audit. It builds with the same
strict warning policy and prints `consumer: lifecycle complete, installed package is
usable` on success.

## Benchmark

`bench/fa_bench_authority` measures completed operations only; see the README for the
methodology. The workload is **SYNTHETIC** (a generated facility of 32 feeds, 8
protected loads, 256 declared paths, 64 permit rules and one diversity obligation, on
local storage, with no electrical equipment); the timings are **REAL** measurements on
this host. The benchmark verifies its own preconditions before reporting: it fails
rather than reporting numbers for a workload in which nothing was eligible or a grant
was not usable.

Measured in Release on this host, one process, one run:

| Operation | Scale | Per operation | Throughput |
| --- | --- | --- | --- |
| `adopt_inputs` (one full publication) | 1 | 17.1 ms | 58/s |
| `evaluate` (32 candidates, full ladder) | 20 000 | 161.5 us | 6 194/s |
| `issue_grant` (full durable publication) | 200 | 27.1 ms | 37/s |
| `authorize` (usability plus evidence re-evaluation) | 20 000 | 147.9 us | 6 760/s |
| `store_audit` (every retained generation) | 20 | 40.0 ms | 25/s |

Run-to-run variation on this host was within roughly a factor of 1.3 for the durable
operations, which are dominated by flush and atomic-replace latency, and within roughly
25% for the read paths. The store measured 1 531 128 bytes of generation content with
200 grants before it was removed; the benchmark removes its store before exiting.

## What was not validated

* **POSIX.** The POSIX branches for advisory locking (`fcntl`), durable writes
  (`fsync`), atomic replacement (`rename`) and directory listing are implemented and
  reviewed, but this host cannot build them. They are unverified at runtime.
* **AddressSanitizer.** Unavailable in this toolchain; see above.
* **Reparse points.** The refusal is implemented and unit-tested through the path
  validator. This host could not create a junction or a directory symlink for the
  end-to-end case, and the test reports that explicitly instead of passing silently.
* **Real electrical equipment.** None was connected. Nothing in this repository was
  validated against hardware, and no hardware claim is made.
* **Sustained load and long-running soak.** The benchmark measures completed operations
  at the scales it reports; it is not a soak test.
