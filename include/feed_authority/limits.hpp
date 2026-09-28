#pragma once

// Every externally influenced bound in one place.
//
// All sizes that can be influenced by an operator, a caller, or persisted input
// are bounded before allocation. A limit is either enforced by a `Limits` value
// carried by the owning component or is a compile-time constant when the value is
// part of the format contract and may never vary between readers.

#include <cstdint>

#include "feed_authority/status.hpp"

namespace feed_authority {

/// Absolute maximum length of an identity in every format this library reads or
/// writes. `Limits::max_id_length` may lower it, never raise it.
inline constexpr std::uint32_t kMaxIdentityLength = 64;

/// Absolute maximum length of a free-text field (reason note, authorizer,
/// justification) in every format this library reads or writes.
inline constexpr std::uint32_t kMaxTextLength = 256;

/// Absolute maximum number of candidate feeds a single evaluation may consider.
inline constexpr std::uint32_t kMaxCandidates = 1024;

/// Absolute maximum generation file size accepted by the store reader.
inline constexpr std::uint64_t kMaxGenerationBytes = 64ull * 1024ull * 1024ull;

/// Absolute maximum length of one canonical payload line.
inline constexpr std::uint64_t kMaxPayloadLineBytes = 4096;

/// Bounds applied to topology, policy, authority state and store artifacts.
struct Limits {
  std::uint32_t max_id_length = kMaxIdentityLength;
  std::uint32_t max_text_length = kMaxTextLength;

  std::uint32_t max_feeds = 4096;
  std::uint32_t max_loads = 4096;
  std::uint32_t max_links = 16384;
  std::uint32_t max_maintenance_records = 4096;

  std::uint32_t max_rules = 1024;
  std::uint32_t max_obligations = 512;
  std::uint32_t max_conditions_per_rule = 8;
  std::uint32_t max_scope_failure_domains = 64;

  std::uint32_t max_candidates = 256;

  std::uint32_t max_grants = 4096;
  std::uint32_t max_emergency_authorizations = 1024;
  std::uint32_t max_override_classes = 8;

  /// Bounded audit history and idempotency retention of the store.
  std::uint32_t max_events = 4096;
  std::uint32_t max_replay_entries = 4096;
  std::uint32_t max_policy_history = 4;
  std::uint32_t max_topology_history = 4;

  /// Decision generations handed out by one lease. The lease ceiling is persisted,
  /// so generations are monotonic across restarts without a write per evaluation.
  std::uint32_t decision_lease = 4096;

  /// Verified generations kept on disk after a successful publication.
  std::uint32_t generation_retention = 8;

  std::uint64_t max_generation_bytes = kMaxGenerationBytes;
  std::uint64_t max_payload_line_bytes = kMaxPayloadLineBytes;

  /// Upper bounds for time-bounded authority, in nanoseconds.
  std::int64_t max_grant_validity_nanos = 30ll * 24ll * 60ll * 60ll * 1000000000ll;
  std::int64_t max_emergency_validity_nanos = 24ll * 60ll * 60ll * 1000000000ll;

  /// Nanoseconds a mutation waits for the cross-process writer lock before it
  /// refuses with `LockConflict`. This is an error bound, not a test timeout.
  std::int64_t lock_acquire_budget_nanos = 30ll * 1000000000ll;

  /// Validates the bounds against each other and against the format constants.
  Status validate() const;
};

}  // namespace feed_authority
