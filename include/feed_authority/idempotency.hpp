#pragma once

// Bounded idempotency retention.
//
// Every mutation carries a caller-supplied attempt identity. A retry of an attempt
// that was already accepted returns the prior accepted result *before* any
// generation check runs, so a lost response can be retried safely even after the
// store has moved on. Reusing an attempt identity with different content is
// refused. The retained window is bounded and its semantics are explicit: once an
// attempt falls out of the window its prior result can no longer be replayed, and a
// retry behaves like a new mutation, including the stale-authority refusal that
// applies to any new mutation.

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "feed_authority/digest.hpp"
#include "feed_authority/generations.hpp"
#include "feed_authority/ids.hpp"
#include "feed_authority/status.hpp"

namespace feed_authority {

/// The mutation kinds that participate in idempotent replay.
enum class AttemptKind : std::int32_t {
  AdoptInputs = 0,
  IssueGrant = 1,
  RevokeGrant = 2,
  RevalidateGrant = 3,
  AuthorizeEmergency = 4,
  RevokeEmergency = 5,
};

const char* to_string(AttemptKind kind) noexcept;
Result<AttemptKind> parse_attempt_kind(std::string_view text);

/// One retained idempotency record.
struct AttemptRecord {
  AttemptId attempt;
  AttemptKind kind = AttemptKind::IssueGrant;
  /// Fingerprint of the logical request, excluding volatile values.
  Digest request_fingerprint;
  /// The grant the attempt produced, when it produced one.
  std::optional<std::uint64_t> grant_id;
  /// The emergency authorization the attempt produced, when it produced one.
  std::optional<std::uint64_t> emergency_id;
  /// The store sequence at which the attempt was accepted.
  StoreSequence recorded_at{};

  friend bool operator==(const AttemptRecord& left, const AttemptRecord& right) noexcept {
    return left.attempt == right.attempt && left.kind == right.kind &&
           left.request_fingerprint == right.request_fingerprint &&
           left.grant_id == right.grant_id && left.emergency_id == right.emergency_id &&
           left.recorded_at == right.recorded_at;
  }
};

}  // namespace feed_authority
