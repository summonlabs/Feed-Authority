#pragma once

// Externally supplied generations, internal sequences, and the writer incarnation.
//
// These counters are semantically different and therefore different types. A
// topology revision is not a policy revision, a decision generation is not a store
// sequence, and an authority epoch is not an incarnation. Nothing here converts
// into a plain integer implicitly, so a caller cannot pass the wrong one by
// accident.

#include <cstdint>
#include <iosfwd>
#include <string>
#include <string_view>

#include "feed_authority/status.hpp"

namespace feed_authority {

template <class Tag>
class Counter {
 public:
  using value_type = std::uint64_t;

  /// The zero counter. For an external revision this means "not supplied"; for an
  /// internal sequence it means "nothing yet".
  constexpr Counter() noexcept = default;

  static constexpr Counter FromValue(std::uint64_t value) noexcept { return Counter(value); }

  constexpr std::uint64_t value() const noexcept { return value_; }
  constexpr bool is_zero() const noexcept { return value_ == 0; }

  /// Checked successor. Returns `LimitExceeded` at the numeric maximum instead of
  /// wrapping.
  Result<Counter> next() const {
    if (value_ == UINT64_MAX_VALUE) {
      return Status::error(StatusCode::LimitExceeded, "counter would overflow");
    }
    return Counter(value_ + 1);
  }

  /// Decimal rendering, with no padding and no separators.
  std::string str() const;

  /// Strict decimal parse: digits only, no sign, no whitespace, no leading zeros
  /// other than "0" itself, bounded to 20 characters.
  static Result<Counter> Parse(std::string_view text);

  friend constexpr bool operator==(Counter left, Counter right) noexcept {
    return left.value_ == right.value_;
  }
  friend constexpr bool operator!=(Counter left, Counter right) noexcept {
    return left.value_ != right.value_;
  }
  friend constexpr bool operator<(Counter left, Counter right) noexcept {
    return left.value_ < right.value_;
  }
  friend constexpr bool operator>(Counter left, Counter right) noexcept { return right < left; }
  friend constexpr bool operator<=(Counter left, Counter right) noexcept { return !(right < left); }
  friend constexpr bool operator>=(Counter left, Counter right) noexcept { return !(left < right); }

 private:
  static constexpr std::uint64_t UINT64_MAX_VALUE = 0xFFFFFFFFFFFFFFFFull;
  explicit constexpr Counter(std::uint64_t value) noexcept : value_(value) {}
  std::uint64_t value_ = 0;
};

struct TopologyRevisionTag;
struct PolicyRevisionTag;
struct ControlRevisionTag;
struct EvidenceRevisionTag;
struct StoreSequenceTag;
struct DecisionGenerationTag;
struct GrantSequenceTag;
struct EventSequenceTag;
struct AuthorityEpochTag;
struct GrantIdTag;
struct EmergencyAuthorizationIdTag;

/// Generation of the externally supplied electrical topology.
using TopologyRevision = Counter<TopologyRevisionTag>;
/// Generation of the externally supplied policy set.
using PolicyRevision = Counter<PolicyRevisionTag>;
/// Generation of the externally supplied control state (operating condition and
/// switching declarations). Feed Authority reads it and never writes it.
using ControlRevision = Counter<ControlRevisionTag>;
/// Generation of the externally supplied evidence sample.
using EvidenceRevision = Counter<EvidenceRevisionTag>;
/// Internal, monotonically increasing publication sequence of the store.
using StoreSequence = Counter<StoreSequenceTag>;
/// Internal, monotonically increasing generation of eligibility decisions.
using DecisionGeneration = Counter<DecisionGenerationTag>;
/// Internal, monotonically increasing sequence of issued grants.
using GrantSequence = Counter<GrantSequenceTag>;
/// Internal, monotonically increasing sequence of audit events.
using EventSequence = Counter<EventSequenceTag>;
/// Epoch of write authority over the store. It advances once per acquired writer
/// session and fences every record that was issued under an older session.
using AuthorityEpoch = Counter<AuthorityEpochTag>;
/// A durable grant identity. It is the grant sequence value, so identities are
/// dense, deterministic and free of randomness.
using GrantId = Counter<GrantIdTag>;
/// A durable emergency authorization identity.
using EmergencyAuthorizationId = Counter<EmergencyAuthorizationIdTag>;

/// One writer session: the epoch that session acquired. Distinct from the epoch
/// because a session is a lifetime while the epoch is a number.
class Incarnation {
 public:
  Incarnation() noexcept = default;

  static Incarnation ForEpoch(AuthorityEpoch epoch) noexcept { return Incarnation(epoch); }

  AuthorityEpoch epoch() const noexcept { return epoch_; }
  bool is_unset() const noexcept { return epoch_.is_zero(); }

  friend bool operator==(Incarnation left, Incarnation right) noexcept {
    return left.epoch_ == right.epoch_;
  }
  friend bool operator!=(Incarnation left, Incarnation right) noexcept { return !(left == right); }
  friend bool operator<(Incarnation left, Incarnation right) noexcept {
    return left.epoch_ < right.epoch_;
  }

  std::string str() const { return "incarnation-" + epoch_.str(); }

 private:
  explicit Incarnation(AuthorityEpoch epoch) noexcept : epoch_(epoch) {}
  AuthorityEpoch epoch_{};
};

template <class Tag>
std::ostream& operator<<(std::ostream& stream, Counter<Tag> counter) {
  return stream << counter.str();
}

std::ostream& operator<<(std::ostream& stream, Incarnation incarnation);

/// All generations that an authoritative decision or grant binds at once. A
/// mutation states the binding it was planned against; the runtime refuses the
/// mutation when the current binding differs.
struct AuthorityBinding {
  AuthorityEpoch epoch{};
  TopologyRevision topology{};
  PolicyRevision policy{};
  ControlRevision control{};
  EvidenceRevision evidence{};
  DecisionGeneration decision{};

  friend bool operator==(const AuthorityBinding& left, const AuthorityBinding& right) noexcept {
    return left.epoch == right.epoch && left.topology == right.topology &&
           left.policy == right.policy && left.control == right.control &&
           left.evidence == right.evidence && left.decision == right.decision;
  }
  friend bool operator!=(const AuthorityBinding& left, const AuthorityBinding& right) noexcept {
    return !(left == right);
  }

  /// True when the externally supplied source generations are equal, ignoring the
  /// writer session and the decision generation. This is the comparison that
  /// decides supersession of a grant: a restarted writer session does not by
  /// itself invalidate a source generation, but a new topology, policy, control or
  /// evidence revision does.
  bool same_source_generations(const AuthorityBinding& other) const noexcept {
    return topology == other.topology && policy == other.policy && control == other.control &&
           evidence == other.evidence;
  }

  std::string to_string() const;
};

}  // namespace feed_authority
