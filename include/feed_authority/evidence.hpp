#pragma once

// Observation and evidence resolution.
//
// Evidence is what an external source reported; it is never authority. A record
// carries a declaration (known / unknown / unsupported / unavailable), the instant
// it was observed, the window it stays valid for, and the source that produced it.
// Resolution happens against an explicit instant, so the same inputs and the same
// instant always produce the same answer.
//
// The resolver is deliberately pessimistic:
//   * missing evidence resolves to Unknown, never to a value;
//   * an observation dated after the evaluation instant (a clock anomaly) resolves
//     to FutureDated, never to a value;
//   * two fresh observations that disagree resolve to Contradictory, never to one
//     of the two values;
//   * only an observation that is declared known, within its window, and not
//     disputed resolves to Fresh.

#include <cstdint>
#include <iosfwd>
#include <string>
#include <string_view>
#include <vector>

#include "feed_authority/ids.hpp"
#include "feed_authority/limits.hpp"
#include "feed_authority/status.hpp"
#include "feed_authority/time.hpp"

namespace feed_authority {

/// Absolute maximum number of independent observations accepted for one subject.
inline constexpr std::uint32_t kMaxObservationsPerSubject = 8;

/// What the source declared about a subject.
enum class EvidenceDeclaration : std::int32_t {
  /// The source reported a value.
  Known = 0,
  /// The source did not report the value.
  Unknown = 1,
  /// The source cannot report this subject at all.
  Unsupported = 2,
  /// The source is reachable in principle but the value is not obtainable now.
  Unavailable = 3,
};

/// The state of evidence at a specific instant, or the reason no value could be
/// established.
enum class EvidenceState : std::int32_t {
  /// Known, within its window, and undisputed.
  Fresh = 0,
  /// Known but observed longer ago than its window allows.
  Stale = 1,
  /// Observed after the instant it is judged at: a clock anomaly, not a value.
  FutureDated = 2,
  /// No observation was supplied.
  Unknown = 3,
  /// The source declared it cannot report this subject.
  Unsupported = 4,
  /// The source declared the value unobtainable right now.
  Unavailable = 5,
  /// Two or more fresh observations disagree.
  Contradictory = 6,
};

const char* to_string(EvidenceDeclaration declaration) noexcept;
const char* to_string(EvidenceState state) noexcept;
Result<EvidenceDeclaration> parse_evidence_declaration(std::string_view text);
Result<EvidenceState> parse_evidence_state(std::string_view text);
std::ostream& operator<<(std::ostream& stream, EvidenceDeclaration declaration);
std::ostream& operator<<(std::ostream& stream, EvidenceState state);

/// The order in which an obstructed subject reports its reason. Lower is reported
/// first. Contradiction outranks staleness because a disputed value is a defect in
/// the evidence itself rather than a property of its age.
int evidence_state_precedence(EvidenceState state) noexcept;

/// One observed value of one subject, from one source.
template <class Value>
class Observation {
 public:
  Observation() noexcept = default;

  static Result<Observation> Known(Value value, AuthorityTime observed_at, Duration max_age,
                                   EvidenceSourceId source) {
    if (!source.valid()) {
      return Status::error(StatusCode::InvalidArgument, "evidence source identity is not set");
    }
    if (max_age.is_zero()) {
      return Status::error(StatusCode::InvalidArgument,
                           "a known observation requires a non-zero validity window");
    }
    Observation observation;
    observation.declaration_ = EvidenceDeclaration::Known;
    observation.value_ = value;
    observation.observed_at_ = observed_at;
    observation.max_age_ = max_age;
    observation.source_ = std::move(source);
    return observation;
  }

  static Observation Unknown(EvidenceSourceId source) {
    return Declared(EvidenceDeclaration::Unknown, std::move(source));
  }
  static Observation Unsupported(EvidenceSourceId source) {
    return Declared(EvidenceDeclaration::Unsupported, std::move(source));
  }
  static Observation Unavailable(EvidenceSourceId source) {
    return Declared(EvidenceDeclaration::Unavailable, std::move(source));
  }

  static Observation Declared(EvidenceDeclaration declaration, EvidenceSourceId source) {
    Observation observation;
    observation.declaration_ = declaration;
    observation.source_ = std::move(source);
    return observation;
  }

  EvidenceDeclaration declaration() const noexcept { return declaration_; }
  Value value() const noexcept { return value_; }
  AuthorityTime observed_at() const noexcept { return observed_at_; }
  Duration max_age() const noexcept { return max_age_; }
  const EvidenceSourceId& source() const noexcept { return source_; }

  EvidenceState state_at(AuthorityTime now) const noexcept {
    switch (declaration_) {
      case EvidenceDeclaration::Unknown:
        return EvidenceState::Unknown;
      case EvidenceDeclaration::Unsupported:
        return EvidenceState::Unsupported;
      case EvidenceDeclaration::Unavailable:
        return EvidenceState::Unavailable;
      case EvidenceDeclaration::Known:
        break;
    }
    if (observed_at_ > now) {
      return EvidenceState::FutureDated;
    }
    const Result<Duration> age = now.Since(observed_at_);
    if (!age.ok()) {
      return EvidenceState::FutureDated;
    }
    return age.value() <= max_age_ ? EvidenceState::Fresh : EvidenceState::Stale;
  }

  friend bool operator==(const Observation& left, const Observation& right) noexcept {
    return left.declaration_ == right.declaration_ && left.value_ == right.value_ &&
           left.observed_at_ == right.observed_at_ && left.max_age_ == right.max_age_ &&
           left.source_ == right.source_;
  }
  friend bool operator!=(const Observation& left, const Observation& right) noexcept {
    return !(left == right);
  }

 private:
  EvidenceDeclaration declaration_ = EvidenceDeclaration::Unknown;
  Value value_{};
  AuthorityTime observed_at_{};
  Duration max_age_{};
  EvidenceSourceId source_{};
};

/// The outcome of resolving every observation of one subject at one instant.
template <class Value>
struct ResolvedEvidence {
  /// The state of the subject. Only `Fresh` establishes a value.
  EvidenceState state = EvidenceState::Unknown;
  /// The established value. Meaningful only when `state == Fresh`.
  Value value{};
  /// The source that established the value when the state is Fresh, or the smallest
  /// source identity among the observations when the subject is obstructed. It is
  /// unset only when no observation was supplied at all. Two runs over the same
  /// observations therefore always report the same source, whatever order they
  /// arrived in.
  EvidenceSourceId source{};

  bool usable() const noexcept { return state == EvidenceState::Fresh; }
};

/// Resolves a bounded set of observations at `now`.
///
/// Deterministic in every case: the reported source of an agreed fresh value is the
/// smallest source identity, and the reported obstruction is chosen by
/// `evidence_state_precedence`. The number of observations is bounded by
/// `kMaxObservationsPerSubject`; a larger set returns LimitExceeded.
template <class Value>
Result<ResolvedEvidence<Value>> resolve_evidence(const std::vector<Observation<Value>>& observations,
                                                 AuthorityTime now,
                                                 std::uint32_t max_observations = kMaxObservationsPerSubject) {
  if (observations.size() > max_observations) {
    return Status::error(StatusCode::LimitExceeded, "too many observations for one subject");
  }
  ResolvedEvidence<Value> resolved;
  if (observations.empty()) {
    resolved.state = EvidenceState::Unknown;
    return resolved;
  }

  bool have_fresh = false;
  Value fresh_value{};
  EvidenceSourceId fresh_source{};
  bool disputed = false;

  EvidenceState obstruction = EvidenceState::Unknown;
  bool have_obstruction = false;
  EvidenceSourceId smallest_source;

  for (const Observation<Value>& observation : observations) {
    if (!smallest_source.valid() || observation.source() < smallest_source) {
      smallest_source = observation.source();
    }
    const EvidenceState state = observation.state_at(now);
    if (state == EvidenceState::Fresh) {
      if (!have_fresh) {
        have_fresh = true;
        fresh_value = observation.value();
        fresh_source = observation.source();
      } else if (!(observation.value() == fresh_value)) {
        disputed = true;
      } else if (observation.source() < fresh_source) {
        fresh_source = observation.source();
      }
      continue;
    }
    if (!have_obstruction || evidence_state_precedence(state) < evidence_state_precedence(obstruction)) {
      obstruction = state;
      have_obstruction = true;
    }
  }

  if (disputed) {
    resolved.state = EvidenceState::Contradictory;
    resolved.source = smallest_source;
    return resolved;
  }
  if (have_fresh) {
    resolved.state = EvidenceState::Fresh;
    resolved.value = fresh_value;
    resolved.source = fresh_source;
    return resolved;
  }
  resolved.state = have_obstruction ? obstruction : EvidenceState::Unknown;
  resolved.source = smallest_source;
  return resolved;
}

}  // namespace feed_authority
