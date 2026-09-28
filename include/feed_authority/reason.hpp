#pragma once

// Stable reason codes.
//
// Every candidate outcome carries a primary reason code plus the full ordered list
// of reasons that contributed. The numeric values are part of the public contract
// and are never reused; the textual tokens are lower_snake_case and stable.

#include <cstdint>
#include <iosfwd>
#include <string_view>

#include "feed_authority/status.hpp"

namespace feed_authority {

enum class ReasonCode : std::int32_t {
  /// The topology path is confirmed present by fresh evidence.
  PathConfirmed = 0,
  /// The topology path is confirmed absent by fresh evidence.
  PathAbsent = 1,
  /// The topology path exists structurally but its evidence is not fresh; the
  /// companion evidence references carry the exact state.
  PathNotEstablished = 2,
  /// The candidate feed is not present in the supplied topology revision.
  FeedUnknown = 3,
  /// The requested load is not present in the supplied topology revision.
  LoadUnknown = 4,
  /// The requested candidate has no declared path to the load. There is no
  /// implicit adjacency in this runtime.
  CandidateNotLinked = 5,
  /// The feed condition is fresh and permits serving.
  FeedConditionAllows = 6,
  /// The feed condition is fresh and prevents serving (de-energized, faulted or
  /// isolated).
  FeedConditionPrevents = 7,
  /// The feed condition could not be established from fresh evidence.
  FeedConditionNotEstablished = 8,
  /// A safety interlock rule denies the pair. This class is never overridable.
  SafetyInterlockDenied = 9,
  /// A protected obligation denies the pair for this candidate.
  ObligationDenied = 10,
  /// A protected-load diversity obligation is not met by the eligible set.
  ObligationDiversityUnmet = 11,
  /// Maintenance exposure withdraws the feed from service.
  MaintenanceWithdrawn = 12,
  /// Maintenance exposure restricts the feed, and policy denies it in this
  /// condition.
  MaintenanceRestricted = 13,
  /// Maintenance exposure could not be established, and a rule depends on it.
  MaintenanceNotEstablished = 14,
  /// An operating-mode rule denies the pair in the current mode.
  OperatingModeDenied = 15,
  /// The operating condition could not be established, and a rule depends on it.
  OperatingModeNotEstablished = 16,
  /// An ordinary policy rule permits the pair through a named authority path.
  RulePermitted = 17,
  /// An ordinary policy rule denies the pair.
  RuleDenied = 18,
  /// No permit rule matched. Admissibility is closed by default.
  NoPermitRuleMatched = 19,
  /// Two rules of equal precedence contradicted each other.
  EqualPrecedenceConflict = 20,
  /// An explicit emergency authorization overrode an overridable denial.
  EmergencyOverrideApplied = 21,
  /// A denial stood because no usable emergency authorization covered it.
  EmergencyOverrideNotAvailable = 22,
  /// The policy does not define a ranking, so selection is left to the controller.
  RankingNotInPolicy = 23,
  /// The policy defines a ranking and it was applied to the eligible set.
  RankingApplied = 24,
  /// A rule or obligation that depends on evidence could not be resolved because
  /// the evidence is not fresh.
  RequiredEvidenceNotFresh = 25,
  /// A rule matched but its authority path is not the one the caller required.
  AuthorityPathMismatch = 26,
  /// The candidate set supplied by the caller exceeded the configured bound.
  CandidateLimitExceeded = 27,
};

const char* to_string(ReasonCode code) noexcept;
Result<ReasonCode> parse_reason_code(std::string_view text);
std::ostream& operator<<(std::ostream& stream, ReasonCode code);

}  // namespace feed_authority
