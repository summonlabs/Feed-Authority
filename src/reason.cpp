#include "feed_authority/reason.hpp"

#include <ostream>

namespace feed_authority {

const char* to_string(ReasonCode code) noexcept {
  switch (code) {
    case ReasonCode::PathConfirmed: return "path_confirmed";
    case ReasonCode::PathAbsent: return "path_absent";
    case ReasonCode::PathNotEstablished: return "path_not_established";
    case ReasonCode::FeedUnknown: return "feed_unknown";
    case ReasonCode::LoadUnknown: return "load_unknown";
    case ReasonCode::CandidateNotLinked: return "candidate_not_linked";
    case ReasonCode::FeedConditionAllows: return "feed_condition_allows";
    case ReasonCode::FeedConditionPrevents: return "feed_condition_prevents";
    case ReasonCode::FeedConditionNotEstablished: return "feed_condition_not_established";
    case ReasonCode::SafetyInterlockDenied: return "safety_interlock_denied";
    case ReasonCode::ObligationDenied: return "obligation_denied";
    case ReasonCode::ObligationDiversityUnmet: return "obligation_diversity_unmet";
    case ReasonCode::MaintenanceWithdrawn: return "maintenance_withdrawn";
    case ReasonCode::MaintenanceRestricted: return "maintenance_restricted";
    case ReasonCode::MaintenanceNotEstablished: return "maintenance_not_established";
    case ReasonCode::OperatingModeDenied: return "operating_mode_denied";
    case ReasonCode::OperatingModeNotEstablished: return "operating_mode_not_established";
    case ReasonCode::RulePermitted: return "rule_permitted";
    case ReasonCode::RuleDenied: return "rule_denied";
    case ReasonCode::NoPermitRuleMatched: return "no_permit_rule_matched";
    case ReasonCode::EqualPrecedenceConflict: return "equal_precedence_conflict";
    case ReasonCode::EmergencyOverrideApplied: return "emergency_override_applied";
    case ReasonCode::EmergencyOverrideNotAvailable: return "emergency_override_not_available";
    case ReasonCode::RankingNotInPolicy: return "ranking_not_in_policy";
    case ReasonCode::RankingApplied: return "ranking_applied";
    case ReasonCode::RequiredEvidenceNotFresh: return "required_evidence_not_fresh";
    case ReasonCode::AuthorityPathMismatch: return "authority_path_mismatch";
    case ReasonCode::CandidateLimitExceeded: return "candidate_limit_exceeded";
  }
  return "unrecognized_reason_code";
}

Result<ReasonCode> parse_reason_code(std::string_view text) {
  for (std::int32_t value = 0; value <= 27; ++value) {
    const ReasonCode code = static_cast<ReasonCode>(value);
    if (text == to_string(code)) {
      return code;
    }
  }
  return Status::error(StatusCode::InvalidArgument, "unrecognized reason code token");
}

std::ostream& operator<<(std::ostream& stream, ReasonCode code) {
  return stream << to_string(code);
}

}  // namespace feed_authority
