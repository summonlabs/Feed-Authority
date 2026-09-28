#pragma once

// Candidate-set evaluation results.
//
// Evaluation never picks a winner. It returns every candidate with its outcome,
// the reasons that produced it, the rules and obligations that matched, and the
// evidence that was consulted. A ranking is produced only when policy explicitly
// defines one; otherwise the eligible set is returned with
// `selection_deferred_to_controller` set, because choosing among admissible feeds
// is switching, and switching is not this runtime's boundary.

#include <cstdint>
#include <iosfwd>
#include <optional>
#include <string>
#include <vector>

#include "feed_authority/digest.hpp"
#include "feed_authority/evidence.hpp"
#include "feed_authority/generations.hpp"
#include "feed_authority/ids.hpp"
#include "feed_authority/limits.hpp"
#include "feed_authority/model.hpp"
#include "feed_authority/policy.hpp"
#include "feed_authority/reason.hpp"
#include "feed_authority/status.hpp"
#include "feed_authority/time.hpp"

namespace feed_authority {

/// The outcome for one candidate feed. `Indeterminate` is not a soft denial: it
/// means the runtime cannot establish admissibility from current evidence, and it
/// never authorizes.
enum class DecisionOutcome : std::int32_t {
  Allow = 0,
  Deny = 1,
  Indeterminate = 2,
};

const char* to_string(DecisionOutcome outcome) noexcept;
Result<DecisionOutcome> parse_decision_outcome(std::string_view text);
std::ostream& operator<<(std::ostream& stream, DecisionOutcome outcome);

/// One piece of evidence that was consulted, with the state it had at the
/// evaluation instant. Evidence references carry no timestamps, so an identical
/// logical evaluation encodes to identical bytes.
struct EvidenceRef {
  EvidenceSourceId source;
  EvidenceState state = EvidenceState::Unknown;

  friend bool operator==(const EvidenceRef& left, const EvidenceRef& right) noexcept {
    return left.source == right.source && left.state == right.state;
  }
  friend bool operator<(const EvidenceRef& left, const EvidenceRef& right) noexcept {
    if (left.source != right.source) {
      return left.source < right.source;
    }
    return static_cast<std::int32_t>(left.state) < static_cast<std::int32_t>(right.state);
  }
};

/// The decision for one candidate pair.
struct CandidateDecision {
  FeedId feed;
  RedundancyRole role = RedundancyRole::Unknown;
  FailureDomainId failure_domain;
  DecisionOutcome outcome = DecisionOutcome::Indeterminate;
  /// The single reason that decided the outcome.
  ReasonCode reason = ReasonCode::RequiredEvidenceNotFresh;
  /// Every reason that contributed, in ascending code order, without duplicates.
  std::vector<ReasonCode> reasons;
  /// Rules that contributed to the outcome, in ascending identity order.
  std::vector<RuleId> matched_rules;
  /// Obligations that contributed to the outcome, in ascending identity order.
  std::vector<ObligationId> matched_obligations;
  /// Evidence consulted, in ascending source order.
  std::vector<EvidenceRef> evidence;
  /// The authority path that permitted the candidate. Set only for Allow.
  AuthorityPathId authority_path;
  /// The precedence class that decided the outcome.
  PrecedenceClass decided_at = PrecedenceClass::OrdinaryPolicy;
  /// True when an explicit emergency authorization overturned a denial.
  bool emergency_override = false;
  /// The authorization that was applied. Set only when `emergency_override`.
  std::string emergency_authorization;  // decimal authorization id, empty when unused

  friend bool operator==(const CandidateDecision& left, const CandidateDecision& right) noexcept {
    return left.feed == right.feed && left.role == right.role &&
           left.failure_domain == right.failure_domain && left.outcome == right.outcome &&
           left.reason == right.reason && left.reasons == right.reasons &&
           left.matched_rules == right.matched_rules &&
           left.matched_obligations == right.matched_obligations && left.evidence == right.evidence &&
           left.authority_path == right.authority_path && left.decided_at == right.decided_at &&
           left.emergency_override == right.emergency_override &&
           left.emergency_authorization == right.emergency_authorization;
  }
};

/// The ranking outcome. Ranking orders an already-eligible set; it never adds or
/// removes a candidate.
struct RankingOutcome {
  /// True when policy defines a ranking and at least one candidate is eligible.
  bool applied = false;
  /// True when this runtime deliberately did not choose among eligible feeds.
  bool selection_deferred_to_controller = true;
  /// Eligible feeds in rank order, most preferred first. Empty when not applied.
  std::vector<FeedId> order;
  /// The first entry of `order`, when a ranking was applied.
  FeedId preferred;
  ReasonCode reason = ReasonCode::RankingNotInPolicy;

  friend bool operator==(const RankingOutcome& left, const RankingOutcome& right) noexcept {
    return left.applied == right.applied &&
           left.selection_deferred_to_controller == right.selection_deferred_to_controller &&
           left.order == right.order && left.preferred == right.preferred &&
           left.reason == right.reason;
  }
};

/// One complete evaluation of one load against one input generation.
struct DecisionSet {
  DecisionGeneration generation{};
  AuthorityEpoch epoch{};
  TopologyRevision topology{};
  PolicyRevision policy{};
  ControlRevision control{};
  EvidenceRevision evidence{};
  LoadId load;
  OperatingCondition condition = OperatingCondition::Unknown;
  /// Every candidate considered, in ascending feed identity order.
  std::vector<CandidateDecision> candidates;
  /// The candidates that may serve, in ascending order. Admissible, not selected.
  std::vector<FeedId> eligible;
  std::vector<FeedId> denied;
  std::vector<FeedId> indeterminate;
  /// True when a set-level obligation blocked an otherwise eligible outcome.
  bool obligation_blocked = false;
  std::vector<ObligationId> blocking_obligations;
  RankingOutcome ranking;
  /// True when the caller's candidate restriction removed candidates that the
  /// topology declares. The removed candidates are not evaluated and are not
  /// reported as denied.
  bool candidate_set_narrowed = false;
  /// Stable SHA-256 over the logical content of this decision. It excludes the
  /// evaluation instant and every other volatile value, so two evaluations of the
  /// same logical state produce the same fingerprint.
  Digest fingerprint;
  /// The instant the evaluation was performed at. Not part of the fingerprint.
  AuthorityTime evaluated_at{};

  std::size_t count(DecisionOutcome outcome) const noexcept;
};

/// One step of the explanation trace for a candidate.
struct TraceStep {
  /// Short stage token: "request", "topology", "path-evidence", "feed-condition",
  /// "interlock", "obligation", "maintenance", "mode", "policy", "emergency",
  /// "diversity", "ranking".
  std::string stage;
  /// False when the step is informational rather than a decision point.
  bool decisive = false;
  DecisionOutcome outcome = DecisionOutcome::Indeterminate;
  ReasonCode reason = ReasonCode::NoPermitRuleMatched;
  std::vector<RuleId> rules;
  std::vector<ObligationId> obligations;

  friend bool operator==(const TraceStep& left, const TraceStep& right) noexcept {
    return left.stage == right.stage && left.decisive == right.decisive &&
           left.outcome == right.outcome && left.reason == right.reason && left.rules == right.rules &&
           left.obligations == right.obligations;
  }
};

struct CandidateTrace {
  FeedId feed;
  std::vector<TraceStep> steps;

  friend bool operator==(const CandidateTrace& left, const CandidateTrace& right) noexcept {
    return left.feed == right.feed && left.steps == right.steps;
  }
};

/// A decision plus the ordered trace of how each candidate reached its outcome.
struct Explanation {
  DecisionSet decision;
  /// Trace per candidate, in the same order as `decision.candidates`.
  std::vector<CandidateTrace> traces;
};

/// The caller's evaluation request.
struct EvaluationRequest {
  LoadId load;
  /// When non-empty, only these feeds are considered. The set is bounded and is
  /// validated against the topology; a candidate that the topology does not link
  /// to the load is denied with `CandidateNotLinked` rather than ignored.
  std::vector<FeedId> candidate_feeds;
  /// The instant the evaluation is judged at.
  AuthorityTime now{};
  /// When set, a candidate is only admissible when the deciding permit rule names
  /// exactly this authority path.
  std::optional<AuthorityPathId> required_authority_path;
  /// When true, the evaluation appends a bounded audit event. This is the only way
  /// an evaluation mutates the store, and it is off by default so that evaluation
  /// stays a pure read of adopted state.
  bool record_event = false;

  /// Stable SHA-256 over the logical content of this request. The evaluation
  /// instant is included because it is a genuine input to the answer; nothing else
  /// volatile is.
  Digest fingerprint() const;
};

}  // namespace feed_authority
