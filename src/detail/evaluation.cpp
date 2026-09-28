#include "detail/evaluation.hpp"

#include <algorithm>
#include <cstdint>
#include <string>
#include <string_view>
#include <unordered_set>
#include <vector>

#include "detail/canonical.hpp"
#include "feed_authority/obligation.hpp"

namespace feed_authority::detail {
namespace {

constexpr std::int32_t kClassCount = kPrecedenceClassCount;

/// One candidate under evaluation, with everything that was resolved about it.
struct Candidate {
  /// The identity the answer is reported against. It is set from the caller's
  /// request when the caller named the candidate, and from the topology path
  /// otherwise, so a candidate the topology does not know is still reported under
  /// the identity the caller used.
  FeedId requested;
  const FeedLink* link = nullptr;
  const FeedDescriptor* feed = nullptr;
  RedundancyRole role = RedundancyRole::Unknown;
  FailureDomainId domain;
  bool has_domain = false;

  EvidenceState path_state = EvidenceState::Unknown;
  bool path_present = false;
  EvidenceState condition_state = EvidenceState::Unknown;
  FeedCondition condition = FeedCondition::Unknown;
  EvidenceState exposure_state = EvidenceState::Fresh;
  MaintenanceExposure exposure = MaintenanceExposure::None;

  std::vector<EvidenceRef> evidence;
  std::vector<ReasonCode> reasons;
  std::vector<RuleId> matched_rules;
  std::vector<ObligationId> matched_obligations;
  AuthorityPathId authority_path;
  bool emergency_override = false;
  EmergencyAuthorizationId emergency_id;
  DecisionOutcome outcome = DecisionOutcome::Indeterminate;
  ReasonCode reason = ReasonCode::RequiredEvidenceNotFresh;
  PrecedenceClass decided_at = PrecedenceClass::OrdinaryPolicy;
  std::vector<TraceStep> steps;
};

void add_reason(Candidate& candidate, ReasonCode code) {
  candidate.reasons.push_back(code);
}

void add_rule(Candidate& candidate, const RuleId& id) {
  candidate.matched_rules.push_back(id);
}

void add_obligation(Candidate& candidate, const ObligationId& id) {
  candidate.matched_obligations.push_back(id);
}

void add_evidence(Candidate& candidate, const EvidenceSourceId& source, EvidenceState state) {
  if (!source.valid()) {
    return;
  }
  candidate.evidence.push_back(EvidenceRef{source, state});
}

void add_step(Candidate& candidate, std::string stage, bool decisive, DecisionOutcome outcome,
              ReasonCode reason) {
  TraceStep step;
  step.stage = std::move(stage);
  step.decisive = decisive;
  step.outcome = outcome;
  step.reason = reason;
  candidate.steps.push_back(std::move(step));
}

void finalize_candidate(Candidate& candidate) {
  std::sort(candidate.reasons.begin(), candidate.reasons.end(),
            [](ReasonCode left, ReasonCode right) {
              return static_cast<std::int32_t>(left) < static_cast<std::int32_t>(right);
            });
  candidate.reasons.erase(std::unique(candidate.reasons.begin(), candidate.reasons.end()),
                          candidate.reasons.end());
  std::sort(candidate.matched_rules.begin(), candidate.matched_rules.end());
  candidate.matched_rules.erase(
      std::unique(candidate.matched_rules.begin(), candidate.matched_rules.end()),
      candidate.matched_rules.end());
  std::sort(candidate.matched_obligations.begin(), candidate.matched_obligations.end());
  candidate.matched_obligations.erase(
      std::unique(candidate.matched_obligations.begin(), candidate.matched_obligations.end()),
      candidate.matched_obligations.end());
  std::sort(candidate.evidence.begin(), candidate.evidence.end());
  candidate.evidence.erase(std::unique(candidate.evidence.begin(), candidate.evidence.end(),
                                       [](const EvidenceRef& left, const EvidenceRef& right) {
                                         return left.source == right.source && left.state == right.state;
                                       }),
                           candidate.evidence.end());
}

enum class MatchKind : std::int32_t { NotApplicable = 0, Applicable = 1, Unresolved = 2 };

MatchKind match_rule(const EligibilityRule& rule, const Candidate& candidate,
                     const LoadDescriptor& load, const ResolvedEvidence<OperatingCondition>& condition,
                     bool condition_known, bool exposure_known) {
  const RuleScope& scope = rule.scope;
  if (scope.feed && !(candidate.feed != nullptr && *scope.feed == candidate.feed->id)) {
    return MatchKind::NotApplicable;
  }
  if (scope.load && !(*scope.load == load.id)) {
    return MatchKind::NotApplicable;
  }
  if (scope.source_class) {
    if (candidate.feed == nullptr) {
      return MatchKind::Unresolved;
    }
    if (!(*scope.source_class == candidate.feed->source_class)) {
      return MatchKind::NotApplicable;
    }
  }
  if (scope.load_class && !(*scope.load_class == load.load_class)) {
    return MatchKind::NotApplicable;
  }
  if (scope.role) {
    if (!(*scope.role == candidate.role)) {
      return MatchKind::NotApplicable;
    }
  }
  if (!scope.failure_domains.empty()) {
    if (!candidate.has_domain) {
      return MatchKind::Unresolved;
    }
    bool found = false;
    for (const FailureDomainId& domain : scope.failure_domains) {
      if (domain == candidate.domain) {
        found = true;
        break;
      }
    }
    if (!found) {
      return MatchKind::NotApplicable;
    }
  }

  bool unresolved = false;
  if (!rule.conditions.empty()) {
    if (!condition_known) {
      unresolved = true;
    } else {
      bool found = false;
      for (const OperatingCondition value : rule.conditions) {
        if (value == condition.value) {
          found = true;
          break;
        }
      }
      if (!found) {
        return MatchKind::NotApplicable;
      }
    }
  }
  if (!rule.maintenance_exposures.empty()) {
    if (!exposure_known) {
      unresolved = true;
    } else {
      bool found = false;
      for (const MaintenanceExposure value : rule.maintenance_exposures) {
        if (value == candidate.exposure) {
          found = true;
          break;
        }
      }
      if (!found) {
        return MatchKind::NotApplicable;
      }
    }
  }
  return unresolved ? MatchKind::Unresolved : MatchKind::Applicable;
}

struct ClassOutcome {
  std::vector<const EligibilityRule*> permits;
  std::vector<const EligibilityRule*> denies;
  bool unresolved = false;
};

struct ObligationOutcome {
  std::vector<const ProtectedObligation*> denies;
  bool unresolved = false;
};

const EmergencyAuthorization* find_override(const EvaluationEnvironment& environment,
                                            const LoadId& load, const FeedId& feed,
                                            PrecedenceClass decided_at, AuthorityTime now) {
  if (environment.emergency == nullptr) {
    return nullptr;
  }
  for (const EmergencyAuthorization& authorization : *environment.emergency) {
    if (!emergency_authorization_is_live(authorization, environment.binding, now)) {
      continue;
    }
    bool covered_load = false;
    for (const LoadId& candidate : authorization.loads) {
      if (candidate == load) {
        covered_load = true;
        break;
      }
    }
    if (!covered_load) {
      continue;
    }
    if (!authorization.feeds.empty()) {
      bool covered_feed = false;
      for (const FeedId& candidate : authorization.feeds) {
        if (candidate == feed) {
          covered_feed = true;
          break;
        }
      }
      if (!covered_feed) {
        continue;
      }
    }
    bool covered_class = false;
    for (const PrecedenceClass value : authorization.overridable_classes) {
      if (value == decided_at) {
        covered_class = true;
        break;
      }
    }
    if (!covered_class) {
      continue;
    }
    return &authorization;
  }
  return nullptr;
}

void encode_decision_core(std::string& payload, const DecisionSet& decision) {
  {
    RecordWriter writer(payload, "decision");
    writer.text("load", decision.load.value());
    writer.token("condition", to_string(decision.condition));
    writer.num("topology", decision.topology.value());
    writer.num("policy", decision.policy.value());
    writer.num("control", decision.control.value());
    writer.num("evidence", decision.evidence.value());
    writer.num("obligation_blocked", decision.obligation_blocked ? 1u : 0u);
    writer.num("narrowed", decision.candidate_set_narrowed ? 1u : 0u);
    writer.end();
  }
  for (const CandidateDecision& candidate : decision.candidates) {
    RecordWriter writer(payload, "candidate");
    writer.text("feed", candidate.feed.value());
    writer.token("role", to_string(candidate.role));
    writer.text("domain", candidate.failure_domain.value());
    writer.token("outcome", to_string(candidate.outcome));
    writer.token("reason", to_string(candidate.reason));
    writer.token("class", to_string(candidate.decided_at));
    writer.text("path", candidate.authority_path.value());
    writer.boolean("emergency", candidate.emergency_override);
    writer.text("emergency_id", candidate.emergency_authorization);
    writer.num("reasons", candidate.reasons.size());
    writer.num("rules", candidate.matched_rules.size());
    writer.num("obligations", candidate.matched_obligations.size());
    writer.num("evidence", candidate.evidence.size());
    writer.end();
    for (const ReasonCode code : candidate.reasons) {
      RecordWriter item(payload, "reason");
      item.token("value", to_string(code));
      item.end();
    }
    for (const RuleId& id : candidate.matched_rules) {
      RecordWriter item(payload, "rule");
      item.text("value", id.value());
      item.end();
    }
    for (const ObligationId& id : candidate.matched_obligations) {
      RecordWriter item(payload, "obligation");
      item.text("value", id.value());
      item.end();
    }
    for (const EvidenceRef& reference : candidate.evidence) {
      RecordWriter item(payload, "evidence");
      item.text("source", reference.source.value());
      item.token("state", to_string(reference.state));
      item.end();
    }
  }
  for (const ObligationId& id : decision.blocking_obligations) {
    RecordWriter item(payload, "blocking");
    item.text("value", id.value());
    item.end();
  }
  {
    RecordWriter writer(payload, "ranking");
    writer.boolean("applied", decision.ranking.applied);
    writer.boolean("deferred", decision.ranking.selection_deferred_to_controller);
    writer.text("preferred", decision.ranking.preferred.value());
    writer.token("reason", to_string(decision.ranking.reason));
    writer.num("order", decision.ranking.order.size());
    writer.end();
    for (const FeedId& feed : decision.ranking.order) {
      RecordWriter item(payload, "rank");
      item.text("value", feed.value());
      item.end();
    }
  }
}

}  // namespace

Result<DecisionSet> evaluate_load(const EvaluationEnvironment& environment,
                                  const EvaluationRequest& request,
                                  std::vector<CandidateTrace>* traces) {
  if (environment.inputs == nullptr || environment.limits == nullptr) {
    return Status::error(StatusCode::InvalidArgument, "the evaluation environment is incomplete");
  }
  const Limits& limits = *environment.limits;
  const AuthorityInputs& inputs = *environment.inputs;

  if (!request.load.valid()) {
    return Status::error(StatusCode::InvalidArgument, "the evaluation request names no load");
  }
  const LoadDescriptor* load = inputs.topology.find_load(request.load);
  if (load == nullptr) {
    return Status::error(StatusCode::NotFound, "the requested load is not in the adopted topology");
  }
  if (request.candidate_feeds.size() > limits.max_candidates) {
    return Status::error(StatusCode::LimitExceeded, "the request names more candidates than the bound allows");
  }
  {
    std::unordered_set<std::string> seen;
    for (const FeedId& feed : request.candidate_feeds) {
      if (!feed.valid()) {
        return Status::error(StatusCode::InvalidArgument, "the request names an empty feed identity");
      }
      if (!seen.insert(feed.value()).second) {
        return Status::error(StatusCode::DuplicateIdentity, "the request names a candidate feed twice");
      }
    }
  }

  const Result<ResolvedEvidence<OperatingCondition>> condition =
      resolve_evidence(inputs.control.condition, request.now, kMaxObservationsPerSubject);
  if (!condition.ok()) {
    return condition.status();
  }
  const bool condition_known = condition.value().state == EvidenceState::Fresh;

  DecisionSet decision;
  decision.generation = environment.binding.decision;
  decision.epoch = environment.binding.epoch;
  decision.topology = inputs.topology.revision;
  decision.policy = inputs.policy.revision;
  decision.control = inputs.control.revision;
  decision.evidence = inputs.evidence;
  decision.load = request.load;
  decision.condition = condition_known ? condition.value().value : OperatingCondition::Unknown;
  decision.evaluated_at = request.now;

  std::vector<Candidate> candidates;
  if (request.candidate_feeds.empty()) {
    for (const FeedLink* link : inputs.topology.paths_for(request.load)) {
      Candidate candidate;
      candidate.requested = link->feed;
      candidate.link = link;
      candidate.feed = inputs.topology.find_feed(link->feed);
      candidate.role = link->role != RedundancyRole::Unknown
                           ? link->role
                           : (candidate.feed != nullptr ? candidate.feed->role : RedundancyRole::Unknown);
      candidate.domain = link->failure_domain.valid()
                             ? link->failure_domain
                             : (candidate.feed != nullptr ? candidate.feed->failure_domain
                                                          : FailureDomainId{});
      candidate.has_domain = candidate.domain.valid();
      candidates.push_back(std::move(candidate));
    }
  } else {
    std::vector<FeedId> requested = request.candidate_feeds;
    std::sort(requested.begin(), requested.end());
    for (const FeedLink& link : inputs.topology.links) {
      if (link.load != request.load) {
        continue;
      }
      if (!std::binary_search(requested.begin(), requested.end(), link.feed)) {
        decision.candidate_set_narrowed = true;
        break;
      }
    }
    for (const FeedId& feed : requested) {
      Candidate candidate;
      candidate.requested = feed;
      for (const FeedLink& link : inputs.topology.links) {
        if (link.load == request.load && link.feed == feed) {
          candidate.link = &link;
          break;
        }
      }
      candidate.feed = inputs.topology.find_feed(feed);
      if (candidate.link != nullptr) {
        candidate.role = candidate.link->role != RedundancyRole::Unknown
                             ? candidate.link->role
                             : (candidate.feed != nullptr ? candidate.feed->role
                                                          : RedundancyRole::Unknown);
        candidate.domain = candidate.link->failure_domain.valid()
                               ? candidate.link->failure_domain
                               : (candidate.feed != nullptr ? candidate.feed->failure_domain
                                                            : FailureDomainId{});
      } else if (candidate.feed != nullptr) {
        candidate.domain = candidate.feed->failure_domain;
      }
      candidate.has_domain = candidate.domain.valid();
      candidates.push_back(std::move(candidate));
    }
  }

  for (Candidate& candidate : candidates) {
    decision.generation = environment.binding.decision;
    add_step(candidate, "request", false, DecisionOutcome::Indeterminate,
             ReasonCode::RequiredEvidenceNotFresh);

    if (candidate.link == nullptr) {
      if (candidate.feed == nullptr) {
        candidate.outcome = DecisionOutcome::Indeterminate;
        candidate.reason = ReasonCode::FeedUnknown;
        add_reason(candidate, ReasonCode::FeedUnknown);
        add_step(candidate, "topology", true, candidate.outcome, candidate.reason);
      } else {
        candidate.outcome = DecisionOutcome::Deny;
        candidate.reason = ReasonCode::CandidateNotLinked;
        add_reason(candidate, ReasonCode::CandidateNotLinked);
        add_step(candidate, "topology", true, candidate.outcome, candidate.reason);
      }
      finalize_candidate(candidate);
      continue;
    }

    if (candidate.feed == nullptr) {
      candidate.outcome = DecisionOutcome::Indeterminate;
      candidate.reason = ReasonCode::FeedUnknown;
      add_reason(candidate, ReasonCode::FeedUnknown);
      add_step(candidate, "topology", true, candidate.outcome, candidate.reason);
      finalize_candidate(candidate);
      continue;
    }

    // Path evidence: a structural path is not permission to serve.
    const Result<ResolvedEvidence<bool>> path =
        resolve_evidence(candidate.link->observed, request.now, kMaxObservationsPerSubject);
    if (!path.ok()) {
      return path.status();
    }
    candidate.path_state = path.value().state;
    candidate.path_present = path.value().value;
    add_evidence(candidate, path.value().source, path.value().state);
    for (const Observation<bool>& observation : candidate.link->observed) {
      add_evidence(candidate, observation.source(), observation.state_at(request.now));
    }

    // Feed condition evidence.
    const Result<ResolvedEvidence<FeedCondition>> feed_condition =
        resolve_evidence(candidate.feed->condition, request.now, kMaxObservationsPerSubject);
    if (!feed_condition.ok()) {
      return feed_condition.status();
    }
    candidate.condition_state = feed_condition.value().state;
    candidate.condition = feed_condition.value().value;
    add_evidence(candidate, feed_condition.value().source, feed_condition.value().state);
    for (const Observation<FeedCondition>& observation : candidate.feed->condition) {
      add_evidence(candidate, observation.source(), observation.state_at(request.now));
    }

    // Maintenance exposure: the absence of a record in this control revision is a
    // declaration that the feed is not exposed, not missing evidence.
    bool exposure_known = true;
    const MaintenanceRecord* maintenance = inputs.control.maintenance_for(candidate.feed->id);
    if (maintenance == nullptr) {
      candidate.exposure_state = EvidenceState::Fresh;
      candidate.exposure = MaintenanceExposure::None;
    } else {
      const Result<ResolvedEvidence<MaintenanceExposure>> exposure = resolve_evidence(
          maintenance->exposure, request.now, kMaxObservationsPerSubject);
      if (!exposure.ok()) {
        return exposure.status();
      }
      candidate.exposure_state = exposure.value().state;
      candidate.exposure = exposure.value().value;
      exposure_known = exposure.value().state == EvidenceState::Fresh;
      add_evidence(candidate, exposure.value().source, exposure.value().state);
      for (const Observation<MaintenanceExposure>& observation : maintenance->exposure) {
        add_evidence(candidate, observation.source(), observation.state_at(request.now));
      }
    }

    if (candidate.path_state != EvidenceState::Fresh) {
      candidate.outcome = DecisionOutcome::Indeterminate;
      candidate.reason = ReasonCode::PathNotEstablished;
      add_reason(candidate, ReasonCode::PathNotEstablished);
      add_step(candidate, "path-evidence", true, candidate.outcome, candidate.reason);
      finalize_candidate(candidate);
      continue;
    }
    if (!candidate.path_present) {
      candidate.outcome = DecisionOutcome::Deny;
      candidate.reason = ReasonCode::PathAbsent;
      add_reason(candidate, ReasonCode::PathAbsent);
      add_step(candidate, "path-evidence", true, candidate.outcome, candidate.reason);
      finalize_candidate(candidate);
      continue;
    }
    add_reason(candidate, ReasonCode::PathConfirmed);
    add_step(candidate, "path-evidence", false, DecisionOutcome::Allow, ReasonCode::PathConfirmed);

    if (candidate.condition_state != EvidenceState::Fresh) {
      candidate.outcome = DecisionOutcome::Indeterminate;
      candidate.reason = ReasonCode::FeedConditionNotEstablished;
      add_reason(candidate, ReasonCode::FeedConditionNotEstablished);
      add_step(candidate, "feed-condition", true, candidate.outcome, candidate.reason);
      finalize_candidate(candidate);
      continue;
    }
    if (!condition_may_serve(candidate.condition)) {
      candidate.outcome = DecisionOutcome::Deny;
      candidate.reason = ReasonCode::FeedConditionPrevents;
      add_reason(candidate, ReasonCode::FeedConditionPrevents);
      add_step(candidate, "feed-condition", true, candidate.outcome, candidate.reason);
      finalize_candidate(candidate);
      continue;
    }
    add_reason(candidate, ReasonCode::FeedConditionAllows);
    add_step(candidate, "feed-condition", false, DecisionOutcome::Allow,
             ReasonCode::FeedConditionAllows);

    // The precedence ladder.
    ClassOutcome per_class[kClassCount];
    ObligationOutcome obligation_outcome;
    for (const EligibilityRule& rule : inputs.policy.rules) {
      const MatchKind kind =
          match_rule(rule, candidate, *load, condition.value(), condition_known, exposure_known);
      if (kind == MatchKind::NotApplicable) {
        continue;
      }
      const std::size_t index = static_cast<std::size_t>(rule.precedence);
      ClassOutcome& bucket = per_class[index];
      if (kind == MatchKind::Unresolved) {
        bucket.unresolved = true;
        continue;
      }
      if (rule.effect == RuleEffect::Permit) {
        bucket.permits.push_back(&rule);
      } else {
        bucket.denies.push_back(&rule);
      }
    }
    for (const ProtectedObligation& obligation : inputs.policy.obligations) {
      if (!obligation.applies_to(*load)) {
        continue;
      }
      bool violated = false;
      if (!obligation.permitted_roles.empty()) {
        bool found = false;
        for (const RedundancyRole role : obligation.permitted_roles) {
          if (role == candidate.role) {
            found = true;
            break;
          }
        }
        if (!found) {
          violated = true;
        }
      }
      if (!violated && !obligation.permitted_source_classes.empty()) {
        bool found = false;
        for (const SourceClass source : obligation.permitted_source_classes) {
          if (source == candidate.feed->source_class) {
            found = true;
            break;
          }
        }
        if (!found) {
          violated = true;
        }
      }
      if (!violated && obligation.requires_feed_protected_capability &&
          !candidate.feed->may_serve_protected_loads) {
        violated = true;
      }
      if (violated) {
        obligation_outcome.denies.push_back(&obligation);
      }
    }

    bool decided = false;
    bool unresolved_before = false;
    for (std::int32_t index = 0; index < kClassCount && !decided; ++index) {
      const PrecedenceClass precedence = static_cast<PrecedenceClass>(index);
      const ClassOutcome& bucket = per_class[static_cast<std::size_t>(index)];
      const bool obligation_class = precedence == PrecedenceClass::ProtectedObligation;
      const std::size_t deny_count = bucket.denies.size() + (obligation_class ? obligation_outcome.denies.size() : 0u);
      const std::size_t permit_count = bucket.permits.size();
      const bool unresolved = bucket.unresolved;

      if (deny_count > 0 && permit_count > 0) {
        candidate.outcome = DecisionOutcome::Indeterminate;
        candidate.reason = ReasonCode::EqualPrecedenceConflict;
        candidate.decided_at = precedence;
        add_reason(candidate, ReasonCode::EqualPrecedenceConflict);
        for (const EligibilityRule* rule : bucket.denies) {
          add_rule(candidate, rule->id);
          add_reason(candidate, rule->reason);
        }
        for (const EligibilityRule* rule : bucket.permits) {
          add_rule(candidate, rule->id);
          add_reason(candidate, rule->reason);
        }
        add_step(candidate, "precedence", true, candidate.outcome, candidate.reason);
        decided = true;
        break;
      }

      if (deny_count > 0) {
        candidate.outcome = DecisionOutcome::Deny;
        candidate.decided_at = precedence;
        candidate.reason = ReasonCode::RuleDenied;
        bool overridable = true;
        bool any_rule = false;
        for (const EligibilityRule* rule : bucket.denies) {
          add_rule(candidate, rule->id);
          add_reason(candidate, rule->reason);
          candidate.reason = rule->reason;
          any_rule = true;
          if (!rule->emergency_overridable) {
            overridable = false;
          }
        }
        if (obligation_class) {
          for (const ProtectedObligation* obligation : obligation_outcome.denies) {
            add_obligation(candidate, obligation->id);
            add_reason(candidate, obligation->reason);
            if (!any_rule) {
              candidate.reason = obligation->reason;
            }
            if (!obligation->emergency_overridable) {
              overridable = false;
            }
          }
        }
        if (precedence == PrecedenceClass::SafetyInterlock) {
          candidate.reason = ReasonCode::SafetyInterlockDenied;
          for (const EligibilityRule* rule : bucket.denies) {
            add_reason(candidate, ReasonCode::SafetyInterlockDenied);
            (void)rule;
          }
        }

        // An override removes a denial; it never creates authority. The pair must
        // still be admissible through an explicit permit rule that names an authority
        // path, so gather the applicable permits before applying anything.
        AuthorityPathId override_path;
        std::vector<const EligibilityRule*> override_permits;
        for (std::int32_t permit_class = 0; permit_class < kClassCount; ++permit_class) {
          for (const EligibilityRule* rule : per_class[static_cast<std::size_t>(permit_class)].permits) {
            if (!rule->authority_path.valid()) {
              continue;
            }
            override_permits.push_back(rule);
            if (!override_path.valid() || rule->authority_path < override_path) {
              override_path = rule->authority_path;
            }
          }
        }

        const EmergencyAuthorization* override_authorization = nullptr;
        if (overridable && !override_permits.empty() &&
            inputs.policy.options.emergency_override_enabled) {
          override_authorization =
              find_override(environment, request.load, candidate.feed->id, precedence, request.now);
        }
        if (override_authorization != nullptr) {
          candidate.outcome = DecisionOutcome::Allow;
          candidate.reason = ReasonCode::EmergencyOverrideApplied;
          candidate.emergency_override = true;
          candidate.emergency_id = override_authorization->id;
          candidate.authority_path = override_path;
          for (const EligibilityRule* rule : override_permits) {
            add_rule(candidate, rule->id);
          }
          add_reason(candidate, ReasonCode::EmergencyOverrideApplied);
          add_step(candidate, "emergency", true, candidate.outcome, candidate.reason);
          decided = true;
          break;
        }
        if (overridable && inputs.policy.options.emergency_override_enabled) {
          // An override was possible for this denial and no live authorization
          // covered it, so the denial stands and the record says why.
          add_reason(candidate, ReasonCode::EmergencyOverrideNotAvailable);
        }
        add_step(candidate, "precedence", true, candidate.outcome, candidate.reason);
        decided = true;
        break;
      }

      if (permit_count > 0) {
        if (unresolved || unresolved_before) {
          candidate.outcome = DecisionOutcome::Indeterminate;
          candidate.reason = ReasonCode::RequiredEvidenceNotFresh;
          candidate.decided_at = precedence;
          add_reason(candidate, ReasonCode::RequiredEvidenceNotFresh);
          for (const EligibilityRule* rule : bucket.permits) {
            add_rule(candidate, rule->id);
          }
          add_step(candidate, "precedence", true, candidate.outcome, candidate.reason);
          decided = true;
          break;
        }
        const EligibilityRule* chosen = bucket.permits.front();
        candidate.outcome = DecisionOutcome::Allow;
        candidate.reason = chosen->reason;
        candidate.decided_at = precedence;
        candidate.authority_path = chosen->authority_path;
        for (const EligibilityRule* rule : bucket.permits) {
          add_rule(candidate, rule->id);
          if (rule->authority_path.valid() && (!candidate.authority_path.valid() ||
                                               rule->authority_path < candidate.authority_path)) {
            candidate.authority_path = rule->authority_path;
          }
        }
        add_step(candidate, "precedence", true, candidate.outcome, candidate.reason);
        decided = true;
        break;
      }

      if (unresolved) {
        unresolved_before = true;
      }
    }

    if (!decided) {
      if (unresolved_before) {
        candidate.outcome = DecisionOutcome::Indeterminate;
        candidate.reason = ReasonCode::RequiredEvidenceNotFresh;
        add_reason(candidate, ReasonCode::RequiredEvidenceNotFresh);
      } else {
        candidate.outcome = DecisionOutcome::Deny;
        candidate.reason = ReasonCode::NoPermitRuleMatched;
        add_reason(candidate, ReasonCode::NoPermitRuleMatched);
      }
      add_step(candidate, "precedence", true, candidate.outcome, candidate.reason);
    }

    finalize_candidate(candidate);
  }

  // Set-level diversity obligations. A protected load whose eligible set does not
  // cover the required failure domains is not authorized at all: the obligation
  // outranks every permit that produced the eligible set.
  for (const ProtectedObligation& obligation : inputs.policy.obligations) {
    if (obligation.min_distinct_failure_domains == 0 || !obligation.applies_to(*load)) {
      continue;
    }
    std::vector<FailureDomainId> domains;
    for (const Candidate& candidate : candidates) {
      if (candidate.outcome != DecisionOutcome::Allow || !candidate.has_domain) {
        continue;
      }
      if (std::find(domains.begin(), domains.end(), candidate.domain) == domains.end()) {
        domains.push_back(candidate.domain);
      }
    }
    if (domains.size() >= obligation.min_distinct_failure_domains) {
      continue;
    }
    decision.obligation_blocked = true;
    decision.blocking_obligations.push_back(obligation.id);
    for (Candidate& candidate : candidates) {
      if (candidate.outcome != DecisionOutcome::Allow) {
        continue;
      }
      candidate.outcome = DecisionOutcome::Indeterminate;
      candidate.reason = ReasonCode::ObligationDiversityUnmet;
      candidate.decided_at = PrecedenceClass::ProtectedObligation;
      candidate.authority_path = AuthorityPathId{};
      add_obligation(candidate, obligation.id);
      add_reason(candidate, ReasonCode::ObligationDiversityUnmet);
      add_step(candidate, "diversity", true, candidate.outcome, candidate.reason);
    }
  }
  std::sort(decision.blocking_obligations.begin(), decision.blocking_obligations.end());
  decision.blocking_obligations.erase(
      std::unique(decision.blocking_obligations.begin(), decision.blocking_obligations.end()),
      decision.blocking_obligations.end());

  // The caller's authority-path requirement is applied last, on purpose: a
  // set-level obligation is a property of the load's admissible set, so narrowing the
  // question to one authority path must not change whether the obligation is met.
  if (request.required_authority_path) {
    for (Candidate& candidate : candidates) {
      if (candidate.outcome != DecisionOutcome::Allow) {
        continue;
      }
      if (candidate.authority_path == *request.required_authority_path) {
        continue;
      }
      candidate.outcome = DecisionOutcome::Deny;
      candidate.reason = ReasonCode::AuthorityPathMismatch;
      candidate.authority_path = AuthorityPathId{};
      add_reason(candidate, ReasonCode::AuthorityPathMismatch);
      add_step(candidate, "authority-path", true, candidate.outcome, candidate.reason);
      finalize_candidate(candidate);
    }
  }

  for (Candidate& candidate : candidates) {
    CandidateDecision entry;
    entry.feed = candidate.requested;
    entry.role = candidate.role;
    entry.failure_domain = candidate.domain;
    entry.outcome = candidate.outcome;
    entry.reason = candidate.reason;
    entry.reasons = candidate.reasons;
    entry.matched_rules = candidate.matched_rules;
    entry.matched_obligations = candidate.matched_obligations;
    entry.evidence = candidate.evidence;
    entry.authority_path = candidate.authority_path;
    entry.decided_at = candidate.decided_at;
    entry.emergency_override = candidate.emergency_override;
    if (candidate.emergency_override) {
      entry.emergency_authorization = candidate.emergency_id.str();
    }
    if (entry.outcome == DecisionOutcome::Allow) {
      decision.eligible.push_back(entry.feed);
    } else if (entry.outcome == DecisionOutcome::Deny) {
      decision.denied.push_back(entry.feed);
    } else {
      decision.indeterminate.push_back(entry.feed);
    }
    decision.candidates.push_back(std::move(entry));
    if (traces != nullptr) {
      CandidateTrace trace;
      trace.feed = decision.candidates.back().feed;
      trace.steps = std::move(candidate.steps);
      traces->push_back(std::move(trace));
    }
  }

  // Ranking never changes admissibility.
  if (!decision.eligible.empty() && inputs.policy.options.ranking.enabled) {
    const std::vector<RedundancyRole>& order = inputs.policy.options.ranking.role_order;
    const auto rank_of = [&order](RedundancyRole role) -> std::int32_t {
      for (std::size_t index = 0; index < order.size(); ++index) {
        if (order[index] == role) {
          return static_cast<std::int32_t>(index);
        }
      }
      return static_cast<std::int32_t>(order.size()) + static_cast<std::int32_t>(role);
    };
    std::vector<const CandidateDecision*> eligible;
    for (const CandidateDecision& candidate : decision.candidates) {
      if (candidate.outcome == DecisionOutcome::Allow) {
        eligible.push_back(&candidate);
      }
    }
    std::sort(eligible.begin(), eligible.end(),
              [&rank_of](const CandidateDecision* left, const CandidateDecision* right) {
                const std::int32_t left_rank = rank_of(left->role);
                const std::int32_t right_rank = rank_of(right->role);
                if (left_rank != right_rank) {
                  return left_rank < right_rank;
                }
                return left->feed < right->feed;
              });
    for (const CandidateDecision* candidate : eligible) {
      decision.ranking.order.push_back(candidate->feed);
    }
    decision.ranking.applied = true;
    decision.ranking.selection_deferred_to_controller = false;
    decision.ranking.preferred = decision.ranking.order.front();
    decision.ranking.reason = ReasonCode::RankingApplied;
  } else {
    decision.ranking.applied = false;
    decision.ranking.selection_deferred_to_controller = true;
    decision.ranking.reason = ReasonCode::RankingNotInPolicy;
  }

  std::sort(decision.eligible.begin(), decision.eligible.end());
  std::sort(decision.denied.begin(), decision.denied.end());
  std::sort(decision.indeterminate.begin(), decision.indeterminate.end());

  std::string payload;
  encode_decision_core(payload, decision);
  decision.fingerprint = Digest::Of(payload);
  return decision;
}

}  // namespace feed_authority::detail
