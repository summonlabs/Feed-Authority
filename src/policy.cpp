#include "feed_authority/policy.hpp"

#include <algorithm>
#include <ostream>
#include <string>
#include <unordered_set>
#include <vector>

#include "detail/serialization.hpp"
#include "feed_authority/obligation.hpp"

namespace feed_authority {
namespace {

Status require_enum_range(std::int32_t value, std::int32_t low, std::int32_t high, const char* what) {
  if (value < low || value > high) {
    return Status::error(StatusCode::InvalidArgument, std::string(what) + " is not a defined value");
  }
  return Status::success();
}

}  // namespace

const char* to_string(PrecedenceClass value) noexcept {
  switch (value) {
    case PrecedenceClass::SafetyInterlock: return "safety_interlock";
    case PrecedenceClass::ProtectedObligation: return "protected_obligation";
    case PrecedenceClass::MaintenanceRestriction: return "maintenance_restriction";
    case PrecedenceClass::OperatingMode: return "operating_mode";
    case PrecedenceClass::OrdinaryPolicy: return "ordinary_policy";
  }
  return "ordinary_policy";
}

Result<PrecedenceClass> parse_precedence_class(std::string_view text) {
  if (text == "safety_interlock") return PrecedenceClass::SafetyInterlock;
  if (text == "protected_obligation") return PrecedenceClass::ProtectedObligation;
  if (text == "maintenance_restriction") return PrecedenceClass::MaintenanceRestriction;
  if (text == "operating_mode") return PrecedenceClass::OperatingMode;
  if (text == "ordinary_policy") return PrecedenceClass::OrdinaryPolicy;
  return Status::error(StatusCode::InvalidArgument, "unrecognized precedence class token");
}

const char* to_string(RuleEffect value) noexcept {
  switch (value) {
    case RuleEffect::Permit: return "permit";
    case RuleEffect::Deny: return "deny";
  }
  return "deny";
}

const char* to_string(AuthorityRank value) noexcept {
  switch (value) {
    case AuthorityRank::Ordinary: return "ordinary";
    case AuthorityRank::Elevated: return "elevated";
    case AuthorityRank::Emergency: return "emergency";
  }
  return "ordinary";
}

Result<RuleEffect> parse_rule_effect(std::string_view text) {
  if (text == "permit") return RuleEffect::Permit;
  if (text == "deny") return RuleEffect::Deny;
  return Status::error(StatusCode::InvalidArgument, "unrecognized rule effect token");
}

Result<AuthorityRank> parse_authority_rank(std::string_view text) {
  if (text == "ordinary") return AuthorityRank::Ordinary;
  if (text == "elevated") return AuthorityRank::Elevated;
  if (text == "emergency") return AuthorityRank::Emergency;
  return Status::error(StatusCode::InvalidArgument, "unrecognized authority rank token");
}

std::ostream& operator<<(std::ostream& stream, PrecedenceClass value) { return stream << to_string(value); }
std::ostream& operator<<(std::ostream& stream, RuleEffect value) { return stream << to_string(value); }
std::ostream& operator<<(std::ostream& stream, AuthorityRank value) { return stream << to_string(value); }

bool precedence_class_is_overridable_by_design(PrecedenceClass value) noexcept {
  return value != PrecedenceClass::SafetyInterlock;
}

const EligibilityRule* PolicySet::find_rule(const RuleId& id) const noexcept {
  for (const EligibilityRule& rule : rules) {
    if (rule.id == id) {
      return &rule;
    }
  }
  return nullptr;
}

Status PolicySet::validate(const Limits& limits) const {
  const Status limits_status = limits.validate();
  if (!limits_status.ok()) {
    return limits_status;
  }
  if (rules.size() > limits.max_rules) {
    return Status::error(StatusCode::LimitExceeded, "the policy declares too many rules");
  }
  if (obligations.size() > limits.max_obligations) {
    return Status::error(StatusCode::LimitExceeded, "the policy declares too many obligations");
  }

  // Validate in canonical identity order so that the same rule set produces the
  // same primary error whatever order the caller supplied it in.
  std::vector<const EligibilityRule*> ordered_rules;
  ordered_rules.reserve(rules.size());
  for (const EligibilityRule& rule : rules) {
    ordered_rules.push_back(&rule);
  }
  std::sort(ordered_rules.begin(), ordered_rules.end(),
            [](const EligibilityRule* left, const EligibilityRule* right) { return left->id < right->id; });

  std::unordered_set<std::string> rule_ids;
  rule_ids.reserve(rules.size() * 2u);
  for (const EligibilityRule* rule : ordered_rules) {
    if (!rule->id.valid()) {
      return Status::error(StatusCode::InvalidArgument, "a rule has no identity");
    }
    if (!rule_ids.insert(rule->id.value()).second) {
      return Status::error(StatusCode::DuplicateIdentity, "the policy declares a rule identity twice");
    }
    const Status precedence = require_enum_range(static_cast<std::int32_t>(rule->precedence), 0,
                                                 kPrecedenceClassCount - 1, "a rule precedence class");
    if (!precedence.ok()) return precedence;
    const Status rank = require_enum_range(static_cast<std::int32_t>(rule->rank), 0, 2, "a rule authority rank");
    if (!rank.ok()) return rank;
    const Status effect = require_enum_range(static_cast<std::int32_t>(rule->effect), 0, 1, "a rule effect");
    if (!effect.ok()) return effect;
    const Status reason = require_enum_range(static_cast<std::int32_t>(rule->reason), 0, 27, "a rule reason code");
    if (!reason.ok()) return reason;
    if (rule->note.size() > limits.max_text_length) {
      return Status::error(StatusCode::LimitExceeded, "a rule note exceeds the configured length bound");
    }
    if (rule->scope.feed && !rule->scope.feed->valid()) {
      return Status::error(StatusCode::InvalidArgument, "a rule names an empty feed identity");
    }
    if (rule->scope.load && !rule->scope.load->valid()) {
      return Status::error(StatusCode::InvalidArgument, "a rule names an empty load identity");
    }
    if (rule->scope.failure_domains.size() > limits.max_scope_failure_domains) {
      return Status::error(StatusCode::LimitExceeded, "a rule names too many failure domains");
    }
    std::unordered_set<std::string> domains;
    for (const FailureDomainId& domain : rule->scope.failure_domains) {
      if (!domain.valid()) {
        return Status::error(StatusCode::InvalidArgument, "a rule names an empty failure domain");
      }
      if (!domains.insert(domain.value()).second) {
        return Status::error(StatusCode::DuplicateIdentity, "a rule names a failure domain twice");
      }
    }
    if (rule->conditions.size() > limits.max_conditions_per_rule) {
      return Status::error(StatusCode::LimitExceeded, "a rule names too many operating conditions");
    }
    std::unordered_set<std::int32_t> conditions;
    for (const OperatingCondition condition : rule->conditions) {
      const Status valid = require_enum_range(static_cast<std::int32_t>(condition), 0, 6,
                                              "a rule operating condition");
      if (!valid.ok()) return valid;
      if (!conditions.insert(static_cast<std::int32_t>(condition)).second) {
        return Status::error(StatusCode::DuplicateIdentity, "a rule names an operating condition twice");
      }
    }
    if (rule->maintenance_exposures.size() > 4u) {
      return Status::error(StatusCode::LimitExceeded, "a rule names too many maintenance exposures");
    }
    std::unordered_set<std::int32_t> exposures;
    for (const MaintenanceExposure exposure : rule->maintenance_exposures) {
      const Status valid = require_enum_range(static_cast<std::int32_t>(exposure), 0, 3,
                                              "a rule maintenance exposure");
      if (!valid.ok()) return valid;
      if (!exposures.insert(static_cast<std::int32_t>(exposure)).second) {
        return Status::error(StatusCode::DuplicateIdentity, "a rule names a maintenance exposure twice");
      }
    }
    if (rule->effect == RuleEffect::Permit && !rule->authority_path.valid()) {
      return Status::error(StatusCode::NotAuthorized,
                           "a permit rule must name the authority path that grants it");
    }
    if (rule->effect == RuleEffect::Permit && rule->emergency_overridable) {
      return Status::error(StatusCode::InvalidArgument,
                           "a permit rule cannot be marked emergency-overridable");
    }
    if (rule->precedence == PrecedenceClass::SafetyInterlock) {
      if (rule->emergency_overridable) {
        return Status::error(StatusCode::InvalidArgument,
                             "a safety interlock rule can never be emergency-overridable");
      }
      if (rule->effect == RuleEffect::Permit) {
        return Status::error(StatusCode::InvalidArgument,
                             "a safety interlock rule cannot permit: interlocks deny or stay silent");
      }
      if (rule->rank != AuthorityRank::Emergency) {
        return Status::error(StatusCode::InvalidArgument,
                             "a safety interlock rule must carry emergency authority rank");
      }
    }
    if (rule->emergency_overridable && rule->rank != AuthorityRank::Emergency) {
      return Status::error(StatusCode::InvalidArgument,
                           "an emergency-overridable rule must carry emergency authority rank");
    }
  }

  std::vector<const ProtectedObligation*> ordered_obligations;
  ordered_obligations.reserve(obligations.size());
  for (const ProtectedObligation& obligation : obligations) {
    ordered_obligations.push_back(&obligation);
  }
  std::sort(ordered_obligations.begin(), ordered_obligations.end(),
            [](const ProtectedObligation* left, const ProtectedObligation* right) {
              return left->id < right->id;
            });

  std::unordered_set<std::string> obligation_ids;
  obligation_ids.reserve(obligations.size() * 2u);
  for (const ProtectedObligation* obligation : ordered_obligations) {
    if (!obligation->id.valid()) {
      return Status::error(StatusCode::InvalidArgument, "an obligation has no identity");
    }
    if (!obligation_ids.insert(obligation->id.value()).second) {
      return Status::error(StatusCode::DuplicateIdentity,
                           "the policy declares an obligation identity twice");
    }
    if (obligation->loads.empty() && !obligation->load_class && !obligation->applies_to_protected_loads) {
      return Status::error(StatusCode::InvalidArgument,
                           "an obligation must name at least one load matcher");
    }
    std::unordered_set<std::string> loads;
    for (const LoadId& load : obligation->loads) {
      if (!load.valid()) {
        return Status::error(StatusCode::InvalidArgument, "an obligation names an empty load identity");
      }
      if (!loads.insert(load.value()).second) {
        return Status::error(StatusCode::DuplicateIdentity, "an obligation names a load twice");
      }
    }
    if (obligation->min_distinct_failure_domains > 1024u) {
      return Status::error(StatusCode::LimitExceeded,
                           "an obligation requires an implausible number of failure domains");
    }
    if (obligation->note.size() > limits.max_text_length) {
      return Status::error(StatusCode::LimitExceeded, "an obligation note exceeds the configured length bound");
    }
    const Status reason = require_enum_range(static_cast<std::int32_t>(obligation->reason), 0, 27,
                                             "an obligation reason code");
    if (!reason.ok()) return reason;
    std::unordered_set<std::int32_t> roles;
    for (const RedundancyRole role : obligation->permitted_roles) {
      const Status valid = require_enum_range(static_cast<std::int32_t>(role), 0, 4,
                                              "an obligation redundancy role");
      if (!valid.ok()) return valid;
      if (!roles.insert(static_cast<std::int32_t>(role)).second) {
        return Status::error(StatusCode::DuplicateIdentity, "an obligation names a role twice");
      }
    }
    std::unordered_set<std::int32_t> sources;
    for (const SourceClass source : obligation->permitted_source_classes) {
      const Status valid = require_enum_range(static_cast<std::int32_t>(source), 0, 7,
                                              "an obligation source class");
      if (!valid.ok()) return valid;
      if (!sources.insert(static_cast<std::int32_t>(source)).second) {
        return Status::error(StatusCode::DuplicateIdentity, "an obligation names a source class twice");
      }
    }
  }

  if (options.ranking.role_order.size() > 4u) {
    return Status::error(StatusCode::LimitExceeded, "a ranking names too many redundancy roles");
  }
  std::unordered_set<std::int32_t> ranked_roles;
  for (const RedundancyRole role : options.ranking.role_order) {
    const Status valid = require_enum_range(static_cast<std::int32_t>(role), 0, 4,
                                            "a ranking redundancy role");
    if (!valid.ok()) return valid;
    if (!ranked_roles.insert(static_cast<std::int32_t>(role)).second) {
      return Status::error(StatusCode::DuplicateIdentity, "a ranking names a redundancy role twice");
    }
  }
  return Status::success();
}

void PolicySet::canonicalize(PolicySet& policy) {
  std::sort(policy.rules.begin(), policy.rules.end(),
            [](const EligibilityRule& left, const EligibilityRule& right) { return left.id < right.id; });
  std::sort(policy.obligations.begin(), policy.obligations.end());
  for (EligibilityRule& rule : policy.rules) {
    std::sort(rule.conditions.begin(), rule.conditions.end(),
              [](OperatingCondition left, OperatingCondition right) {
                return static_cast<std::int32_t>(left) < static_cast<std::int32_t>(right);
              });
    std::sort(rule.maintenance_exposures.begin(), rule.maintenance_exposures.end(),
              [](MaintenanceExposure left, MaintenanceExposure right) {
                return static_cast<std::int32_t>(left) < static_cast<std::int32_t>(right);
              });
    std::sort(rule.scope.failure_domains.begin(), rule.scope.failure_domains.end());
  }
  for (ProtectedObligation& obligation : policy.obligations) {
    std::sort(obligation.loads.begin(), obligation.loads.end());
    std::sort(obligation.permitted_roles.begin(), obligation.permitted_roles.end(),
              [](RedundancyRole left, RedundancyRole right) {
                return static_cast<std::int32_t>(left) < static_cast<std::int32_t>(right);
              });
    std::sort(obligation.permitted_source_classes.begin(), obligation.permitted_source_classes.end(),
              [](SourceClass left, SourceClass right) {
                return static_cast<std::int32_t>(left) < static_cast<std::int32_t>(right);
              });
  }
}

bool operator==(const PolicySet& left, const PolicySet& right) noexcept {
  return left.revision == right.revision && left.rules == right.rules &&
         left.obligations == right.obligations && left.options == right.options;
}

bool operator!=(const PolicySet& left, const PolicySet& right) noexcept { return !(left == right); }

Digest PolicySet::fingerprint() const {
  std::string payload;
  detail::encode_policy_records(payload, *this, Limits{});
  return Digest::Of(payload);
}

}  // namespace feed_authority
