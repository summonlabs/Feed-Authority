#pragma once

// Explicit eligibility policy.
//
// Admissibility is decided by rules with an explicit precedence class and an
// explicit effect. Nothing is admissible by default: a load/feed pair becomes
// eligible only when a permit rule matches it and every higher-precedence class
// stays silent. Preference is not admissibility, so ranking is a separate,
// explicitly enabled policy option that never changes which candidates are
// eligible.

#include <cstdint>
#include <iosfwd>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "feed_authority/digest.hpp"
#include "feed_authority/generations.hpp"
#include "feed_authority/ids.hpp"
#include "feed_authority/limits.hpp"
#include "feed_authority/model.hpp"
#include "feed_authority/reason.hpp"
#include "feed_authority/status.hpp"

namespace feed_authority {

/// The precedence ladder, from the class that decides first to the class that
/// decides last. A denial in a higher class is final for that candidate unless an
/// explicit emergency authorization overrides it, and preference is never a
/// decisive class.
enum class PrecedenceClass : std::int32_t {
  /// Protective interlocks. Never emergency-overridable, by validation.
  SafetyInterlock = 0,
  /// Protected-load obligations.
  ProtectedObligation = 1,
  /// Maintenance restrictions.
  MaintenanceRestriction = 2,
  /// Operating-mode restrictions.
  OperatingMode = 3,
  /// Ordinary serving policy.
  OrdinaryPolicy = 4,
};

constexpr std::int32_t kPrecedenceClassCount = 5;

const char* to_string(PrecedenceClass value) noexcept;
Result<PrecedenceClass> parse_precedence_class(std::string_view text);
std::ostream& operator<<(std::ostream& stream, PrecedenceClass value);

/// What a rule does when it matches.
enum class RuleEffect : std::int32_t {
  Permit = 0,
  Deny = 1,
};

/// The rank of the authority a rule cites. Rules of ordinary rank are the normal
/// case; emergency rank exists so that an explicit, recorded authorization can be
/// distinguished from ordinary policy.
enum class AuthorityRank : std::int32_t {
  Ordinary = 0,
  Elevated = 1,
  Emergency = 2,
};

const char* to_string(RuleEffect value) noexcept;
const char* to_string(AuthorityRank value) noexcept;
Result<RuleEffect> parse_rule_effect(std::string_view text);
Result<AuthorityRank> parse_authority_rank(std::string_view text);
std::ostream& operator<<(std::ostream& stream, RuleEffect value);
std::ostream& operator<<(std::ostream& stream, AuthorityRank value);

/// The subjects a rule applies to. An unset member does not constrain the rule.
struct RuleScope {
  std::optional<FeedId> feed;
  std::optional<LoadId> load;
  std::optional<SourceClass> source_class;
  std::optional<LoadClass> load_class;
  std::optional<RedundancyRole> role;
  std::vector<FailureDomainId> failure_domains;

  friend bool operator==(const RuleScope& left, const RuleScope& right) noexcept {
    return left.feed == right.feed && left.load == right.load &&
           left.source_class == right.source_class && left.load_class == right.load_class &&
           left.role == right.role && left.failure_domains == right.failure_domains;
  }
};

/// One eligibility rule.
struct EligibilityRule {
  RuleId id;
  PrecedenceClass precedence = PrecedenceClass::OrdinaryPolicy;
  AuthorityRank rank = AuthorityRank::Ordinary;
  RuleEffect effect = RuleEffect::Deny;
  RuleScope scope;
  /// Operating conditions the rule applies in. Empty means every condition.
  std::vector<OperatingCondition> conditions;
  /// Maintenance exposures the rule applies to. Empty means every exposure. A
  /// non-empty list makes the rule depend on maintenance evidence.
  std::vector<MaintenanceExposure> maintenance_exposures;
  /// Whether the rule's effect depends on evidence being fresh. A permit rule with
  /// this set to false still cannot permit a pair whose path or feed condition is
  /// not established: those checks are structural and always apply.
  bool requires_fresh_evidence = true;
  /// Whether an explicit emergency authorization of sufficient scope may override
  /// this rule's denial. Validation refuses this for interlock rules.
  bool emergency_overridable = false;
  /// The named authority path that permits the pair. Required for permit rules.
  AuthorityPathId authority_path;
  /// The reason code recorded when the rule contributes to an outcome.
  ReasonCode reason = ReasonCode::RuleDenied;
  /// Optional short operator note. Recorded, never interpreted.
  std::string note;

  friend bool operator==(const EligibilityRule& left, const EligibilityRule& right) noexcept {
    return left.id == right.id && left.precedence == right.precedence && left.rank == right.rank &&
           left.effect == right.effect && left.scope == right.scope &&
           left.conditions == right.conditions &&
           left.maintenance_exposures == right.maintenance_exposures &&
           left.requires_fresh_evidence == right.requires_fresh_evidence &&
           left.emergency_overridable == right.emergency_overridable &&
           left.authority_path == right.authority_path && left.reason == right.reason &&
           left.note == right.note;
  }
};

/// Explicit ranking of an already-eligible set. Ranking never changes
/// admissibility and is disabled unless a policy enables it.
struct RankingPolicy {
  bool enabled = false;
  /// Role order, most preferred first. Roles absent from this list rank after
  /// those present, ordered by their numeric value, and ties break on feed
  /// identity so the order is total and deterministic.
  std::vector<RedundancyRole> role_order;

  friend bool operator==(const RankingPolicy& left, const RankingPolicy& right) noexcept {
    return left.enabled == right.enabled && left.role_order == right.role_order;
  }
};

/// Non-rule policy switches.
struct PolicyOptions {
  RankingPolicy ranking;
  /// Whether explicit emergency authorizations may be issued and applied at all.
  /// When false, an emergency authorization cannot even be recorded.
  bool emergency_override_enabled = false;

  friend bool operator==(const PolicyOptions& left, const PolicyOptions& right) noexcept {
    return left.ranking == right.ranking &&
           left.emergency_override_enabled == right.emergency_override_enabled;
  }
};

/// A protected-load obligation.
///
/// An obligation is a constraint that must hold for a load the topology source
/// marked as protected. Obligations are evaluated in the `ProtectedObligation`
/// precedence class, which decides before maintenance, mode and ordinary policy, so
/// an obligation is never outranked by a preference or by an ordinary permit. An
/// obligation can narrow admissibility and can never widen it: it has no permit
/// effect.
struct ProtectedObligation {
  ObligationId id;

  /// The loads the obligation applies to. It applies when any matcher matches; an
  /// obligation with no matcher at all applies to nothing, which validation refuses.
  std::vector<LoadId> loads;
  std::optional<LoadClass> load_class;
  bool applies_to_protected_loads = false;

  /// Per-candidate requirements. An empty list constrains nothing.
  std::vector<RedundancyRole> permitted_roles;
  std::vector<SourceClass> permitted_source_classes;
  /// When set, a feed the topology source did not mark as able to serve protected
  /// loads may not be used for this load.
  bool requires_feed_protected_capability = true;

  /// Set-level requirement: the eligible candidates together must cover at least
  /// this many distinct failure domains. Zero disables the check. When the
  /// requirement cannot be met, every otherwise eligible candidate for the load is
  /// downgraded to indeterminate rather than authorizing an unprotected outcome.
  std::uint32_t min_distinct_failure_domains = 0;

  /// Whether an explicit emergency authorization may override this obligation.
  bool emergency_overridable = false;

  ReasonCode reason = ReasonCode::ObligationDenied;
  std::string note;

  /// True when this obligation applies to the given load.
  bool applies_to(const LoadDescriptor& load) const noexcept;

  friend bool operator==(const ProtectedObligation& left, const ProtectedObligation& right) noexcept {
    return left.id == right.id && left.loads == right.loads && left.load_class == right.load_class &&
           left.applies_to_protected_loads == right.applies_to_protected_loads &&
           left.permitted_roles == right.permitted_roles &&
           left.permitted_source_classes == right.permitted_source_classes &&
           left.requires_feed_protected_capability == right.requires_feed_protected_capability &&
           left.min_distinct_failure_domains == right.min_distinct_failure_domains &&
           left.emergency_overridable == right.emergency_overridable && left.reason == right.reason &&
           left.note == right.note;
  }
  friend bool operator<(const ProtectedObligation& left, const ProtectedObligation& right) noexcept {
    return left.id < right.id;
  }
};


/// One externally supplied policy generation.
struct PolicySet {
  PolicyRevision revision{};
  std::vector<EligibilityRule> rules;
  std::vector<ProtectedObligation> obligations;
  PolicyOptions options;

  const EligibilityRule* find_rule(const RuleId& id) const noexcept;

  /// Validates bounds, identity form, duplicate identities and every documented
  /// policy invariant. Returns the first failure in a fixed order.
  Status validate(const Limits& limits) const;

  /// Sorts rules by identity, obligations by identity, and inside each rule the
  /// condition, exposure and failure-domain lists, so that logically equal policy
  /// sets encode to identical bytes.
  static void canonicalize(PolicySet& policy);

  /// Stable SHA-256 over the canonical encoding of this policy generation.
  Digest fingerprint() const;

  /// Logical equality. Defined out of line because the obligations it compares are
  /// completed only in obligation.hpp.
  friend bool operator==(const PolicySet& left, const PolicySet& right) noexcept;
  friend bool operator!=(const PolicySet& left, const PolicySet& right) noexcept;
};

/// The class a denial was decided at, used when an emergency authorization names
/// the classes it may override.
bool precedence_class_is_overridable_by_design(PrecedenceClass value) noexcept;

}  // namespace feed_authority
