// Proof obligations: policy validation is strict and its primary error is
// deterministic; a permit always names an authority path; interlocks can never be
// overridden or made permissive; canonical form is independent of input order.

#include <algorithm>

#include "support/test_harness.hpp"
#include "support/fixtures.hpp"

using namespace feed_authority;

namespace {

EligibilityRule permit_rule(const char* id, const char* path) {
  EligibilityRule rule;
  rule.id = fa_test::rule(id);
  rule.effect = RuleEffect::Permit;
  rule.precedence = PrecedenceClass::OrdinaryPolicy;
  rule.authority_path = fa_test::path(path);
  rule.reason = ReasonCode::RulePermitted;
  return rule;
}

EligibilityRule deny_rule(const char* id) {
  EligibilityRule rule;
  rule.id = fa_test::rule(id);
  rule.effect = RuleEffect::Deny;
  rule.precedence = PrecedenceClass::OrdinaryPolicy;
  rule.reason = ReasonCode::RuleDenied;
  return rule;
}

PolicySet policy_with(const std::vector<EligibilityRule>& rules) {
  PolicySet policy;
  policy.revision = PolicyRevision::FromValue(1);
  policy.rules = rules;
  return policy;
}

std::vector<std::string> minimal_topology() {
  return {};
}

}  // namespace

FA_TEST(policy, permit_requires_an_authority_path) {
  EligibilityRule without_path = permit_rule("R1", "AUTH-1");
  without_path.authority_path = AuthorityPathId{};
  PolicySet policy = policy_with({without_path});
  const Status status = policy.validate(Limits{});
  FA_CHECK(!status.ok());
  FA_CHECK_EQ(status.code(), StatusCode::NotAuthorized);
}

FA_TEST(policy, duplicate_rule_identity_is_refused) {
  PolicySet policy = policy_with({permit_rule("R1", "AUTH-1"), permit_rule("R1", "AUTH-2")});
  const Status status = policy.validate(Limits{});
  FA_CHECK(!status.ok());
  FA_CHECK_EQ(status.code(), StatusCode::DuplicateIdentity);
}

FA_TEST(policy, interlock_rules_cannot_permit_or_be_overridden) {
  {
    EligibilityRule interlock = deny_rule("R1");
    interlock.precedence = PrecedenceClass::SafetyInterlock;
    interlock.rank = AuthorityRank::Emergency;
    interlock.effect = RuleEffect::Permit;
    interlock.authority_path = fa_test::path("AUTH-INTERLOCK");
    const Status status = policy_with({interlock}).validate(Limits{});
    FA_CHECK(!status.ok());
    FA_CHECK_EQ(status.code(), StatusCode::InvalidArgument);
  }
  {
    EligibilityRule interlock = deny_rule("R1");
    interlock.precedence = PrecedenceClass::SafetyInterlock;
    interlock.rank = AuthorityRank::Emergency;
    interlock.emergency_overridable = true;
    const Status status = policy_with({interlock}).validate(Limits{});
    FA_CHECK(!status.ok());
    FA_CHECK_EQ(status.code(), StatusCode::InvalidArgument);
  }
  {
    EligibilityRule interlock = deny_rule("R1");
    interlock.precedence = PrecedenceClass::SafetyInterlock;
    interlock.rank = AuthorityRank::Ordinary;
    const Status status = policy_with({interlock}).validate(Limits{});
    FA_CHECK(!status.ok());
    FA_CHECK_EQ(status.code(), StatusCode::InvalidArgument);
  }
}

FA_TEST(policy, overridable_denials_need_emergency_rank) {
  EligibilityRule denial = deny_rule("R1");
  denial.emergency_overridable = true;
  denial.rank = AuthorityRank::Ordinary;
  const Status status = policy_with({denial}).validate(Limits{});
  FA_CHECK(!status.ok());
  FA_CHECK_EQ(status.code(), StatusCode::InvalidArgument);

  denial.rank = AuthorityRank::Emergency;
  FA_REQUIRE_OK(policy_with({denial}).validate(Limits{}));
}

FA_TEST(policy, permit_rules_cannot_be_marked_overridable) {
  EligibilityRule permit = permit_rule("R1", "AUTH-1");
  permit.emergency_overridable = true;
  permit.rank = AuthorityRank::Emergency;
  const Status status = policy_with({permit}).validate(Limits{});
  FA_CHECK(!status.ok());
  FA_CHECK_EQ(status.code(), StatusCode::InvalidArgument);
}

FA_TEST(policy, validation_primary_error_is_deterministic_across_order) {
  EligibilityRule first = permit_rule("R2", "AUTH-2");
  first.authority_path = AuthorityPathId{};
  EligibilityRule second = deny_rule("R1");
  second.scope.failure_domains = {fa_test::domain("D1"), fa_test::domain("D1")};

  const PolicySet forward = policy_with({first, second});
  const PolicySet reversed = policy_with({second, first});
  const Status forward_status = forward.validate(Limits{});
  const Status reversed_status = reversed.validate(Limits{});
  FA_CHECK(!forward_status.ok());
  FA_CHECK_EQ(forward_status.code(), reversed_status.code());
  FA_CHECK_EQ(forward_status.message(), reversed_status.message());
}

FA_TEST(policy, obligations_need_a_matcher_and_unique_identities) {
  {
    ProtectedObligation obligation;
    obligation.id = fa_test::obligation("O1");
    PolicySet policy;
    policy.obligations.push_back(obligation);
    const Status status = policy.validate(Limits{});
    FA_CHECK(!status.ok());
    FA_CHECK_EQ(status.code(), StatusCode::InvalidArgument);
  }
  {
    ProtectedObligation obligation;
    obligation.id = fa_test::obligation("O1");
    obligation.applies_to_protected_loads = true;
    PolicySet policy;
    policy.obligations.push_back(obligation);
    policy.obligations.push_back(obligation);
    const Status status = policy.validate(Limits{});
    FA_CHECK(!status.ok());
    FA_CHECK_EQ(status.code(), StatusCode::DuplicateIdentity);
  }
}

FA_TEST(policy, ranking_roles_must_be_unique_and_defined) {
  PolicySet policy;
  policy.options.ranking.enabled = true;
  policy.options.ranking.role_order = {RedundancyRole::Primary, RedundancyRole::Primary};
  FA_CHECK_EQ(policy.validate(Limits{}).code(), StatusCode::DuplicateIdentity);
}

FA_TEST(policy, canonical_form_is_independent_of_input_order) {
  std::vector<EligibilityRule> rules;
  for (int index = 0; index < 8; ++index) {
    EligibilityRule rule = permit_rule(("R" + std::to_string(index)).c_str(),
                                       ("AUTH-" + std::to_string(index)).c_str());
    rule.scope.failure_domains = {fa_test::domain("D2"), fa_test::domain("D1")};
    rule.conditions = {OperatingCondition::Failover, OperatingCondition::Normal};
    rules.push_back(rule);
  }
  PolicySet forward = policy_with(rules);
  PolicySet reversed = policy_with(rules);
  std::reverse(reversed.rules.begin(), reversed.rules.end());
  for (EligibilityRule& rule : reversed.rules) {
    std::reverse(rule.scope.failure_domains.begin(), rule.scope.failure_domains.end());
    std::reverse(rule.conditions.begin(), rule.conditions.end());
  }
  FA_CHECK(!(forward == reversed));
  PolicySet::canonicalize(forward);
  PolicySet::canonicalize(reversed);
  FA_CHECK(forward == reversed);
  FA_CHECK_EQ(forward.fingerprint().hex(), reversed.fingerprint().hex());
}

FA_TEST(policy, bounds_are_enforced_before_anything_else) {
  PolicySet policy;
  policy.rules.resize(Limits{}.max_rules + 1);
  for (std::size_t index = 0; index < policy.rules.size(); ++index) {
    policy.rules[index].id = fa_test::rule(("R" + std::to_string(index)).c_str());
    policy.rules[index].effect = RuleEffect::Deny;
  }
  const Status status = policy.validate(Limits{});
  FA_CHECK(!status.ok());
  FA_CHECK_EQ(status.code(), StatusCode::LimitExceeded);
}

FA_TEST(policy, precedence_class_design_rules) {
  FA_CHECK(!precedence_class_is_overridable_by_design(PrecedenceClass::SafetyInterlock));
  FA_CHECK(precedence_class_is_overridable_by_design(PrecedenceClass::ProtectedObligation));
  FA_CHECK(precedence_class_is_overridable_by_design(PrecedenceClass::MaintenanceRestriction));
  FA_CHECK(precedence_class_is_overridable_by_design(PrecedenceClass::OperatingMode));
  FA_CHECK(precedence_class_is_overridable_by_design(PrecedenceClass::OrdinaryPolicy));
  FA_CHECK_EQ(kPrecedenceClassCount, 5);
}
