// Proof obligations: there is no magic bypass. An emergency override needs policy
// enablement, an identified authorizer, a recorded justification, a bounded scope, a
// current generation binding, an overridable denial, a named precedence class and an
// unrevoked, unexpired authorization -- and it leaves an auditable explanation.

#include "detail/codec.hpp"
#include "support/fixtures.hpp"
#include "support/test_harness.hpp"

using namespace feed_authority;

namespace {

/// A maintenance denial that is explicitly emergency-overridable, plus the permit
/// that would otherwise apply.
const char* kOverridable = R"(revisions topology=10 policy=4 control=7 evidence=9
option emergency=on
feed F1 source=utility role=primary domain=D1 protected=yes
load L1 class=critical protected=yes
link F1 L1 role=primary domain=D1
obs feed F1 condition=energized at=1735689600 max_age=300s source=S1
obs link F1 L1 present=yes at=1735689600 max_age=300s source=S1
obs state condition=emergency at=1735689600 max_age=300s source=S1
obs maintenance F1 exposure=withdrawn at=1735689600 max_age=300s source=S1
rule R1 effect=permit precedence=ordinary_policy feed=F1 load=L1 path=AUTH-PRIMARY
rule R2 effect=deny precedence=maintenance_restriction rank=emergency overridable=yes feed=F1 load=L1 reason=maintenance_withdrawn
)";

struct Rig {
  std::filesystem::path root;
  Result<FeedAuthority> authority;
  AuthorityInputs inputs;

  explicit Rig(const char* scenario, const char* name)
      : root(fa_test::fresh_store(name)),
        authority(fa_test::open_store(root, true)),
        inputs(fa_test::inputs(scenario)) {
    if (!authority.ok()) {
      return;
    }
    const Status adopted = fa_test::adopt(authority.value(), inputs, "adopt-1", fa_test::at(1735689600));
    if (!adopted.ok()) {
      fa_test::report_failure(__FILE__, __LINE__, "adopt", adopted.to_string());
    }
  }
};

Result<EmergencyAuthorization> authorize_emergency(FeedAuthority& authority, const char* loads,
                                                   const char* classes, const char* attempt,
                                                   std::int64_t validity_seconds = 600,
                                                   const char* authorizer_text = "INCIDENT-COMMANDER") {
  EmergencyAuthorizationRequest request;
  request.authorizer = fa_test::authorizer(authorizer_text);
  request.justification = "loss of the secondary path during a declared incident";
  const Result<std::vector<std::string>> load_list = detail::split_list(loads, 16u);
  if (!load_list.ok()) {
    return load_list.status();
  }
  for (const std::string& item : load_list.value()) {
    request.loads.push_back(fa_test::load(item));
  }
  const Result<std::vector<std::string>> class_list = detail::split_list(classes, 16u);
  if (!class_list.ok()) {
    return class_list.status();
  }
  for (const std::string& item : class_list.value()) {
    const Result<PrecedenceClass> parsed = parse_precedence_class(item);
    if (!parsed.ok()) {
      return parsed.status();
    }
    request.overridable_classes.push_back(parsed.value());
  }
  request.validity = fa_test::secs(validity_seconds);
  request.now = fa_test::at(1735689600);
  request.attempt = fa_test::attempt(attempt);
  request.precondition.expected = authority.current_binding();
  return authority.AuthorizeEmergency(request);
}

}  // namespace

FA_TEST(emergency, requires_policy_enablement_and_a_recorded_authorizer) {
  Rig disabled(R"(revisions topology=10 policy=4 control=7 evidence=9
feed F1 source=utility role=primary domain=D1
load L1 class=critical
link F1 L1 role=primary domain=D1
obs feed F1 condition=energized at=1735689600 max_age=300s source=S1
obs link F1 L1 present=yes at=1735689600 max_age=300s source=S1
rule R1 effect=permit precedence=ordinary_policy feed=F1 load=L1 path=AUTH-PRIMARY
)", "emergency-disabled");
  FA_REQUIRE_OK(disabled.authority);
  const Result<EmergencyAuthorization> refused =
      authorize_emergency(disabled.authority.value(), "L1", "maintenance_restriction", "e1");
  FA_REQUIRE_ERR(refused, StatusCode::Unsupported);
}

FA_TEST(emergency, scope_and_classes_are_validated) {
  Rig rig(kOverridable, "emergency-scope");
  FA_REQUIRE_OK(rig.authority);
  {
    EmergencyAuthorizationRequest request;
    request.justification = "x";
    request.loads.push_back(fa_test::load("L1"));
    request.overridable_classes.push_back(PrecedenceClass::MaintenanceRestriction);
    request.validity = fa_test::secs(60);
    request.now = fa_test::at(1735689600);
    request.attempt = fa_test::attempt("e-no-authorizer");
    request.precondition.expected = rig.authority.value().current_binding();
    FA_REQUIRE_ERR(rig.authority.value().AuthorizeEmergency(request), StatusCode::InvalidArgument);
  }
  {
    EmergencyAuthorizationRequest request;
    request.authorizer = fa_test::authorizer("INCIDENT-COMMANDER");
    request.loads.push_back(fa_test::load("L1"));
    request.overridable_classes.push_back(PrecedenceClass::MaintenanceRestriction);
    request.validity = fa_test::secs(60);
    request.now = fa_test::at(1735689600);
    request.attempt = fa_test::attempt("e-no-justification");
    request.precondition.expected = rig.authority.value().current_binding();
    FA_REQUIRE_ERR(rig.authority.value().AuthorizeEmergency(request), StatusCode::InvalidArgument);
  }
  {
    EmergencyAuthorizationRequest request;
    request.authorizer = fa_test::authorizer("INCIDENT-COMMANDER");
    request.justification = "declared incident";
    request.overridable_classes.push_back(PrecedenceClass::MaintenanceRestriction);
    request.validity = fa_test::secs(60);
    request.now = fa_test::at(1735689600);
    request.attempt = fa_test::attempt("e-no-loads");
    request.precondition.expected = rig.authority.value().current_binding();
    FA_REQUIRE_ERR(rig.authority.value().AuthorizeEmergency(request), StatusCode::InvalidArgument);
  }
  {
    // A safety interlock can never be named as overridable.
    const Result<EmergencyAuthorization> refused =
        authorize_emergency(rig.authority.value(), "L1", "safety_interlock", "e-interlock");
    FA_REQUIRE_ERR(refused, StatusCode::NotAuthorized);
  }
  {
    // A load the topology does not declare can never be covered.
    const Result<EmergencyAuthorization> refused =
        authorize_emergency(rig.authority.value(), "L9", "maintenance_restriction", "e-unknown-load");
    FA_REQUIRE_ERR(refused, StatusCode::NotFound);
  }
}

FA_TEST(emergency, an_explicit_authorization_overrides_an_overridable_denial_with_an_audit_trail) {
  Rig rig(kOverridable, "emergency-override");
  FA_REQUIRE_OK(rig.authority);

  const Result<DecisionSet> before =
      fa_test::evaluate(rig.authority.value(), "L1", fa_test::at(1735689600));
  FA_REQUIRE_OK(before);
  FA_REQUIRE(before.value().candidates.size() == 1u);
  FA_CHECK_EQ(before.value().candidates.front().outcome, DecisionOutcome::Deny);
  FA_CHECK(!before.value().candidates.front().emergency_override);

  const Result<EmergencyAuthorization> authorization =
      authorize_emergency(rig.authority.value(), "L1", "maintenance_restriction", "e1");
  FA_REQUIRE_OK(authorization);
  FA_CHECK(authorization.value().id.value() != 0u);
  FA_CHECK_EQ(authorization.value().authorizer.value(), std::string("INCIDENT-COMMANDER"));

  const Result<DecisionSet> after =
      fa_test::evaluate(rig.authority.value(), "L1", fa_test::at(1735689700));
  FA_REQUIRE_OK(after);
  FA_REQUIRE(after.value().candidates.size() == 1u);
  const CandidateDecision& candidate = after.value().candidates.front();
  FA_CHECK_EQ(candidate.outcome, DecisionOutcome::Allow);
  FA_CHECK_EQ(candidate.reason, ReasonCode::EmergencyOverrideApplied);
  FA_CHECK(candidate.emergency_override);
  FA_CHECK_EQ(candidate.emergency_authorization, authorization.value().id.str());
  FA_CHECK_EQ(candidate.decided_at, PrecedenceClass::MaintenanceRestriction);
  FA_CHECK_EQ(candidate.authority_path.value(), std::string("AUTH-PRIMARY"));
  bool saw_denied_rule = false;
  for (const RuleId& id : candidate.matched_rules) {
    if (id.value() == "R2") {
      saw_denied_rule = true;
    }
  }
  FA_CHECK(saw_denied_rule);

  bool saw_event = false;
  for (const EventRecord& event : rig.authority.value().History(32)) {
    if (event.kind == EventKind::EmergencyAuthorized && event.emergency &&
        event.emergency->value() == authorization.value().id.value()) {
      saw_event = true;
      FA_CHECK(!event.detail.empty());
    }
  }
  FA_CHECK(saw_event);
}

FA_TEST(emergency, an_expired_or_revoked_authorization_is_not_applied) {
  Rig rig(kOverridable, "emergency-expiry");
  FA_REQUIRE_OK(rig.authority);
  const Result<EmergencyAuthorization> authorization =
      authorize_emergency(rig.authority.value(), "L1", "maintenance_restriction", "e1", 60);
  FA_REQUIRE_OK(authorization);

  const Result<DecisionSet> expired =
      fa_test::evaluate(rig.authority.value(), "L1", fa_test::at(1735689600 + 120));
  FA_REQUIRE_OK(expired);
  FA_CHECK_EQ(expired.value().candidates.front().outcome, DecisionOutcome::Deny);

  RevokeEmergencyAuthorizationRequest revoke;
  revoke.authorization = authorization.value().id;
  revoke.authorizer = fa_test::authorizer("INCIDENT-COMMANDER");
  revoke.reason = "incident closed";
  revoke.now = fa_test::at(1735689610);
  revoke.attempt = fa_test::attempt("revoke-emergency-1");
  revoke.precondition.expected = rig.authority.value().current_binding();
  FA_REQUIRE_OK(rig.authority.value().RevokeEmergency(revoke));

  const Result<DecisionSet> revoked =
      fa_test::evaluate(rig.authority.value(), "L1", fa_test::at(1735689620));
  FA_REQUIRE_OK(revoked);
  FA_CHECK_EQ(revoked.value().candidates.front().outcome, DecisionOutcome::Deny);
  FA_CHECK(!revoked.value().candidates.front().emergency_override);
}

FA_TEST(emergency, a_denial_that_is_not_overridable_is_never_overridden) {
  Rig rig(R"(revisions topology=10 policy=4 control=7 evidence=9
option emergency=on
feed F1 source=utility role=primary domain=D1
load L1 class=critical
link F1 L1 role=primary domain=D1
obs feed F1 condition=energized at=1735689600 max_age=300s source=S1
obs link F1 L1 present=yes at=1735689600 max_age=300s source=S1
obs maintenance F1 exposure=withdrawn at=1735689600 max_age=300s source=S1
rule R1 effect=permit precedence=ordinary_policy feed=F1 load=L1 path=AUTH-PRIMARY
rule R2 effect=deny precedence=maintenance_restriction rank=emergency overridable=no feed=F1 load=L1 reason=maintenance_withdrawn
)", "emergency-not-overridable");
  FA_REQUIRE_OK(rig.authority);
  FA_REQUIRE_OK(authorize_emergency(rig.authority.value(), "L1", "maintenance_restriction", "e1"));
  const Result<DecisionSet> decision =
      fa_test::evaluate(rig.authority.value(), "L1", fa_test::at(1735689700));
  FA_REQUIRE_OK(decision);
  FA_CHECK_EQ(decision.value().candidates.front().outcome, DecisionOutcome::Deny);
  FA_CHECK(!decision.value().candidates.front().emergency_override);
  bool saw_unavailable = false;
  for (const ReasonCode code : decision.value().candidates.front().reasons) {
    if (code == ReasonCode::EmergencyOverrideNotAvailable) {
      saw_unavailable = true;
    }
  }
  FA_CHECK(!saw_unavailable);
}

FA_TEST(emergency, authorization_superseded_by_a_new_input_generation_is_not_applied) {
  Rig rig(kOverridable, "emergency-superseded");
  FA_REQUIRE_OK(rig.authority);
  FA_REQUIRE_OK(authorize_emergency(rig.authority.value(), "L1", "maintenance_restriction", "e1"));

  const AuthorityInputs newer = fa_test::inputs(R"(revisions topology=12 policy=4 control=8 evidence=9
option emergency=on
feed F1 source=utility role=primary domain=D1 protected=yes
load L1 class=critical protected=yes
link F1 L1 role=primary domain=D1
obs feed F1 condition=energized at=1735689600 max_age=300s source=S1
obs link F1 L1 present=yes at=1735689600 max_age=300s source=S1
obs state condition=emergency at=1735689600 max_age=300s source=S1
obs maintenance F1 exposure=withdrawn at=1735689600 max_age=300s source=S1
rule R1 effect=permit precedence=ordinary_policy feed=F1 load=L1 path=AUTH-PRIMARY
rule R2 effect=deny precedence=maintenance_restriction rank=emergency overridable=yes feed=F1 load=L1 reason=maintenance_withdrawn
)");
  FA_REQUIRE_OK(fa_test::adopt(rig.authority.value(), newer, "adopt-2", fa_test::at(1735689650)));

  const Result<DecisionSet> decision =
      fa_test::evaluate(rig.authority.value(), "L1", fa_test::at(1735689700));
  FA_REQUIRE_OK(decision);
  FA_CHECK_EQ(decision.value().candidates.front().outcome, DecisionOutcome::Deny);
  FA_CHECK(!decision.value().candidates.front().emergency_override);
}

FA_TEST(emergency, an_authorization_for_another_load_does_not_apply) {
  Rig rig(R"(revisions topology=10 policy=4 control=7 evidence=9
option emergency=on
feed F1 source=utility role=primary domain=D1 protected=yes
load L1 class=critical protected=yes
load L2 class=critical protected=yes
link F1 L1 role=primary domain=D1
link F1 L2 role=primary domain=D1
obs feed F1 condition=energized at=1735689600 max_age=300s source=S1
obs link F1 L1 present=yes at=1735689600 max_age=300s source=S1
obs link F1 L2 present=yes at=1735689600 max_age=300s source=S1
obs maintenance F1 exposure=withdrawn at=1735689600 max_age=300s source=S1
rule R1 effect=permit precedence=ordinary_policy feed=F1 load=L1 path=AUTH-PRIMARY
rule R2 effect=permit precedence=ordinary_policy feed=F1 load=L2 path=AUTH-PRIMARY
rule R3 effect=deny precedence=maintenance_restriction rank=emergency overridable=yes feed=F1 load=L1 reason=maintenance_withdrawn
rule R4 effect=deny precedence=maintenance_restriction rank=emergency overridable=yes feed=F1 load=L2 reason=maintenance_withdrawn
)", "emergency-scope-loads");
  FA_REQUIRE_OK(rig.authority);
  FA_REQUIRE_OK(authorize_emergency(rig.authority.value(), "L2", "maintenance_restriction", "e1"));
  const Result<DecisionSet> decision =
      fa_test::evaluate(rig.authority.value(), "L1", fa_test::at(1735689700));
  FA_REQUIRE_OK(decision);
  FA_CHECK_EQ(decision.value().candidates.front().outcome, DecisionOutcome::Deny);
  const Result<DecisionSet> covered =
      fa_test::evaluate(rig.authority.value(), "L2", fa_test::at(1735689700));
  FA_REQUIRE_OK(covered);
  FA_CHECK_EQ(covered.value().candidates.front().outcome, DecisionOutcome::Allow);
}

FA_TEST(emergency, validity_is_bounded) {
  Rig rig(kOverridable, "emergency-validity");
  FA_REQUIRE_OK(rig.authority);
  const Result<EmergencyAuthorization> too_long =
      authorize_emergency(rig.authority.value(), "L1", "maintenance_restriction", "e1", 25 * 60 * 60);
  FA_REQUIRE_ERR(too_long, StatusCode::InvalidArgument);
  const Result<EmergencyAuthorization> zero =
      authorize_emergency(rig.authority.value(), "L1", "maintenance_restriction", "e2", 0);
  FA_REQUIRE_ERR(zero, StatusCode::InvalidArgument);
}
