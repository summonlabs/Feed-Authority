// Proof obligations: a grant is bound to exact generations and to the decision that
// authorized it; it refuses to authorize when it is revoked, expired, superseded or
// recovered without revalidation; revalidation never revives a revoked or expired
// grant; a stale precondition is refused rather than merged.

#include "support/test_harness.hpp"
#include "support/fixtures.hpp"

using namespace feed_authority;

namespace {

const char* kScenarioV1 = R"(revisions topology=10 policy=4 control=7 evidence=9
option emergency=on
feed F1 source=utility role=primary domain=D1 protected=yes
feed F2 source=generator role=secondary domain=D2 protected=yes
load L1 class=critical protected=yes
link F1 L1 role=primary domain=D1
link F2 L1 role=secondary domain=D2
obs feed F1 condition=energized at=1735689600 max_age=300s source=S1
obs feed F2 condition=energized at=1735689600 max_age=300s source=S1
obs link F1 L1 present=yes at=1735689600 max_age=300s source=S1
obs link F2 L1 present=yes at=1735689600 max_age=300s source=S1
obs state condition=normal at=1735689600 max_age=300s source=S1
rule R1 effect=permit precedence=ordinary_policy feed=F1 load=L1 path=AUTH-PRIMARY
rule R2 effect=permit precedence=ordinary_policy feed=F2 load=L1 path=AUTH-SECONDARY
)";

/// The same facility with a newer policy revision that withdraws the secondary path.
const char* kScenarioV2 = R"(revisions topology=10 policy=5 control=7 evidence=10
option emergency=on
feed F1 source=utility role=primary domain=D1 protected=yes
feed F2 source=generator role=secondary domain=D2 protected=yes
load L1 class=critical protected=yes
link F1 L1 role=primary domain=D1
link F2 L1 role=secondary domain=D2
obs feed F1 condition=energized at=1735689600 max_age=300s source=S1
obs feed F2 condition=energized at=1735689600 max_age=300s source=S1
obs link F1 L1 present=yes at=1735689600 max_age=300s source=S1
obs link F2 L1 present=yes at=1735689600 max_age=300s source=S1
obs state condition=normal at=1735689600 max_age=300s source=S1
rule R1 effect=permit precedence=ordinary_policy feed=F1 load=L1 path=AUTH-PRIMARY
rule R2 effect=deny precedence=ordinary_policy feed=F2 load=L1 reason=rule_denied
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

}  // namespace

FA_TEST(grants, issuing_without_adopted_inputs_is_refused) {
  const std::filesystem::path root = fa_test::fresh_store("grant-no-inputs");
  Result<FeedAuthority> authority = fa_test::open_store(root, true);
  FA_REQUIRE_OK(authority);
  const Result<Grant> grant =
      fa_test::issue_grant(authority.value(), "L1", "F1", fa_test::at(1735689600), "attempt-1");
  FA_REQUIRE_ERR(grant, StatusCode::NotFound);
}

FA_TEST(grants, issued_grant_authorizes_within_the_session) {
  Rig rig(kScenarioV1, "grant-lifecycle");
  FA_REQUIRE_OK(rig.authority);
  const Result<Grant> grant =
      fa_test::issue_grant(rig.authority.value(), "L1", "F1", fa_test::at(1735689600), "attempt-1");
  FA_REQUIRE_OK(grant);
  FA_CHECK_EQ(grant.value().authority_path.value(), std::string("AUTH-PRIMARY"));
  FA_CHECK_EQ(grant.value().issued_binding.policy.value(), 4u);
  FA_CHECK_EQ(grant.value().load.value(), std::string("L1"));
  FA_CHECK_EQ(grant.value().feed.value(), std::string("F1"));

  CheckGrantRequest check;
  check.grant = grant.value().id;
  check.now = fa_test::at(1735689700);
  const Result<GrantAuthorization> authorization = rig.authority.value().Authorize(check);
  FA_REQUIRE_OK(authorization);
  FA_CHECK(authorization.value().authorized);
  FA_CHECK_EQ(authorization.value().usability, GrantUsability::Usable);
}

FA_TEST(grants, an_inadmissible_pair_never_gets_a_grant) {
  Rig rig(kScenarioV1, "grant-inadmissible");
  FA_REQUIRE_OK(rig.authority);
  const Result<Grant> grant =
      fa_test::issue_grant(rig.authority.value(), "L1", "F2", fa_test::at(1735689600), "attempt-1",
                           300, "AUTH-PRIMARY");
  FA_REQUIRE_ERR(grant, StatusCode::Denied);
}

FA_TEST(grants, decision_binding_is_enforced) {
  Rig rig(kScenarioV1, "grant-binding");
  FA_REQUIRE_OK(rig.authority);
  const Result<DecisionSet> decision =
      fa_test::evaluate(rig.authority.value(), "L1", fa_test::at(1735689600));
  FA_REQUIRE_OK(decision);
  GrantRequest request;
  request.load = fa_test::load("L1");
  request.feed = fa_test::feed("F1");
  request.decision = decision.value().generation;
  request.decision_fingerprint = Digest::Of("not the decision");
  request.validity = fa_test::secs(300);
  request.now = fa_test::at(1735689600);
  request.attempt = fa_test::attempt("attempt-binding");
  request.precondition.expected = rig.authority.value().current_binding();
  FA_REQUIRE_ERR(rig.authority.value().IssueGrant(request), StatusCode::StaleGeneration);

  // A generation that was never handed out is refused as well.
  request.decision_fingerprint = decision.value().fingerprint;
  request.decision = DecisionGeneration::FromValue(decision.value().generation.value() + 1000);
  FA_REQUIRE_ERR(rig.authority.value().IssueGrant(request), StatusCode::StaleGeneration);
}

FA_TEST(grants, stale_precondition_is_refused) {
  Rig rig(kScenarioV1, "grant-stale-precondition");
  FA_REQUIRE_OK(rig.authority);
  const Result<DecisionSet> decision =
      fa_test::evaluate(rig.authority.value(), "L1", fa_test::at(1735689600));
  FA_REQUIRE_OK(decision);
  GrantRequest request;
  request.load = fa_test::load("L1");
  request.feed = fa_test::feed("F1");
  request.decision = decision.value().generation;
  request.decision_fingerprint = decision.value().fingerprint;
  request.validity = fa_test::secs(300);
  request.now = fa_test::at(1735689600);
  request.attempt = fa_test::attempt("attempt-stale");
  request.precondition.expected = rig.authority.value().current_binding();
  request.precondition.expected.epoch =
      AuthorityEpoch::FromValue(rig.authority.value().current_binding().epoch.value() + 5);
  FA_REQUIRE_ERR(rig.authority.value().IssueGrant(request), StatusCode::StaleAuthority);

  request.precondition.expected = rig.authority.value().current_binding();
  request.precondition.expected.control = ControlRevision::FromValue(99);
  FA_REQUIRE_ERR(rig.authority.value().IssueGrant(request), StatusCode::StaleSourceGeneration);
}

FA_TEST(grants, validity_bounds_are_enforced) {
  Rig rig(kScenarioV1, "grant-validity");
  FA_REQUIRE_OK(rig.authority);
  const Result<DecisionSet> decision =
      fa_test::evaluate(rig.authority.value(), "L1", fa_test::at(1735689600));
  FA_REQUIRE_OK(decision);
  GrantRequest request;
  request.load = fa_test::load("L1");
  request.feed = fa_test::feed("F1");
  request.decision = decision.value().generation;
  request.decision_fingerprint = decision.value().fingerprint;
  request.validity = fa_test::secs(365ll * 24ll * 60ll * 60ll + 1ll);
  request.now = fa_test::at(1735689600);
  request.attempt = fa_test::attempt("attempt-validity");
  request.precondition.expected = rig.authority.value().current_binding();
  FA_REQUIRE_ERR(rig.authority.value().IssueGrant(request), StatusCode::LimitExceeded);

  request.validity = Duration{};
  FA_REQUIRE_ERR(rig.authority.value().IssueGrant(request), StatusCode::InvalidArgument);
}

FA_TEST(grants, revocation_is_final_and_idempotent_by_attempt) {
  Rig rig(kScenarioV1, "grant-revoke");
  FA_REQUIRE_OK(rig.authority);
  const Result<Grant> grant =
      fa_test::issue_grant(rig.authority.value(), "L1", "F1", fa_test::at(1735689600), "attempt-1");
  FA_REQUIRE_OK(grant);

  RevokeGrantRequest revoke;
  revoke.grant = grant.value().id;
  revoke.authorizer = fa_test::authorizer("OPERATOR-1");
  revoke.reason = "planned transfer";
  revoke.now = fa_test::at(1735689700);
  revoke.attempt = fa_test::attempt("revoke-1");
  revoke.precondition.expected = rig.authority.value().current_binding();
  const Result<Grant> revoked = rig.authority.value().RevokeGrant(revoke);
  FA_REQUIRE_OK(revoked);
  FA_CHECK(revoked.value().revoked);
  FA_CHECK_EQ(revoked.value().revocation_reason, std::string("planned transfer"));

  // Replaying the same attempt returns the same accepted result.
  const Result<Grant> replayed = rig.authority.value().RevokeGrant(revoke);
  FA_REQUIRE_OK(replayed);
  FA_CHECK_EQ(replayed.value().revoked_at.unix_nanos(), revoked.value().revoked_at.unix_nanos());

  // A different attempt is a new mutation and is refused.
  revoke.attempt = fa_test::attempt("revoke-2");
  FA_REQUIRE_ERR(rig.authority.value().RevokeGrant(revoke), StatusCode::AlreadyExists);

  CheckGrantRequest check;
  check.grant = grant.value().id;
  check.now = fa_test::at(1735689800);
  const Result<GrantAuthorization> authorization = rig.authority.value().Authorize(check);
  FA_REQUIRE_OK(authorization);
  FA_CHECK(!authorization.value().authorized);
  FA_CHECK_EQ(authorization.value().usability, GrantUsability::Revoked);

  RevalidateGrantRequest revalidate;
  revalidate.grant = grant.value().id;
  revalidate.now = fa_test::at(1735689900);
  revalidate.attempt = fa_test::attempt("revalidate-1");
  revalidate.precondition.expected = rig.authority.value().current_binding();
  FA_REQUIRE_ERR(rig.authority.value().RevalidateGrant(revalidate), StatusCode::Revoked);
}

FA_TEST(grants, expiry_is_enforced) {
  Rig rig(kScenarioV1, "grant-expiry");
  FA_REQUIRE_OK(rig.authority);
  const Result<Grant> grant = fa_test::issue_grant(rig.authority.value(), "L1", "F1",
                                                   fa_test::at(1735689600), "attempt-1", 60);
  FA_REQUIRE_OK(grant);
  CheckGrantRequest check;
  check.grant = grant.value().id;
  check.now = fa_test::at(1735689660);
  const Result<GrantAuthorization> expired = rig.authority.value().Authorize(check);
  FA_REQUIRE_OK(expired);
  FA_CHECK(!expired.value().authorized);
  FA_CHECK_EQ(expired.value().usability, GrantUsability::Expired);

  RevalidateGrantRequest revalidate;
  revalidate.grant = grant.value().id;
  revalidate.now = fa_test::at(1735689700);
  revalidate.attempt = fa_test::attempt("revalidate-expired");
  revalidate.precondition.expected = rig.authority.value().current_binding();
  FA_REQUIRE_ERR(rig.authority.value().RevalidateGrant(revalidate), StatusCode::Expired);
}

FA_TEST(grants, a_new_policy_revision_supersedes_a_grant_until_revalidated) {
  Rig rig(kScenarioV1, "grant-supersession");
  FA_REQUIRE_OK(rig.authority);
  const Result<Grant> grant =
      fa_test::issue_grant(rig.authority.value(), "L1", "F1", fa_test::at(1735689600), "attempt-1");
  FA_REQUIRE_OK(grant);

  const AuthorityInputs v2 = fa_test::inputs(kScenarioV2);
  FA_REQUIRE_OK(fa_test::adopt(rig.authority.value(), v2, "adopt-2", fa_test::at(1735689700)));

  CheckGrantRequest check;
  check.grant = grant.value().id;
  check.now = fa_test::at(1735689700);
  const Result<GrantAuthorization> superseded = rig.authority.value().Authorize(check);
  FA_REQUIRE_OK(superseded);
  FA_CHECK(!superseded.value().authorized);
  FA_CHECK_EQ(superseded.value().usability, GrantUsability::Superseded);

  // Revalidation re-evaluates: the primary path is still admissible, so the grant
  // is restored under the current generation.
  RevalidateGrantRequest revalidate;
  revalidate.grant = grant.value().id;
  revalidate.now = fa_test::at(1735689700);
  revalidate.attempt = fa_test::attempt("revalidate-1");
  revalidate.precondition.expected = rig.authority.value().current_binding();
  const Result<Grant> revalidated = rig.authority.value().RevalidateGrant(revalidate);
  FA_REQUIRE_OK(revalidated);
  FA_CHECK(revalidated.value().revalidated);
  FA_CHECK_EQ(revalidated.value().revalidated_binding.policy.value(), 5u);

  const Result<GrantAuthorization> usable = rig.authority.value().Authorize(check);
  FA_REQUIRE_OK(usable);
  FA_CHECK(usable.value().authorized);
}

FA_TEST(grants, revalidation_is_refused_when_the_pair_is_no_longer_admissible) {
  Rig rig(kScenarioV1, "grant-revalidate-refused");
  FA_REQUIRE_OK(rig.authority);
  const Result<Grant> grant =
      fa_test::issue_grant(rig.authority.value(), "L1", "F2", fa_test::at(1735689600), "attempt-1");
  FA_REQUIRE_OK(grant);

  // The secondary feed loses its path in the newer topology.
  const AuthorityInputs v2 = fa_test::inputs(R"(revisions topology=11 policy=5 control=8 evidence=10
feed F1 source=utility role=primary domain=D1 protected=yes
feed F2 source=generator role=secondary domain=D2 protected=yes
load L1 class=critical protected=yes
link F1 L1 role=primary domain=D1
obs feed F1 condition=energized at=1735689600 max_age=300s source=S1
obs link F1 L1 present=yes at=1735689600 max_age=300s source=S1
rule R1 effect=permit precedence=ordinary_policy feed=F1 load=L1 path=AUTH-PRIMARY
)");
  FA_REQUIRE_OK(fa_test::adopt(rig.authority.value(), v2, "adopt-2", fa_test::at(1735689700)));

  RevalidateGrantRequest revalidate;
  revalidate.grant = grant.value().id;
  revalidate.now = fa_test::at(1735689700);
  revalidate.attempt = fa_test::attempt("revalidate-1");
  revalidate.precondition.expected = rig.authority.value().current_binding();
  const Result<Grant> refused = rig.authority.value().RevalidateGrant(revalidate);
  FA_CHECK(!refused.ok());
  FA_CHECK(refused.status().code() == StatusCode::Denied ||
           refused.status().code() == StatusCode::NotFound ||
           refused.status().code() == StatusCode::Indeterminate);

  // The refusal is recorded in the audit history with a reason.
  const std::vector<EventRecord> history = rig.authority.value().History(16);
  bool found_refusal = false;
  for (const EventRecord& event : history) {
    if (event.kind == EventKind::GrantRevalidationRefused) {
      found_refusal = true;
      FA_CHECK(!event.detail.empty());
    }
  }
  FA_CHECK(found_refusal);
}

FA_TEST(grants, evidence_withdrawal_is_reported_at_authorization_time) {
  Rig rig(kScenarioV1, "grant-evidence-withdrawal");
  FA_REQUIRE_OK(rig.authority);
  const Result<Grant> grant = fa_test::issue_grant(rig.authority.value(), "L1", "F1",
                                                   fa_test::at(1735689600), "attempt-1", 3600);
  FA_REQUIRE_OK(grant);

  CheckGrantRequest check;
  check.grant = grant.value().id;
  // Long after the observations were taken, and past their window, but still
  // inside the grant's own validity.
  check.now = fa_test::at(1735689600 + 400);
  const Result<GrantAuthorization> authorization = rig.authority.value().Authorize(check);
  FA_REQUIRE_OK(authorization);
  FA_CHECK(!authorization.value().authorized);
  FA_CHECK_EQ(authorization.value().usability, GrantUsability::EvidenceWithdrawn);
  FA_CHECK_EQ(authorization.value().reason, ReasonCode::PathNotEstablished);
}

FA_TEST(grants, a_grant_cannot_be_issued_without_an_authority_path) {
  Rig rig(kScenarioV1, "grant-no-path");
  FA_REQUIRE_OK(rig.authority);
  // Evaluating with a required path that no permit names denies the pair, so no
  // grant can be bound to a path that does not exist.
  const Result<Grant> grant = fa_test::issue_grant(rig.authority.value(), "L1", "F1",
                                                   fa_test::at(1735689600), "attempt-1", 300,
                                                   "AUTH-UNKNOWN");
  FA_REQUIRE_ERR(grant, StatusCode::Denied);
}

FA_TEST(grants, grant_capacity_is_bounded) {
  const std::filesystem::path root = fa_test::fresh_store("grant-capacity");
  OpenOptions options;
  options.root = root;
  options.create_if_missing = true;
  options.opened_at = fa_test::at(1735689600);
  options.limits.max_grants = 2;
  Result<FeedAuthority> authority = FeedAuthority::Open(options);
  FA_REQUIRE_OK(authority);
  const AuthorityInputs inputs = fa_test::inputs(kScenarioV1);
  FA_REQUIRE_OK(fa_test::adopt(authority.value(), inputs, "adopt-1", fa_test::at(1735689600)));
  FA_REQUIRE_OK(fa_test::issue_grant(authority.value(), "L1", "F1", fa_test::at(1735689600), "a1"));
  FA_REQUIRE_OK(fa_test::issue_grant(authority.value(), "L1", "F2", fa_test::at(1735689600), "a2"));
  FA_REQUIRE_ERR(fa_test::issue_grant(authority.value(), "L1", "F1", fa_test::at(1735689600), "a3"),
                 StatusCode::LimitExceeded);
}

FA_TEST(grants, revocation_requires_an_identified_authorizer_and_reason) {
  Rig rig(kScenarioV1, "grant-revoke-validation");
  FA_REQUIRE_OK(rig.authority);
  const Result<Grant> grant =
      fa_test::issue_grant(rig.authority.value(), "L1", "F1", fa_test::at(1735689600), "attempt-1");
  FA_REQUIRE_OK(grant);
  RevokeGrantRequest revoke;
  revoke.grant = grant.value().id;
  revoke.now = fa_test::at(1735689700);
  revoke.attempt = fa_test::attempt("revoke-1");
  revoke.precondition.expected = rig.authority.value().current_binding();
  FA_REQUIRE_ERR(rig.authority.value().RevokeGrant(revoke), StatusCode::InvalidArgument);
  revoke.authorizer = fa_test::authorizer("OPERATOR-1");
  FA_REQUIRE_ERR(rig.authority.value().RevokeGrant(revoke), StatusCode::InvalidArgument);
  revoke.reason = std::string(Limits{}.max_text_length + 1, 'x');
  FA_REQUIRE_ERR(rig.authority.value().RevokeGrant(revoke), StatusCode::InvalidArgument);
}
