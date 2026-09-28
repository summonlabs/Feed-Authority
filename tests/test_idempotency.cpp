// Proof obligations: a retry of an already accepted attempt returns the prior
// accepted result before any generation check runs, even after the store moved on;
// reusing an attempt identity with different content is refused; the retained window
// is bounded and its eviction semantics are explicit.

#include "support/test_harness.hpp"
#include "support/fixtures.hpp"

using namespace feed_authority;

namespace {

const char* kScenario = R"(revisions topology=10 policy=4 control=7 evidence=9
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

const char* kScenarioNext = R"(revisions topology=10 policy=5 control=7 evidence=10
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

struct Rig {
  std::filesystem::path root;
  Result<FeedAuthority> authority;

  explicit Rig(const char* name, std::uint32_t replay_capacity = 4096)
      : root(fa_test::fresh_store(name)), authority(fa_test::open_store(root, true)) {
    if (!authority.ok()) {
      return;
    }
    const Status adopted = fa_test::adopt(authority.value(), fa_test::inputs(kScenario), "adopt-1",
                                          fa_test::at(1735689600));
    if (!adopted.ok()) {
      fa_test::report_failure(__FILE__, __LINE__, "adopt", adopted.to_string());
    }
    (void)replay_capacity;
  }
};

}  // namespace

FA_TEST(idempotency, a_retry_of_an_accepted_attempt_returns_the_prior_result) {
  Rig rig("idempotency-replay");
  FA_REQUIRE_OK(rig.authority);
  const Result<Grant> first =
      fa_test::issue_grant(rig.authority.value(), "L1", "F1", fa_test::at(1735689600), "attempt-1");
  FA_REQUIRE_OK(first);

  // The response was lost, so the caller retries the identical request.
  const Result<Grant> retry =
      fa_test::issue_grant(rig.authority.value(), "L1", "F1", fa_test::at(1735689600), "attempt-1");
  FA_REQUIRE_OK(retry);
  FA_CHECK_EQ(retry.value().id.value(), first.value().id.value());
  FA_CHECK_EQ(retry.value().issued_at.unix_nanos(), first.value().issued_at.unix_nanos());
  FA_CHECK_EQ(rig.authority.value().Grants().size(), 1u);
}

FA_TEST(idempotency, replay_wins_over_a_now_stale_generation) {
  Rig rig("idempotency-stale-replay");
  FA_REQUIRE_OK(rig.authority);
  // The caller builds the request once and keeps it: a lost response means the same
  // bytes are sent again.
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
  request.attempt = fa_test::attempt("attempt-1");
  request.precondition.expected = rig.authority.value().current_binding();
  const Result<Grant> first = rig.authority.value().IssueGrant(request);
  FA_REQUIRE_OK(first);

  // The store moves on: a newer policy generation is adopted, so the preconditions
  // the request carries are now stale.
  FA_REQUIRE_OK(fa_test::adopt(rig.authority.value(), fa_test::inputs(kScenarioNext), "adopt-2",
                               fa_test::at(1735689610)));

  // The retry must get the prior accepted result rather than a stale-authority
  // refusal: replay is decided before any generation check runs.
  const Result<Grant> replay = rig.authority.value().IssueGrant(request);
  FA_REQUIRE_OK(replay);
  FA_CHECK_EQ(replay.value().id.value(), first.value().id.value());
  FA_CHECK_EQ(rig.authority.value().Grants().size(), 1u);
}

FA_TEST(idempotency, reusing_an_attempt_identity_with_different_content_is_refused) {
  Rig rig("idempotency-conflict");
  FA_REQUIRE_OK(rig.authority);
  FA_REQUIRE_OK(
      fa_test::issue_grant(rig.authority.value(), "L1", "F1", fa_test::at(1735689600), "attempt-1"));
  const Result<Grant> conflicting =
      fa_test::issue_grant(rig.authority.value(), "L1", "F2", fa_test::at(1735689600), "attempt-1");
  FA_REQUIRE_ERR(conflicting, StatusCode::AttemptConflict);
  FA_CHECK_EQ(rig.authority.value().Grants().size(), 1u);
}

FA_TEST(idempotency, revocation_and_revalidation_participate_in_replay) {
  Rig rig("idempotency-revoke");
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
  const Result<Grant> replay = rig.authority.value().RevokeGrant(revoke);
  FA_REQUIRE_OK(replay);
  FA_CHECK_EQ(replay.value().revoked_at.unix_nanos(), revoked.value().revoked_at.unix_nanos());

  // A refusal is not an accepted attempt, so it is not recorded and re-running it
  // produces the same refusal rather than a phantom success.
  RevokeGrantRequest second = revoke;
  second.attempt = fa_test::attempt("revoke-2");
  FA_REQUIRE_ERR(rig.authority.value().RevokeGrant(second), StatusCode::AlreadyExists);
  std::size_t revoke_attempts = 0;
  for (const AttemptRecord& record : rig.authority.value().RetainedAttempts()) {
    if (record.kind == AttemptKind::RevokeGrant) {
      ++revoke_attempts;
    }
  }
  FA_CHECK_EQ(revoke_attempts, 1u);
}

FA_TEST(idempotency, the_retained_window_is_bounded_and_evicts_the_oldest_first) {
  const std::filesystem::path root = fa_test::fresh_store("idempotency-window");
  OpenOptions options;
  options.root = root;
  options.create_if_missing = true;
  options.opened_at = fa_test::at(1735689600);
  options.limits.max_replay_entries = 2;
  Result<FeedAuthority> authority = FeedAuthority::Open(options);
  FA_REQUIRE_OK(authority);
  FA_REQUIRE_OK(fa_test::adopt(authority.value(), fa_test::inputs(kScenario), "adopt-1",
                               fa_test::at(1735689600)));
  FA_REQUIRE_OK(fa_test::issue_grant(authority.value(), "L1", "F1", fa_test::at(1735689600), "a1"));
  FA_REQUIRE_OK(fa_test::issue_grant(authority.value(), "L1", "F2", fa_test::at(1735689600), "a2"));
  // The third attempt evicts the admit attempt and the first grant attempt.
  FA_REQUIRE_OK(fa_test::issue_grant(authority.value(), "L1", "F1", fa_test::at(1735689600), "a3"));
  const std::vector<AttemptRecord> retained = authority.value().RetainedAttempts();
  FA_CHECK_EQ(retained.size(), 2u);
  bool saw_first = false;
  for (const AttemptRecord& record : retained) {
    if (record.attempt.value() == "a1") {
      saw_first = true;
    }
  }
  FA_CHECK(!saw_first);

  // An evicted attempt is no longer recognised, so retrying it is a new mutation:
  // it is judged against the current generations and it produces a new grant rather
  // than replaying the old one. That is the documented cost of the bounded window.
  const Result<Grant> evicted =
      fa_test::issue_grant(authority.value(), "L1", "F1", fa_test::at(1735689600), "a1");
  FA_REQUIRE_OK(evicted);
  FA_CHECK(evicted.value().id.value() != 0u);
  FA_CHECK_EQ(authority.value().Grants().size(), 4u);
  FA_CHECK_EQ(authority.value().RetainedAttempts().size(), 2u);

  // With a stale precondition the same retry is refused: nothing about an evicted
  // attempt resurrects authority it no longer has.
  const Result<DecisionSet> decision =
      fa_test::evaluate(authority.value(), "L1", fa_test::at(1735689600));
  FA_REQUIRE_OK(decision);
  GrantRequest stale;
  stale.load = fa_test::load("L1");
  stale.feed = fa_test::feed("F2");
  stale.decision = decision.value().generation;
  stale.decision_fingerprint = decision.value().fingerprint;
  stale.validity = fa_test::secs(300);
  stale.now = fa_test::at(1735689600);
  stale.attempt = fa_test::attempt("a4");
  stale.precondition.expected = authority.value().current_binding();
  stale.precondition.expected.epoch = AuthorityEpoch::FromValue(99);
  FA_REQUIRE_ERR(authority.value().IssueGrant(stale), StatusCode::StaleAuthority);
}

FA_TEST(idempotency, replay_survives_a_restart) {
  const std::filesystem::path root = fa_test::fresh_store("idempotency-restart");
  GrantId issued;
  {
    Result<FeedAuthority> authority = fa_test::open_store(root, true);
    FA_REQUIRE_OK(authority);
    FA_REQUIRE_OK(fa_test::adopt(authority.value(), fa_test::inputs(kScenario), "adopt-1",
                                 fa_test::at(1735689600)));
    const Result<Grant> grant =
        fa_test::issue_grant(authority.value(), "L1", "F1", fa_test::at(1735689600), "attempt-1");
    FA_REQUIRE_OK(grant);
    issued = grant.value().id;
  }
  {
    Result<FeedAuthority> authority = fa_test::open_store(root, false);
    FA_REQUIRE_OK(authority);
    // Provision the session so the retry has adopted inputs, then retry the attempt
    // with the preconditions it was originally planned against.
    const Result<DecisionSet> decision =
        fa_test::evaluate(authority.value(), "L1", fa_test::at(1735689600));
    FA_REQUIRE_OK(decision);
    GrantRequest request;
    request.load = fa_test::load("L1");
    request.feed = fa_test::feed("F1");
    request.decision = decision.value().generation;
    request.decision_fingerprint = decision.value().fingerprint;
    request.validity = fa_test::secs(300);
    request.now = fa_test::at(1735689600);
    request.attempt = fa_test::attempt("attempt-1");
    request.precondition.expected = authority.value().current_binding();
    request.precondition.expected.epoch = AuthorityEpoch::FromValue(1);
    const Result<Grant> replay = authority.value().IssueGrant(request);
    FA_REQUIRE_OK(replay);
    FA_CHECK_EQ(replay.value().id.value(), issued.value());
    FA_CHECK_EQ(authority.value().Grants().size(), 1u);
  }
}

FA_TEST(idempotency, adoption_is_idempotent_for_identical_input) {
  Rig rig("idempotency-adopt");
  FA_REQUIRE_OK(rig.authority);
  const AuthorityInputs inputs = fa_test::inputs(kScenario);
  // A different attempt identity with identical content is a successful no-op: it
  // records no new event and it does not disturb the state.
  const std::size_t before = rig.authority.value().History(64).size();
  FA_REQUIRE_OK(fa_test::adopt(rig.authority.value(), inputs, "adopt-2", fa_test::at(1735689610)));
  FA_CHECK_EQ(rig.authority.value().History(64).size(), before);
  FA_REQUIRE_OK(fa_test::adopt(rig.authority.value(), inputs, "adopt-3", fa_test::at(1735689620)));
  FA_CHECK_EQ(rig.authority.value().History(64).size(), before);
}
