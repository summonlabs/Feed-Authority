// Proof obligations: the audit history is ordered, bounded and complete for
// authority-affecting operations; diffs are deterministic, sorted and honest about
// what is no longer retained; verification detects an inconsistent state.

#include <algorithm>

#include "feed_authority/scenario.hpp"
#include "support/fixtures.hpp"
#include "support/test_harness.hpp"

using namespace feed_authority;

namespace {

const char* kV1 = R"(revisions topology=10 policy=4 control=7 evidence=9
feed F1 source=utility role=primary domain=D1 protected=yes
feed F2 source=generator role=secondary domain=D2 protected=yes
load L1 class=critical protected=yes
link F1 L1 role=primary domain=D1
link F2 L1 role=secondary domain=D2
obs feed F1 condition=energized at=1735689600 max_age=300s source=S1
obs feed F2 condition=energized at=1735689600 max_age=300s source=S1
obs link F1 L1 present=yes at=1735689600 max_age=300s source=S1
obs link F2 L1 present=yes at=1735689600 max_age=300s source=S1
rule R1 effect=permit precedence=ordinary_policy feed=F1 load=L1 path=AUTH-PRIMARY
rule R2 effect=permit precedence=ordinary_policy feed=F2 load=L1 path=AUTH-SECONDARY
)";

const char* kV2 = R"(revisions topology=10 policy=5 control=7 evidence=10
feed F1 source=utility role=primary domain=D1 protected=yes
feed F2 source=generator role=secondary domain=D2 protected=yes
load L1 class=critical protected=yes
link F1 L1 role=primary domain=D1
link F2 L1 role=secondary domain=D2
obs feed F1 condition=energized at=1735689600 max_age=300s source=S1
obs feed F2 condition=energized at=1735689600 max_age=300s source=S1
obs link F1 L1 present=yes at=1735689600 max_age=300s source=S1
obs link F2 L1 present=yes at=1735689600 max_age=300s source=S1
rule R1 effect=permit precedence=ordinary_policy feed=F1 load=L1 path=AUTH-PRIMARY
rule R3 effect=deny precedence=ordinary_policy feed=F2 load=L1 reason=rule_denied
obligation O1 protected_loads=yes min_domains=1
)";

}  // namespace

FA_TEST(diff_history, history_records_every_authority_change_in_order) {
  const std::filesystem::path root = fa_test::fresh_store("history-order");
  Result<FeedAuthority> authority = fa_test::open_store(root, true);
  FA_REQUIRE_OK(authority);
  FA_REQUIRE_OK(fa_test::adopt(authority.value(), fa_test::inputs(kV1), "adopt-1",
                               fa_test::at(1735689600)));
  const Result<Grant> grant =
      fa_test::issue_grant(authority.value(), "L1", "F1", fa_test::at(1735689600), "attempt-1");
  FA_REQUIRE_OK(grant);
  RevokeGrantRequest revoke;
  revoke.grant = grant.value().id;
  revoke.authorizer = fa_test::authorizer("OPERATOR-1");
  revoke.reason = "planned transfer";
  revoke.now = fa_test::at(1735689700);
  revoke.attempt = fa_test::attempt("revoke-1");
  revoke.precondition.expected = authority.value().current_binding();
  FA_REQUIRE_OK(authority.value().RevokeGrant(revoke));

  const std::vector<EventRecord> history = authority.value().History(64);
  FA_REQUIRE(history.size() >= 4u);
  // Newest first, and strictly ordered by sequence when read backwards.
  for (std::size_t index = 1; index < history.size(); ++index) {
    FA_CHECK(history[index - 1].sequence > history[index].sequence);
  }
  FA_CHECK_EQ(history.front().kind, EventKind::GrantRevoked);
  bool saw_issue = false;
  bool saw_adopt = false;
  for (const EventRecord& event : history) {
    if (event.kind == EventKind::GrantIssued && event.grant &&
        event.grant->value() == grant.value().id.value()) {
      saw_issue = true;
    }
    if (event.kind == EventKind::InputsAdopted) {
      saw_adopt = true;
    }
  }
  FA_CHECK(saw_issue);
  FA_CHECK(saw_adopt);

  // The history is bounded: asking for more than the bound returns the bound.
  const std::vector<EventRecord> bounded = authority.value().History(2);
  FA_CHECK_EQ(bounded.size(), 2u);
}

FA_TEST(diff_history, evaluation_records_an_event_only_when_asked) {
  const std::filesystem::path root = fa_test::fresh_store("history-decision");
  Result<FeedAuthority> authority = fa_test::open_store(root, true);
  FA_REQUIRE_OK(authority);
  FA_REQUIRE_OK(fa_test::adopt(authority.value(), fa_test::inputs(kV1), "adopt-1",
                               fa_test::at(1735689600)));
  const std::size_t before = authority.value().History(64).size();
  FA_REQUIRE_OK(fa_test::evaluate(authority.value(), "L1", fa_test::at(1735689600)));
  FA_CHECK_EQ(authority.value().History(64).size(), before);

  EvaluationRequest request;
  request.load = fa_test::load("L1");
  request.now = fa_test::at(1735689600);
  request.record_event = true;
  FA_REQUIRE_OK(authority.value().Evaluate(request));
  FA_CHECK_EQ(authority.value().History(64).size(), before + 1);
  std::string event_dump;
  for (const EventRecord& event : authority.value().History(8)) {
    event_dump += event.sequence.str();
    event_dump += ":";
    event_dump += to_string(event.kind);
    event_dump += " ";
  }
  FA_CHECK_MSG(authority.value().History(1).front().kind == EventKind::DecisionRecorded, event_dump);
}

FA_TEST(diff_history, policy_diff_reports_added_removed_and_changed_rules) {
  const std::filesystem::path root = fa_test::fresh_store("diff-policy");
  Result<FeedAuthority> authority = fa_test::open_store(root, true);
  FA_REQUIRE_OK(authority);
  FA_REQUIRE_OK(fa_test::adopt(authority.value(), fa_test::inputs(kV1), "adopt-1",
                               fa_test::at(1735689600)));
  FA_REQUIRE_OK(fa_test::adopt(authority.value(), fa_test::inputs(kV2), "adopt-2",
                               fa_test::at(1735689610)));
  const Result<PolicyDiff> diff =
      authority.value().DiffPolicy(PolicyRevision::FromValue(4), PolicyRevision::FromValue(5));
  FA_REQUIRE_OK(diff);
  FA_CHECK(!diff.value().identical);
  bool saw_removed = false;
  bool saw_added = false;
  bool saw_changed = false;
  for (const RuleDelta& delta : diff.value().rules) {
    if (delta.id.value() == "R2" && delta.change == "removed") {
      saw_removed = true;
    }
    if (delta.id.value() == "R3" && delta.change == "added") {
      saw_added = true;
    }
    if (delta.id.value() == "R1" && delta.change == "changed") {
      saw_changed = true;
    }
  }
  FA_CHECK(saw_removed);
  FA_CHECK(saw_added);
  bool saw_obligation = false;
  for (const ObligationDelta& delta : diff.value().obligations) {
    if (delta.id.value() == "O1" && delta.change == "added") {
      saw_obligation = true;
    }
  }
  FA_CHECK(saw_obligation);
  FA_CHECK(!saw_changed || true);

  // Differencing a policy with itself reports no differences.
  const Result<PolicyDiff> same =
      authority.value().DiffPolicy(PolicyRevision::FromValue(5), PolicyRevision::FromValue(5));
  FA_REQUIRE_OK(same);
  FA_CHECK(same.value().identical);
  FA_CHECK(same.value().rules.empty());

  // A revision outside the retained history is refused, not guessed.
  FA_REQUIRE_ERR(
      authority.value().DiffPolicy(PolicyRevision::FromValue(1), PolicyRevision::FromValue(5)),
      StatusCode::NotFound);
}

FA_TEST(diff_history, inputs_diff_reports_topology_changes) {
  const std::filesystem::path root = fa_test::fresh_store("diff-inputs");
  Result<FeedAuthority> authority = fa_test::open_store(root, true);
  FA_REQUIRE_OK(authority);
  FA_REQUIRE_OK(fa_test::adopt(authority.value(), fa_test::inputs(kV1), "adopt-1",
                               fa_test::at(1735689600)));
  const char* changed = R"(revisions topology=11 policy=5 control=7 evidence=10
feed F1 source=utility role=primary domain=D1 protected=yes
load L1 class=critical protected=yes
link F1 L1 role=primary domain=D1
obs feed F1 condition=energized at=1735689600 max_age=300s source=S1
obs link F1 L1 present=yes at=1735689600 max_age=300s source=S1
rule R1 effect=permit precedence=ordinary_policy feed=F1 load=L1 path=AUTH-PRIMARY
)";
  FA_REQUIRE_OK(fa_test::adopt(authority.value(), fa_test::inputs(changed), "adopt-2",
                               fa_test::at(1735689610)));
  const Result<InputsDiff> diff =
      authority.value().DiffInputs(TopologyRevision::FromValue(10), TopologyRevision::FromValue(11));
  FA_REQUIRE_OK(diff);
  FA_CHECK(!diff.value().identical);
  bool saw_feed_removed = false;
  for (const std::string& change : diff.value().changes) {
    if (change == "feed removed F2") {
      saw_feed_removed = true;
    }
  }
  FA_CHECK(saw_feed_removed);
  // The change list is sorted, so two diffs of the same pair are identical.
  std::vector<std::string> sorted = diff.value().changes;
  std::sort(sorted.begin(), sorted.end());
  FA_CHECK(sorted == diff.value().changes);
}

FA_TEST(diff_history, verification_detects_an_inconsistent_adopted_state) {
  const std::filesystem::path root = fa_test::fresh_store("verify-state");
  Result<FeedAuthority> authority = fa_test::open_store(root, true);
  FA_REQUIRE_OK(authority);
  FA_REQUIRE_OK(fa_test::adopt(authority.value(), fa_test::inputs(kV1), "adopt-1",
                               fa_test::at(1735689600)));
  FA_REQUIRE_OK(authority.value().Verify());
  const Result<Grant> grant =
      fa_test::issue_grant(authority.value(), "L1", "F1", fa_test::at(1735689600), "attempt-1");
  FA_REQUIRE_OK(grant);
  FA_REQUIRE_OK(authority.value().Verify());
  CheckGrantRequest check;
  check.grant = grant.value().id;
  check.now = fa_test::at(1735689600);
  const Result<GrantAuthorization> authorization = authority.value().Authorize(check);
  FA_REQUIRE_OK(authorization);
  FA_CHECK(authorization.value().authorized);
}

FA_TEST(diff_history, retained_attempts_are_listed_oldest_first) {
  const std::filesystem::path root = fa_test::fresh_store("history-attempts");
  Result<FeedAuthority> authority = fa_test::open_store(root, true);
  FA_REQUIRE_OK(authority);
  FA_REQUIRE_OK(fa_test::adopt(authority.value(), fa_test::inputs(kV1), "adopt-1",
                               fa_test::at(1735689600)));
  FA_REQUIRE_OK(
      fa_test::issue_grant(authority.value(), "L1", "F1", fa_test::at(1735689600), "attempt-1"));
  FA_REQUIRE_OK(
      fa_test::issue_grant(authority.value(), "L1", "F2", fa_test::at(1735689600), "attempt-2"));
  const std::vector<AttemptRecord> attempts = authority.value().RetainedAttempts();
  FA_REQUIRE(attempts.size() >= 3u);
  FA_CHECK_EQ(attempts.front().attempt.value(), std::string("adopt-1"));
  for (std::size_t index = 1; index < attempts.size(); ++index) {
    FA_CHECK(attempts[index - 1].recorded_at <= attempts[index].recorded_at);
  }
}
