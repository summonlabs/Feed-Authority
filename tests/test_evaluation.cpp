// Proof obligations for the eligibility engine: admissibility is closed by default;
// precedence is explicit and deterministic; equal-precedence contradictions are
// indeterminate; obligations and maintenance outrank ordinary policy; stale,
// unknown or contradictory evidence never becomes permission; insertion order does
// not change the answer; ranking never changes admissibility.

#include <algorithm>

#include "support/test_harness.hpp"
#include "support/fixtures.hpp"
#include "feed_authority/scenario.hpp"

using namespace feed_authority;

namespace {

/// Two independent feeds serving one protected critical load.
const char* kBase = R"(revisions topology=10 policy=4 control=7 evidence=9
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
rule R1 effect=permit precedence=ordinary_policy feed=F1 load=L1 path=AUTH-PRIMARY reason=rule_permitted
rule R2 effect=permit precedence=ordinary_policy feed=F2 load=L1 path=AUTH-SECONDARY reason=rule_permitted
)";

const CandidateDecision* find(const DecisionSet& decision, const char* id) {
  for (const CandidateDecision& candidate : decision.candidates) {
    if (candidate.feed.value() == id) {
      return &candidate;
    }
  }
  return nullptr;
}

struct Fixture {
  std::filesystem::path root;
  Result<FeedAuthority> authority;

  explicit Fixture(const char* scenario, const char* name = "evaluation")
      : root(fa_test::fresh_store(name)), authority(fa_test::open_store(root, true)) {
    if (!authority.ok()) {
      return;
    }
    const Status adopted = fa_test::adopt(authority.value(), fa_test::inputs(scenario), "adopt-1",
                                          fa_test::at(1735689600));
    if (!adopted.ok()) {
      fa_test::report_failure(__FILE__, __LINE__, "adopt", adopted.to_string());
    }
  }
};

}  // namespace

FA_TEST(evaluation, admissibility_is_closed_by_default) {
  Fixture fixture(R"(revisions topology=10 policy=4 control=7 evidence=9
feed F1 source=utility role=primary domain=D1
load L1 class=critical
link F1 L1 role=primary domain=D1
obs feed F1 condition=energized at=1735689600 max_age=300s source=S1
obs link F1 L1 present=yes at=1735689600 max_age=300s source=S1
)");
  FA_REQUIRE_OK(fixture.authority);
  const Result<DecisionSet> decision =
      fa_test::evaluate(fixture.authority.value(), "L1", fa_test::at(1735689600));
  FA_REQUIRE_OK(decision);
  FA_CHECK_EQ(decision.value().eligible.size(), 0u);
  FA_CHECK_EQ(decision.value().denied.size(), 1u);
  const CandidateDecision* candidate = find(decision.value(), "F1");
  FA_REQUIRE(candidate != nullptr);
  FA_CHECK_EQ(candidate->outcome, DecisionOutcome::Deny);
  FA_CHECK_EQ(candidate->reason, ReasonCode::NoPermitRuleMatched);
  FA_CHECK(!candidate->authority_path.valid());
}

FA_TEST(evaluation, explicit_permit_carries_its_authority_path) {
  Fixture fixture(kBase);
  FA_REQUIRE_OK(fixture.authority);
  const Result<DecisionSet> decision =
      fa_test::evaluate(fixture.authority.value(), "L1", fa_test::at(1735689600));
  FA_REQUIRE_OK(decision);
  const CandidateDecision* primary = find(decision.value(), "F1");
  FA_REQUIRE(primary != nullptr);
  FA_CHECK_EQ(primary->outcome, DecisionOutcome::Allow);
  FA_CHECK_EQ(primary->authority_path.value(), std::string("AUTH-PRIMARY"));
  FA_CHECK_EQ(primary->decided_at, PrecedenceClass::OrdinaryPolicy);
  FA_CHECK(std::find(primary->reasons.begin(), primary->reasons.end(), ReasonCode::PathConfirmed) !=
           primary->reasons.end());
  FA_CHECK_EQ(decision.value().eligible.size(), 2u);
}

FA_TEST(evaluation, equal_precedence_contradiction_is_indeterminate) {
  Fixture fixture(R"(revisions topology=10 policy=4 control=7 evidence=9
feed F1 source=utility role=primary domain=D1
load L1 class=critical
link F1 L1 role=primary domain=D1
obs feed F1 condition=energized at=1735689600 max_age=300s source=S1
obs link F1 L1 present=yes at=1735689600 max_age=300s source=S1
rule R1 effect=permit precedence=ordinary_policy feed=F1 load=L1 path=AUTH-PRIMARY
rule R2 effect=deny precedence=ordinary_policy feed=F1 load=L1 reason=rule_denied
)");
  FA_REQUIRE_OK(fixture.authority);
  const Result<DecisionSet> decision =
      fa_test::evaluate(fixture.authority.value(), "L1", fa_test::at(1735689600));
  FA_REQUIRE_OK(decision);
  const CandidateDecision* candidate = find(decision.value(), "F1");
  FA_REQUIRE(candidate != nullptr);
  FA_CHECK_EQ(candidate->outcome, DecisionOutcome::Indeterminate);
  FA_CHECK_EQ(candidate->reason, ReasonCode::EqualPrecedenceConflict);
  FA_CHECK_EQ(decision.value().eligible.size(), 0u);
}

FA_TEST(evaluation, maintenance_denial_outranks_an_ordinary_permit) {
  Fixture fixture(R"(revisions topology=10 policy=4 control=7 evidence=9
feed F1 source=utility role=primary domain=D1
load L1 class=critical
link F1 L1 role=primary domain=D1
obs feed F1 condition=energized at=1735689600 max_age=300s source=S1
obs link F1 L1 present=yes at=1735689600 max_age=300s source=S1
obs state condition=maintenance at=1735689600 max_age=300s source=S1
obs maintenance F1 exposure=withdrawn at=1735689600 max_age=300s source=S1
rule R1 effect=permit precedence=ordinary_policy feed=F1 load=L1 path=AUTH-PRIMARY
rule R2 effect=deny precedence=maintenance_restriction feed=F1 load=L1 reason=maintenance_withdrawn
)");
  FA_REQUIRE_OK(fixture.authority);
  const Result<DecisionSet> decision =
      fa_test::evaluate(fixture.authority.value(), "L1", fa_test::at(1735689600));
  FA_REQUIRE_OK(decision);
  const CandidateDecision* candidate = find(decision.value(), "F1");
  FA_REQUIRE(candidate != nullptr);
  FA_CHECK_EQ(candidate->outcome, DecisionOutcome::Deny);
  FA_CHECK_EQ(candidate->decided_at, PrecedenceClass::MaintenanceRestriction);
  FA_CHECK_EQ(candidate->reason, ReasonCode::MaintenanceWithdrawn);
}

FA_TEST(evaluation, a_narrow_maintenance_permit_outranks_an_ordinary_denial) {
  Fixture fixture(R"(revisions topology=10 policy=4 control=7 evidence=9
feed F1 source=utility role=primary domain=D1
load L1 class=critical
link F1 L1 role=primary domain=D1
obs feed F1 condition=energized at=1735689600 max_age=300s source=S1
obs link F1 L1 present=yes at=1735689600 max_age=300s source=S1
obs maintenance F1 exposure=restricted at=1735689600 max_age=300s source=S1
rule R1 effect=permit precedence=maintenance_restriction exposures=restricted feed=F1 load=L1 path=AUTH-MAINTENANCE
rule R2 effect=deny precedence=ordinary_policy feed=F1 load=L1 reason=rule_denied
)");
  FA_REQUIRE_OK(fixture.authority);
  const Result<DecisionSet> decision =
      fa_test::evaluate(fixture.authority.value(), "L1", fa_test::at(1735689600));
  FA_REQUIRE_OK(decision);
  const CandidateDecision* candidate = find(decision.value(), "F1");
  FA_REQUIRE(candidate != nullptr);
  FA_CHECK_EQ(candidate->outcome, DecisionOutcome::Allow);
  FA_CHECK_EQ(candidate->decided_at, PrecedenceClass::MaintenanceRestriction);
  FA_CHECK_EQ(candidate->authority_path.value(), std::string("AUTH-MAINTENANCE"));
}

FA_TEST(evaluation, unestablished_path_evidence_is_indeterminate_not_permission) {
  Fixture fixture(R"(revisions topology=10 policy=4 control=7 evidence=9
feed F1 source=utility role=primary domain=D1
load L1 class=critical
link F1 L1 role=primary domain=D1
obs feed F1 condition=energized at=1735689600 max_age=300s source=S1
obs link F1 L1 present=yes at=1735000000 max_age=300s source=S1
rule R1 effect=permit precedence=ordinary_policy feed=F1 load=L1 path=AUTH-PRIMARY
)");
  FA_REQUIRE_OK(fixture.authority);
  const Result<DecisionSet> decision =
      fa_test::evaluate(fixture.authority.value(), "L1", fa_test::at(1735689600));
  FA_REQUIRE_OK(decision);
  const CandidateDecision* candidate = find(decision.value(), "F1");
  FA_REQUIRE(candidate != nullptr);
  FA_CHECK_EQ(candidate->outcome, DecisionOutcome::Indeterminate);
  FA_CHECK_EQ(candidate->reason, ReasonCode::PathNotEstablished);
  bool saw_stale_path = false;
  for (const EvidenceRef& reference : candidate->evidence) {
    if (reference.state == EvidenceState::Stale && reference.source.value() == "S1") {
      saw_stale_path = true;
    }
  }
  FA_CHECK(saw_stale_path);
}

FA_TEST(evaluation, missing_observations_are_indeterminate) {
  Fixture fixture(R"(revisions topology=10 policy=4 control=7 evidence=9
feed F1 source=utility role=primary domain=D1
load L1 class=critical
link F1 L1 role=primary domain=D1
rule R1 effect=permit precedence=ordinary_policy feed=F1 load=L1 path=AUTH-PRIMARY
)");
  FA_REQUIRE_OK(fixture.authority);
  const Result<DecisionSet> decision =
      fa_test::evaluate(fixture.authority.value(), "L1", fa_test::at(1735689600));
  FA_REQUIRE_OK(decision);
  const CandidateDecision* candidate = find(decision.value(), "F1");
  FA_REQUIRE(candidate != nullptr);
  FA_CHECK_EQ(candidate->outcome, DecisionOutcome::Indeterminate);
  FA_CHECK_EQ(candidate->reason, ReasonCode::PathNotEstablished);
  // No observation was supplied at all, so there is no evidence to reference: the
  // absence is reported by the reason, never as a value.
  FA_CHECK(candidate->evidence.empty());
}

FA_TEST(evaluation, contradictory_path_evidence_is_indeterminate) {
  Fixture fixture(R"(revisions topology=10 policy=4 control=7 evidence=9
feed F1 source=utility role=primary domain=D1
load L1 class=critical
link F1 L1 role=primary domain=D1
obs feed F1 condition=energized at=1735689600 max_age=300s source=S1
obs link F1 L1 present=yes at=1735689600 max_age=300s source=S1
obs link F1 L1 present=no at=1735689600 max_age=300s source=S2
rule R1 effect=permit precedence=ordinary_policy feed=F1 load=L1 path=AUTH-PRIMARY
)");
  FA_REQUIRE_OK(fixture.authority);
  const Result<DecisionSet> decision =
      fa_test::evaluate(fixture.authority.value(), "L1", fa_test::at(1735689600));
  FA_REQUIRE_OK(decision);
  const CandidateDecision* candidate = find(decision.value(), "F1");
  FA_REQUIRE(candidate != nullptr);
  FA_CHECK_EQ(candidate->outcome, DecisionOutcome::Indeterminate);
  bool saw_contradiction = false;
  for (const EvidenceRef& reference : candidate->evidence) {
    if (reference.state == EvidenceState::Contradictory) {
      saw_contradiction = true;
    }
  }
  FA_CHECK(saw_contradiction);
}

FA_TEST(evaluation, de_energized_feed_is_denied) {
  Fixture fixture(R"(revisions topology=10 policy=4 control=7 evidence=9
feed F1 source=utility role=primary domain=D1
load L1 class=critical
link F1 L1 role=primary domain=D1
obs feed F1 condition=de_energized at=1735689600 max_age=300s source=S1
obs link F1 L1 present=yes at=1735689600 max_age=300s source=S1
rule R1 effect=permit precedence=ordinary_policy feed=F1 load=L1 path=AUTH-PRIMARY
)");
  FA_REQUIRE_OK(fixture.authority);
  const Result<DecisionSet> decision =
      fa_test::evaluate(fixture.authority.value(), "L1", fa_test::at(1735689600));
  FA_REQUIRE_OK(decision);
  const CandidateDecision* candidate = find(decision.value(), "F1");
  FA_REQUIRE(candidate != nullptr);
  FA_CHECK_EQ(candidate->outcome, DecisionOutcome::Deny);
  FA_CHECK_EQ(candidate->reason, ReasonCode::FeedConditionPrevents);
}

FA_TEST(evaluation, unlinked_candidate_is_denied_and_unknown_feed_is_indeterminate) {
  Fixture fixture(kBase);
  FA_REQUIRE_OK(fixture.authority);
  {
    const std::vector<std::string> candidates = {"F1", "F9"};
    const Result<DecisionSet> decision =
        fa_test::evaluate(fixture.authority.value(), "L1", fa_test::at(1735689600), candidates);
    FA_REQUIRE_OK(decision);
    const CandidateDecision* unknown = find(decision.value(), "F9");
    FA_REQUIRE(unknown != nullptr);
    FA_CHECK_EQ(unknown->outcome, DecisionOutcome::Indeterminate);
    FA_CHECK_EQ(unknown->reason, ReasonCode::FeedUnknown);
    FA_CHECK(decision.value().candidate_set_narrowed);
  }
  {
    const Result<AuthorityInputs> alternate = parse_scenario(R"(revisions topology=11 policy=6 control=8 evidence=9
feed F1 source=utility role=primary domain=D1
feed F3 source=ups role=spare domain=D3
load L1 class=critical
link F1 L1 role=primary domain=D1
obs feed F1 condition=energized at=1735689600 max_age=300s source=S1
obs link F1 L1 present=yes at=1735689600 max_age=300s source=S1
rule R1 effect=permit precedence=ordinary_policy feed=F1 load=L1 path=AUTH-PRIMARY
)", Limits{}, "test");
    FA_REQUIRE_OK(alternate);
    FA_REQUIRE_OK(fa_test::adopt(fixture.authority.value(), alternate.value(), "adopt-2",
                                 fa_test::at(1735689600)));
    const std::vector<std::string> candidates = {"F3"};
    const Result<DecisionSet> decision =
        fa_test::evaluate(fixture.authority.value(), "L1", fa_test::at(1735689600), candidates);
    FA_REQUIRE_OK(decision);
    const CandidateDecision* candidate = find(decision.value(), "F3");
    FA_REQUIRE(candidate != nullptr);
    FA_CHECK_EQ(candidate->outcome, DecisionOutcome::Deny);
    FA_CHECK_EQ(candidate->reason, ReasonCode::CandidateNotLinked);
  }
}

FA_TEST(evaluation, required_authority_path_is_enforced) {
  Fixture fixture(kBase);
  FA_REQUIRE_OK(fixture.authority);
  const Result<DecisionSet> decision = fa_test::evaluate(fixture.authority.value(), "L1",
                                                        fa_test::at(1735689600), {"F1"},
                                                        "AUTH-SECONDARY");
  FA_REQUIRE_OK(decision);
  const CandidateDecision* candidate = find(decision.value(), "F1");
  FA_REQUIRE(candidate != nullptr);
  FA_CHECK_EQ(candidate->outcome, DecisionOutcome::Deny);
  FA_CHECK_EQ(candidate->reason, ReasonCode::AuthorityPathMismatch);
}

FA_TEST(evaluation, insertion_order_does_not_change_the_decision) {
  const char* forward = R"(revisions topology=10 policy=4 control=7 evidence=9
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
  const char* reversed = R"(revisions topology=10 policy=4 control=7 evidence=9
rule R2 effect=permit precedence=ordinary_policy feed=F2 load=L1 path=AUTH-SECONDARY
rule R1 effect=permit precedence=ordinary_policy feed=F1 load=L1 path=AUTH-PRIMARY
obs link F2 L1 present=yes at=1735689600 max_age=300s source=S1
obs link F1 L1 present=yes at=1735689600 max_age=300s source=S1
obs feed F2 condition=energized at=1735689600 max_age=300s source=S1
obs feed F1 condition=energized at=1735689600 max_age=300s source=S1
link F2 L1 role=secondary domain=D2
link F1 L1 role=primary domain=D1
load L1 class=critical protected=yes
feed F2 source=generator role=secondary domain=D2 protected=yes
feed F1 source=utility role=primary domain=D1 protected=yes
)";
  const Result<AuthorityInputs> forward_inputs = parse_scenario(forward, Limits{}, "forward");
  FA_REQUIRE_OK(forward_inputs);
  const Result<AuthorityInputs> reversed_inputs = parse_scenario(reversed, Limits{}, "reversed");
  FA_REQUIRE_OK(reversed_inputs);
  FA_CHECK(forward_inputs.value().identical_to(reversed_inputs.value()));
  FA_CHECK_EQ(forward_inputs.value().fingerprint().hex(), reversed_inputs.value().fingerprint().hex());
  FA_CHECK_EQ(forward_inputs.value().policy.fingerprint().hex(),
              reversed_inputs.value().policy.fingerprint().hex());

  Fixture forward_store(forward, "order-forward");
  Fixture reversed_store(reversed, "order-reversed");
  FA_REQUIRE_OK(forward_store.authority);
  FA_REQUIRE_OK(reversed_store.authority);
  const Result<DecisionSet> first =
      fa_test::evaluate(forward_store.authority.value(), "L1", fa_test::at(1735689600));
  const Result<DecisionSet> second =
      fa_test::evaluate(reversed_store.authority.value(), "L1", fa_test::at(1735689600));
  FA_REQUIRE_OK(first);
  FA_REQUIRE_OK(second);
  FA_CHECK_EQ(first.value().fingerprint.hex(), second.value().fingerprint.hex());
}

FA_TEST(evaluation, ranking_is_not_admissibility) {
  Fixture plain(kBase);
  FA_REQUIRE_OK(plain.authority);
  const Result<DecisionSet> unranked =
      fa_test::evaluate(plain.authority.value(), "L1", fa_test::at(1735689600));
  FA_REQUIRE_OK(unranked);
  FA_CHECK(!unranked.value().ranking.applied);
  FA_CHECK(unranked.value().ranking.selection_deferred_to_controller);
  FA_CHECK_EQ(unranked.value().ranking.reason, ReasonCode::RankingNotInPolicy);
  FA_CHECK(unranked.value().ranking.order.empty());
  FA_CHECK_EQ(unranked.value().eligible.size(), 2u);

  Fixture ranked(R"(revisions topology=10 policy=5 control=7 evidence=9
option ranking=on roles=secondary,primary
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
)", "ranking");
  FA_REQUIRE_OK(ranked.authority);
  const Result<DecisionSet> decision =
      fa_test::evaluate(ranked.authority.value(), "L1", fa_test::at(1735689600));
  FA_REQUIRE_OK(decision);
  FA_CHECK(decision.value().ranking.applied);
  FA_CHECK(!decision.value().ranking.selection_deferred_to_controller);
  FA_CHECK_EQ(decision.value().ranking.order.size(), 2u);
  FA_CHECK_EQ(decision.value().ranking.preferred.value(), std::string("F2"));
  FA_CHECK_EQ(decision.value().eligible.size(), 2u);
}

FA_TEST(evaluation, protected_obligation_diversity_blocks_the_whole_set) {
  Fixture fixture(R"(revisions topology=10 policy=4 control=7 evidence=9
feed F1 source=utility role=primary domain=D1 protected=yes
feed F2 source=generator role=secondary domain=D1 protected=yes
load L1 class=critical protected=yes
link F1 L1 role=primary domain=D1
link F2 L1 role=secondary domain=D1
obs feed F1 condition=energized at=1735689600 max_age=300s source=S1
obs feed F2 condition=energized at=1735689600 max_age=300s source=S1
obs link F1 L1 present=yes at=1735689600 max_age=300s source=S1
obs link F2 L1 present=yes at=1735689600 max_age=300s source=S1
rule R1 effect=permit precedence=ordinary_policy feed=F1 load=L1 path=AUTH-PRIMARY
rule R2 effect=permit precedence=ordinary_policy feed=F2 load=L1 path=AUTH-SECONDARY
obligation O1 protected_loads=yes min_domains=2
)", "obligation-diversity");
  FA_REQUIRE_OK(fixture.authority);
  const Result<DecisionSet> decision =
      fa_test::evaluate(fixture.authority.value(), "L1", fa_test::at(1735689600));
  FA_REQUIRE_OK(decision);
  FA_CHECK(decision.value().obligation_blocked);
  FA_CHECK_EQ(decision.value().blocking_obligations.size(), 1u);
  FA_CHECK_EQ(decision.value().eligible.size(), 0u);
  FA_CHECK_EQ(decision.value().indeterminate.size(), 2u);
  const CandidateDecision* candidate = find(decision.value(), "F1");
  FA_REQUIRE(candidate != nullptr);
  FA_CHECK_EQ(candidate->reason, ReasonCode::ObligationDiversityUnmet);
  FA_CHECK_EQ(candidate->decided_at, PrecedenceClass::ProtectedObligation);
}

FA_TEST(evaluation, obligation_role_restriction_outranks_ordinary_policy) {
  Fixture fixture(R"(revisions topology=10 policy=4 control=7 evidence=9
feed F1 source=ups role=spare domain=D1 protected=yes
load L1 class=critical protected=yes
link F1 L1 role=spare domain=D1
obs feed F1 condition=energized at=1735689600 max_age=300s source=S1
obs link F1 L1 present=yes at=1735689600 max_age=300s source=S1
rule R1 effect=permit precedence=ordinary_policy feed=F1 load=L1 path=AUTH-SPARE
obligation O1 protected_loads=yes roles=primary,secondary min_domains=1
)", "obligation-role");
  FA_REQUIRE_OK(fixture.authority);
  const Result<DecisionSet> decision =
      fa_test::evaluate(fixture.authority.value(), "L1", fa_test::at(1735689600));
  FA_REQUIRE_OK(decision);
  const CandidateDecision* candidate = find(decision.value(), "F1");
  FA_REQUIRE(candidate != nullptr);
  FA_CHECK_EQ(candidate->outcome, DecisionOutcome::Deny);
  FA_CHECK_EQ(candidate->decided_at, PrecedenceClass::ProtectedObligation);
  FA_CHECK_EQ(candidate->matched_obligations.size(), 1u);
}

FA_TEST(evaluation, maintenance_without_a_record_is_declared_none) {
  Fixture fixture(R"(revisions topology=10 policy=4 control=7 evidence=9
feed F1 source=utility role=primary domain=D1
load L1 class=critical
link F1 L1 role=primary domain=D1
obs feed F1 condition=energized at=1735689600 max_age=300s source=S1
obs link F1 L1 present=yes at=1735689600 max_age=300s source=S1
obs state condition=normal at=1735689600 max_age=300s source=S1
rule R1 effect=permit precedence=maintenance_restriction exposures=none feed=F1 load=L1 path=AUTH-NORMAL
)", "maintenance-none");
  FA_REQUIRE_OK(fixture.authority);
  const Result<DecisionSet> decision =
      fa_test::evaluate(fixture.authority.value(), "L1", fa_test::at(1735689600));
  FA_REQUIRE_OK(decision);
  const CandidateDecision* candidate = find(decision.value(), "F1");
  FA_REQUIRE(candidate != nullptr);
  FA_CHECK_EQ(candidate->outcome, DecisionOutcome::Allow);
}

FA_TEST(evaluation, unresolved_maintenance_blocks_a_higher_precedence_rule) {
  Fixture fixture(R"(revisions topology=10 policy=4 control=7 evidence=9
feed F1 source=utility role=primary domain=D1
load L1 class=critical
link F1 L1 role=primary domain=D1
obs feed F1 condition=energized at=1735689600 max_age=300s source=S1
obs link F1 L1 present=yes at=1735689600 max_age=300s source=S1
obs maintenance F1 exposure=withdrawn at=1735000000 max_age=1s source=S1
rule R1 effect=permit precedence=ordinary_policy feed=F1 load=L1 path=AUTH-PRIMARY
rule R2 effect=deny precedence=maintenance_restriction exposures=withdrawn feed=F1 load=L1 reason=maintenance_withdrawn
)", "maintenance-unresolved");
  FA_REQUIRE_OK(fixture.authority);
  const Result<DecisionSet> decision =
      fa_test::evaluate(fixture.authority.value(), "L1", fa_test::at(1735689600));
  FA_REQUIRE_OK(decision);
  const CandidateDecision* candidate = find(decision.value(), "F1");
  FA_REQUIRE(candidate != nullptr);
  FA_CHECK_EQ(candidate->outcome, DecisionOutcome::Indeterminate);
  FA_CHECK_EQ(candidate->reason, ReasonCode::RequiredEvidenceNotFresh);
}

FA_TEST(evaluation, unknown_load_is_refused) {
  Fixture fixture(kBase);
  FA_REQUIRE_OK(fixture.authority);
  FA_REQUIRE_ERR(fa_test::evaluate(fixture.authority.value(), "L9", fa_test::at(1735689600)),
                 StatusCode::NotFound);
}

FA_TEST(evaluation, safety_interlock_denies_and_never_permits) {
  Fixture fixture(R"(revisions topology=10 policy=4 control=7 evidence=9
feed F1 source=utility role=primary domain=D1
load L1 class=critical
link F1 L1 role=primary domain=D1
obs feed F1 condition=energized at=1735689600 max_age=300s source=S1
obs link F1 L1 present=yes at=1735689600 max_age=300s source=S1
rule R1 effect=deny precedence=safety_interlock rank=emergency reason=safety_interlock_denied
rule R2 effect=permit precedence=ordinary_policy feed=F1 load=L1 path=AUTH-PRIMARY
)", "interlock");
  FA_REQUIRE_OK(fixture.authority);
  const Result<DecisionSet> decision =
      fa_test::evaluate(fixture.authority.value(), "L1", fa_test::at(1735689600));
  FA_REQUIRE_OK(decision);
  const CandidateDecision* candidate = find(decision.value(), "F1");
  FA_REQUIRE(candidate != nullptr);
  FA_CHECK_EQ(candidate->outcome, DecisionOutcome::Deny);
  FA_CHECK_EQ(candidate->reason, ReasonCode::SafetyInterlockDenied);
  FA_CHECK_EQ(candidate->decided_at, PrecedenceClass::SafetyInterlock);
}
