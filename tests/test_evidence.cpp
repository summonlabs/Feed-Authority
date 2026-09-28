// Proof obligations: evidence states are distinct and never collapse into a value;
// stale, unknown, unsupported, unavailable, future-dated and contradictory evidence
// never resolve to a usable value.

#include "support/test_harness.hpp"
#include "support/fixtures.hpp"

using namespace feed_authority;

namespace {

Observation<FeedCondition> fresh_energized(AuthorityTime when, Duration window, const char* source) {
  return Observation<FeedCondition>::Known(FeedCondition::Energized, when, window, fa_test::source(source))
      .value();
}

}  // namespace

FA_TEST(evidence, resolution_states_are_distinct) {
  const AuthorityTime now = fa_test::at(1000);
  const Duration window = fa_test::secs(60);

  {
    const std::vector<Observation<FeedCondition>> none;
    const Result<ResolvedEvidence<FeedCondition>> resolved = resolve_evidence(none, now);
    FA_REQUIRE_OK(resolved);
    FA_CHECK_EQ(resolved.value().state, EvidenceState::Unknown);
    FA_CHECK(!resolved.value().usable());
  }
  {
    const std::vector<Observation<FeedCondition>> records = {fresh_energized(now, window, "S1")};
    const Result<ResolvedEvidence<FeedCondition>> resolved = resolve_evidence(records, now);
    FA_REQUIRE_OK(resolved);
    FA_CHECK_EQ(resolved.value().state, EvidenceState::Fresh);
    FA_CHECK_EQ(resolved.value().value, FeedCondition::Energized);
    FA_CHECK_EQ(resolved.value().source.value(), std::string("S1"));
  }
  {
    const std::vector<Observation<FeedCondition>> records = {
        fresh_energized(fa_test::at(900), window, "S1")};
    const Result<ResolvedEvidence<FeedCondition>> resolved = resolve_evidence(records, now);
    FA_REQUIRE_OK(resolved);
    FA_CHECK_EQ(resolved.value().state, EvidenceState::Stale);
    FA_CHECK(!resolved.value().usable());
  }
  {
    const std::vector<Observation<FeedCondition>> records = {
        Observation<FeedCondition>::Unknown(fa_test::source("S1"))};
    const Result<ResolvedEvidence<FeedCondition>> resolved = resolve_evidence(records, now);
    FA_REQUIRE_OK(resolved);
    FA_CHECK_EQ(resolved.value().state, EvidenceState::Unknown);
  }
  {
    const std::vector<Observation<FeedCondition>> records = {
        Observation<FeedCondition>::Unsupported(fa_test::source("S1"))};
    const Result<ResolvedEvidence<FeedCondition>> resolved = resolve_evidence(records, now);
    FA_REQUIRE_OK(resolved);
    FA_CHECK_EQ(resolved.value().state, EvidenceState::Unsupported);
  }
  {
    const std::vector<Observation<FeedCondition>> records = {
        Observation<FeedCondition>::Unavailable(fa_test::source("S1"))};
    const Result<ResolvedEvidence<FeedCondition>> resolved = resolve_evidence(records, now);
    FA_REQUIRE_OK(resolved);
    FA_CHECK_EQ(resolved.value().state, EvidenceState::Unavailable);
  }
  {
    const std::vector<Observation<FeedCondition>> records = {
        fresh_energized(fa_test::at(2000), window, "S1")};
    const Result<ResolvedEvidence<FeedCondition>> resolved = resolve_evidence(records, now);
    FA_REQUIRE_OK(resolved);
    FA_CHECK_EQ(resolved.value().state, EvidenceState::FutureDated);
    FA_CHECK(!resolved.value().usable());
  }
}

FA_TEST(evidence, contradictory_fresh_observations_never_pick_a_side) {
  const AuthorityTime now = fa_test::at(1000);
  std::vector<Observation<FeedCondition>> records = {
      fresh_energized(now, fa_test::secs(60), "S1"),
      Observation<FeedCondition>::Known(FeedCondition::DeEnergized, now, fa_test::secs(60),
                                        fa_test::source("S2"))
          .value()};
  const Result<ResolvedEvidence<FeedCondition>> resolved = resolve_evidence(records, now);
  FA_REQUIRE_OK(resolved);
  FA_CHECK_EQ(resolved.value().state, EvidenceState::Contradictory);
  FA_CHECK(!resolved.value().usable());

  // Agreement resolves, and the recorded source is the smallest identity, so the
  // answer does not depend on the order the observations arrived in.
  std::vector<Observation<FeedCondition>> agreeing = {
      fresh_energized(now, fa_test::secs(60), "S2"),
      fresh_energized(now, fa_test::secs(60), "S1")};
  const Result<ResolvedEvidence<FeedCondition>> agreed = resolve_evidence(agreeing, now);
  FA_REQUIRE_OK(agreed);
  FA_CHECK_EQ(agreed.value().state, EvidenceState::Fresh);
  FA_CHECK_EQ(agreed.value().source.value(), std::string("S1"));
  std::reverse(agreeing.begin(), agreeing.end());
  const Result<ResolvedEvidence<FeedCondition>> reordered = resolve_evidence(agreeing, now);
  FA_REQUIRE_OK(reordered);
  FA_CHECK_EQ(reordered.value().source.value(), std::string("S1"));
}

FA_TEST(evidence, obstruction_precedence_is_fixed) {
  FA_CHECK(evidence_state_precedence(EvidenceState::Contradictory) <
           evidence_state_precedence(EvidenceState::FutureDated));
  FA_CHECK(evidence_state_precedence(EvidenceState::FutureDated) <
           evidence_state_precedence(EvidenceState::Stale));
  FA_CHECK(evidence_state_precedence(EvidenceState::Stale) <
           evidence_state_precedence(EvidenceState::Unavailable));
  FA_CHECK(evidence_state_precedence(EvidenceState::Unavailable) <
           evidence_state_precedence(EvidenceState::Unsupported));
  FA_CHECK(evidence_state_precedence(EvidenceState::Unsupported) <
           evidence_state_precedence(EvidenceState::Unknown));

  // A stale observation and an unknown one report staleness: it is the more
  // specific obstruction.
  const std::vector<Observation<FeedCondition>> records = {
      fresh_energized(fa_test::at(1), fa_test::secs(1), "S1"),
      Observation<FeedCondition>::Unknown(fa_test::source("S2"))};
  const Result<ResolvedEvidence<FeedCondition>> resolved = resolve_evidence(records, fa_test::at(1000));
  FA_REQUIRE_OK(resolved);
  FA_CHECK_EQ(resolved.value().state, EvidenceState::Stale);
}

FA_TEST(evidence, bounded_number_of_observations) {
  std::vector<Observation<FeedCondition>> records;
  for (std::uint32_t index = 0; index < kMaxObservationsPerSubject; ++index) {
    records.push_back(fresh_energized(fa_test::at(1000), fa_test::secs(60),
                                      ("S" + std::to_string(index)).c_str()));
  }
  FA_REQUIRE_OK(resolve_evidence(records, fa_test::at(1000)));
  records.push_back(fresh_energized(fa_test::at(1000), fa_test::secs(60), "S9"));
  FA_REQUIRE_ERR(resolve_evidence(records, fa_test::at(1000)), StatusCode::LimitExceeded);
}

FA_TEST(evidence, known_observation_requires_a_window_and_a_source) {
  FA_CHECK(!Observation<FeedCondition>::Known(FeedCondition::Energized, fa_test::at(1),
                                              Duration{}, fa_test::source("S1"))
                .ok());
  FA_CHECK(!Observation<FeedCondition>::Known(FeedCondition::Energized, fa_test::at(1),
                                              fa_test::secs(1), EvidenceSourceId{})
                .ok());
}
