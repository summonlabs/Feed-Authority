// Proof obligations: identities are strongly typed and strictly validated; counters
// never wrap; time parsing is exact; the declared bounds are consistent.

#include "support/test_harness.hpp"

using namespace feed_authority;

FA_TEST(ids, rejects_malformed_identity_text) {
  FA_CHECK(!is_valid_identity_text(""));
  FA_CHECK(!is_valid_identity_text(".leading"));
  FA_CHECK(!is_valid_identity_text("trailing."));
  FA_CHECK(!is_valid_identity_text("double..dot"));
  FA_CHECK(!is_valid_identity_text("has space"));
  FA_CHECK(!is_valid_identity_text("has/slash"));
  FA_CHECK(!is_valid_identity_text("has\\backslash"));
  FA_CHECK(!is_valid_identity_text(std::string(65, 'a')));
  FA_CHECK(is_valid_identity_text("F1"));
  FA_CHECK(is_valid_identity_text("feed-1.secondary:main_a"));
  FA_CHECK(is_valid_identity_text(std::string(64, 'a')));
}

FA_TEST(ids, identity_kinds_do_not_interchange) {
  const Result<FeedId> feed = FeedId::Parse("F1");
  FA_REQUIRE_OK(feed);
  FA_CHECK_EQ(feed.value().value(), std::string("F1"));
  const Result<LoadId> load = LoadId::Parse("..");
  FA_CHECK(!load.ok());
  FA_CHECK_EQ(load.status().code(), StatusCode::InvalidArgument);
  const Result<AttemptId> attempt = AttemptId::Parse("attempt-1");
  FA_REQUIRE_OK(attempt);
  FA_CHECK(attempt.value().valid());
  FA_CHECK(!AttemptId{}.valid());
}

FA_TEST(counters, do_not_wrap_and_parse_strictly) {
  const Counter<StoreSequenceTag> zero;
  FA_CHECK(zero.is_zero());
  FA_CHECK_EQ(zero.str(), std::string("0"));
  const Result<StoreSequence> one = zero.next();
  FA_REQUIRE_OK(one);
  FA_CHECK_EQ(one.value().value(), 1u);
  const StoreSequence maximum = StoreSequence::FromValue(0xFFFFFFFFFFFFFFFFull);
  const Result<StoreSequence> overflow = maximum.next();
  FA_CHECK(!overflow.ok());
  FA_CHECK_EQ(overflow.status().code(), StatusCode::LimitExceeded);
  FA_CHECK(!StoreSequence::Parse("01").ok());
  FA_CHECK(!StoreSequence::Parse("-1").ok());
  FA_CHECK(!StoreSequence::Parse("").ok());
  FA_CHECK(!StoreSequence::Parse("1a").ok());
  FA_CHECK_EQ(StoreSequence::Parse("18446744073709551615").value().value(), 0xFFFFFFFFFFFFFFFFull);
  FA_CHECK(!StoreSequence::Parse("18446744073709551616").ok());
}

FA_TEST(counters, kinds_are_distinct_types) {
  // A topology revision and a policy revision are different types; this compiles
  // only because each keeps its own tag.
  const TopologyRevision topology = TopologyRevision::FromValue(7);
  const PolicyRevision policy = PolicyRevision::FromValue(7);
  FA_CHECK_EQ(topology.value(), policy.value());
  FA_CHECK(!(topology == TopologyRevision::FromValue(8)));
  const AuthorityEpoch epoch = AuthorityEpoch::FromValue(3);
  const Incarnation incarnation = Incarnation::ForEpoch(epoch);
  FA_CHECK_EQ(incarnation.epoch().value(), 3u);
  FA_CHECK_EQ(incarnation.str(), std::string("incarnation-3"));
}

FA_TEST(time, renders_and_parses_iso8601) {
  const Result<AuthorityTime> instant = AuthorityTime::FromUnixSeconds(1735689600);
  FA_REQUIRE_OK(instant);
  FA_CHECK_EQ(instant.value().to_iso8601(), std::string("2025-01-01T00:00:00.000000000Z"));
  const Result<AuthorityTime> parsed = AuthorityTime::ParseIso8601("2025-01-01T00:00:00Z");
  FA_REQUIRE_OK(parsed);
  FA_CHECK_EQ(parsed.value().unix_nanos(), instant.value().unix_nanos());
  const Result<AuthorityTime> fractional = AuthorityTime::ParseIso8601("2025-01-01T00:00:00.5Z");
  FA_REQUIRE_OK(fractional);
  FA_CHECK_EQ(fractional.value().unix_nanos(), instant.value().unix_nanos() + 500000000ll);
}

FA_TEST(time, refuses_malformed_timestamps) {
  FA_CHECK(!AuthorityTime::ParseIso8601("").ok());
  FA_CHECK(!AuthorityTime::ParseIso8601("2025-01-01").ok());
  FA_CHECK(!AuthorityTime::ParseIso8601("2025-01-01T00:00:00").ok());
  FA_CHECK(!AuthorityTime::ParseIso8601("2025-13-01T00:00:00Z").ok());
  FA_CHECK(!AuthorityTime::ParseIso8601("2025-02-30T00:00:00Z").ok());
  FA_CHECK(!AuthorityTime::ParseIso8601("2025-01-01T24:00:00Z").ok());
  FA_CHECK(!AuthorityTime::ParseIso8601("2025-01-01T00:00:60Z").ok());
  FA_CHECK(!AuthorityTime::ParseIso8601("2025-01-01T00:00:00+01:00").ok());
  FA_CHECK(!AuthorityTime::ParseIso8601("2025-01-01T00:00:00.1234567890Z").ok());
}

FA_TEST(time, durations_are_exact_and_bounded) {
  const Result<Duration> minute = Duration::FromMinutes(1);
  FA_REQUIRE_OK(minute);
  FA_CHECK_EQ(minute.value().nanos(), 60000000000ll);
  FA_CHECK_EQ(minute.value().to_string(), std::string("1m"));
  FA_CHECK(!Duration::FromSeconds(-1).ok());
  FA_CHECK(!Duration::FromHours(1000000000).ok());
  const Result<Duration> age = AuthorityTime::FromUnixSeconds(100).value().Since(
      AuthorityTime::FromUnixSeconds(40).value());
  FA_REQUIRE_OK(age);
  FA_CHECK_EQ(age.value().to_string(), std::string("1m"));
  FA_CHECK(!AuthorityTime::FromUnixSeconds(40).value().Since(
                AuthorityTime::FromUnixSeconds(100).value())
                .ok());
}

FA_TEST(limits, defaults_are_consistent_and_bounds_are_enforced) {
  const Limits limits;
  FA_REQUIRE_OK(limits.validate());
  Limits bad = limits;
  bad.max_id_length = 0;
  FA_CHECK(!bad.validate().ok());
  bad = limits;
  bad.max_candidates = kMaxCandidates + 1;
  FA_CHECK(!bad.validate().ok());
  bad = limits;
  bad.generation_retention = 0;
  FA_CHECK(!bad.validate().ok());
  bad = limits;
  bad.max_generation_bytes = 1;
  FA_CHECK(!bad.validate().ok());
  bad = limits;
  bad.decision_lease = 0;
  FA_CHECK(!bad.validate().ok());
  bad = limits;
  bad.max_grant_validity_nanos = 0;
  FA_CHECK(!bad.validate().ok());
  bad = limits;
  bad.lock_acquire_budget_nanos = 0;
  FA_CHECK(!bad.validate().ok());
}

FA_TEST(limits, status_and_reason_tokens_round_trip) {
  for (std::int32_t value = 0; value <= 34; ++value) {
    const StatusCode code = static_cast<StatusCode>(value);
    const std::string token = to_string(code);
    FA_CHECK(!token.empty());
    FA_CHECK(token != std::string("unrecognized_status_code"));
  }
  for (std::int32_t value = 0; value <= 27; ++value) {
    const ReasonCode code = static_cast<ReasonCode>(value);
    const std::string token = to_string(code);
    const Result<ReasonCode> parsed = parse_reason_code(token);
    FA_REQUIRE_OK(parsed);
    FA_CHECK_EQ(parsed.value(), code);
  }
  FA_CHECK(!parse_reason_code("not_a_reason").ok());
}
