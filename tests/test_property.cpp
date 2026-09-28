// Property and randomized state-machine tests.
//
// Every randomized case is driven by an explicit seed that is printed before it
// runs, so a failure reproduces exactly. The engine is compared against an
// independent reference model of the precedence ladder for a restricted policy
// language (no evidence-dependent rule conditions), and canonical determinism is
// checked by rebuilding the same logical state in different insertion orders.

#include <algorithm>
#include <iostream>
#include <string>
#include <vector>

#include "feed_authority/scenario.hpp"
#include "support/fixtures.hpp"
#include "support/test_harness.hpp"

using namespace feed_authority;

namespace {

struct Generated {
  std::string scenario;
  std::string load;
  std::vector<std::string> feeds;
  /// Per feed: permitted by an ordinary rule, denied by an ordinary rule.
  std::vector<bool> permitted;
  std::vector<bool> denied;
  std::vector<bool> linked;
  std::vector<bool> energized;
  std::vector<bool> path_present;
  std::vector<bool> path_fresh;
};

/// Builds a random but well-formed facility: feeds, one load, one path per feed, an
/// independent observation for each, and ordinary rules that permit or deny.
Generated generate(Rng& rng, std::size_t feed_count) {
  Generated generated;
  generated.load = "L1";
  std::string text = "revisions topology=10 policy=4 control=7 evidence=9\n";
  text += "load L1 class=critical\n";
  for (std::size_t index = 0; index < feed_count; ++index) {
    const std::string id = "F" + std::to_string(index);
    generated.feeds.push_back(id);
    const bool linked = rng.coin();
    const bool energized = rng.below(4) != 0;
    const bool present = rng.below(4) != 0;
    const bool fresh = rng.below(4) != 0;
    const bool permitted = rng.coin();
    const bool denied = rng.coin();
    generated.linked.push_back(linked);
    generated.energized.push_back(energized);
    generated.path_present.push_back(present);
    generated.path_fresh.push_back(fresh);
    generated.permitted.push_back(permitted);
    generated.denied.push_back(denied);

    const std::string role = index == 0 ? "primary" : "secondary";
    const std::string domain = "D" + std::to_string(index % 2);
    text += "feed " + id + " source=utility role=" + role + " domain=" + domain + "\n";
    if (linked) {
      text += "link " + id + " L1 role=" + role + " domain=" + domain + "\n";
      text += "obs link " + id + " L1 present=" + (present ? "yes" : "no") +
              " at=" + (fresh ? "1735689600" : "1735600000") + " max_age=300s source=S1\n";
    }
    text += "obs feed " + id + " condition=" + (energized ? "energized" : "de_energized") +
            " at=1735689600 max_age=300s source=S1\n";
    if (permitted) {
      text += "rule R" + std::to_string(index) + "p effect=permit precedence=ordinary_policy feed=" +
              id + " load=L1 path=AUTH-" + id + "\n";
    }
    if (denied) {
      text += "rule R" + std::to_string(index) + "d effect=deny precedence=ordinary_policy feed=" + id +
              " load=L1 reason=rule_denied\n";
    }
  }
  generated.scenario = text;
  return generated;
}

/// The independent reference model: the same documented rules for this restricted
/// language, written without reference to the engine's implementation.
struct Reference {
  DecisionOutcome outcome = DecisionOutcome::Indeterminate;
  ReasonCode reason = ReasonCode::RequiredEvidenceNotFresh;
};

Reference reference_for(const Generated& generated, std::size_t index) {
  Reference reference;
  if (!generated.linked[index]) {
    reference.outcome = DecisionOutcome::Deny;
    reference.reason = ReasonCode::CandidateNotLinked;
    return reference;
  }
  if (!generated.path_fresh[index]) {
    reference.outcome = DecisionOutcome::Indeterminate;
    reference.reason = ReasonCode::PathNotEstablished;
    return reference;
  }
  if (!generated.path_present[index]) {
    reference.outcome = DecisionOutcome::Deny;
    reference.reason = ReasonCode::PathAbsent;
    return reference;
  }
  if (!generated.energized[index]) {
    reference.outcome = DecisionOutcome::Deny;
    reference.reason = ReasonCode::FeedConditionPrevents;
    return reference;
  }
  const bool permitted = generated.permitted[index];
  const bool denied = generated.denied[index];
  if (permitted && denied) {
    reference.outcome = DecisionOutcome::Indeterminate;
    reference.reason = ReasonCode::EqualPrecedenceConflict;
    return reference;
  }
  if (denied) {
    reference.outcome = DecisionOutcome::Deny;
    reference.reason = ReasonCode::RuleDenied;
    return reference;
  }
  if (permitted) {
    reference.outcome = DecisionOutcome::Allow;
    reference.reason = ReasonCode::RulePermitted;
    return reference;
  }
  reference.outcome = DecisionOutcome::Deny;
  reference.reason = ReasonCode::NoPermitRuleMatched;
  return reference;
}

}  // namespace

FA_TEST(property, randomized_evaluation_matches_the_reference_model) {
  for (std::uint64_t seed = 1; seed <= 40; ++seed) {
    Rng rng(seed);
    const std::size_t feed_count = 1 + static_cast<std::size_t>(rng.below(4));
    const Generated generated = generate(rng, feed_count);
    const std::string context = "seed=" + std::to_string(seed);
    const std::filesystem::path root = fa_test::fresh_store("property-" + std::to_string(seed));
    Result<FeedAuthority> authority = fa_test::open_store(root, true);
    FA_REQUIRE_OK(authority);
    const Result<AuthorityInputs> inputs =
        parse_scenario(generated.scenario, authority.value().limits(), "property");
    if (!inputs.ok()) {
      FA_CHECK_MSG(false, context + " scenario refused: " + inputs.status().to_string());
      continue;
    }
    const Status adopted = fa_test::adopt(authority.value(), inputs.value(), "adopt-1",
                                          fa_test::at(1735689600));
    if (!adopted.ok()) {
      FA_CHECK_MSG(false, context + " adopt failed: " + adopted.to_string());
      continue;
    }
    const Result<DecisionSet> decision =
        fa_test::evaluate(authority.value(), "L1", fa_test::at(1735689600), generated.feeds);
    if (!decision.ok()) {
      FA_CHECK_MSG(false, context + " evaluate failed: " + decision.status().to_string());
      continue;
    }
    for (std::size_t index = 0; index < generated.feeds.size(); ++index) {
      const Reference reference = reference_for(generated, index);
      const CandidateDecision* candidate = nullptr;
      for (const CandidateDecision& entry : decision.value().candidates) {
        if (entry.feed.value() == generated.feeds[index]) {
          candidate = &entry;
        }
      }
      if (candidate == nullptr) {
        FA_CHECK_MSG(false, context + " candidate " + generated.feeds[index] +
                                 " missing from the reported candidate set");
        continue;
      }
      FA_CHECK_MSG(candidate->outcome == reference.outcome,
                   context + " feed=" + generated.feeds[index] + " engine=" +
                       to_string(candidate->outcome) + " reference=" + to_string(reference.outcome));
      FA_CHECK_MSG(candidate->reason == reference.reason,
                   context + " feed=" + generated.feeds[index] + " engine=" +
                       to_string(candidate->reason) + " reference=" + to_string(reference.reason));
    }

  }
}

FA_TEST(property, randomized_state_round_trips_through_the_store) {
  for (std::uint64_t seed = 100; seed <= 130; ++seed) {
    Rng rng(seed);
    const Generated generated = generate(rng, 1 + static_cast<std::size_t>(rng.below(5)));
    const std::string context = "seed=" + std::to_string(seed);
    const std::filesystem::path root = fa_test::fresh_store("property-round-trip-" + std::to_string(seed));
    Result<FeedAuthority> authority = fa_test::open_store(root, true);
    FA_REQUIRE_OK(authority);
    const Result<AuthorityInputs> inputs =
        parse_scenario(generated.scenario, authority.value().limits(), "property");
    if (!inputs.ok()) {
      FA_CHECK_MSG(false, context + " scenario refused: " + inputs.status().to_string());
      continue;
    }
    const Status adopted = fa_test::adopt(authority.value(), inputs.value(), "adopt-1",
                                          fa_test::at(1735689600));
    if (!adopted.ok()) {
      FA_CHECK_MSG(false, context + " adopt failed: " + adopted.to_string());
      continue;
    }
    const Digest before = authority.value().inputs().fingerprint();
    const Status verified = authority.value().Verify();
    FA_CHECK_MSG(verified.ok(), context + " verify: " + verified.to_string());
    // Reopening must produce exactly the same logical input generation.
    Result<FeedAuthority> reopened = fa_test::open_store(root, false);
    if (!reopened.ok()) {
      FA_CHECK_MSG(false, context + " reopen failed: " + reopened.status().to_string());
      continue;
    }
    FA_CHECK_MSG(reopened.value().inputs().fingerprint().hex() == before.hex(),
                 context + " the reopened input generation differs");
    const Status reopened_verified = reopened.value().Verify();
    FA_CHECK_MSG(reopened_verified.ok(), context + " reopened verify: " + reopened_verified.to_string());
  }
}

FA_TEST(property, randomized_canonical_encoding_is_order_independent) {
  for (std::uint64_t seed = 200; seed <= 240; ++seed) {
    Rng rng(seed);
    const Generated generated = generate(rng, 2 + static_cast<std::size_t>(rng.below(4)));
    const Result<AuthorityInputs> forward =
        parse_scenario(generated.scenario, Limits{}, "property-forward");
    FA_REQUIRE_OK(forward);

    // Rebuild the same facility with the records emitted in the reverse order.
    std::vector<std::string> lines;
    std::string current;
    for (const char character : generated.scenario) {
      if (character == '\n') {
        if (!current.empty()) {
          lines.push_back(current);
        }
        current.clear();
        continue;
      }
      current.push_back(character);
    }
    std::reverse(lines.begin(), lines.end());
    std::string reversed_text;
    for (const std::string& line : lines) {
      reversed_text += line;
      reversed_text.push_back('\n');
    }
    const Result<AuthorityInputs> reversed = parse_scenario(reversed_text, Limits{}, "property-reversed");
    const std::string context = "seed=" + std::to_string(seed);
    if (!reversed.ok()) {
      FA_CHECK_MSG(false, context + " reversed scenario refused: " + reversed.status().to_string());
      continue;
    }
    FA_CHECK_MSG(forward.value().fingerprint().hex() == reversed.value().fingerprint().hex(),
                 context + " canonical fingerprints differ");
    FA_CHECK(forward.value().identical_to(reversed.value()));
  }
}
