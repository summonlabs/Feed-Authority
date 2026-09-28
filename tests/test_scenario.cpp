// Proof obligations for the scenario reader: the grammar is strict, defaults are
// explicit, and the same logical content is accepted whatever order the records
// appear in.

#include <string>

#include "feed_authority/scenario.hpp"
#include "support/fixtures.hpp"
#include "support/proc.hpp"
#include "support/test_harness.hpp"

using namespace feed_authority;

namespace {

const char* kMinimal = R"(revisions topology=10 policy=4 control=7 evidence=9
feed F1 source=utility role=primary domain=D1 protected=yes
load L1 class=critical protected=yes
link F1 L1 role=primary domain=D1
obs feed F1 condition=energized at=1735689600 max_age=300s source=S1
obs link F1 L1 present=yes at=1735689600 max_age=300s source=S1
rule R1 effect=permit precedence=ordinary_policy feed=F1 load=L1 path=AUTH-PRIMARY
)";

}  // namespace

FA_TEST(scenario, a_minimal_scenario_parses_with_explicit_defaults) {
  const Result<AuthorityInputs> inputs = parse_scenario(kMinimal, Limits{}, "minimal");
  FA_REQUIRE_OK(inputs);
  FA_CHECK_EQ(inputs.value().topology.revision.value(), 10u);
  FA_CHECK_EQ(inputs.value().policy.revision.value(), 4u);
  FA_CHECK_EQ(inputs.value().control.revision.value(), 7u);
  FA_CHECK_EQ(inputs.value().evidence.value(), 9u);
  FA_CHECK(!inputs.value().policy.options.ranking.enabled);
  FA_CHECK(!inputs.value().policy.options.emergency_override_enabled);
  FA_REQUIRE(inputs.value().topology.feeds.size() == 1u);
  FA_CHECK(inputs.value().topology.feeds.front().may_serve_protected_loads);
  FA_CHECK_EQ(inputs.value().topology.feeds.front().condition.size(), 1u);
  FA_REQUIRE(inputs.value().topology.links.size() == 1u);
  FA_CHECK_EQ(inputs.value().topology.links.front().observed.size(), 1u);
}

FA_TEST(scenario, comments_blank_lines_and_names_are_ignored) {
  const std::string text = std::string("# a comment\n\nname facility-a\n") + kMinimal +
                           "\n# trailing comment\n";
  const Result<AuthorityInputs> inputs = parse_scenario(text, Limits{}, "comments");
  FA_REQUIRE_OK(inputs);
  FA_CHECK(inputs.value().identical_to(parse_scenario(kMinimal, Limits{}, "minimal").value()));
}

FA_TEST(scenario, record_order_does_not_matter) {
  const char* reordered = R"(rule R1 effect=permit precedence=ordinary_policy feed=F1 load=L1 path=AUTH-PRIMARY
obs link F1 L1 present=yes at=1735689600 max_age=300s source=S1
obs feed F1 condition=energized at=1735689600 max_age=300s source=S1
link F1 L1 role=primary domain=D1
load L1 class=critical protected=yes
feed F1 source=utility role=primary domain=D1 protected=yes
revisions topology=10 policy=4 control=7 evidence=9
)";
  const Result<AuthorityInputs> first = parse_scenario(kMinimal, Limits{}, "ordered");
  FA_REQUIRE_OK(first);
  const Result<AuthorityInputs> second = parse_scenario(reordered, Limits{}, "reordered");
  FA_REQUIRE_OK(second);
  FA_CHECK(first.value().identical_to(second.value()));
  FA_CHECK_EQ(first.value().fingerprint().hex(), second.value().fingerprint().hex());
}

FA_TEST(scenario, options_obligations_and_maintenance_are_parsed) {
  const char* text = R"(revisions topology=10 policy=4 control=7 evidence=9
option ranking=on roles=primary,secondary
option emergency=on
feed F1 source=utility role=primary domain=D1 protected=yes
feed F2 source=generator role=secondary domain=D2 protected=yes
load L1 class=critical protected=yes
link F1 L1 role=primary domain=D1
link F2 L1 role=secondary domain=D2
obs maintenance F1 window=W1 exposure=restricted at=1735689600 max_age=300s source=S1
obs state condition=maintenance at=1735689600 max_age=300s source=S1
rule R1 effect=permit precedence=ordinary_policy feed=F1 load=L1 path=AUTH-PRIMARY conditions=maintenance
obligation O1 protected_loads=yes min_domains=2 roles=primary,secondary capability=yes
)";
  const Result<AuthorityInputs> inputs = parse_scenario(text, Limits{}, "options");
  FA_REQUIRE_OK(inputs);
  FA_CHECK(inputs.value().policy.options.ranking.enabled);
  FA_CHECK(inputs.value().policy.options.emergency_override_enabled);
  FA_CHECK_EQ(inputs.value().policy.options.ranking.role_order.size(), 2u);
  FA_CHECK_EQ(inputs.value().policy.options.ranking.role_order.front(), RedundancyRole::Primary);
  FA_REQUIRE(inputs.value().control.maintenance.size() == 1u);
  FA_CHECK_EQ(inputs.value().control.maintenance.front().window.value(), std::string("W1"));
  FA_CHECK_EQ(inputs.value().control.condition.size(), 1u);
  FA_REQUIRE(inputs.value().policy.rules.size() == 1u);
  FA_CHECK_EQ(inputs.value().policy.rules.front().conditions.size(), 1u);
  FA_REQUIRE(inputs.value().policy.obligations.size() == 1u);
  FA_CHECK_EQ(inputs.value().policy.obligations.front().min_distinct_failure_domains, 2u);
}

FA_TEST(scenario, declaration_forms_are_parsed) {
  const char* text = R"(revisions topology=10 policy=4 control=7 evidence=9
feed F1 source=utility role=primary domain=D1
feed F2 source=generator role=secondary domain=D2
load L1 class=critical
link F1 L1 role=primary domain=D1
link F2 L1 role=secondary domain=D2
obs feed F1 condition=energized at=1735689600 max_age=300s source=S1
obs feed F2 unknown source=S2
obs link F1 L1 present=yes at=2025-01-01T00:00:00Z max_age=5m source=S1
obs link F2 L1 unavailable source=S2
obs state unsupported source=S1
rule R1 effect=permit precedence=ordinary_policy feed=F1 load=L1 path=AUTH-PRIMARY
)";
  const Result<AuthorityInputs> inputs = parse_scenario(text, Limits{}, "declarations");
  FA_REQUIRE_OK(inputs);
  FA_REQUIRE(inputs.value().topology.feeds.size() == 2u);
  FA_CHECK_EQ(inputs.value().topology.feeds[1].condition.front().declaration(),
              EvidenceDeclaration::Unknown);
  const FeedLink& first_link = inputs.value().topology.links.front();
  FA_REQUIRE(!first_link.observed.empty());
  FA_CHECK_EQ(first_link.observed.front().observed_at().to_iso8601(),
              std::string("2025-01-01T00:00:00.000000000Z"));
  FA_CHECK_EQ(first_link.observed.front().max_age().to_string(), std::string("5m"));
  const FeedLink& second_link = inputs.value().topology.links.back();
  FA_CHECK_EQ(second_link.observed.front().declaration(), EvidenceDeclaration::Unavailable);
  FA_CHECK_EQ(inputs.value().control.condition.front().declaration(),
              EvidenceDeclaration::Unsupported);
}

FA_TEST(scenario, malformed_values_are_refused_with_a_line_reference) {
  const char* cases[] = {
      "revisions topology=10 policy=4 control=7\n",
      "revisions topology=10 policy=4 control=7 evidence=0x9\n",
      "revisions topology=10 policy=4 control=7 evidence=9\nfeed F1 source=utility role=primary\n"
      "obs feed F1 condition=energized at=1735689600 max_age=0s source=S1\n",
      "revisions topology=10 policy=4 control=7 evidence=9\nfeed F1 source=utility role=primary\n"
      "obs feed F1 condition=energized at=1735689600 max_age=300x source=S1\n",
      "revisions topology=10 policy=4 control=7 evidence=9\nfeed F1 source=utility role=primary\n"
      "obs feed F1 condition=not_a_condition at=1735689600 max_age=300s source=S1\n",
      "revisions topology=10 policy=4 control=7 evidence=9\nload L1 class=critical\n"
      "rule R1 effect=sideways load=L1 path=AUTH-1\n",
      "revisions topology=10 policy=4 control=7 evidence=9\nload L1 class=critical\n"
      "rule R1 effect=permit load=L1 path=AUTH-1 conditions=normal,normal\n",
      "revisions topology=10 policy=4 control=7 evidence=9\nload L1 class=critical\n"
      "obligation O1\n",
  };
  for (const char* text : cases) {
    const Result<AuthorityInputs> inputs = parse_scenario(text, Limits{}, "malformed");
    FA_CHECK_MSG(!inputs.ok(), std::string("accepted: ") + text);
    if (!inputs.ok()) {
      FA_CHECK(inputs.status().code() == StatusCode::InvalidArgument ||
               inputs.status().code() == StatusCode::DuplicateIdentity ||
               inputs.status().code() == StatusCode::LimitExceeded ||
               inputs.status().code() == StatusCode::NotFound);
      // The message names the source and the line.
      FA_CHECK(inputs.status().message().find("malformed:") != std::string::npos);
    }
  }
}

FA_TEST(scenario, a_scenario_file_is_read_through_the_public_loader) {
  const std::filesystem::path root = fa_test::fresh_store("scenario-file");
  const std::filesystem::path path = root / "facility.fa";
  FA_REQUIRE(fa_test::write_file(path, kMinimal));
  const Result<AuthorityInputs> inputs = load_scenario_file(path, Limits{});
  FA_REQUIRE_OK(inputs);
  FA_CHECK_EQ(inputs.value().topology.feeds.size(), 1u);
  FA_REQUIRE_ERR(load_scenario_file(root / "absent.fa", Limits{}), StatusCode::NotFound);
}
