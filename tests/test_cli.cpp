// Proof obligations for the administration tool: it drives real library behaviour
// end to end in a separate process, refuses malformed input with a usage exit code,
// and reports refusals distinctly from usage errors.

#include <string>
#include <vector>

#include "feed_authority/version.hpp"
#include "support/fixtures.hpp"
#include "support/proc.hpp"
#include "support/test_harness.hpp"

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

struct CliRun {
  int exit_code = 0;
  std::string output;
};

CliRun run_cli(const std::filesystem::path& root, const std::vector<std::string>& arguments) {
  CliRun run;
  const std::filesystem::path output_file = root / "cli-output.txt";
  std::string error;
  if (!fa_test::run_captured(fa_test::cli_path(), arguments, output_file, run.exit_code, error)) {
    fa_test::report_failure(__FILE__, __LINE__, "run_cli", error);
    return run;
  }
  const std::vector<std::string> lines = fa_test::read_lines(output_file);
  for (const std::string& line : lines) {
    run.output += line;
    run.output.push_back('\n');
  }
  return run;
}

bool contains(const std::string& text, const std::string& needle) {
  return text.find(needle) != std::string::npos;
}

}  // namespace

FA_TEST(cli, version_and_help_are_available) {
  const std::filesystem::path root = fa_test::fresh_store("cli-basics");
  const CliRun version = run_cli(root, {"version"});
  FA_CHECK_EQ(version.exit_code, 0);
  FA_CHECK(contains(version.output, std::string(version_string())));
  const CliRun help = run_cli(root, {"help"});
  FA_CHECK_EQ(help.exit_code, 2);
  FA_CHECK(contains(help.output, "Usage: feed-authority"));
}

FA_TEST(cli, usage_errors_are_distinct_from_refusals) {
  const std::filesystem::path root = fa_test::fresh_store("cli-usage");
  FA_CHECK_EQ(run_cli(root, {"nonsense"}).exit_code, 2);
  FA_CHECK_EQ(run_cli(root, {"store", "audit", "--mystery"}).exit_code, 2);
  FA_CHECK_EQ(run_cli(root, {"evaluate", "--store", (root / "absent").string(), "--load", "L1"})
                  .exit_code,
              1);
}

FA_TEST(cli, the_full_lifecycle_runs_through_the_tool) {
  const std::filesystem::path root = fa_test::fresh_store("cli-lifecycle");
  const std::filesystem::path scenario = root / "facility.fa";
  FA_REQUIRE(fa_test::write_file(scenario, kScenario));
  const std::string store = root.string();
  const std::string scenario_path = scenario.string();

  const CliRun create = run_cli(root, {"store", "create", "--store", store});
  FA_CHECK_EQ(create.exit_code, 0);
  FA_CHECK(contains(create.output, "recovery"));

  const CliRun adopt = run_cli(root, {"inputs", "adopt", "--store", store, "--scenario", scenario_path});
  FA_CHECK_EQ(adopt.exit_code, 0);

  const CliRun evaluate =
      run_cli(root, {"evaluate", "--store", store, "--load", "L1", "--scenario", scenario_path,
                     "--now", "1735689600"});
  FA_CHECK_EQ(evaluate.exit_code, 0);
  FA_CHECK(contains(evaluate.output, "eligible=F1,F2"));
  FA_CHECK(contains(evaluate.output, "fingerprint="));
  FA_CHECK(contains(evaluate.output, "ranking applied=false"));

  const CliRun explain =
      run_cli(root, {"explain", "--store", store, "--load", "L1", "--scenario", scenario_path,
                     "--now", "1735689600"});
  FA_CHECK_EQ(explain.exit_code, 0);
  FA_CHECK(contains(explain.output, "trace F1"));
  FA_CHECK(contains(explain.output, "step path-evidence"));

  const CliRun issue =
      run_cli(root, {"grant", "issue", "--store", store, "--load", "L1", "--feed", "F1",
                     "--validity", "300s", "--scenario", scenario_path, "--now", "1735689600",
                     "--attempt", "cli-attempt-1"});
  FA_CHECK_EQ(issue.exit_code, 0);
  FA_CHECK(contains(issue.output, "grant 1"));
  FA_CHECK(contains(issue.output, "path=AUTH-PRIMARY"));

  // A later process is a new writer session: the grant is persisted but not yet
  // usable, which is exactly what the tool reports, and revalidation is what makes
  // it usable again.
  const CliRun needs_revalidation =
      run_cli(root, {"grant", "check", "--store", store, "--id", "1", "--scenario", scenario_path,
                     "--now", "1735689700"});
  FA_CHECK_EQ(needs_revalidation.exit_code, 1);
  FA_CHECK(contains(needs_revalidation.output, "usability=needs_revalidation"));

  const CliRun revalidate =
      run_cli(root, {"grant", "revalidate", "--store", store, "--id", "1", "--scenario",
                     scenario_path, "--attempt", "cli-revalidate-1", "--now", "1735689700",
                     "--check"});
  FA_CHECK_EQ(revalidate.exit_code, 0);
  FA_CHECK(contains(revalidate.output, "revalidated=true"));
  FA_CHECK(contains(revalidate.output, "authorized=true"));

  const CliRun revoke =
      run_cli(root, {"grant", "revoke", "--store", store, "--id", "1", "--authorizer", "OPERATOR-1",
                     "--reason", "planned transfer", "--attempt", "cli-revoke-1"});
  FA_CHECK_EQ(revoke.exit_code, 0);

  const CliRun revoked = run_cli(root, {"grant", "check", "--store", store, "--id", "1",
                                        "--scenario", scenario_path, "--now", "1735689800"});
  FA_CHECK_EQ(revoked.exit_code, 1);
  FA_CHECK(contains(revoked.output, "authorized=false"));
  FA_CHECK(contains(revoked.output, "usability=revoked"));

  const CliRun audit = run_cli(root, {"store", "audit", "--store", store});
  FA_CHECK_EQ(audit.exit_code, 0);
  FA_CHECK(contains(audit.output, "ok=true"));
  FA_CHECK(contains(audit.output, "class=head"));

  const CliRun verify = run_cli(root, {"store", "verify", "--store", store});
  FA_CHECK_EQ(verify.exit_code, 0);

  const CliRun history = run_cli(root, {"store", "history", "--store", store, "--limit", "5"});
  FA_CHECK_EQ(history.exit_code, 0);
  FA_CHECK(contains(history.output, "grant_revoked"));

  const CliRun attempts = run_cli(root, {"store", "attempts", "--store", store});
  FA_CHECK_EQ(attempts.exit_code, 0);
  FA_CHECK(contains(attempts.output, "cli-attempt-1"));

  const CliRun json = run_cli(root, {"evaluate", "--store", store, "--load", "L1", "--scenario",
                                     scenario_path, "--now", "1735689600", "--json"});
  FA_CHECK_EQ(json.exit_code, 0);
  FA_CHECK(contains(json.output, "\"kind\":\"decision\""));
  FA_CHECK(contains(json.output, "\"eligible\":[\"F1\",\"F2\"]"));
}

FA_TEST(cli, a_maintenance_scenario_and_an_emergency_override_are_visible_in_the_tool) {
  const std::filesystem::path root = fa_test::fresh_store("cli-emergency");
  const char* restricted = R"(revisions topology=10 policy=4 control=7 evidence=9
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
obs state condition=maintenance at=1735689600 max_age=300s source=S1
obs maintenance F1 exposure=withdrawn at=1735689600 max_age=300s source=S1
rule R1 effect=permit precedence=ordinary_policy feed=F1 load=L1 path=AUTH-PRIMARY
rule R2 effect=permit precedence=ordinary_policy feed=F2 load=L1 path=AUTH-SECONDARY
rule R3 effect=deny precedence=maintenance_restriction rank=emergency overridable=yes feed=F1 load=L1 reason=maintenance_withdrawn
)";
  const std::filesystem::path scenario = root / "restricted.fa";
  FA_REQUIRE(fa_test::write_file(scenario, restricted));
  const std::string store = root.string();
  const std::string scenario_path = scenario.string();

  const CliRun before =
      run_cli(root, {"evaluate", "--store", store, "--load", "L1", "--scenario", scenario_path,
                     "--now", "1735689600"});
  FA_CHECK_EQ(before.exit_code, 0);
  FA_CHECK(contains(before.output, "eligible=F2"));
  FA_CHECK(contains(before.output, "denied=F1"));

  const CliRun authorize =
      run_cli(root, {"emergency", "authorize", "--store", store, "--authorizer", "INCIDENT-COMMANDER",
                     "--justification", "loss of the secondary path", "--loads", "L1", "--classes",
                     "maintenance_restriction", "--validity", "600s", "--attempt", "cli-emergency-1",
                     "--scenario", scenario_path, "--now", "1735689600"});
  FA_CHECK_EQ(authorize.exit_code, 0);
  FA_CHECK(contains(authorize.output, "emergency 1"));

  const CliRun after =
      run_cli(root, {"evaluate", "--store", store, "--load", "L1", "--scenario", scenario_path,
                     "--now", "1735689700"});
  FA_CHECK_EQ(after.exit_code, 0);
  FA_CHECK(contains(after.output, "eligible=F1,F2"));
  FA_CHECK(contains(after.output, "emergency_override_applied"));

  const CliRun list = run_cli(root, {"emergency", "list", "--store", store});
  FA_CHECK_EQ(list.exit_code, 0);
  FA_CHECK(contains(list.output, "authorizer=INCIDENT-COMMANDER"));
}
