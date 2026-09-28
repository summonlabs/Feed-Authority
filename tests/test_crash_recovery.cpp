// Proof obligations for crash semantics: a process killed at any durable stage of
// the publication protocol leaves a store that reopens as exactly one whole verified
// state, never as a mixture, and never with the uncommitted change applied.

#include <fstream>

#include "feed_authority/scenario.hpp"
#include "support/fixtures.hpp"
#include "support/proc.hpp"
#include "support/test_harness.hpp"

#include "detail/platform_io.hpp"

using namespace feed_authority;

namespace {

const char* kScenario = R"(revisions topology=10 policy=4 control=7 evidence=9
feed F1 source=utility role=primary domain=D1
load L1 class=critical
link F1 L1 role=primary domain=D1
obs feed F1 condition=energized at=1735689600 max_age=300s source=S1
obs link F1 L1 present=yes at=1735689600 max_age=300s source=S1
rule R1 effect=permit precedence=ordinary_policy feed=F1 load=L1 path=AUTH-PRIMARY
)";

struct CrashCase {
  const char* stage;
  bool adoption_commits;
};

/// Kills an independent process at `stage` while it adopts a scenario, then proves
/// what the store looks like afterwards.
void run_crash_case(const CrashCase& test_case, const char* name) {
  const std::filesystem::path root = fa_test::fresh_store(name);
  const std::filesystem::path scenario = root / "scenario.fa";
  FA_REQUIRE(fa_test::write_file(scenario, kScenario));

  // A committed baseline generation exists before the crash.
  StoreSequence baseline;
  {
    OpenOptions options;
    options.root = root;
    options.create_if_missing = true;
    options.opened_at = fa_test::at(1735689600);
    Result<FeedAuthority> authority = FeedAuthority::Open(options);
    FA_REQUIRE_OK(authority);
    baseline = authority.value().recovery().sequence;
    // A writer session that opens and closes cleanly leaves no residue.
    Result<FeedAuthority> writer = fa_test::open_store(root, false);
    FA_REQUIRE_OK(writer);
    baseline = writer.value().recovery().sequence;
  }

  const std::filesystem::path result = root / "result.txt";
  int exit_code = 0;
  std::string error;
  // The session-opening publication is allowed through, so the crash lands on the
  // adoption publication that follows it.
  FA_REQUIRE(fa_test::run_captured(
      fa_test::probe_path(),
      {"crash", root.string(), scenario.string(), test_case.stage, result.string(), "1"},
      root / "crash-output.txt", exit_code, error));

  // The probe terminates itself at the stage, so it must not report a normal
  // completion. A surviving probe means the injection did not happen.
  FA_CHECK_MSG(exit_code != 0, std::string("stage ") + test_case.stage + " did not terminate the process");
  const std::vector<std::string> survived = fa_test::read_lines(result);
  if (!survived.empty() && survived.front().rfind("survived", 0) == 0) {
    FA_CHECK_MSG(false, std::string("the process survived stage ") + test_case.stage);
    return;
  }

  // Reopening must adopt exactly one whole verified state.
  {
    Result<FeedAuthority> authority = fa_test::open_store(root, false);
    FA_REQUIRE_OK(authority);
    FA_REQUIRE_OK(authority.value().Verify());
    const Result<StoreAuditReport> audit = authority.value().AuditStore();
    FA_REQUIRE_OK(audit);
    FA_CHECK_MSG(audit.value().ok(), std::string("stage ") + test_case.stage);
    if (!test_case.adoption_commits) {
      // Before the head commit the adoption is part of no state at all: the store is
      // still exactly the generation the baseline session committed.
      FA_CHECK_EQ(authority.value().inputs().topology.revision.value(), 0u);
      FA_CHECK(authority.value().recovery().sequence >= baseline);
    } else {
      // After the head commit the adoption is the whole state.
      FA_CHECK_EQ(authority.value().inputs().topology.revision.value(), 10u);
      FA_CHECK(authority.value().recovery().sequence > baseline);
    }
  }

  // The store keeps working: a fresh writer session adopts and verifies.
  {
    Result<FeedAuthority> authority = fa_test::open_store(root, false);
    FA_REQUIRE_OK(authority);
    const Result<AuthorityInputs> inputs =
        load_scenario_file(scenario, authority.value().limits());
    FA_REQUIRE_OK(inputs);
    FA_REQUIRE_OK(fa_test::adopt(authority.value(), inputs.value(), "post-crash-adopt",
                                 fa_test::at(1735689700)));
    FA_REQUIRE_OK(authority.value().Verify());
    const Result<StoreAuditReport> audit = authority.value().AuditStore();
    FA_REQUIRE_OK(audit);
    FA_CHECK(audit.value().ok());
  }
}

}  // namespace

FA_TEST(crash_recovery, after_staging_write) {
  run_crash_case(CrashCase{"after_staging_write", false}, "crash-staging-write");
}

FA_TEST(crash_recovery, after_staging_readback) {
  run_crash_case(CrashCase{"after_staging_readback", false}, "crash-staging-readback");
}

FA_TEST(crash_recovery, after_generation_publish) {
  run_crash_case(CrashCase{"after_generation_publish", false}, "crash-generation-publish");
}

FA_TEST(crash_recovery, after_head_staging_write) {
  run_crash_case(CrashCase{"after_head_staging_write", false}, "crash-head-staging");
}

FA_TEST(crash_recovery, after_head_commit) {
  run_crash_case(CrashCase{"after_head_commit", true}, "crash-head-commit");
}

FA_TEST(crash_recovery, a_crash_during_the_first_publication_is_not_adopted) {
  const std::filesystem::path root = fa_test::fresh_store("crash-first-publication");
  const std::filesystem::path scenario = root / "scenario.fa";
  FA_REQUIRE(fa_test::write_file(scenario, kScenario));
  // The crash happens while the store is being created, so the head may not exist
  // yet. Either outcome is acceptable, but the store must never be a mixture: it
  // either opens whole or refuses with a specific status.
  int exit_code = 0;
  std::string error;
  FA_REQUIRE(fa_test::run_captured(
      fa_test::probe_path(),
      {"crash", root.string(), scenario.string(), "after_generation_publish",
       (root / "result.txt").string()},
      root / "crash-output.txt", exit_code, error));
  FA_CHECK(exit_code != 0);
  Result<FeedAuthority> authority = fa_test::open_store(root, true);
  if (authority.ok()) {
    FA_REQUIRE_OK(authority.value().Verify());
    const Result<StoreAuditReport> audit = authority.value().AuditStore();
    FA_REQUIRE_OK(audit);
    FA_CHECK(audit.value().ok());
  } else {
    FA_CHECK(authority.status().code() == StatusCode::Corruption ||
             authority.status().code() == StatusCode::NotFound);
  }
}
