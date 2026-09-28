// Proof obligations for cross-process writer authority: real operating-system
// processes, real exclusion, real release on process death, real fencing of a stale
// writer, and a still-valid store after abrupt termination.

#include <algorithm>
#include <chrono>
#include <fstream>
#include <thread>
#include <vector>

#include "feed_authority/scenario.hpp"
#include "support/fixtures.hpp"
#include "support/proc.hpp"
#include "support/test_harness.hpp"

#include "detail/file_lock.hpp"
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

void write_scenario(const std::filesystem::path& path) {
  std::ofstream stream(path, std::ios::binary | std::ios::trunc);
  stream << kScenario;
}

std::filesystem::path lock_path(const std::filesystem::path& root) {
  return root / std::string(kLockFileName);
}

}  // namespace

FA_TEST(process_authority, another_process_can_observe_that_the_lock_is_held) {
  const std::filesystem::path root = fa_test::fresh_store("process-lock-state");
  {
    Result<FeedAuthority> authority = fa_test::open_store(root, true);
    FA_REQUIRE_OK(authority);
  }
  const std::filesystem::path output = root / "lock-state.txt";
  int exit_code = 0;
  std::string error;
  FA_REQUIRE(fa_test::run_captured(fa_test::probe_path(),
                                   {"lock-state", root.string(), output.string()}, output, exit_code,
                                   error));
  FA_CHECK_EQ(exit_code, 0);
  const std::vector<std::string> lines = fa_test::read_lines(output);
  FA_REQUIRE(!lines.empty());
  FA_CHECK_EQ(lines.front(), std::string("free"));
}

FA_TEST(process_authority, a_second_process_is_locked_out_while_the_first_holds_authority) {
  const std::filesystem::path root = fa_test::fresh_store("process-exclusion");
  const std::filesystem::path scenario = root / "scenario.fa";
  write_scenario(scenario);
  {
    OpenOptions options;
    options.root = root;
    options.create_if_missing = true;
    options.opened_at = fa_test::at(1735689600);
    Result<FeedAuthority> authority = FeedAuthority::Open(options);
    FA_REQUIRE_OK(authority);
  }
  const std::filesystem::path ready = root / "ready.txt";
  const std::filesystem::path release = root / "release.txt";
  std::uint64_t pid = 0;
  std::string error;
  const std::filesystem::path holder_output = root / "holder.txt";
  FA_REQUIRE(fa_test::spawn_nowait(fa_test::probe_path(),
                                   {"hold-lock", root.string(), ready.string(), release.string()},
                                   holder_output, pid, error));
  FA_REQUIRE(fa_test::wait_for_file(ready, 400, error));

  // While the holder has the lock, a writer in this process must refuse rather than
  // merge or block forever.
  {
    OpenOptions options;
    options.root = root;
    options.opened_at = fa_test::at(1735689600);
    options.limits.lock_acquire_budget_nanos = 200ll * 1000ll * 1000ll;
    Result<FeedAuthority> authority = FeedAuthority::Open(options);
    FA_REQUIRE_ERR(authority, StatusCode::LockConflict);
  }

  // A process in the middle of a mutation is also excluded.
  {
    const std::filesystem::path lock = lock_path(root);
    Result<bool> held = detail::FileLock::is_held_by_any_process(lock);
    FA_REQUIRE_OK(held);
    FA_CHECK(held.value());
  }

  FA_REQUIRE(fa_test::write_file(release, "release"));
  int exit_code = 0;
  FA_REQUIRE(fa_test::spawn_wait(fa_test::probe_path(),
                                 {"hold-lock", root.string(),
                                  (root / "ready2.txt").string(), release.string()},
                                 root / "holder2.txt", exit_code, error));
  FA_CHECK_EQ(exit_code, 0);
  std::string terminate_error;
  fa_test::terminate_process(pid, terminate_error);
}

FA_TEST(process_authority, process_death_releases_authority_and_leaves_a_valid_store) {
  const std::filesystem::path root = fa_test::fresh_store("process-death");
  const std::filesystem::path scenario = root / "scenario.fa";
  write_scenario(scenario);
  {
    OpenOptions options;
    options.root = root;
    options.create_if_missing = true;
    options.opened_at = fa_test::at(1735689600);
    Result<FeedAuthority> authority = FeedAuthority::Open(options);
    FA_REQUIRE_OK(authority);
  }
  const std::filesystem::path ready = root / "ready.txt";
  const std::filesystem::path release = root / "release.txt";
  std::uint64_t pid = 0;
  std::string error;
  FA_REQUIRE(fa_test::spawn_nowait(fa_test::probe_path(),
                                   {"hold-lock", root.string(), ready.string(), release.string()},
                                   root / "holder.txt", pid, error));
  FA_REQUIRE(fa_test::wait_for_file(ready, 400, error));
  FA_CHECK(fa_test::terminate_process(pid, error));
  FA_CHECK(!fa_test::process_is_running(pid));

  // The operating system released the lock with the process: a new writer session
  // can take authority immediately and the store is still whole.
  Result<FeedAuthority> authority = fa_test::open_store(root, false);
  FA_REQUIRE_OK(authority);
  FA_REQUIRE_OK(authority.value().Verify());
  const Result<StoreAuditReport> audit = authority.value().AuditStore();
  FA_REQUIRE_OK(audit);
  FA_CHECK(audit.value().ok());
}

FA_TEST(process_authority, a_stale_writer_is_fenced_after_another_process_publishes) {
  const std::filesystem::path root = fa_test::fresh_store("process-fencing");
  const std::filesystem::path scenario = root / "scenario.fa";
  write_scenario(scenario);
  // The session that will be fenced adopts the first generation and keeps it.
  Result<FeedAuthority> stale = fa_test::open_store(root, true);
  FA_REQUIRE_OK(stale);
  FA_REQUIRE_OK(fa_test::adopt(stale.value(), fa_test::inputs(kScenario), "seed-adopt",
                               fa_test::at(1735689600)));
  const AuthorityBinding stale_binding = stale.value().current_binding();
  // The decision this session plans against is taken before the other process moves
  // the store on: a request is planned against one state and states that binding.
  const Result<DecisionSet> decision =
      fa_test::evaluate(stale.value(), "L1", fa_test::at(1735689600));
  FA_REQUIRE_OK(decision);

  // The other process publishes a genuinely newer generation.
  const std::filesystem::path newer = root / "newer.fa";
  FA_REQUIRE(fa_test::write_file(newer, R"(revisions topology=11 policy=5 control=8 evidence=10
feed F1 source=utility role=primary domain=D1
load L1 class=critical
link F1 L1 role=primary domain=D1
obs feed F1 condition=energized at=1735689600 max_age=300s source=S1
obs link F1 L1 present=yes at=1735689600 max_age=300s source=S1
rule R1 effect=permit precedence=ordinary_policy feed=F1 load=L1 path=AUTH-PRIMARY
)"));

  // A second process publishes a new input generation.
  int exit_code = 0;
  std::string error;
  const std::filesystem::path result = root / "mutate.txt";
  FA_REQUIRE(fa_test::run_captured(fa_test::probe_path(),
                                   {"mutate", root.string(), newer.string(), "probe-attempt-1",
                                    result.string()},
                                   root / "mutate-output.txt", exit_code, error));
  FA_CHECK_EQ(exit_code, 0);
  const std::map<std::string, std::string> values = fa_test::read_key_values(result);
  FA_REQUIRE(values.count("sequence") != 0);
  FA_CHECK_EQ(values.at("ok"), std::string("true"));

  // The first handle still believes it holds the older state. Its mutation must be
  // refused rather than merged.
  GrantRequest request;
  request.load = fa_test::load("L1");
  request.feed = fa_test::feed("F1");
  request.decision = decision.value().generation;
  request.decision_fingerprint = decision.value().fingerprint;
  request.validity = fa_test::secs(300);
  request.now = fa_test::at(1735689600);
  request.attempt = fa_test::attempt("stale-grant");
  request.precondition = AuthorityPrecondition{stale_binding};
  FA_REQUIRE_ERR(stale.value().IssueGrant(request), StatusCode::StaleAuthority);

  // Reloading adopts the newer head. The inputs the session had adopted are no
  // longer the current generation, so the session must adopt them again before it
  // can issue anything: recovery never makes an input generation current by itself.
  FA_REQUIRE_OK(stale.value().Reload());
  FA_CHECK(stale.value().epoch() > stale_binding.epoch);
  FA_CHECK(!stale.value().session_inputs_adopted());
  FA_REQUIRE_OK(fa_test::adopt(stale.value(), stale.value().inputs(), "after-reload-adopt",
                               fa_test::at(1735689700)));
  const Result<DecisionSet> reloaded =
      fa_test::evaluate(stale.value(), "L1", fa_test::at(1735689700));
  FA_REQUIRE_OK(reloaded);
  GrantRequest after_reload;
  after_reload.load = fa_test::load("L1");
  after_reload.feed = fa_test::feed("F1");
  after_reload.decision = reloaded.value().generation;
  after_reload.decision_fingerprint = reloaded.value().fingerprint;
  after_reload.validity = fa_test::secs(300);
  after_reload.now = fa_test::at(1735689700);
  after_reload.attempt = fa_test::attempt("after-reload");
  after_reload.precondition = AuthorityPrecondition{stale.value().current_binding()};
  FA_REQUIRE_OK(stale.value().IssueGrant(after_reload));
  FA_REQUIRE_OK(stale.value().Verify());
}

FA_TEST(process_authority, concurrent_mutations_leave_one_whole_state) {
  const std::filesystem::path root = fa_test::fresh_store("process-race");
  constexpr int kRacers = 4;
  std::vector<std::filesystem::path> scenarios;
  std::vector<std::filesystem::path> results;
  for (int index = 0; index < kRacers; ++index) {
    const std::filesystem::path scenario = root / ("racer-" + std::to_string(index) + ".fa");
    const std::string text = "revisions topology=" + std::to_string(10 + index) +
                             " policy=" + std::to_string(4 + index) +
                             " control=" + std::to_string(7 + index) +
                             " evidence=" + std::to_string(9 + index) + "\n" +
                             "feed F1 source=utility role=primary domain=D1\n" +
                             "load L1 class=critical\n" +
                             "link F1 L1 role=primary domain=D1\n" +
                             "obs feed F1 condition=energized at=1735689600 max_age=300s source=S1\n" +
                             "obs link F1 L1 present=yes at=1735689600 max_age=300s source=S1\n" +
                             "rule R1 effect=permit precedence=ordinary_policy feed=F1 load=L1 path=AUTH-PRIMARY\n";
    FA_REQUIRE(fa_test::write_file(scenario, text));
    scenarios.push_back(scenario);
    results.push_back(root / ("racer-" + std::to_string(index) + ".txt"));
  }
  {
    OpenOptions options;
    options.root = root;
    options.create_if_missing = true;
    options.opened_at = fa_test::at(1735689600);
    FA_REQUIRE_OK(FeedAuthority::Open(options));
  }

  std::vector<std::uint64_t> pids;
  std::string error;
  for (int index = 0; index < kRacers; ++index) {
    std::uint64_t pid = 0;
    FA_REQUIRE(fa_test::spawn_nowait(
        fa_test::probe_path(),
        {"mutate", root.string(), scenarios[static_cast<std::size_t>(index)].string(),
         "racer-" + std::to_string(index), results[static_cast<std::size_t>(index)].string()},
        root / ("racer-" + std::to_string(index) + ".log"), pid, error));
    pids.push_back(pid);
  }
  for (const std::uint64_t pid : pids) {
    while (fa_test::process_is_running(pid)) {
      std::this_thread::sleep_for(std::chrono::milliseconds(2));
    }
  }

  // Whatever the interleaving was, the store must be one whole verified state, and
  // every racer must have either committed a distinct sequence or been refused.
  Result<FeedAuthority> authority = fa_test::open_store(root, false);
  FA_REQUIRE_OK(authority);
  FA_REQUIRE_OK(authority.value().Verify());
  const Result<StoreAuditReport> audit = authority.value().AuditStore();
  FA_REQUIRE_OK(audit);
  FA_CHECK(audit.value().ok());

  std::vector<std::uint64_t> sequences;
  std::size_t committed = 0;
  for (const std::filesystem::path& result : results) {
    const std::map<std::string, std::string> values = fa_test::read_key_values(result);
    if (values.count("ok") == 0) {
      continue;
    }
    if (values.at("ok") == "true") {
      ++committed;
      sequences.push_back(std::stoull(values.at("sequence")));
    } else {
      FA_CHECK(values.at("error").find("stale_authority") != std::string::npos ||
               values.at("error").find("lock_conflict") != std::string::npos ||
               values.at("error").find("stale_source_generation") != std::string::npos);
    }
  }
  FA_CHECK(committed >= 1u);
  FA_CHECK(committed <= static_cast<std::size_t>(kRacers));
  std::sort(sequences.begin(), sequences.end());
  for (std::size_t index = 1; index < sequences.size(); ++index) {
    FA_CHECK(sequences[index - 1] < sequences[index]);
  }
}

FA_TEST(process_authority, an_epoch_advances_once_per_writer_session) {
  const std::filesystem::path root = fa_test::fresh_store("process-epoch");
  AuthorityEpoch first{};
  AuthorityEpoch second{};
  {
    Result<FeedAuthority> authority = fa_test::open_store(root, true);
    FA_REQUIRE_OK(authority);
    first = authority.value().epoch();
    FA_CHECK_EQ(authority.value().incarnation().epoch().value(), first.value());
  }
  {
    Result<FeedAuthority> authority = fa_test::open_store(root, false);
    FA_REQUIRE_OK(authority);
    second = authority.value().epoch();
  }
  FA_CHECK(second > first);

  // A read-only session observes the epoch without advancing it.
  {
    Result<FeedAuthority> authority = fa_test::open_store_read_only(root);
    FA_REQUIRE_OK(authority);
    FA_CHECK_EQ(authority.value().epoch().value(), second.value());
  }
  {
    Result<FeedAuthority> authority = fa_test::open_store_read_only(root);
    FA_REQUIRE_OK(authority);
    FA_CHECK_EQ(authority.value().epoch().value(), second.value());
  }
}

FA_TEST(process_authority, two_processes_can_mutate_in_sequence) {
  const std::filesystem::path root = fa_test::fresh_store("process-sequence");
  const std::filesystem::path first_scenario = root / "first.fa";
  write_scenario(first_scenario);
  const char* second_text = R"(revisions topology=11 policy=5 control=8 evidence=10
feed F1 source=utility role=primary domain=D1
load L1 class=critical
link F1 L1 role=primary domain=D1
obs feed F1 condition=energized at=1735689600 max_age=300s source=S1
obs link F1 L1 present=yes at=1735689600 max_age=300s source=S1
rule R1 effect=permit precedence=ordinary_policy feed=F1 load=L1 path=AUTH-PRIMARY
)";
  const std::filesystem::path second_scenario = root / "second.fa";
  FA_REQUIRE(fa_test::write_file(second_scenario, second_text));

  int exit_code = 0;
  std::string error;
  FA_REQUIRE(fa_test::run_captured(
      fa_test::probe_path(),
      {"mutate", root.string(), first_scenario.string(), "attempt-a", (root / "a.txt").string()},
      root / "a-output.txt", exit_code, error));
  FA_CHECK_EQ(exit_code, 0);
  FA_REQUIRE(fa_test::run_captured(
      fa_test::probe_path(),
      {"mutate", root.string(), second_scenario.string(), "attempt-b", (root / "b.txt").string()},
      root / "b-output.txt", exit_code, error));
  FA_CHECK_EQ(exit_code, 0);
  const std::map<std::string, std::string> first = fa_test::read_key_values(root / "a.txt");
  const std::map<std::string, std::string> second = fa_test::read_key_values(root / "b.txt");
  FA_REQUIRE(first.count("sequence") != 0);
  FA_REQUIRE(second.count("sequence") != 0);
  FA_CHECK_EQ(first.at("ok"), std::string("true"));
  FA_CHECK_EQ(second.at("ok"), std::string("true"));
  FA_CHECK(std::stoull(second.at("sequence")) > std::stoull(first.at("sequence")));
  FA_CHECK(std::stoull(second.at("epoch")) > std::stoull(first.at("epoch")));

  Result<FeedAuthority> authority = fa_test::open_store_read_only(root);
  FA_REQUIRE_OK(authority);
  FA_REQUIRE_OK(authority.value().Verify());
  FA_CHECK_EQ(authority.value().inputs().topology.revision.value(), 11u);
}
