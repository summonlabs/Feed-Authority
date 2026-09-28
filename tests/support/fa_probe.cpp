// fa_probe: an independent process used by the multiprocess, fencing and crash
// recovery tests.
//
// It performs real work through the library in a real operating system process and
// writes a machine-readable result file. The crash subcommand terminates the process
// at a chosen durable stage with TerminateProcess (or _exit on POSIX): a
// non-interactive termination that cannot raise a dialog and cannot run CRT abort
// handling.

#include <cstdint>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <string>
#include <thread>
#include <vector>

#include "detail/file_lock.hpp"
#include "feed_authority/authority.hpp"
#include "feed_authority/scenario.hpp"

#if defined(_WIN32)
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#else
#include <unistd.h>
#endif

namespace {

using namespace feed_authority;

std::string read_file(const std::string& path) {
  std::ifstream stream(path, std::ios::binary);
  std::string content((std::istreambuf_iterator<char>(stream)), std::istreambuf_iterator<char>());
  return content;
}

void write_result(const std::string& path, const std::string& content) {
  std::ofstream stream(path, std::ios::binary | std::ios::trunc);
  stream << content;
}

void terminate_self_now() {
#if defined(_WIN32)
  TerminateProcess(GetCurrentProcess(), 3);
#else
  _exit(3);
#endif
}

Result<AuthorityInputs> scenario_inputs(const std::string& path, const Limits& limits) {
  const std::string text = read_file(path);
  if (text.empty()) {
    return Status::error(StatusCode::IoFailure, "the scenario file is empty or unreadable");
  }
  return parse_scenario(text, limits, "probe-scenario");
}

int fail(const std::string& message) {
  std::cout << "error " << message << "\n";
  return 2;
}

}  // namespace

int main(int argc, char** argv) {
  std::vector<std::string> arguments;
  for (int index = 1; index < argc; ++index) {
    arguments.emplace_back(argv[index]);
  }
  if (arguments.size() < 2) {
    return fail("usage");
  }
  const std::string& command = arguments[0];

  if (command == "hold-lock") {
    if (arguments.size() < 4) return fail("hold-lock needs a store, a ready file and a release file");
    OpenOptions options;
    options.root = arguments[1];
    options.create_if_missing = true;
    options.opened_at = AuthorityTime::FromUnixSeconds(1735689600).value();
    Result<FeedAuthority> authority = FeedAuthority::Open(options);
    if (!authority.ok()) {
      return fail(authority.status().to_string());
    }
    const std::string ready = arguments[2];
    const std::string release = arguments[3];
    {
      std::ofstream stream(ready, std::ios::binary | std::ios::trunc);
#if defined(_WIN32)
      stream << "pid=" << GetCurrentProcessId() << "\n";
#else
      stream << "pid=" << static_cast<unsigned long>(::getpid()) << "\n";
#endif
      stream << "sequence=" << authority.value().recovery().sequence.str() << "\n";
    }
    // Hold the writer lock through a direct acquisition, which is what a mutation
    // does, then release it when the harness asks.
    const std::filesystem::path lock_path =
        std::filesystem::path(arguments[1]) / std::string(kLockFileName);
    Result<detail::FileLock> lock =
        detail::FileLock::acquire(lock_path, 30ll * 1000ll * 1000ll * 1000ll);
    if (!lock.ok()) {
      return fail(lock.status().to_string());
    }
    for (int attempt = 0; attempt < 20000; ++attempt) {
      std::ifstream check(release, std::ios::binary);
      if (check.good()) {
        break;
      }
      std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
    const Status released = lock.value().release();
    if (!released.ok()) {
      return fail(released.to_string());
    }
    std::cout << "released\n";
    return 0;
  }

  if (command == "lock-state") {
    if (arguments.size() < 3) return fail("lock-state needs a store and an output file");
    const std::filesystem::path lock_path =
        std::filesystem::path(arguments[1]) / std::string(kLockFileName);
    const Result<bool> held = detail::FileLock::is_held_by_any_process(lock_path);
    if (!held.ok()) {
      return fail(held.status().to_string());
    }
    write_result(arguments[2], held.value() ? "held\n" : "free\n");
    return 0;
  }

  if (command == "mutate") {
    if (arguments.size() < 5) return fail("mutate needs a store, a scenario, an attempt and an output file");
    OpenOptions options;
    options.root = arguments[1];
    options.create_if_missing = true;
    options.opened_at = AuthorityTime::FromUnixSeconds(1735689600).value();
    Result<FeedAuthority> authority = FeedAuthority::Open(options);
    if (!authority.ok()) {
      write_result(arguments[4], "error " + authority.status().to_string() + "\n");
      return 1;
    }
    const Result<AuthorityInputs> inputs = scenario_inputs(arguments[2], authority.value().limits());
    if (!inputs.ok()) {
      write_result(arguments[4], "error " + inputs.status().to_string() + "\n");
      return 1;
    }
    AdoptInputsRequest request;
    request.inputs = inputs.value();
    request.now = AuthorityTime::FromUnixSeconds(1735689600).value();
    request.attempt = AttemptId::Parse(arguments[3]).value();
    const Status adopted = authority.value().AdoptInputs(request);
    std::string text = std::string("ok=") + (adopted.ok() ? "true" : "false") + "\n";
    text += "sequence=" + authority.value().recovery().sequence.str() + "\n";
    text += "epoch=" + authority.value().epoch().str() + "\n";
    if (!adopted.ok()) {
      text += "error=" + adopted.to_string() + "\n";
    }
    write_result(arguments[4], text);
    return adopted.ok() ? 0 : 1;
  }

  if (command == "grant") {
    if (arguments.size() < 7) return fail("grant needs a store, scenario, load, feed, validity, attempt, output");
    OpenOptions options;
    options.root = arguments[1];
    options.create_if_missing = true;
    options.opened_at = AuthorityTime::FromUnixSeconds(1735689600).value();
    Result<FeedAuthority> authority = FeedAuthority::Open(options);
    if (!authority.ok()) {
      write_result(arguments[6], "error " + authority.status().to_string() + "\n");
      return 1;
    }
    const Result<AuthorityInputs> inputs = scenario_inputs(arguments[2], authority.value().limits());
    if (!inputs.ok()) {
      write_result(arguments[6], "error " + inputs.status().to_string() + "\n");
      return 1;
    }
    AdoptInputsRequest adopt;
    adopt.inputs = inputs.value();
    adopt.now = AuthorityTime::FromUnixSeconds(1735689600).value();
    adopt.attempt = AttemptId::Parse(std::string("probe-adopt-") + arguments[5]).value();
    const Status adopted = authority.value().AdoptInputs(adopt);
    if (!adopted.ok()) {
      write_result(arguments[6], "error " + adopted.to_string() + "\n");
      return 1;
    }
    EvaluationRequest evaluation;
    evaluation.load = LoadId::Parse(arguments[3]).value();
    evaluation.now = AuthorityTime::FromUnixSeconds(1735689600).value();
    const Result<DecisionSet> decision = authority.value().Evaluate(evaluation);
    if (!decision.ok()) {
      write_result(arguments[6], "error " + decision.status().to_string() + "\n");
      return 1;
    }
    GrantRequest request;
    request.load = evaluation.load;
    request.feed = FeedId::Parse(arguments[4]).value();
    request.decision = decision.value().generation;
    request.decision_fingerprint = decision.value().fingerprint;
    request.validity = Duration::FromSeconds(std::stoll(arguments[5])).value();
    request.now = evaluation.now;
    request.attempt = AttemptId::Parse(arguments[5]).value();
    request.precondition.expected = authority.value().current_binding();
    const Result<Grant> grant = authority.value().IssueGrant(request);
    if (!grant.ok()) {
      write_result(arguments[6], "error " + grant.status().to_string() + "\n");
      return 1;
    }
    write_result(arguments[6], "ok=true\ngrant=" + grant.value().id.str() +
                                   "\nsequence=" + authority.value().recovery().sequence.str() + "\n");
    return 0;
  }

  if (command == "check-grant") {
    if (arguments.size() < 6) return fail("check-grant needs a store, scenario, grant id, now, output");
    OpenOptions options;
    options.root = arguments[1];
    options.opened_at = AuthorityTime::FromUnixSeconds(1735689600).value();
    Result<FeedAuthority> authority = FeedAuthority::Open(options);
    if (!authority.ok()) {
      write_result(arguments[4], "error " + authority.status().to_string() + "\n");
      return 1;
    }
    const Result<AuthorityInputs> inputs = scenario_inputs(arguments[2], authority.value().limits());
    if (inputs.ok()) {
      AdoptInputsRequest adopt;
      adopt.inputs = inputs.value();
      adopt.now = AuthorityTime::FromUnixSeconds(1735689600).value();
      adopt.attempt = AttemptId::Parse("probe-check-adopt").value();
      const Status adopted = authority.value().AdoptInputs(adopt);
      if (!adopted.ok() && adopted.code() != StatusCode::Conflict &&
          adopted.code() != StatusCode::StaleSourceGeneration) {
        write_result(arguments[4], "error " + adopted.to_string() + "\n");
        return 1;
      }
    }
    CheckGrantRequest check;
    check.grant = GrantId::FromValue(std::stoull(arguments[3]));
    check.now = AuthorityTime::FromUnixSeconds(std::stoll(arguments[4])).value();
    const Result<GrantAuthorization> authorization = authority.value().Authorize(check);
    if (!authorization.ok()) {
      write_result(arguments[4], "error " + authorization.status().to_string() + "\n");
      return 1;
    }
    write_result(arguments[4], std::string("authorized=") +
                                   (authorization.value().authorized ? "true" : "false") +
                                   " usability=" + to_string(authorization.value().usability) + "\n");
    return authorization.value().authorized ? 0 : 1;
  }

  if (command == "crash") {
    if (arguments.size() < 5) return fail("crash needs a store, a scenario, a stage and an output file");
    // The optional fifth argument is how many publications to let through before the
    // fault is live, so a harness can aim the crash at the mutation under test rather
    // than at the session-opening publication.
    std::uint32_t skip_publications = 0;
    if (arguments.size() >= 6) {
      skip_publications = static_cast<std::uint32_t>(std::stoul(arguments[5]));
    }
    const std::string stage = arguments[3];
    FaultPoint point = FaultPoint::None;
    if (stage == "after_staging_write") point = FaultPoint::AfterStagingWrite;
    else if (stage == "after_staging_readback") point = FaultPoint::AfterStagingReadback;
    else if (stage == "after_generation_publish") point = FaultPoint::AfterGenerationPublish;
    else if (stage == "after_head_staging_write") point = FaultPoint::AfterHeadStagingWrite;
    else if (stage == "after_head_commit") point = FaultPoint::AfterHeadCommit;
    else return fail("unknown crash stage");

    OpenOptions options;
    options.root = arguments[1];
    options.create_if_missing = true;
    options.opened_at = AuthorityTime::FromUnixSeconds(1735689600).value();
    options.fault_point = point;
    options.fault_skip_publications = skip_publications;
    options.on_fault = [](FaultPoint) { terminate_self_now(); };
    Result<FeedAuthority> authority = FeedAuthority::Open(options);
    if (!authority.ok()) {
      write_result(arguments[4], "error " + authority.status().to_string() + "\n");
      return 1;
    }
    const Result<AuthorityInputs> inputs = scenario_inputs(arguments[2], authority.value().limits());
    if (!inputs.ok()) {
      write_result(arguments[4], "error " + inputs.status().to_string() + "\n");
      return 1;
    }
    AdoptInputsRequest request;
    request.inputs = inputs.value();
    request.now = AuthorityTime::FromUnixSeconds(1735689600).value();
    request.attempt = AttemptId::Parse("probe-crash-adopt").value();
    const Status adopted = authority.value().AdoptInputs(request);
    write_result(arguments[4], std::string("survived ") + adopted.to_string() + "\n");
    return 0;
  }

  if (command == "evaluate") {
    if (arguments.size() < 6) return fail("evaluate needs a store, scenario, load, now and output file");
    OpenOptions options;
    options.root = arguments[1];
    options.create_if_missing = true;
    options.opened_at = AuthorityTime::FromUnixSeconds(1735689600).value();
    Result<FeedAuthority> authority = FeedAuthority::Open(options);
    if (!authority.ok()) {
      write_result(arguments[5], "error " + authority.status().to_string() + "\n");
      return 1;
    }
    const Result<AuthorityInputs> inputs = scenario_inputs(arguments[2], authority.value().limits());
    if (!inputs.ok()) {
      write_result(arguments[5], "error " + inputs.status().to_string() + "\n");
      return 1;
    }
    AdoptInputsRequest adopt;
    adopt.inputs = inputs.value();
    adopt.now = AuthorityTime::FromUnixSeconds(1735689600).value();
    adopt.attempt = AttemptId::Parse("probe-evaluate-adopt").value();
    const Status adopted = authority.value().AdoptInputs(adopt);
    if (!adopted.ok()) {
      write_result(arguments[5], "error " + adopted.to_string() + "\n");
      return 1;
    }
    EvaluationRequest request;
    request.load = LoadId::Parse(arguments[3]).value();
    request.now = AuthorityTime::FromUnixSeconds(std::stoll(arguments[4])).value();
    const Result<DecisionSet> decision = authority.value().Evaluate(request);
    if (!decision.ok()) {
      write_result(arguments[5], "error " + decision.status().to_string() + "\n");
      return 1;
    }
    std::string text = "eligible=";
    for (std::size_t index = 0; index < decision.value().eligible.size(); ++index) {
      if (index != 0) text += ",";
      text += decision.value().eligible[index].value();
    }
    text += " fingerprint=" + decision.value().fingerprint.hex();
    text += "\n";
    write_result(arguments[5], text);
    return 0;
  }

  return fail("unknown command");
}
