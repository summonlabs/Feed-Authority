// Benchmark: completed operations only.
//
// Every measured operation runs the whole path that makes it complete:
//   * evaluation: request validation, evidence resolution, the precedence ladder,
//     decision fingerprinting over the canonical encoding;
//   * grant issuance: replay lookup, precondition check, re-evaluation, the decision
//     binding check, staging write, flush, read-back verification, atomic publish of
//     the generation, head-marker commit, residue retirement, and the audit event;
//   * grant authorization: precondition evaluation plus the fresh evidence
//     re-evaluation of the bound pair.
//
// Nothing is timed at submission: there is no queue in this runtime.
//
// Evidence labelling: the workload is SYNTHETIC (a generated facility in a scratch
// store on local storage, no electrical equipment involved). The timings themselves
// are REAL measurements of this process on this host. No hardware is exercised.

#include <chrono>
#include <cstdint>
#include <cstdio>
#include <filesystem>
#include <string>
#include <vector>

#include "feed_authority/authority.hpp"
#include "feed_authority/scenario.hpp"
#include "feed_authority/version.hpp"

namespace {

using namespace feed_authority;

constexpr std::int64_t kBaseInstant = 1735689600;

AuthorityTime at(std::int64_t seconds) { return AuthorityTime::FromUnixSeconds(seconds).value(); }

/// A facility with 32 feeds and 8 protected loads, all linked to every feed.
std::string facility_scenario() {
  std::string text = "revisions topology=10 policy=4 control=7 evidence=9\noption ranking=on roles=primary,secondary,standby\n";
  for (int index = 0; index < 32; ++index) {
    const std::string id = "F" + std::to_string(index);
    const std::string role = index % 4 == 0 ? "primary" : (index % 4 == 1 ? "secondary" : (index % 4 == 2 ? "standby" : "spare"));
    // Failure domains are deliberately independent of redundancy roles, so the
    // eligible set really does span several domains.
    text += "feed " + id + " source=utility role=" + role + " domain=D" + std::to_string(index % 8) +
            " protected=yes\n";
    text += "obs feed " + id + " condition=energized at=" + std::to_string(kBaseInstant) +
            " max_age=3600s source=S1\n";
  }
  for (int load = 0; load < 8; ++load) {
    const std::string load_id = "L" + std::to_string(load);
    text += "load " + load_id + " class=critical protected=yes\n";
    for (int index = 0; index < 32; ++index) {
      const std::string id = "F" + std::to_string(index);
      text += "link " + id + " " + load_id + " role=primary domain=D" + std::to_string(index % 8) +
              "\n";
      text += "obs link " + id + " " + load_id + " present=yes at=" + std::to_string(kBaseInstant) +
              " max_age=3600s source=S1\n";
    }
  }
  text += "obs state condition=normal at=" + std::to_string(kBaseInstant) +
          " max_age=3600s source=S1\n";
  for (int index = 0; index < 32; ++index) {
    const std::string id = "F" + std::to_string(index);
    text += "rule R" + std::to_string(index) + " effect=permit precedence=ordinary_policy feed=" + id +
            " load=L0 path=AUTH-" + id + "\n";
    text += "rule S" + std::to_string(index) + " effect=permit precedence=ordinary_policy feed=" + id +
            " load=L7 path=AUTH-" + id + "\n";
  }
  text += "obligation O1 protected_loads=yes min_domains=4 roles=primary,secondary,standby\n";
  return text;
}

struct BenchmarkResult {
  std::string name;
  std::string label;
  std::uint64_t operations = 0;
  double total_millis = 0.0;
  double per_operation_micros = 0.0;
  double operations_per_second = 0.0;
};

void report(const BenchmarkResult& result) {
  std::printf("%-46s %-9s ops=%-8llu total=%9.2f ms  per_op=%9.1f us  ops/s=%10.1f\n",
              result.name.c_str(), result.label.c_str(),
              static_cast<unsigned long long>(result.operations), result.total_millis,
              result.per_operation_micros, result.operations_per_second);
}

}  // namespace

int main() {
  std::printf("feed-authority %s benchmark\n", std::string(version_string()).c_str());
  std::printf("host workload: SYNTHETIC facility (32 feeds, 8 protected loads, 64 rules, 1 obligation)\n");
  std::printf("storage: local filesystem under the working directory; store removed afterwards\n");

  const std::filesystem::path root = std::filesystem::current_path() / "fa-benchmark-store";
  std::error_code error;
  std::filesystem::remove_all(root, error);

  OpenOptions options;
  options.root = root;
  options.create_if_missing = true;
  options.opened_at = at(kBaseInstant);
  options.limits.max_events = 8192;
  Result<FeedAuthority> authority = FeedAuthority::Open(options);
  if (!authority.ok()) {
    std::printf("store error: %s\n", authority.status().to_string().c_str());
    return 1;
  }

  const std::string scenario_text = facility_scenario();
  const Result<AuthorityInputs> inputs =
      parse_scenario(scenario_text, authority.value().limits(), "benchmark");
  if (!inputs.ok()) {
    std::printf("scenario error: %s\n", inputs.status().to_string().c_str());
    return 1;
  }
  std::printf("scenario: %zu feeds, %zu loads, %zu paths, %zu rules\n",
              inputs.value().topology.feeds.size(), inputs.value().topology.loads.size(),
              inputs.value().topology.links.size(), inputs.value().policy.rules.size());

  // Adoption is a completed publication, measured on its own.
  {
    AdoptInputsRequest request;
    request.inputs = inputs.value();
    request.now = at(kBaseInstant);
    request.attempt = AttemptId::Parse("bench-adopt").value();
    const auto start = std::chrono::steady_clock::now();
    const Status adopted = authority.value().AdoptInputs(request);
    const auto elapsed = std::chrono::steady_clock::now() - start;
    if (!adopted.ok()) {
      std::printf("adopt error: %s\n", adopted.to_string().c_str());
      return 1;
    }
    BenchmarkResult result;
    result.name = "adopt_inputs (one publication)";
    result.label = "SYNTHETIC";
    result.operations = 1;
    result.total_millis = std::chrono::duration<double, std::milli>(elapsed).count();
    result.per_operation_micros = result.total_millis * 1000.0;
    result.operations_per_second = 1000.0 / result.total_millis;
    report(result);
  }

  // Evaluation: a pure read of adopted state, one decision per operation.
  {
    constexpr std::uint64_t kOperations = 20000;
    EvaluationRequest request;
    request.load = LoadId::Parse("L0").value();
    request.now = at(kBaseInstant);
    std::uint64_t eligible_total = 0;
    const auto start = std::chrono::steady_clock::now();
    for (std::uint64_t index = 0; index < kOperations; ++index) {
      const Result<DecisionSet> decision = authority.value().Evaluate(request);
      if (!decision.ok()) {
        std::printf("evaluate error: %s\n", decision.status().to_string().c_str());
        return 1;
      }
      eligible_total += decision.value().eligible.size();
    }
    const auto elapsed = std::chrono::steady_clock::now() - start;
    BenchmarkResult result;
    result.name = "evaluate (32 candidates, full ladder)";
    result.label = "SYNTHETIC";
    result.operations = kOperations;
    result.total_millis = std::chrono::duration<double, std::milli>(elapsed).count();
    result.per_operation_micros = result.total_millis * 1000.0 / static_cast<double>(kOperations);
    result.operations_per_second = static_cast<double>(kOperations) * 1000.0 / result.total_millis;
    report(result);
    if (eligible_total == 0) {
      std::printf("no candidate was eligible; the benchmark measured nothing useful\n");
      return 1;
    }
  }

  // Grant issuance: a complete durable publication per operation.
  {
    constexpr std::uint64_t kOperations = 200;
    const auto start = std::chrono::steady_clock::now();
    for (std::uint64_t index = 0; index < kOperations; ++index) {
      EvaluationRequest request;
      request.load = LoadId::Parse("L0").value();
      request.now = at(kBaseInstant);
      const Result<DecisionSet> decision = authority.value().Evaluate(request);
      if (!decision.ok()) {
        std::printf("evaluate error: %s\n", decision.status().to_string().c_str());
        return 1;
      }
      GrantRequest issue;
      issue.load = request.load;
      issue.feed = FeedId::Parse("F0").value();
      issue.decision = decision.value().generation;
      issue.decision_fingerprint = decision.value().fingerprint;
      issue.validity = Duration::FromHours(1).value();
      issue.now = request.now;
      issue.attempt = AttemptId::Parse("bench-grant-" + std::to_string(index)).value();
      issue.precondition.expected = authority.value().current_binding();
      const Result<Grant> grant = authority.value().IssueGrant(issue);
      if (!grant.ok()) {
        std::printf("grant error: %s\n", grant.status().to_string().c_str());
        return 1;
      }
    }
    const auto elapsed = std::chrono::steady_clock::now() - start;
    BenchmarkResult result;
    result.name = "issue_grant (full durable publication)";
    result.label = "SYNTHETIC";
    result.operations = kOperations;
    result.total_millis = std::chrono::duration<double, std::milli>(elapsed).count();
    result.per_operation_micros = result.total_millis * 1000.0 / static_cast<double>(kOperations);
    result.operations_per_second = static_cast<double>(kOperations) * 1000.0 / result.total_millis;
    report(result);
  }

  // Grant authorization: precondition plus evidence re-evaluation.
  {
    constexpr std::uint64_t kOperations = 20000;
    CheckGrantRequest check;
    check.grant = GrantId::FromValue(1);
    check.now = at(kBaseInstant + 60);
    std::uint64_t authorized = 0;
    std::uint64_t refused = 0;
    const auto start = std::chrono::steady_clock::now();
    for (std::uint64_t index = 0; index < kOperations; ++index) {
      const Result<GrantAuthorization> authorization = authority.value().Authorize(check);
      if (!authorization.ok()) {
        std::printf("authorize error: %s\n", authorization.status().to_string().c_str());
        return 1;
      }
      if (authorization.value().authorized) {
        ++authorized;
      } else if (authorized + 1 == index + 1 && refused == 0) {
        ++refused;
        std::printf("first refusal: usability=%s reason=%s detail=%s\n",
                    to_string(authorization.value().usability),
                    to_string(authorization.value().reason),
                    authorization.value().detail.c_str());
      }
    }
    const auto elapsed = std::chrono::steady_clock::now() - start;
    BenchmarkResult result;
    result.name = "authorize (grant usability + evidence)";
    result.label = "SYNTHETIC";
    result.operations = kOperations;
    result.total_millis = std::chrono::duration<double, std::milli>(elapsed).count();
    result.per_operation_micros = result.total_millis * 1000.0 / static_cast<double>(kOperations);
    result.operations_per_second = static_cast<double>(kOperations) * 1000.0 / result.total_millis;
    report(result);
    if (authorized != kOperations) {
      std::printf("the grant was not authorized on every check; the benchmark measured a refusal path\n");
      return 1;
    }
  }

  // Store audit: a full integrity walk of every retained generation.
  {
    constexpr std::uint64_t kOperations = 20;
    const auto start = std::chrono::steady_clock::now();
    for (std::uint64_t index = 0; index < kOperations; ++index) {
      const Result<StoreAuditReport> audit = authority.value().AuditStore();
      if (!audit.ok() || !audit.value().ok()) {
        std::printf("audit error\n");
        return 1;
      }
    }
    const auto elapsed = std::chrono::steady_clock::now() - start;
    BenchmarkResult result;
    result.name = "store_audit (all retained generations)";
    result.label = "SYNTHETIC";
    result.operations = kOperations;
    result.total_millis = std::chrono::duration<double, std::milli>(elapsed).count();
    result.per_operation_micros = result.total_millis * 1000.0 / static_cast<double>(kOperations);
    result.operations_per_second = static_cast<double>(kOperations) * 1000.0 / result.total_millis;
    report(result);
  }

  // Benchmark residue is removed before the process exits.
  const std::uint64_t generation_bytes = [&root]() {
    std::uint64_t total = 0;
    std::error_code code;
    for (const auto& entry : std::filesystem::directory_iterator(root / "generations", code)) {
      total += std::filesystem::file_size(entry.path(), code);
    }
    return total;
  }();
  std::printf("store size before cleanup: %llu generation bytes, %zu grants\n",
              static_cast<unsigned long long>(generation_bytes), authority.value().Grants().size());
  authority.value().Close();
  std::filesystem::remove_all(root, error);
  std::printf("benchmark store removed: %s\n",
              std::filesystem::exists(root) ? "NO" : "yes");
  return 0;
}
