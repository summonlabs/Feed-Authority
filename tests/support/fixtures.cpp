#include "fixtures.hpp"

#include <string>

#include "feed_authority/scenario.hpp"
#include "proc.hpp"

namespace fa_test {
namespace {

void note(const std::string& what) {
  ::fa_test::report_failure(__FILE__, __LINE__, "fixture", what);
}

}  // namespace

feed_authority::AuthorityTime at(std::int64_t unix_seconds) {
  const feed_authority::Result<feed_authority::AuthorityTime> parsed =
      feed_authority::AuthorityTime::FromUnixSeconds(unix_seconds);
  if (!parsed.ok()) {
    note("the instant " + std::to_string(unix_seconds) + " is not representable");
    return feed_authority::AuthorityTime{};
  }
  return parsed.value();
}

feed_authority::Duration secs(std::int64_t seconds) {
  const feed_authority::Result<feed_authority::Duration> parsed =
      feed_authority::Duration::FromSeconds(seconds);
  if (!parsed.ok()) {
    note("the duration is not representable");
    return feed_authority::Duration{};
  }
  return parsed.value();
}

feed_authority::Duration millis(std::int64_t milliseconds) {
  const feed_authority::Result<feed_authority::Duration> parsed =
      feed_authority::Duration::FromMillis(milliseconds);
  if (!parsed.ok()) {
    note("the duration is not representable");
    return feed_authority::Duration{};
  }
  return parsed.value();
}

#define FA_FIXTURE_ID(function_name, type_name, label)                                          \
  feed_authority::type_name function_name(const std::string& text) {                            \
    const feed_authority::Result<feed_authority::type_name> parsed =                            \
        feed_authority::type_name::Parse(text);                                                 \
    if (!parsed.ok()) {                                                                         \
      note(std::string(label) + " '" + text + "' is not well-formed");                          \
      return feed_authority::type_name{};                                                       \
    }                                                                                           \
    return parsed.value();                                                                      \
  }

FA_FIXTURE_ID(feed, FeedId, "feed")
FA_FIXTURE_ID(load, LoadId, "load")
FA_FIXTURE_ID(rule, RuleId, "rule")
FA_FIXTURE_ID(obligation, ObligationId, "obligation")
FA_FIXTURE_ID(domain, FailureDomainId, "domain")
FA_FIXTURE_ID(source, EvidenceSourceId, "evidence source")
FA_FIXTURE_ID(path, AuthorityPathId, "authority path")
FA_FIXTURE_ID(authorizer, AuthorizerId, "authorizer")
FA_FIXTURE_ID(attempt, AttemptId, "attempt")
FA_FIXTURE_ID(window, MaintenanceWindowId, "window")

#undef FA_FIXTURE_ID

feed_authority::AuthorityInputs inputs(const std::string& scenario_text) {
  const feed_authority::Result<feed_authority::AuthorityInputs> parsed =
      feed_authority::parse_scenario(scenario_text, feed_authority::Limits{}, "fixture");
  if (!parsed.ok()) {
    note("the scenario was refused: " + parsed.status().to_string());
    return feed_authority::AuthorityInputs{};
  }
  return parsed.value();
}

std::filesystem::path fresh_store(const std::string& name) {
  const std::filesystem::path root = scratch_directory(name);
  std::error_code error;
  std::filesystem::remove_all(root, error);
  std::filesystem::create_directories(root, error);
  return root;
}

feed_authority::Result<feed_authority::FeedAuthority> open_store(
    const std::filesystem::path& root, bool create, bool read_write, std::int64_t opened_at_seconds) {
  feed_authority::OpenOptions options;
  options.root = root;
  options.create_if_missing = create;
  options.mode = read_write ? feed_authority::OpenMode::ReadWrite : feed_authority::OpenMode::ReadOnly;
  options.opened_at = at(opened_at_seconds);
  return feed_authority::FeedAuthority::Open(options);
}

feed_authority::Result<feed_authority::FeedAuthority> open_store_read_only(
    const std::filesystem::path& root) {
  return open_store(root, false, false);
}

feed_authority::Status adopt(feed_authority::FeedAuthority& authority,
                             const feed_authority::AuthorityInputs& inputs,
                             const std::string& attempt_text, feed_authority::AuthorityTime now) {
  feed_authority::AdoptInputsRequest request;
  request.inputs = inputs;
  request.now = now;
  const feed_authority::Result<feed_authority::AttemptId> parsed =
      feed_authority::AttemptId::Parse(attempt_text);
  if (!parsed.ok()) {
    return parsed.status();
  }
  request.attempt = parsed.value();
  return authority.AdoptInputs(request);
}

feed_authority::Result<feed_authority::DecisionSet> evaluate(
    feed_authority::FeedAuthority& authority, const std::string& load_text,
    feed_authority::AuthorityTime now, const std::vector<std::string>& candidate_feeds,
    const std::string& required_path) {
  feed_authority::EvaluationRequest request;
  request.load = load(load_text);
  request.now = now;
  for (const std::string& text : candidate_feeds) {
    request.candidate_feeds.push_back(feed(text));
  }
  if (!required_path.empty()) {
    request.required_authority_path = path(required_path);
  }
  return authority.Evaluate(request);
}

feed_authority::Result<feed_authority::Grant> issue_grant(
    feed_authority::FeedAuthority& authority, const std::string& load_text,
    const std::string& feed_text, feed_authority::AuthorityTime now, const std::string& attempt_text,
    std::int64_t validity_seconds, const std::string& required_path) {
  feed_authority::Result<feed_authority::DecisionSet> decision =
      evaluate(authority, load_text, now, {}, required_path);
  if (!decision.ok()) {
    return decision.status();
  }
  feed_authority::GrantRequest request;
  request.load = load(load_text);
  request.feed = feed(feed_text);
  request.decision = decision.value().generation;
  request.decision_fingerprint = decision.value().fingerprint;
  request.validity = secs(validity_seconds);
  request.now = now;
  const feed_authority::Result<feed_authority::AttemptId> parsed =
      feed_authority::AttemptId::Parse(attempt_text);
  if (!parsed.ok()) {
    return parsed.status();
  }
  request.attempt = parsed.value();
  request.precondition.expected = authority.current_binding();
  if (!required_path.empty()) {
    request.required_authority_path = path(required_path);
  }
  return authority.IssueGrant(request);
}

}  // namespace fa_test
