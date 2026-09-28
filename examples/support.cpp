#include "support.hpp"

namespace example {

std::filesystem::path scratch(const std::string& name) {
  const std::filesystem::path root = std::filesystem::current_path() / ("fa-example-" + name);
  std::error_code error;
  std::filesystem::remove_all(root, error);
  std::filesystem::create_directories(root, error);
  return root;
}

Result<FeedAuthority> open(const std::filesystem::path& root, std::int64_t opened_at) {
  OpenOptions options;
  options.root = root;
  options.create_if_missing = true;
  options.opened_at = at(opened_at);
  return FeedAuthority::Open(options);
}

Status adopt(FeedAuthority& authority, const std::string& scenario, const std::string& attempt,
             std::int64_t now) {
  const Result<AuthorityInputs> inputs = parse_scenario(scenario, authority.limits(), "example");
  if (!inputs.ok()) {
    return inputs.status();
  }
  AdoptInputsRequest request;
  request.inputs = inputs.value();
  request.now = at(now);
  const Result<AttemptId> parsed = AttemptId::Parse(attempt);
  if (!parsed.ok()) {
    return parsed.status();
  }
  request.attempt = parsed.value();
  return authority.AdoptInputs(request);
}

AuthorityTime at(std::int64_t unix_seconds) {
  const Result<AuthorityTime> instant = AuthorityTime::FromUnixSeconds(unix_seconds);
  return instant.ok() ? instant.value() : AuthorityTime{};
}

void heading(const std::string& title) {
  std::cout << "== " << title << "\n";
}

void line(const std::string& text) { std::cout << text << "\n"; }

}  // namespace example
