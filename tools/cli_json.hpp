#pragma once

// Command line support: strict option parsing, path construction from UTF-8, and
// stable output helpers. The tool calls the library for every answer; nothing here
// reimplements an authority decision.

#include <cstdint>
#include <filesystem>
#include <map>
#include <set>
#include <string>
#include <vector>

#include "feed_authority/status.hpp"
#include "feed_authority/time.hpp"

namespace feed_authority::cli {

/// Parsed command line. Every option must be declared by the command that accepts
/// it; an unknown option is a usage error rather than an ignored word.
struct Options {
  std::vector<std::string> positionals;
  std::map<std::string, std::string> values;
  std::set<std::string> flags;

  bool has(std::string_view name) const { return values.count(std::string(name)) != 0; }
  bool flag(std::string_view name) const { return flags.count(std::string(name)) != 0; }
  std::string value(std::string_view name) const {
    const auto found = values.find(std::string(name));
    return found == values.end() ? std::string() : found->second;
  }
  std::string value_or(std::string_view name, std::string fallback) const {
    const auto found = values.find(std::string(name));
    return found == values.end() ? std::move(fallback) : found->second;
  }
};

/// Parses `arguments` (excluding the program name). `value_options` names every
/// option that takes a value, `flag_options` every option that does not.
Result<Options> parse_options(const std::vector<std::string>& arguments,
                              const std::set<std::string>& value_options,
                              const std::set<std::string>& flag_options);

/// Builds a filesystem path from UTF-8 text, converting on Windows.
std::filesystem::path path_from_utf8(const std::string& text);

/// Parses an instant: either an ISO-8601 timestamp ending in 'Z' or whole Unix
/// seconds.
Result<AuthorityTime> parse_instant(const std::string& text);

/// Parses a duration such as "500ms", "30s", "5m", "2h", "1d".
Result<Duration> parse_duration(const std::string& text);

/// The instant to use when the caller supplied no `--now`.
Result<AuthorityTime> resolve_now(const Options& options);

/// Parses a comma-separated list of identities into a vector of strings.
Result<std::vector<std::string>> parse_list(const std::string& text);

/// Strict unsigned decimal parse, used for command-line numbers.
Result<std::uint64_t> parse_uint(const std::string& text);

/// Strict signed decimal parse, used for command-line numbers and instants.
Result<std::int64_t> parse_int(const std::string& text);

/// Prints a status to stderr in a stable form and returns the process exit code.
int report(const Status& status);

}  // namespace feed_authority::cli
