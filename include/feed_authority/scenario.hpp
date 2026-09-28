#pragma once

// The scenario text format.
//
// A scenario file is one complete external input generation in a human-readable,
// line-oriented form: revisions, feeds, loads, paths, maintenance, operating
// condition, observations, rules and obligations. It exists so that operators,
// examples and tests can describe an electrical situation without writing C++.
//
// The grammar is documented in docs/artifact-format.md. The reader is strict: an
// unknown record, an unknown key, a duplicate key, a malformed value, an
// out-of-range number or a count above the configured limit is an error, never a
// silently ignored line.

#include <filesystem>
#include <string>
#include <string_view>

#include "feed_authority/inputs.hpp"
#include "feed_authority/limits.hpp"
#include "feed_authority/status.hpp"

namespace feed_authority {

/// Parses one scenario. `source_name` is used only in error messages.
Result<AuthorityInputs> parse_scenario(std::string_view text, const Limits& limits,
                                       std::string_view source_name = "<scenario>");

/// Reads and parses a scenario file. The file is bounded before it is read.
Result<AuthorityInputs> load_scenario_file(const std::filesystem::path& path, const Limits& limits);

/// Upper bound for a scenario file accepted from disk.
inline constexpr std::uint64_t kMaxScenarioBytes = 8ull * 1024ull * 1024ull;

}  // namespace feed_authority
