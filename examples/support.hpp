// Shared scaffolding for the examples: a scratch store, a scenario, and a small
// reporting helper. Examples are deterministic: every instant is supplied.

#pragma once

#include <filesystem>
#include <iostream>
#include <string>

#include "feed_authority/authority.hpp"
#include "feed_authority/render.hpp"
#include "feed_authority/scenario.hpp"

namespace example {

using namespace feed_authority;

/// A scratch store under the current directory, removed on construction.
std::filesystem::path scratch(const std::string& name);

/// Opens (creating when needed) a store for the example.
Result<FeedAuthority> open(const std::filesystem::path& root, std::int64_t opened_at);

/// Adopts scenario text.
Status adopt(FeedAuthority& authority, const std::string& scenario, const std::string& attempt,
             std::int64_t now);

/// A fixed instant, so every example prints the same bytes on every run.
AuthorityTime at(std::int64_t unix_seconds);

/// Prints a heading and a line.
void heading(const std::string& title);
void line(const std::string& text);

}  // namespace example
