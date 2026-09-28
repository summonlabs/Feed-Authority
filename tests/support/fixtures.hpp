#pragma once

// Test fixtures: terse constructors for identities, instants and scenario-backed
// input generations.
//
// A fixture that cannot build what it was asked for records a failure through the
// harness and returns an unset value, so a malformed test never turns into a pass.

#include <cstdint>
#include <filesystem>
#include <string>

#include "test_harness.hpp"

namespace fa_test {

feed_authority::AuthorityTime at(std::int64_t unix_seconds);
feed_authority::Duration secs(std::int64_t seconds);
feed_authority::Duration millis(std::int64_t milliseconds);

feed_authority::FeedId feed(const std::string& text);
feed_authority::LoadId load(const std::string& text);
feed_authority::RuleId rule(const std::string& text);
feed_authority::ObligationId obligation(const std::string& text);
feed_authority::FailureDomainId domain(const std::string& text);
feed_authority::EvidenceSourceId source(const std::string& text);
feed_authority::AuthorityPathId path(const std::string& text);
feed_authority::AuthorizerId authorizer(const std::string& text);
feed_authority::AttemptId attempt(const std::string& text);
feed_authority::MaintenanceWindowId window(const std::string& text);

/// Parses scenario text into an input generation, recording a failure when the
/// text is not accepted.
feed_authority::AuthorityInputs inputs(const std::string& scenario_text);

/// A store root under the test binary directory that this call removes and
/// recreates.
std::filesystem::path fresh_store(const std::string& name);

/// Opens a store read-write. The caller checks the result.
feed_authority::Result<feed_authority::FeedAuthority> open_store(
    const std::filesystem::path& root, bool create, bool read_write = true,
    std::int64_t opened_at_seconds = 1735689600);

/// Opens a store read-only. The caller checks the result.
feed_authority::Result<feed_authority::FeedAuthority> open_store_read_only(
    const std::filesystem::path& root);

/// Adopts an input generation with a caller-chosen attempt identity.
feed_authority::Status adopt(feed_authority::FeedAuthority& authority,
                             const feed_authority::AuthorityInputs& inputs,
                             const std::string& attempt_text, feed_authority::AuthorityTime now);

/// Evaluates one load over the whole candidate set.
feed_authority::Result<feed_authority::DecisionSet> evaluate(
    feed_authority::FeedAuthority& authority, const std::string& load_text,
    feed_authority::AuthorityTime now,
    const std::vector<std::string>& candidate_feeds = {},
    const std::string& required_path = std::string());

/// Evaluates and issues a grant for the pair in one step, the way a controller
/// would: the grant is bound to the decision that authorized it.
feed_authority::Result<feed_authority::Grant> issue_grant(
    feed_authority::FeedAuthority& authority, const std::string& load_text,
    const std::string& feed_text, feed_authority::AuthorityTime now, const std::string& attempt_text,
    std::int64_t validity_seconds = 300, const std::string& required_path = std::string());

}  // namespace fa_test
