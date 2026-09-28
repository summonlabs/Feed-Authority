#pragma once

// Deterministic rendering.
//
// Rendered output is a pure function of the value rendered: no addresses, no
// timestamps other than the ones the value itself carries, no locale, no
// hash-map iteration order. The same value renders to the same bytes on every run
// and every host, which is what makes the CLI output usable in a diff and in a
// test.

#include <string>
#include <vector>

#include "feed_authority/authority.hpp"
#include "feed_authority/decision.hpp"
#include "feed_authority/diff.hpp"
#include "feed_authority/emergency.hpp"
#include "feed_authority/event.hpp"
#include "feed_authority/grant.hpp"
#include "feed_authority/inputs.hpp"
#include "feed_authority/limits.hpp"
#include "feed_authority/policy.hpp"
#include "feed_authority/store.hpp"

namespace feed_authority {

/// Rendering options. JSON output is a stable, hand-written encoding; it is not a
/// general serialization and contains only the fields documented in the README.
struct RenderOptions {
  /// Emit one-line-per-record JSON instead of the human-readable form.
  bool json = false;
  /// Include explanation traces where the value carries them.
  bool include_traces = true;
};

std::string render_decision(const DecisionSet& decision, const RenderOptions& options = {});
std::string render_explanation(const Explanation& explanation, const RenderOptions& options = {});
std::string render_grant(const Grant& grant, const RenderOptions& options = {});
std::string render_grant_authorization(const GrantAuthorization& authorization,
                                       const RenderOptions& options = {});
std::string render_emergency(const EmergencyAuthorization& authorization,
                             const RenderOptions& options = {});
std::string render_policy(const PolicySet& policy, const RenderOptions& options = {});
std::string render_topology(const TopologyView& topology, const RenderOptions& options = {});
std::string render_inputs(const AuthorityInputs& inputs, const RenderOptions& options = {});
std::string render_recovery(const RecoveryReport& report, const RenderOptions& options = {});
std::string render_audit(const StoreAuditReport& report, const RenderOptions& options = {});
std::string render_history(const std::vector<EventRecord>& events, const RenderOptions& options = {});
std::string render_attempts(const std::vector<AttemptRecord>& attempts,
                            const RenderOptions& options = {});
std::string render_policy_diff(const PolicyDiff& diff, const RenderOptions& options = {});
std::string render_inputs_diff(const InputsDiff& diff, const RenderOptions& options = {});
std::string render_limits(const Limits& limits, const RenderOptions& options = {});
std::string render_status(const Status& status, const RenderOptions& options = {});

}  // namespace feed_authority
