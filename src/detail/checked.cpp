#include "detail/checked.hpp"

#include <string>

#include "feed_authority/limits.hpp"

namespace feed_authority {
namespace {

constexpr std::uint32_t kMaxCountLimit = 1000000u;

Status require_range(std::uint32_t value, std::uint32_t low, std::uint32_t high, const char* what) {
  if (value < low || value > high) {
    return Status::error(StatusCode::InvalidArgument,
                         std::string(what) + " is outside the supported range");
  }
  return Status::success();
}

}  // namespace

Status Limits::validate() const {
  Status status = require_range(max_id_length, 1u, kMaxIdentityLength, "max_id_length");
  if (!status.ok()) return status;
  status = require_range(max_text_length, 1u, kMaxTextLength, "max_text_length");
  if (!status.ok()) return status;
  status = require_range(max_feeds, 1u, kMaxCountLimit, "max_feeds");
  if (!status.ok()) return status;
  status = require_range(max_loads, 1u, kMaxCountLimit, "max_loads");
  if (!status.ok()) return status;
  status = require_range(max_links, 1u, kMaxCountLimit, "max_links");
  if (!status.ok()) return status;
  status = require_range(max_maintenance_records, 1u, kMaxCountLimit, "max_maintenance_records");
  if (!status.ok()) return status;
  status = require_range(max_rules, 1u, kMaxCountLimit, "max_rules");
  if (!status.ok()) return status;
  status = require_range(max_obligations, 1u, kMaxCountLimit, "max_obligations");
  if (!status.ok()) return status;
  status = require_range(max_conditions_per_rule, 1u, 32u, "max_conditions_per_rule");
  if (!status.ok()) return status;
  status = require_range(max_scope_failure_domains, 1u, kMaxCountLimit, "max_scope_failure_domains");
  if (!status.ok()) return status;
  status = require_range(max_candidates, 1u, kMaxCandidates, "max_candidates");
  if (!status.ok()) return status;
  status = require_range(max_grants, 1u, kMaxCountLimit, "max_grants");
  if (!status.ok()) return status;
  status = require_range(max_emergency_authorizations, 1u, kMaxCountLimit,
                         "max_emergency_authorizations");
  if (!status.ok()) return status;
  status = require_range(max_override_classes, 1u, 8u, "max_override_classes");
  if (!status.ok()) return status;
  status = require_range(max_events, 1u, kMaxCountLimit, "max_events");
  if (!status.ok()) return status;
  status = require_range(max_replay_entries, 1u, kMaxCountLimit, "max_replay_entries");
  if (!status.ok()) return status;
  status = require_range(max_policy_history, 1u, 64u, "max_policy_history");
  if (!status.ok()) return status;
  status = require_range(max_topology_history, 1u, 64u, "max_topology_history");
  if (!status.ok()) return status;
  status = require_range(decision_lease, 1u, 1u << 20, "decision_lease");
  if (!status.ok()) return status;
  status = require_range(generation_retention, 1u, 64u, "generation_retention");
  if (!status.ok()) return status;
  if (max_generation_bytes < 4096u || max_generation_bytes > kMaxGenerationBytes) {
    return Status::error(StatusCode::InvalidArgument, "max_generation_bytes is outside the supported range");
  }
  if (max_payload_line_bytes < 64u || max_payload_line_bytes > kMaxPayloadLineBytes) {
    return Status::error(StatusCode::InvalidArgument,
                         "max_payload_line_bytes is outside the supported range");
  }
  if (max_grant_validity_nanos <= 0 ||
      max_grant_validity_nanos > 365ll * 24ll * 60ll * 60ll * 1000000000ll) {
    return Status::error(StatusCode::InvalidArgument,
                         "max_grant_validity_nanos is outside the supported range");
  }
  if (max_emergency_validity_nanos <= 0 ||
      max_emergency_validity_nanos > 7ll * 24ll * 60ll * 60ll * 1000000000ll) {
    return Status::error(StatusCode::InvalidArgument,
                         "max_emergency_validity_nanos is outside the supported range");
  }
  if (lock_acquire_budget_nanos <= 0 ||
      lock_acquire_budget_nanos > 3600ll * 1000000000ll) {
    return Status::error(StatusCode::InvalidArgument,
                         "lock_acquire_budget_nanos is outside the supported range");
  }
  return Status::success();
}

}  // namespace feed_authority::detail
