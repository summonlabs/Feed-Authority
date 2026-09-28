#include "feed_authority/inputs.hpp"

#include <algorithm>
#include <string>
#include <unordered_set>

#include "detail/serialization.hpp"
#include "feed_authority/obligation.hpp"

namespace feed_authority {

Status AuthorityInputs::validate(const Limits& limits) const {
  Status status = limits.validate();
  if (!status.ok()) {
    return status;
  }
  status = topology.validate(limits);
  if (!status.ok()) {
    return status;
  }
  status = control.validate(limits);
  if (!status.ok()) {
    return status;
  }
  status = policy.validate(limits);
  if (!status.ok()) {
    return status;
  }

  // Cross-component references: maintenance and rule scopes may only name feeds
  // and loads this same generation declares, because an authority answer may never
  // depend on an object that was not supplied.
  for (const MaintenanceRecord& record : control.maintenance) {
    if (topology.find_feed(record.feed) == nullptr) {
      return Status::error(StatusCode::NotFound,
                           "a maintenance record references a feed the topology does not declare");
    }
  }
  for (const EligibilityRule& rule : policy.rules) {
    if (rule.scope.feed && topology.find_feed(*rule.scope.feed) == nullptr) {
      return Status::error(StatusCode::NotFound,
                           "a rule references a feed the topology does not declare");
    }
    if (rule.scope.load && topology.find_load(*rule.scope.load) == nullptr) {
      return Status::error(StatusCode::NotFound,
                           "a rule references a load the topology does not declare");
    }
  }
  for (const ProtectedObligation& obligation : policy.obligations) {
    for (const LoadId& load : obligation.loads) {
      if (topology.find_load(load) == nullptr) {
        return Status::error(StatusCode::NotFound,
                             "an obligation references a load the topology does not declare");
      }
    }
  }
  return Status::success();
}

void AuthorityInputs::canonicalize(AuthorityInputs& inputs) {
  TopologyView::canonicalize(inputs.topology);
  ControlState::canonicalize(inputs.control);
  PolicySet::canonicalize(inputs.policy);
}

bool AuthorityInputs::same_source_generations(const AuthorityInputs& other) const noexcept {
  return topology.revision == other.topology.revision && policy.revision == other.policy.revision &&
         control.revision == other.control.revision && evidence == other.evidence;
}

bool AuthorityInputs::identical_to(const AuthorityInputs& other) const {
  if (!same_source_generations(other)) {
    return false;
  }
  AuthorityInputs left = *this;
  AuthorityInputs right = other;
  canonicalize(left);
  canonicalize(right);
  return left == right;
}

Digest AuthorityInputs::topology_fingerprint() const {
  std::string payload;
  detail::encode_topology_records(payload, topology, Limits{});
  return Digest::Of(payload);
}

Digest AuthorityInputs::control_fingerprint() const {
  std::string payload;
  detail::encode_control_records(payload, control, Limits{});
  return Digest::Of(payload);
}

Digest AuthorityInputs::policy_fingerprint() const {
  std::string payload;
  detail::encode_policy_records(payload, policy, Limits{});
  return Digest::Of(payload);
}

Digest AuthorityInputs::fingerprint() const {
  std::string payload;
  detail::encode_input_records(payload, *this, Limits{});
  return Digest::Of(payload);
}

}  // namespace feed_authority
