#pragma once

// Deterministic comparison of policy and input generations.
//
// The store keeps a bounded history of adopted input generations, so a caller can
// ask what changed between two revisions. Every list in a diff is sorted by
// identity, and every rendered line is stable, so two diffs of the same two
// generations are byte-identical.

#include <cstdint>
#include <string>
#include <vector>

#include "feed_authority/generations.hpp"
#include "feed_authority/ids.hpp"
#include "feed_authority/status.hpp"

namespace feed_authority {

/// One changed policy rule.
struct RuleDelta {
  RuleId id;
  /// "added", "removed" or "changed".
  std::string change;
  /// Canonical one-line summary of the rule before the change; empty when added.
  std::string before;
  /// Canonical one-line summary of the rule after the change; empty when removed.
  std::string after;

  friend bool operator==(const RuleDelta& left, const RuleDelta& right) noexcept {
    return left.id == right.id && left.change == right.change && left.before == right.before &&
           left.after == right.after;
  }
};

struct ObligationDelta {
  ObligationId id;
  std::string change;
  std::string before;
  std::string after;

  friend bool operator==(const ObligationDelta& left, const ObligationDelta& right) noexcept {
    return left.id == right.id && left.change == right.change && left.before == right.before &&
           left.after == right.after;
  }
};

struct PolicyDiff {
  PolicyRevision from{};
  PolicyRevision to{};
  bool identical = false;
  std::vector<RuleDelta> rules;
  std::vector<ObligationDelta> obligations;
  std::vector<std::string> option_changes;

  std::string to_string() const;
};

/// A summary diff of two adopted input generations.
struct InputsDiff {
  bool identical = false;
  TopologyRevision from_topology{};
  TopologyRevision to_topology{};
  PolicyRevision from_policy{};
  PolicyRevision to_policy{};
  ControlRevision from_control{};
  ControlRevision to_control{};
  EvidenceRevision from_evidence{};
  EvidenceRevision to_evidence{};
  /// Sorted, stable, human-readable change lines.
  std::vector<std::string> changes;
  PolicyDiff policy_diff;

  std::string to_string() const;
};

}  // namespace feed_authority
