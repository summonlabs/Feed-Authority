#pragma once

// The complete externally supplied input generation.
//
// One input generation is a topology revision, a control revision, a policy
// revision and an evidence revision, together with their content. Feed Authority
// adopts it, stamps it, and answers questions against exactly that generation. A
// revision may never be reused with different content, and a revision may never go
// backwards: both are refused rather than merged.

#include <string>
#include <vector>

#include "feed_authority/digest.hpp"
#include "feed_authority/generations.hpp"
#include "feed_authority/limits.hpp"
#include "feed_authority/model.hpp"
#include "feed_authority/policy.hpp"
#include "feed_authority/status.hpp"

namespace feed_authority {

struct AuthorityInputs {
  TopologyView topology;
  ControlState control;
  PolicySet policy;
  EvidenceRevision evidence{};

  /// Validates every component and the cross-component references, in a fixed
  /// documented order: limits, then topology, then control, then policy, then
  /// cross references, then revision consistency.
  Status validate(const Limits& limits) const;

  /// Canonicalizes every component so that logically equal inputs encode to
  /// identical bytes.
  static void canonicalize(AuthorityInputs& inputs);

  /// True when every source revision is equal to `other`'s.
  bool same_source_generations(const AuthorityInputs& other) const noexcept;

  /// True when every source revision and every byte of canonical content is equal.
  bool identical_to(const AuthorityInputs& other) const;

  Digest topology_fingerprint() const;
  Digest control_fingerprint() const;
  Digest policy_fingerprint() const;
  /// Fingerprint of the whole input generation, including the revisions.
  Digest fingerprint() const;

  friend bool operator==(const AuthorityInputs& left, const AuthorityInputs& right) noexcept {
    return left.topology == right.topology && left.control == right.control &&
           left.policy == right.policy && left.evidence == right.evidence;
  }
};

}  // namespace feed_authority
