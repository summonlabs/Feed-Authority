#pragma once

// Explicit emergency authority.
//
// There is no magic bypass in this runtime. An emergency override exists only when
// policy enables emergency overrides, an identified authorizer recorded a bounded
// justification, the authorization's scope covers the load and feed, the
// authorization is unrevoked and unexpired, its generation binding is still
// current, the denied rule declared itself emergency-overridable, and the
// authorization names the precedence class it overrides. Safety interlocks are
// never overridable, and neither is an obligation that policy did not mark
// overridable.

#include <cstdint>
#include <iosfwd>
#include <string>
#include <string_view>
#include <vector>

#include "feed_authority/generations.hpp"
#include "feed_authority/ids.hpp"
#include "feed_authority/policy.hpp"
#include "feed_authority/status.hpp"
#include "feed_authority/time.hpp"

namespace feed_authority {

struct EmergencyAuthorizationIdTag;
/// A durable emergency authorization identity: the authorization sequence value.
using EmergencyAuthorizationId = Counter<EmergencyAuthorizationIdTag>;

struct EmergencyAuthorization {
  EmergencyAuthorizationId id;
  /// The identified authorizer. Required and never empty.
  AuthorizerId authorizer;
  /// The recorded justification. Required, non-empty and bounded.
  std::string justification;
  /// The loads the authorization covers. Required and never empty: an
  /// authorization that covers everything is not an authorization.
  std::vector<LoadId> loads;
  /// The feeds the authorization covers. Empty means every feed linked to the
  /// covered loads; it never widens the candidate set.
  std::vector<FeedId> feeds;
  /// The precedence classes this authorization may override. Safety interlocks are
  /// refused at issue time.
  std::vector<PrecedenceClass> overridable_classes;
  /// The generation binding in force when the authorization was issued.
  AuthorityBinding binding{};
  AuthorityTime issued_at{};
  AuthorityTime expires_at{};

  bool revoked = false;
  AuthorityTime revoked_at{};
  AuthorizerId revoked_by;
  std::string revocation_reason;

  AttemptId attempt;

  friend bool operator==(const EmergencyAuthorization& left,
                         const EmergencyAuthorization& right) noexcept {
    return left.id == right.id && left.authorizer == right.authorizer &&
           left.justification == right.justification && left.loads == right.loads &&
           left.feeds == right.feeds &&
           left.overridable_classes == right.overridable_classes &&
           left.binding == right.binding && left.issued_at == right.issued_at &&
           left.expires_at == right.expires_at && left.revoked == right.revoked &&
           left.revoked_at == right.revoked_at && left.revoked_by == right.revoked_by &&
           left.revocation_reason == right.revocation_reason && left.attempt == right.attempt;
  }
};

/// True when `authorization` is unrevoked, unexpired at `now`, and bound to the
/// same source generations as `current`.
bool emergency_authorization_is_live(const EmergencyAuthorization& authorization,
                                     const AuthorityBinding& current,
                                     AuthorityTime now) noexcept;

}  // namespace feed_authority
