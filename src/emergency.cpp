#include "feed_authority/emergency.hpp"

#include <ostream>

namespace feed_authority {

bool emergency_authorization_is_live(const EmergencyAuthorization& authorization,
                                     const AuthorityBinding& current,
                                     AuthorityTime now) noexcept {
  if (authorization.revoked) {
    return false;
  }
  if (!(now < authorization.expires_at)) {
    return false;
  }
  if (now < authorization.issued_at) {
    return false;
  }
  // The authorization is bound to the source generations it was issued under: a
  // new topology, policy, control or evidence revision supersedes it and it must be
  // re-issued, never silently reused.
  return authorization.binding.same_source_generations(current);
}

}  // namespace feed_authority
