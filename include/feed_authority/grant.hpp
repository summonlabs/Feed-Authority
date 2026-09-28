#pragma once

// Durable grants of feed-serving eligibility.
//
// A grant records that an explicit authority path permitted one load/feed pair
// under exactly one input generation. It is not a switching command, it does not
// close a breaker, and it proves no physical effect: it states that under the
// bound generations the pair was admissible, and that current evidence still
// supports it.
//
// A grant is refused rather than silently reused when it is revoked, expired,
// superseded by a newer topology, policy or control revision, or recovered from
// disk without revalidation in the current writer session.

#include <cstdint>
#include <iosfwd>
#include <string>
#include <string_view>
#include <vector>

#include "feed_authority/digest.hpp"
#include "feed_authority/generations.hpp"
#include "feed_authority/ids.hpp"
#include "feed_authority/reason.hpp"
#include "feed_authority/status.hpp"
#include "feed_authority/time.hpp"

namespace feed_authority {

struct GrantIdTag;
/// A durable grant identity. It is the grant sequence value, so identities are
/// dense, deterministic and free of randomness.
using GrantId = Counter<GrantIdTag>;

/// The lifecycle state of a grant at a specific instant and writer session.
enum class GrantUsability : std::int32_t {
  /// Current, unrevoked, unexpired, revalidated for this session, and still
  /// supported by fresh evidence.
  Usable = 0,
  /// Explicitly revoked. Never usable again.
  Revoked = 1,
  /// Past its expiry instant.
  Expired = 2,
  /// The topology, policy or control revision bound at issue is no longer current.
  Superseded = 3,
  /// Recovered from durable state, or bound to an older writer session, and not
  /// yet revalidated against current inputs.
  NeedsRevalidation = 4,
  /// Current generations, but current evidence no longer supports the pair.
  EvidenceWithdrawn = 5,
};

const char* to_string(GrantUsability value) noexcept;
std::ostream& operator<<(std::ostream& stream, GrantUsability value);

/// The durable grant record.
struct Grant {
  GrantId id;
  LoadId load;
  FeedId feed;
  /// The named authority path of the permit rule that authorized the pair.
  AuthorityPathId authority_path;
  /// The binding the grant was issued under, including the decision generation
  /// and the decision fingerprint that authorized it.
  AuthorityBinding issued_binding{};
  Digest decision_fingerprint;
  AuthorityTime issued_at{};
  AuthorityTime expires_at{};

  bool revoked = false;
  AuthorityTime revoked_at{};
  AuthorizerId revoked_by;
  std::string revocation_reason;

  /// The last successful revalidation. A grant recovered from disk carries none
  /// until the current writer session revalidates it.
  bool revalidated = false;
  AuthorityEpoch revalidated_epoch{};
  AuthorityBinding revalidated_binding{};
  AuthorityTime revalidated_at{};

  /// The idempotency identity of the attempt that created the grant.
  AttemptId attempt;

  friend bool operator==(const Grant& left, const Grant& right) noexcept {
    return left.id == right.id && left.load == right.load && left.feed == right.feed &&
           left.authority_path == right.authority_path &&
           left.issued_binding == right.issued_binding &&
           left.decision_fingerprint == right.decision_fingerprint &&
           left.issued_at == right.issued_at && left.expires_at == right.expires_at &&
           left.revoked == right.revoked && left.revoked_at == right.revoked_at &&
           left.revoked_by == right.revoked_by &&
           left.revocation_reason == right.revocation_reason &&
           left.revalidated == right.revalidated &&
           left.revalidated_epoch == right.revalidated_epoch &&
           left.revalidated_binding == right.revalidated_binding &&
           left.revalidated_at == right.revalidated_at && left.attempt == right.attempt;
  }
};

/// The answer to "may this grant authorize anything right now?". `authorized` is
/// true only for `GrantUsability::Usable`, and even then it authorizes eligibility
/// under the bound generations — never actuation.
struct GrantAuthorization {
  Grant grant;
  bool authorized = false;
  GrantUsability usability = GrantUsability::NeedsRevalidation;
  ReasonCode reason = ReasonCode::RequiredEvidenceNotFresh;
  std::string detail;
  /// The authority path that must be reported to the switching controller.
  AuthorityPathId authority_path;
};

}  // namespace feed_authority
