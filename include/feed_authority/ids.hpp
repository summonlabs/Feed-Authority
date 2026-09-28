#pragma once

// Strongly typed opaque identities.
//
// Every identity is an opaque reference to a record owned by another registry or
// by the facility topology source. Feed Authority never derives meaning from the
// text of an identity, never parses structure out of it, and never lets one
// identity kind stand in for another: FeedId, LoadId, RuleId and the rest are
// distinct types that do not convert into each other or into a plain string.

#include <functional>
#include <iosfwd>
#include <string>
#include <string_view>

#include "feed_authority/limits.hpp"
#include "feed_authority/status.hpp"

namespace feed_authority {

/// True when `text` is a well-formed identity: 1..kMaxIdentityLength characters
/// from [A-Za-z0-9._:-], no leading or trailing '.', and no ".." sequence. The
/// check is deliberately narrow: identities are untrusted external input.
bool is_valid_identity_text(std::string_view text) noexcept;

template <class Tag>
class OpaqueId {
 public:
  /// The unset identity. It is never valid and never matches anything.
  OpaqueId() noexcept = default;

  static Result<OpaqueId> Parse(std::string_view text) {
    if (!is_valid_identity_text(text)) {
      return Status::error(StatusCode::InvalidArgument,
                           "identity is not a well-formed opaque reference");
    }
    return OpaqueId(std::string(text));
  }

  bool valid() const noexcept { return !value_.empty(); }
  const std::string& value() const noexcept { return value_; }
  const std::string& str() const noexcept { return value_; }

  friend bool operator==(const OpaqueId& left, const OpaqueId& right) noexcept {
    return left.value_ == right.value_;
  }
  friend bool operator!=(const OpaqueId& left, const OpaqueId& right) noexcept {
    return !(left == right);
  }
  friend bool operator<(const OpaqueId& left, const OpaqueId& right) noexcept {
    return left.value_ < right.value_;
  }
  friend bool operator>(const OpaqueId& left, const OpaqueId& right) noexcept { return right < left; }
  friend bool operator<=(const OpaqueId& left, const OpaqueId& right) noexcept { return !(right < left); }
  friend bool operator>=(const OpaqueId& left, const OpaqueId& right) noexcept { return !(left < right); }

 private:
  explicit OpaqueId(std::string value) : value_(std::move(value)) {}
  std::string value_;
};

struct FeedTag;
struct LoadTag;
struct RuleTag;
struct ObligationTag;
struct FailureDomainTag;
struct EvidenceSourceTag;
struct AuthorityPathTag;
struct AuthorizerTag;
struct MaintenanceWindowTag;
struct AttemptTag;

/// A feed identity owned by the facility topology source.
using FeedId = OpaqueId<FeedTag>;
/// A load (or service) identity owned by the facility topology source.
using LoadId = OpaqueId<LoadTag>;
/// A rule identity owned by the policy source.
using RuleId = OpaqueId<RuleTag>;
/// A protected-obligation identity owned by the policy source.
using ObligationId = OpaqueId<ObligationTag>;
/// An electrical failure-domain identity owned by the topology source.
using FailureDomainId = OpaqueId<FailureDomainTag>;
/// An evidence-source identity owned by the observation source.
using EvidenceSourceId = OpaqueId<EvidenceSourceTag>;
/// The named authority path a permit rule cites. A permit is only meaningful when
/// it names the authority that grants it.
using AuthorityPathId = OpaqueId<AuthorityPathTag>;
/// The identity of the human or system that issued, revoked, or overrode an
/// authority record. Never interpreted, always recorded.
using AuthorizerId = OpaqueId<AuthorizerTag>;
/// A maintenance-window identity owned by the maintenance source.
using MaintenanceWindowId = OpaqueId<MaintenanceWindowTag>;
/// A caller-supplied idempotency identity for one attempt to mutate authority.
using AttemptId = OpaqueId<AttemptTag>;

template <class Tag>
std::ostream& operator<<(std::ostream& stream, const OpaqueId<Tag>& id) {
  return stream << id.value();
}

}  // namespace feed_authority

namespace std {

template <class Tag>
struct hash<feed_authority::OpaqueId<Tag>> {
  std::size_t operator()(const feed_authority::OpaqueId<Tag>& id) const noexcept {
    return std::hash<std::string>{}(id.value());
  }
};

}  // namespace std
