#pragma once

// The bounded audit history of authority-affecting operations.
//
// Evaluation is a pure read and records nothing unless the caller asks for it.
// Every operation that changes authority -- adopting inputs, issuing, revoking or
// revalidating a grant, authorizing or revoking emergency authority, opening a
// writer session -- records an event. The history is bounded and the oldest events
// are dropped first; the bound is explicit in `Limits::max_events`.

#include <cstdint>
#include <iosfwd>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "feed_authority/generations.hpp"
#include "feed_authority/ids.hpp"
#include "feed_authority/status.hpp"
#include "feed_authority/time.hpp"

namespace feed_authority {

struct GrantIdTag;
using GrantId = Counter<GrantIdTag>;
struct EmergencyAuthorizationIdTag;
using EmergencyAuthorizationId = Counter<EmergencyAuthorizationIdTag>;

enum class EventKind : std::int32_t {
  /// A new store was created.
  StoreCreated = 0,
  /// A writer session opened an existing store and advanced the authority epoch.
  WriterSessionOpened = 1,
  /// Inputs were adopted.
  InputsAdopted = 2,
  /// An evaluation was recorded at the caller's request.
  DecisionRecorded = 3,
  /// A grant was issued.
  GrantIssued = 4,
  /// A grant was revoked.
  GrantRevoked = 5,
  /// A grant was revalidated against current inputs.
  GrantRevalidated = 6,
  /// A revalidation was refused.
  GrantRevalidationRefused = 7,
  /// An emergency authorization was recorded.
  EmergencyAuthorized = 8,
  /// An emergency authorization was revoked.
  EmergencyRevoked = 9,
  /// The in-memory state adopted a newer head written by another session.
  StoreReloaded = 10,
};

const char* to_string(EventKind kind) noexcept;
Result<EventKind> parse_event_kind(std::string_view text);
std::ostream& operator<<(std::ostream& stream, EventKind kind);

struct EventRecord {
  EventSequence sequence{};
  EventKind kind = EventKind::InputsAdopted;
  AuthorityTime at{};
  AuthorityEpoch epoch{};
  /// Bounded human-readable detail. Recorded, never interpreted.
  std::string detail;
  std::optional<GrantId> grant;
  std::optional<EmergencyAuthorizationId> emergency;
  std::optional<DecisionGeneration> decision;

  friend bool operator==(const EventRecord& left, const EventRecord& right) noexcept {
    return left.sequence == right.sequence && left.kind == right.kind && left.at == right.at &&
           left.epoch == right.epoch && left.detail == right.detail && left.grant == right.grant &&
           left.emergency == right.emergency && left.decision == right.decision;
  }
};

}  // namespace feed_authority
