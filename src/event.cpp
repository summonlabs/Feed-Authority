#include "feed_authority/event.hpp"

#include <ostream>

namespace feed_authority {

const char* to_string(EventKind kind) noexcept {
  switch (kind) {
    case EventKind::StoreCreated: return "store_created";
    case EventKind::WriterSessionOpened: return "writer_session_opened";
    case EventKind::InputsAdopted: return "inputs_adopted";
    case EventKind::DecisionRecorded: return "decision_recorded";
    case EventKind::GrantIssued: return "grant_issued";
    case EventKind::GrantRevoked: return "grant_revoked";
    case EventKind::GrantRevalidated: return "grant_revalidated";
    case EventKind::GrantRevalidationRefused: return "grant_revalidation_refused";
    case EventKind::EmergencyAuthorized: return "emergency_authorized";
    case EventKind::EmergencyRevoked: return "emergency_revoked";
    case EventKind::StoreReloaded: return "store_reloaded";
  }
  return "inputs_adopted";
}

Result<EventKind> parse_event_kind(std::string_view text) {
  for (std::int32_t value = 0; value <= 10; ++value) {
    const EventKind kind = static_cast<EventKind>(value);
    if (text == to_string(kind)) {
      return kind;
    }
  }
  return Status::error(StatusCode::InvalidArgument, "unrecognized event kind token");
}

std::ostream& operator<<(std::ostream& stream, EventKind kind) {
  return stream << to_string(kind);
}

}  // namespace feed_authority
