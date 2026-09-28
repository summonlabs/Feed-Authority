#include "feed_authority/evidence.hpp"

#include <ostream>

namespace feed_authority {

const char* to_string(EvidenceDeclaration declaration) noexcept {
  switch (declaration) {
    case EvidenceDeclaration::Known: return "known";
    case EvidenceDeclaration::Unknown: return "unknown";
    case EvidenceDeclaration::Unsupported: return "unsupported";
    case EvidenceDeclaration::Unavailable: return "unavailable";
  }
  return "unknown";
}

const char* to_string(EvidenceState state) noexcept {
  switch (state) {
    case EvidenceState::Fresh: return "fresh";
    case EvidenceState::Stale: return "stale";
    case EvidenceState::FutureDated: return "future_dated";
    case EvidenceState::Unknown: return "unknown";
    case EvidenceState::Unsupported: return "unsupported";
    case EvidenceState::Unavailable: return "unavailable";
    case EvidenceState::Contradictory: return "contradictory";
  }
  return "unknown";
}

Result<EvidenceDeclaration> parse_evidence_declaration(std::string_view text) {
  if (text == "known") return EvidenceDeclaration::Known;
  if (text == "unknown") return EvidenceDeclaration::Unknown;
  if (text == "unsupported") return EvidenceDeclaration::Unsupported;
  if (text == "unavailable") return EvidenceDeclaration::Unavailable;
  return Status::error(StatusCode::InvalidArgument, "unrecognized evidence declaration token");
}

Result<EvidenceState> parse_evidence_state(std::string_view text) {
  if (text == "fresh") return EvidenceState::Fresh;
  if (text == "stale") return EvidenceState::Stale;
  if (text == "future_dated") return EvidenceState::FutureDated;
  if (text == "unknown") return EvidenceState::Unknown;
  if (text == "unsupported") return EvidenceState::Unsupported;
  if (text == "unavailable") return EvidenceState::Unavailable;
  if (text == "contradictory") return EvidenceState::Contradictory;
  return Status::error(StatusCode::InvalidArgument, "unrecognized evidence state token");
}

std::ostream& operator<<(std::ostream& stream, EvidenceDeclaration declaration) {
  return stream << to_string(declaration);
}

std::ostream& operator<<(std::ostream& stream, EvidenceState state) {
  return stream << to_string(state);
}

int evidence_state_precedence(EvidenceState state) noexcept {
  // A disputed value is reported before a stale one: a contradiction is a defect
  // in the evidence itself, and it stays a defect however fresh the records are.
  switch (state) {
    case EvidenceState::Contradictory: return 0;
    case EvidenceState::FutureDated: return 1;
    case EvidenceState::Stale: return 2;
    case EvidenceState::Unavailable: return 3;
    case EvidenceState::Unsupported: return 4;
    case EvidenceState::Unknown: return 5;
    case EvidenceState::Fresh: return 6;
  }
  return 5;
}

}  // namespace feed_authority
