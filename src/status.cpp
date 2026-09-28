#include "feed_authority/status.hpp"

#include <utility>

namespace feed_authority {

const char* to_string(StatusCode code) noexcept {
  switch (code) {
    case StatusCode::Ok: return "ok";
    case StatusCode::InvalidArgument: return "invalid_argument";
    case StatusCode::NotFound: return "not_found";
    case StatusCode::AlreadyExists: return "already_exists";
    case StatusCode::DuplicateIdentity: return "duplicate_identity";
    case StatusCode::Conflict: return "conflict";
    case StatusCode::PreconditionFailed: return "precondition_failed";
    case StatusCode::StaleGeneration: return "stale_generation";
    case StatusCode::StaleAuthority: return "stale_authority";
    case StatusCode::StaleSourceGeneration: return "stale_source_generation";
    case StatusCode::IncompatibleVersion: return "incompatible_version";
    case StatusCode::Corruption: return "corruption";
    case StatusCode::LimitExceeded: return "limit_exceeded";
    case StatusCode::Unsupported: return "unsupported";
    case StatusCode::Unavailable: return "unavailable";
    case StatusCode::Unknown: return "unknown";
    case StatusCode::Indeterminate: return "indeterminate";
    case StatusCode::PermissionDenied: return "permission_denied";
    case StatusCode::IoFailure: return "io_failure";
    case StatusCode::LockConflict: return "lock_conflict";
    case StatusCode::InvariantViolation: return "invariant_violation";
    case StatusCode::NotAuthorized: return "not_authorized";
    case StatusCode::Denied: return "denied";
    case StatusCode::Revoked: return "revoked";
    case StatusCode::Expired: return "expired";
    case StatusCode::NotRevalidated: return "not_revalidated";
    case StatusCode::Closed: return "closed";
    case StatusCode::EndianMismatch: return "endian_mismatch";
    case StatusCode::ReadOnly: return "read_only";
    case StatusCode::AttemptConflict: return "attempt_conflict";
    case StatusCode::AttemptEvicted: return "attempt_evicted";
    case StatusCode::EvidenceStale: return "evidence_stale";
    case StatusCode::EvidenceMissing: return "evidence_missing";
    case StatusCode::RollbackDetected: return "rollback_detected";
    case StatusCode::PathRejected: return "path_rejected";
  }
  return "unrecognized_status_code";
}

Status Status::error(StatusCode code, std::string message) {
  Status status;
  status.code_ = code;
  status.message_ = std::move(message);
  return status;
}

std::string Status::to_string() const {
  if (ok()) {
    return "ok";
  }
  std::string text = feed_authority::to_string(code_);
  if (!message_.empty()) {
    text += ": ";
    text += message_;
  }
  return text;
}

}  // namespace feed_authority
