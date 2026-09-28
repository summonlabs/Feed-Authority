#include "feed_authority/idempotency.hpp"

namespace feed_authority {

const char* to_string(AttemptKind kind) noexcept {
  switch (kind) {
    case AttemptKind::AdoptInputs: return "adopt_inputs";
    case AttemptKind::IssueGrant: return "issue_grant";
    case AttemptKind::RevokeGrant: return "revoke_grant";
    case AttemptKind::RevalidateGrant: return "revalidate_grant";
    case AttemptKind::AuthorizeEmergency: return "authorize_emergency";
    case AttemptKind::RevokeEmergency: return "revoke_emergency";
  }
  return "issue_grant";
}

Result<AttemptKind> parse_attempt_kind(std::string_view text) {
  if (text == "adopt_inputs") return AttemptKind::AdoptInputs;
  if (text == "issue_grant") return AttemptKind::IssueGrant;
  if (text == "revoke_grant") return AttemptKind::RevokeGrant;
  if (text == "revalidate_grant") return AttemptKind::RevalidateGrant;
  if (text == "authorize_emergency") return AttemptKind::AuthorizeEmergency;
  if (text == "revoke_emergency") return AttemptKind::RevokeEmergency;
  return Status::error(StatusCode::InvalidArgument, "unrecognized attempt kind token");
}

}  // namespace feed_authority
