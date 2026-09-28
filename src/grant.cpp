#include "feed_authority/grant.hpp"

#include <ostream>

namespace feed_authority {

const char* to_string(GrantUsability value) noexcept {
  switch (value) {
    case GrantUsability::Usable: return "usable";
    case GrantUsability::Revoked: return "revoked";
    case GrantUsability::Expired: return "expired";
    case GrantUsability::Superseded: return "superseded";
    case GrantUsability::NeedsRevalidation: return "needs_revalidation";
    case GrantUsability::EvidenceWithdrawn: return "evidence_withdrawn";
  }
  return "needs_revalidation";
}

std::ostream& operator<<(std::ostream& stream, GrantUsability value) {
  return stream << to_string(value);
}

}  // namespace feed_authority
