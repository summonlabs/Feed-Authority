#include "feed_authority/store.hpp"

#include <cstddef>
#include <string>

namespace feed_authority {

bool StoreAuditReport::ok() const noexcept {
  if (!head_present || !head_valid || rollback_suspected) {
    return false;
  }
  for (const GenerationAudit& entry : generations) {
    // Residue is not a failure: an orphan generation and a staging file are the
    // expected remains of an interrupted publication. Anything that claims to be a
    // generation and cannot be read whole is a failure.
    if (entry.classification == "corrupt" || entry.classification == "unexpected") {
      return false;
    }
    if (entry.classification == "head" || entry.classification == "retained") {
      if (!entry.header_ok || !entry.digest_ok || !entry.payload_ok) {
        return false;
      }
    }
  }
  return true;
}

std::string StoreAuditReport::to_string() const {
  std::string text = "store-audit ok=";
  text += ok() ? "true" : "false";
  text += " head=";
  text += head_sequence.str();
  text += " epoch=";
  text += epoch.str();
  text += " generations=";
  text += std::to_string(generations.size());
  text += " staging-residue=";
  text += std::to_string(staging_residue.size());
  text += " unexpected=";
  text += std::to_string(unexpected_entries.size());
  text += " rollback-suspected=";
  text += rollback_suspected ? "true" : "false";
  text += "\n";
  return text;
}

std::string RecoveryReport::to_string() const {
  std::string text = "recovery sequence=";
  text += sequence.str();
  text += " epoch=";
  text += epoch.str();
  text += " incarnation=";
  text += incarnation.str();
  text += " created=";
  text += created_new_store ? "true" : "false";
  text += " grants=";
  text += std::to_string(grants_loaded);
  text += " needing-revalidation=";
  text += std::to_string(grants_needing_revalidation);
  text += " residue=";
  text += residue_present ? "true" : "false";
  text += "\n";
  return text;
}

}  // namespace feed_authority
