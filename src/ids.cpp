#include "feed_authority/ids.hpp"

#include "feed_authority/limits.hpp"

namespace feed_authority {

bool is_valid_identity_text(std::string_view text) noexcept {
  if (text.empty() || text.size() > kMaxIdentityLength) {
    return false;
  }
  if (text.front() == '.' || text.back() == '.') {
    return false;
  }
  bool previous_dot = false;
  for (const char character : text) {
    const bool is_alphanumeric = (character >= '0' && character <= '9') ||
                                 (character >= 'a' && character <= 'z') ||
                                 (character >= 'A' && character <= 'Z');
    if (is_alphanumeric) {
      previous_dot = false;
      continue;
    }
    if (character == '.') {
      if (previous_dot) {
        return false;
      }
      previous_dot = true;
      continue;
    }
    if (character == '-' || character == '_' || character == ':') {
      previous_dot = false;
      continue;
    }
    return false;
  }
  return true;
}

}  // namespace feed_authority
