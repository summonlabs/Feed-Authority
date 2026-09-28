#include "feed_authority/obligation.hpp"

namespace feed_authority {

bool ProtectedObligation::applies_to(const LoadDescriptor& load) const noexcept {
  for (const LoadId& candidate : loads) {
    if (candidate == load.id) {
      return true;
    }
  }
  if (load_class && *load_class == load.load_class) {
    return true;
  }
  if (applies_to_protected_loads && load.protected_load) {
    return true;
  }
  return false;
}

}  // namespace feed_authority
