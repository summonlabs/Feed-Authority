#pragma once

// Checked integer arithmetic for every authoritative calculation.

#include <cstdint>
#include <limits>
#include <string>

#include "feed_authority/status.hpp"

namespace feed_authority::detail {

inline bool add_overflow(std::uint64_t left, std::uint64_t right, std::uint64_t& out) noexcept {
#if defined(__GNUC__) || defined(__clang__)
  return __builtin_add_overflow(left, right, &out);
#else
  out = left + right;
  return out < left;
#endif
}

inline bool mul_overflow(std::uint64_t left, std::uint64_t right, std::uint64_t& out) noexcept {
#if defined(__GNUC__) || defined(__clang__)
  return __builtin_mul_overflow(left, right, &out);
#else
  if (left != 0 && right > (std::numeric_limits<std::uint64_t>::max() / left)) {
    return true;
  }
  out = left * right;
  return false;
#endif
}

inline bool add_overflow(std::int64_t left, std::int64_t right, std::int64_t& out) noexcept {
#if defined(__GNUC__) || defined(__clang__)
  return __builtin_add_overflow(left, right, &out);
#else
  if ((right > 0 && left > std::numeric_limits<std::int64_t>::max() - right) ||
      (right < 0 && left < std::numeric_limits<std::int64_t>::min() - right)) {
    return true;
  }
  out = left + right;
  return false;
#endif
}

inline bool mul_overflow(std::int64_t left, std::int64_t right, std::int64_t& out) noexcept {
#if defined(__GNUC__) || defined(__clang__)
  return __builtin_mul_overflow(left, right, &out);
#else
  if (left == 0 || right == 0) {
    out = 0;
    return false;
  }
  const bool negative = (left < 0) != (right < 0);
  const std::int64_t max_value = std::numeric_limits<std::int64_t>::max();
  const std::int64_t min_value = std::numeric_limits<std::int64_t>::min();
  if (left > 0 && right > 0 && left > max_value / right) {
    return true;
  }
  if (left > 0 && right < 0 && right < min_value / left) {
    return true;
  }
  if (left < 0 && right > 0 && left < min_value / right) {
    return true;
  }
  if (left < 0 && right < 0 && left < max_value / right) {
    return true;
  }
  out = left * right;
  (void)negative;
  return false;
#endif
}

/// Converts a size to `std::uint32_t`, refusing a value that does not fit.
inline Result<std::uint32_t> to_u32(std::uint64_t value, const char* what) {
  if (value > std::numeric_limits<std::uint32_t>::max()) {
    return Status::error(StatusCode::LimitExceeded, std::string(what) + " does not fit in 32 bits");
  }
  return static_cast<std::uint32_t>(value);
}

/// Converts a size to `std::uint64_t`.
inline std::uint64_t to_u64(std::size_t value) noexcept {
  return static_cast<std::uint64_t>(value);
}

}  // namespace feed_authority::detail
