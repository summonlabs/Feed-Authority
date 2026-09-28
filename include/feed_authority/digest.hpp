#pragma once

#include <array>
#include <cstdint>
#include <iosfwd>
#include <string>
#include <string_view>

#include "feed_authority/status.hpp"

namespace feed_authority {

/// A SHA-256 digest (FIPS 180-4), used for content integrity and canonical
/// fingerprints. The byte order is the natural digest byte order; the textual form
/// is 64 lowercase hexadecimal characters.
class Digest {
 public:
  using Bytes = std::array<std::uint8_t, 32>;

  Digest() noexcept = default;
  explicit Digest(Bytes bytes) noexcept : bytes_(bytes) {}

  static Digest Of(std::string_view content);

  /// Parses exactly 64 lowercase or uppercase hexadecimal characters.
  static Result<Digest> ParseHex(std::string_view text);

  const Bytes& bytes() const noexcept { return bytes_; }
  /// 64 lowercase hexadecimal characters.
  std::string hex() const;
  bool is_zero() const noexcept;

  friend bool operator==(const Digest& left, const Digest& right) noexcept {
    return left.bytes_ == right.bytes_;
  }
  friend bool operator!=(const Digest& left, const Digest& right) noexcept {
    return !(left == right);
  }
  friend bool operator<(const Digest& left, const Digest& right) noexcept {
    return left.bytes_ < right.bytes_;
  }

 private:
  Bytes bytes_{};
};

std::ostream& operator<<(std::ostream& stream, const Digest& digest);

/// Incremental SHA-256. `finish` may be called once; the object is not reusable
/// after it.
class Sha256 {
 public:
  Sha256() noexcept;
  void update(std::string_view data) noexcept;
  Digest finish() noexcept;

 private:
  void process_block(const std::uint8_t* block) noexcept;

  std::array<std::uint32_t, 8> state_{};
  std::array<std::uint8_t, 64> buffer_{};
  std::uint64_t total_bytes_ = 0;
  std::uint32_t buffer_used_ = 0;
};

}  // namespace feed_authority
