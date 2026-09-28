#include "feed_authority/digest.hpp"

#include <cstddef>
#include <cstring>
#include <ostream>

namespace feed_authority {
namespace {

constexpr std::uint32_t kRoundConstants[64] = {
    0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u, 0x3956c25bu, 0x59f111f1u, 0x923f82a4u,
    0xab1c5ed5u, 0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u, 0x72be5d74u, 0x80deb1feu,
    0x9bdc06a7u, 0xc19bf174u, 0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu, 0x2de92c6fu,
    0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau, 0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u,
    0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u, 0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu,
    0x53380d13u, 0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u, 0xa2bfe8a1u, 0xa81a664bu,
    0xc24b8b70u, 0xc76c51a3u, 0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u, 0x19a4c116u,
    0x1e376c08u, 0x2748774cu, 0x34b0bcb5u, 0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,
    0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u, 0x90befffau, 0xa4506cebu, 0xbef9a3f7u,
    0xc67178f2u};

inline std::uint32_t rotate_right(std::uint32_t value, std::uint32_t count) noexcept {
  return (value >> count) | (value << (32u - count));
}

inline std::uint32_t load_be(const std::uint8_t* data) noexcept {
  return (static_cast<std::uint32_t>(data[0]) << 24u) | (static_cast<std::uint32_t>(data[1]) << 16u) |
         (static_cast<std::uint32_t>(data[2]) << 8u) | static_cast<std::uint32_t>(data[3]);
}

inline void store_be(std::uint32_t value, std::uint8_t* out) noexcept {
  out[0] = static_cast<std::uint8_t>((value >> 24u) & 0xFFu);
  out[1] = static_cast<std::uint8_t>((value >> 16u) & 0xFFu);
  out[2] = static_cast<std::uint8_t>((value >> 8u) & 0xFFu);
  out[3] = static_cast<std::uint8_t>(value & 0xFFu);
}

}  // namespace

Sha256::Sha256() noexcept {
  state_ = {0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au,
            0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u};
}

void Sha256::process_block(const std::uint8_t* block) noexcept {
  std::uint32_t schedule[64];
  for (std::uint32_t index = 0; index < 16u; ++index) {
    schedule[index] = load_be(block + index * 4u);
  }
  for (std::uint32_t index = 16u; index < 64u; ++index) {
    const std::uint32_t s0 = rotate_right(schedule[index - 15u], 7u) ^
                             rotate_right(schedule[index - 15u], 18u) ^
                             (schedule[index - 15u] >> 3u);
    const std::uint32_t s1 = rotate_right(schedule[index - 2u], 17u) ^
                             rotate_right(schedule[index - 2u], 19u) ^
                             (schedule[index - 2u] >> 10u);
    schedule[index] = schedule[index - 16u] + s0 + schedule[index - 7u] + s1;
  }

  std::uint32_t a = state_[0];
  std::uint32_t b = state_[1];
  std::uint32_t c = state_[2];
  std::uint32_t d0 = state_[3];
  std::uint32_t e = state_[4];
  std::uint32_t f = state_[5];
  std::uint32_t g = state_[6];
  std::uint32_t h = state_[7];

  for (std::uint32_t index = 0; index < 64u; ++index) {
    const std::uint32_t s1 = rotate_right(e, 6u) ^ rotate_right(e, 11u) ^ rotate_right(e, 25u);
    const std::uint32_t choice = (e & f) ^ ((~e) & g);
    const std::uint32_t temp1 = h + s1 + choice + kRoundConstants[index] + schedule[index];
    const std::uint32_t s0 = rotate_right(a, 2u) ^ rotate_right(a, 13u) ^ rotate_right(a, 22u);
    const std::uint32_t majority = (a & b) ^ (a & c) ^ (b & c);
    const std::uint32_t temp2 = s0 + majority;
    h = g;
    g = f;
    f = e;
    e = d0 + temp1;
    d0 = c;
    c = b;
    b = a;
    a = temp1 + temp2;
  }

  state_[0] += a;
  state_[1] += b;
  state_[2] += c;
  state_[3] += d0;
  state_[4] += e;
  state_[5] += f;
  state_[6] += g;
  state_[7] += h;
}

void Sha256::update(std::string_view data) noexcept {
  const std::uint8_t* bytes = reinterpret_cast<const std::uint8_t*>(data.data());
  std::size_t remaining = data.size();
  total_bytes_ += static_cast<std::uint64_t>(remaining);
  while (remaining > 0) {
    const std::size_t space = 64u - static_cast<std::size_t>(buffer_used_);
    const std::size_t chunk = remaining < space ? remaining : space;
    std::memcpy(buffer_.data() + buffer_used_, bytes, chunk);
    buffer_used_ += static_cast<std::uint32_t>(chunk);
    bytes += chunk;
    remaining -= chunk;
    if (buffer_used_ == 64u) {
      process_block(buffer_.data());
      buffer_used_ = 0;
    }
  }
}

Digest Sha256::finish() noexcept {
  const std::uint64_t total_bits = total_bytes_ * 8ull;
  // `update` always drains full blocks, so at most 63 buffered bytes remain.
  buffer_[buffer_used_] = 0x80u;
  ++buffer_used_;
  if (buffer_used_ > 56u) {
    std::memset(buffer_.data() + buffer_used_, 0, 64u - buffer_used_);
    process_block(buffer_.data());
    buffer_used_ = 0;
  }
  std::memset(buffer_.data() + buffer_used_, 0, 56u - buffer_used_);
  for (std::size_t index = 0; index < 8; ++index) {
    buffer_[56u + index] = static_cast<std::uint8_t>((total_bits >> (56u - 8u * index)) & 0xFFu);
  }
  process_block(buffer_.data());
  buffer_used_ = 0;

  Digest::Bytes out{};
  for (std::size_t index = 0; index < 8; ++index) {
    store_be(state_[index], out.data() + index * 4u);
  }
  return Digest(out);
}

Digest Digest::Of(std::string_view content) {
  Sha256 hasher;
  hasher.update(content);
  return hasher.finish();
}

Result<Digest> Digest::ParseHex(std::string_view text) {
  if (text.size() != 64) {
    return Status::error(StatusCode::InvalidArgument, "a digest is exactly 64 hexadecimal characters");
  }
  Bytes bytes{};
  for (std::size_t index = 0; index < 32; ++index) {
    const char high = text[index * 2];
    const char low = text[index * 2 + 1];
    const auto value_of = [](char character) -> int {
      if (character >= '0' && character <= '9') return character - '0';
      if (character >= 'a' && character <= 'f') return character - 'a' + 10;
      if (character >= 'A' && character <= 'F') return character - 'A' + 10;
      return -1;
    };
    const int high_value = value_of(high);
    const int low_value = value_of(low);
    if (high_value < 0 || low_value < 0) {
      return Status::error(StatusCode::InvalidArgument, "a digest contains a non-hexadecimal character");
    }
    bytes[index] = static_cast<std::uint8_t>(high_value * 16 + low_value);
  }
  return Digest(bytes);
}

std::string Digest::hex() const {
  static const char kDigits[] = "0123456789abcdef";
  std::string text(64, '0');
  for (std::size_t index = 0; index < 32; ++index) {
    text[index * 2] = kDigits[(bytes_[index] >> 4u) & 0x0Fu];
    text[index * 2 + 1] = kDigits[bytes_[index] & 0x0Fu];
  }
  return text;
}

bool Digest::is_zero() const noexcept {
  for (const std::uint8_t byte : bytes_) {
    if (byte != 0u) {
      return false;
    }
  }
  return true;
}

std::ostream& operator<<(std::ostream& stream, const Digest& digest) {
  return stream << digest.hex();
}

}  // namespace feed_authority
