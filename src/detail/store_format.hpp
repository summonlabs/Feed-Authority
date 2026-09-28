#pragma once

// The on-disk generation and head formats.
//
// Both are fixed-layout little-endian binary files with an explicit magic, format
// version, declared sizes and a SHA-256 integrity digest, and both are rejected
// whole when anything about them is wrong. The formats are documented in
// docs/artifact-format.md.

#include <cstdint>
#include <string>
#include <string_view>

#include "feed_authority/digest.hpp"
#include "feed_authority/generations.hpp"
#include "feed_authority/limits.hpp"
#include "feed_authority/status.hpp"
#include "feed_authority/time.hpp"

namespace feed_authority::detail {

inline constexpr std::string_view kGenerationMagic = "FEEDAUTH";
inline constexpr std::string_view kGenerationTrailerMagic = "FAEND001";
inline constexpr std::string_view kHeadMagic = "FAHEAD01";

inline constexpr std::uint32_t kStoreFormatVersion = 1;

inline constexpr std::uint64_t kGenerationHeaderSize = 72;
inline constexpr std::uint64_t kGenerationTrailerSize = 16;
inline constexpr std::uint64_t kHeadHeaderSize = 24;
inline constexpr std::uint64_t kHeadBodySize = 152;
inline constexpr std::uint64_t kHeadTotalSize = kHeadHeaderSize + kHeadBodySize;
inline constexpr std::uint64_t kGenerationNameBytes = 32;
/// "gen-" + 19 digits + ".fas"
inline constexpr std::uint64_t kGenerationNameLength = 27;

struct HeadRecord {
  StoreSequence sequence{};
  AuthorityEpoch epoch{};
  AuthorityTime committed_at{};
  std::string generation_file;
  Digest generation_digest;
  Digest previous_head_digest;
  /// SHA-256 over the whole head file, so a torn or edited head is detected.
  Digest head_digest;
};

/// Encodes a generation file from canonical payload bytes.
std::string encode_generation(const std::string& payload);

/// Verifies and unwraps a generation file, returning its payload.
Result<std::string> decode_generation(std::string_view bytes, const Limits& limits);

std::string encode_head(const HeadRecord& head);

/// Verifies and unwraps a head marker file. The returned record carries the
/// self-digest that was verified.
Result<HeadRecord> decode_head(std::string_view bytes);

/// "gen-0000000000000000042.fas"
std::string generation_file_name(StoreSequence sequence);

/// Parses a generation file name, refusing anything that is not exactly the
/// canonical form (including a name with leading zeros removed or extra text).
Result<StoreSequence> parse_generation_file_name(std::string_view name);

}  // namespace feed_authority::detail
