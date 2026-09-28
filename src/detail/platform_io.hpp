#pragma once

// Narrow operating-system abstractions.
//
// Everything here has a documented Windows implementation and a documented POSIX
// implementation. Nothing in this header is allowed to change the meaning of a
// publication step: durable write means the bytes reached stable storage, atomic
// replace means a reader sees either the old file or the new file and never a
// mixture.

#include <cstdint>
#include <filesystem>
#include <string>
#include <string_view>
#include <vector>

#include "feed_authority/status.hpp"

namespace feed_authority::detail {

/// Reads a file whole, refusing anything larger than `max_bytes` and anything that
/// is not a regular file.
Result<std::string> read_file_bounded(const std::filesystem::path& path, std::uint64_t max_bytes);

/// Writes `bytes` to `path` and flushes them to stable storage before returning.
Status write_file_durable(const std::filesystem::path& path, std::string_view bytes);

/// Atomically replaces `to` with `from`. The destination must not be a directory.
/// On Windows this is `MoveFileExW` with `MOVEFILE_REPLACE_EXISTING` and
/// `MOVEFILE_WRITE_THROUGH`; on POSIX it is `rename` followed by a directory sync.
Status atomic_replace_file(const std::filesystem::path& from, const std::filesystem::path& to);

/// Renames `from` to `to` and refuses when `to` already exists.
Status rename_file_exclusive(const std::filesystem::path& from, const std::filesystem::path& to);

Status remove_file(const std::filesystem::path& path) noexcept;

bool file_exists(const std::filesystem::path& path) noexcept;

/// Sorted names of the entries in `path`, bounded. Directories are returned with
/// no trailing separator; nothing is followed.
Result<std::vector<std::string>> list_directory_names(const std::filesystem::path& path,
                                                      std::uint32_t max_entries);

/// Size of a regular file, refusing a directory and refusing a reparse point.
Result<std::uint64_t> regular_file_size(const std::filesystem::path& path);

/// A short, stable description of the last operating-system error.
std::string last_os_error_text();

}  // namespace feed_authority::detail
