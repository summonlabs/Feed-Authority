#pragma once

// Path validation and directory preparation for the store.
//
// Trust model: the store root is chosen by the operator and is the only
// caller-controlled path the library accepts. Everything inside the root is named
// by this library from a fixed vocabulary, so a child name is validated against
// that vocabulary rather than sanitized. The root itself is refused when it
// escapes through "..", when a component is a reserved device name, when a
// component ends in a space or a dot, when it is not a directory, when it is a
// reparse point (symbolic link, junction, mount point) unless the caller accepts
// that explicitly, and when it is longer than the platform allows.

#include <filesystem>
#include <string>
#include <string_view>
#include <vector>

#include "feed_authority/status.hpp"

namespace feed_authority::detail {

/// Validates the textual form of a path before it is used or normalized, so that
/// normalization cannot erase evidence of an attack.
Status validate_path_text(const std::filesystem::path& path, std::string_view what);

/// Validates a store root and prepares it when `create_if_missing` is set.
Status prepare_store_root(const std::filesystem::path& root, bool create_if_missing,
                          bool allow_reparse_root);

/// Validates a store child name against the fixed vocabulary.
Status validate_child_name(std::string_view name);

/// Joins a validated child name onto a validated root.
std::filesystem::path child_path(const std::filesystem::path& root, std::string_view name);

/// Creates `path` when it does not exist and refuses a non-directory in its place.
Status ensure_directory(const std::filesystem::path& path);

/// Refuses a path that exists and is not a regular file.
Status require_regular_file(const std::filesystem::path& path);

/// True when the path exists and is a directory. Named to avoid ambiguity with
/// `std::filesystem::is_directory` under argument-dependent lookup.
Result<bool> path_is_directory(const std::filesystem::path& path);

/// True when the path is a symbolic link, junction, or other reparse point.
Result<bool> path_is_reparse_point(const std::filesystem::path& path);

}  // namespace feed_authority::detail
