#include "detail/store_path.hpp"

#include "detail/platform_io.hpp"

#include <algorithm>
#include <cstddef>
#include <string>
#include <vector>

#if defined(_WIN32)
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#else
#include <sys/stat.h>
#include <unistd.h>
#include <cerrno>
#endif

namespace feed_authority::detail {
namespace {

bool is_reserved_device_name(std::string_view component) {
  std::string upper;
  upper.reserve(component.size());
  for (const char character : component) {
    if (character >= 'a' && character <= 'z') {
      upper.push_back(static_cast<char>(character - 'a' + 'A'));
    } else {
      upper.push_back(character);
    }
  }
  const std::size_t dot = upper.find('.');
  const std::string stem = dot == std::string::npos ? upper : upper.substr(0, dot);
  if (stem == "CON" || stem == "PRN" || stem == "AUX" || stem == "NUL") {
    return true;
  }
  if (stem.size() == 4 && (stem.compare(0, 3, "COM") == 0 || stem.compare(0, 3, "LPT") == 0)) {
    const char digit = stem[3];
    if (digit >= '1' && digit <= '9') {
      return true;
    }
  }
  return false;
}

#if defined(_WIN32)

bool is_surrogate(wchar_t value) { return value >= 0xD800 && value <= 0xDFFF; }

Status validate_native_component(const std::wstring& component, std::string_view what) {
  if (component.empty()) {
    return Status::error(StatusCode::PathRejected, std::string(what) + " has an empty component");
  }
  if (component == L"..") {
    return Status::error(StatusCode::PathRejected, std::string(what) + " contains a traversal component");
  }
  if (component == L".") {
    // A current-directory component is a no-op and never escapes anywhere.
    return Status::success();
  }
  if (component.back() == L' ' || component.back() == L'.') {
    return Status::error(StatusCode::PathRejected,
                         std::string(what) + " has a component ending in a space or a dot");
  }
  for (std::size_t index = 0; index < component.size(); ++index) {
    const wchar_t character = component[index];
    if (character < 0x20 || character == 0x7F) {
      return Status::error(StatusCode::PathRejected, std::string(what) + " contains a control character");
    }
    if (character == L'<' || character == L'>' || character == L':' || character == L'"' ||
        character == L'|' || character == L'?' || character == L'*') {
      return Status::error(StatusCode::PathRejected,
                           std::string(what) + " contains a character the platform reserves");
    }
    if (is_surrogate(character)) {
      const bool high = character >= 0xD800 && character <= 0xDBFF;
      if (high) {
        if (index + 1 >= component.size() || component[index + 1] < 0xDC00 || component[index + 1] > 0xDFFF) {
          return Status::error(StatusCode::PathRejected,
                               std::string(what) + " contains an unpaired surrogate");
        }
        ++index;
      } else {
        return Status::error(StatusCode::PathRejected,
                             std::string(what) + " contains an unpaired surrogate");
      }
    }
  }
  std::string narrow;
  narrow.reserve(component.size());
  for (const wchar_t character : component) {
    narrow.push_back(character <= 0x7E ? static_cast<char>(character) : '?');
  }
  if (is_reserved_device_name(narrow)) {
    return Status::error(StatusCode::PathRejected,
                         std::string(what) + " contains a reserved device name");
  }
  if (component.size() > 255u) {
    return Status::error(StatusCode::PathRejected, std::string(what) + " has an over-long component");
  }
  return Status::success();
}

Status validate_native_path(const std::filesystem::path& path, std::string_view what) {
  const std::wstring native = path.native();
  if (native.empty()) {
    return Status::error(StatusCode::PathRejected, std::string(what) + " is empty");
  }
  if (native.size() > 4096u) {
    return Status::error(StatusCode::PathRejected, std::string(what) + " is longer than the platform allows");
  }
  std::size_t start = 0;
  if (native.size() >= 2u && native[1] == L':') {
    start = 2u;
  }
  while (start < native.size() && (native[start] == L'\\' || native[start] == L'/')) {
    ++start;
  }
  std::size_t index = start;
  while (index <= native.size()) {
    std::size_t end = index;
    while (end < native.size() && native[end] != L'\\' && native[end] != L'/') {
      ++end;
    }
    if (end > index) {
      const Status component = validate_native_component(native.substr(index, end - index), what);
      if (!component.ok()) {
        return component;
      }
    }
    if (end >= native.size()) {
      break;
    }
    index = end + 1u;
  }
  return Status::success();
}

#else

Status validate_utf8(std::string_view text) {
  std::size_t index = 0;
  while (index < text.size()) {
    const unsigned char lead = static_cast<unsigned char>(text[index]);
    std::size_t extra = 0;
    std::uint32_t code_point = 0;
    if (lead < 0x80u) {
      ++index;
      continue;
    } else if ((lead & 0xE0u) == 0xC0u) {
      extra = 1;
      code_point = lead & 0x1Fu;
      if (code_point == 0) {
        return Status::error(StatusCode::PathRejected, "a path contains an overlong UTF-8 sequence");
      }
    } else if ((lead & 0xF0u) == 0xE0u) {
      extra = 2;
      code_point = lead & 0x0Fu;
    } else if ((lead & 0xF8u) == 0xF0u) {
      extra = 3;
      code_point = lead & 0x07u;
    } else {
      return Status::error(StatusCode::PathRejected, "a path is not valid UTF-8");
    }
    if (index + extra >= text.size()) {
      return Status::error(StatusCode::PathRejected, "a path ends inside a UTF-8 sequence");
    }
    for (std::size_t offset = 1; offset <= extra; ++offset) {
      const unsigned char continuation = static_cast<unsigned char>(text[index + offset]);
      if ((continuation & 0xC0u) != 0x80u) {
        return Status::error(StatusCode::PathRejected, "a path is not valid UTF-8");
      }
      code_point = (code_point << 6u) | (continuation & 0x3Fu);
    }
    if ((extra == 2 && code_point < 0x800u) || (extra == 3 && code_point < 0x10000u) ||
        code_point > 0x10FFFFu || (code_point >= 0xD800u && code_point <= 0xDFFFu)) {
      return Status::error(StatusCode::PathRejected, "a path is not valid UTF-8");
    }
    index += extra + 1u;
  }
  return Status::success();
}

Status validate_native_path(const std::filesystem::path& path, std::string_view what) {
  const std::string native = path.native();
  if (native.empty()) {
    return Status::error(StatusCode::PathRejected, std::string(what) + " is empty");
  }
  if (native.size() > 4096u) {
    return Status::error(StatusCode::PathRejected, std::string(what) + " is longer than the platform allows");
  }
  const Status utf8 = validate_utf8(native);
  if (!utf8.ok()) {
    return utf8;
  }
  std::size_t index = 0;
  while (index <= native.size()) {
    std::size_t end = native.find('/', index);
    if (end == std::string::npos) {
      end = native.size();
    }
    const std::string_view component(native.data() + index, end - index);
    if (!component.empty()) {
      if (component == "..") {
        return Status::error(StatusCode::PathRejected, std::string(what) + " contains a traversal component");
      }
      if (component != "." && component.back() == ' ') {
        return Status::error(StatusCode::PathRejected, std::string(what) + " has a component ending in a space");
      }
      for (const char character : component) {
        if (static_cast<unsigned char>(character) < 0x20u || character == 0x7F) {
          return Status::error(StatusCode::PathRejected, std::string(what) + " contains a control character");
        }
      }
      if (is_reserved_device_name(component)) {
        return Status::error(StatusCode::PathRejected, std::string(what) + " contains a reserved device name");
      }
      if (component.size() > 255u) {
        return Status::error(StatusCode::PathRejected, std::string(what) + " has an over-long component");
      }
    }
    if (end >= native.size()) {
      break;
    }
    index = end + 1u;
  }
  return Status::success();
}

#endif

}  // namespace

Status validate_path_text(const std::filesystem::path& path, std::string_view what) {
  return validate_native_path(path, what);
}

Status validate_child_name(std::string_view name) {
  if (name.empty() || name.size() > 64u) {
    return Status::error(StatusCode::PathRejected, "a store child name is empty or too long");
  }
  for (const char character : name) {
    const bool alnum = (character >= '0' && character <= '9') ||
                       (character >= 'a' && character <= 'z') ||
                       (character >= 'A' && character <= 'Z');
    if (!alnum && character != '.' && character != '-' && character != '_') {
      return Status::error(StatusCode::PathRejected, "a store child name contains an unexpected character");
    }
  }
  if (name == "." || name == "..") {
    return Status::error(StatusCode::PathRejected, "a store child name is a traversal component");
  }
  if (is_reserved_device_name(name)) {
    return Status::error(StatusCode::PathRejected, "a store child name is a reserved device name");
  }
  return Status::success();
}

std::filesystem::path child_path(const std::filesystem::path& root, std::string_view name) {
  return root / std::filesystem::path(std::string(name));
}

Status prepare_store_root(const std::filesystem::path& root, bool create_if_missing,
                          bool allow_reparse_root) {
  const Status valid = validate_path_text(root, "the store root");
  if (!valid.ok()) {
    return valid;
  }
  if (root.filename().empty() && root.has_parent_path()) {
    return Status::error(StatusCode::PathRejected, "the store root ends with a separator");
  }
  const bool exists = file_exists(root);
  if (!exists) {
    if (!create_if_missing) {
      return Status::error(StatusCode::NotFound, "the store root does not exist");
    }
    const std::filesystem::path parent = root.parent_path();
    if (!parent.empty()) {
      const Result<bool> parent_is_directory = path_is_directory(parent);
      if (!parent_is_directory.ok() || !parent_is_directory.value()) {
        return Status::error(StatusCode::NotFound, "the parent of the store root is not an existing directory");
      }
    }
    std::error_code error;
    if (!std::filesystem::create_directory(root, error) || error) {
      return Status::error(StatusCode::IoFailure, "the store root could not be created");
    }
  }
  const Result<bool> directory = path_is_directory(root);
  if (!directory.ok()) {
    return directory.status();
  }
  if (!directory.value()) {
    return Status::error(StatusCode::PathRejected, "the store root exists and is not a directory");
  }
  const Result<bool> reparse = path_is_reparse_point(root);
  if (!reparse.ok()) {
    return reparse.status();
  }
  if (reparse.value() && !allow_reparse_root) {
    return Status::error(StatusCode::PathRejected,
                         "the store root is a symbolic link, junction or other reparse point");
  }
  return Status::success();
}

Status ensure_directory(const std::filesystem::path& path) {
  const Status valid = validate_path_text(path, "a store directory");
  if (!valid.ok()) {
    return valid;
  }
  if (!file_exists(path)) {
    std::error_code error;
    if (!std::filesystem::create_directory(path, error) || error) {
      return Status::error(StatusCode::IoFailure, "the store directory could not be created");
    }
    return Status::success();
  }
  const Result<bool> directory = path_is_directory(path);
  if (!directory.ok()) {
    return directory.status();
  }
  if (!directory.value()) {
    return Status::error(StatusCode::PathRejected, "a file exists where the store needs a directory");
  }
  return Status::success();
}

Status require_regular_file(const std::filesystem::path& path) {
  if (!file_exists(path)) {
    return Status::error(StatusCode::NotFound, "the file does not exist");
  }
  const Result<std::uint64_t> size = regular_file_size(path);
  if (!size.ok()) {
    return size.status();
  }
  return Status::success();
}

Result<bool> path_is_directory(const std::filesystem::path& path) {
#if defined(_WIN32)
  const DWORD attributes = GetFileAttributesW(path.native().c_str());
  if (attributes == INVALID_FILE_ATTRIBUTES) {
    const DWORD code = GetLastError();
    if (code == ERROR_FILE_NOT_FOUND || code == ERROR_PATH_NOT_FOUND) {
      return false;
    }
    return Status::error(StatusCode::IoFailure, "the path could not be inspected");
  }
  return (attributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
#else
  struct stat info {};
  if (::stat(path.native().c_str(), &info) != 0) {
    if (errno == ENOENT) {
      return false;
    }
    return Status::error(StatusCode::IoFailure, "the path could not be inspected");
  }
  return S_ISDIR(info.st_mode);
#endif
}

Result<bool> path_is_reparse_point(const std::filesystem::path& path) {
#if defined(_WIN32)
  const DWORD attributes = GetFileAttributesW(path.native().c_str());
  if (attributes == INVALID_FILE_ATTRIBUTES) {
    const DWORD code = GetLastError();
    if (code == ERROR_FILE_NOT_FOUND || code == ERROR_PATH_NOT_FOUND) {
      return false;
    }
    return Status::error(StatusCode::IoFailure, "the path could not be inspected");
  }
  return (attributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0;
#else
  struct stat info {};
  if (::lstat(path.native().c_str(), &info) != 0) {
    if (errno == ENOENT) {
      return false;
    }
    return Status::error(StatusCode::IoFailure, "the path could not be inspected");
  }
  return S_ISLNK(info.st_mode);
#endif
}

}  // namespace feed_authority::detail
