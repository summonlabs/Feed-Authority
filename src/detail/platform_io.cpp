#include "detail/platform_io.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdio>
#include <string>
#include <system_error>
#include <vector>

#if defined(_WIN32)
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#else
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#endif

namespace feed_authority::detail {
namespace {

#if defined(_WIN32)

std::wstring native_of(const std::filesystem::path& path) { return path.native(); }

#else

std::string native_of(const std::filesystem::path& path) { return path.native(); }

#endif

}  // namespace

std::string last_os_error_text() {
#if defined(_WIN32)
  const DWORD code = GetLastError();
  if (code == 0) {
    return "no operating system error is pending";
  }
  return "os error " + std::to_string(static_cast<unsigned long>(code));
#else
  const int code = errno;
  if (code == 0) {
    return "no operating system error is pending";
  }
  return "os error " + std::to_string(code) + " (" + std::generic_category().message(code) + ")";
#endif
}

Result<std::string> read_file_bounded(const std::filesystem::path& path, std::uint64_t max_bytes) {
  const Result<std::uint64_t> size = regular_file_size(path);
  if (!size.ok()) {
    return size.status();
  }
  if (size.value() > max_bytes) {
    return Status::error(StatusCode::LimitExceeded, "the file exceeds the configured size bound");
  }
  std::FILE* file = nullptr;
#if defined(_WIN32)
  if (_wfopen_s(&file, native_of(path).c_str(), L"rb") != 0) {
    file = nullptr;
  }
#else
  file = std::fopen(native_of(path).c_str(), "rb");
#endif
  if (file == nullptr) {
    return Status::error(StatusCode::IoFailure, "the file could not be opened for reading");
  }
  std::string bytes;
  bytes.reserve(static_cast<std::size_t>(size.value()));
  char buffer[8192];
  while (true) {
    const std::size_t read = std::fread(buffer, 1, sizeof(buffer), file);
    if (read > 0) {
      bytes.append(buffer, read);
      if (static_cast<std::uint64_t>(bytes.size()) > max_bytes) {
        std::fclose(file);
        return Status::error(StatusCode::LimitExceeded, "the file grew beyond the configured size bound");
      }
    }
    if (read < sizeof(buffer)) {
      if (std::ferror(file) != 0) {
        std::fclose(file);
        return Status::error(StatusCode::IoFailure, "the file could not be read");
      }
      break;
    }
  }
  std::fclose(file);
  if (static_cast<std::uint64_t>(bytes.size()) != size.value()) {
    return Status::error(StatusCode::Corruption, "the file size changed while it was being read");
  }
  return bytes;
}

Status write_file_durable(const std::filesystem::path& path, std::string_view bytes) {
#if defined(_WIN32)
  HANDLE handle = CreateFileW(native_of(path).c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
                              FILE_ATTRIBUTE_NORMAL, nullptr);
  if (handle == INVALID_HANDLE_VALUE) {
    const DWORD code = GetLastError();
    if (code == ERROR_ACCESS_DENIED || code == ERROR_SHARING_VIOLATION) {
      return Status::error(StatusCode::PermissionDenied, "the file could not be opened for writing");
    }
    return Status::error(StatusCode::IoFailure, "the file could not be created for writing");
  }
  std::size_t written_total = 0;
  while (written_total < bytes.size()) {
    const DWORD chunk = static_cast<DWORD>(
        (bytes.size() - written_total) > 0x10000000ull ? 0x10000000ull : (bytes.size() - written_total));
    DWORD written = 0;
    if (WriteFile(handle, bytes.data() + written_total, chunk, &written, nullptr) == 0) {
      CloseHandle(handle);
      return Status::error(StatusCode::IoFailure, "the file could not be written");
    }
    written_total += written;
  }
  if (FlushFileBuffers(handle) == 0) {
    CloseHandle(handle);
    return Status::error(StatusCode::IoFailure, "the file could not be flushed to stable storage");
  }
  CloseHandle(handle);
  return Status::success();
#else
  const int descriptor = ::open(native_of(path).c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0644);
  if (descriptor < 0) {
    return Status::error(StatusCode::IoFailure, "the file could not be created for writing");
  }
  std::size_t written_total = 0;
  while (written_total < bytes.size()) {
    const ssize_t written = ::write(descriptor, bytes.data() + written_total, bytes.size() - written_total);
    if (written <= 0) {
      ::close(descriptor);
      return Status::error(StatusCode::IoFailure, "the file could not be written");
    }
    written_total += static_cast<std::size_t>(written);
  }
  if (::fsync(descriptor) != 0) {
    ::close(descriptor);
    return Status::error(StatusCode::IoFailure, "the file could not be flushed to stable storage");
  }
  ::close(descriptor);
  return Status::success();
#endif
}

Status atomic_replace_file(const std::filesystem::path& from, const std::filesystem::path& to) {
#if defined(_WIN32)
  if (MoveFileExW(native_of(from).c_str(), native_of(to).c_str(),
                  MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH) == 0) {
    return Status::error(StatusCode::IoFailure, "the atomic replacement failed");
  }
  return Status::success();
#else
  if (::rename(native_of(from).c_str(), native_of(to).c_str()) != 0) {
    return Status::error(StatusCode::IoFailure, "the atomic replacement failed");
  }
  return Status::success();
#endif
}

Status rename_file_exclusive(const std::filesystem::path& from, const std::filesystem::path& to) {
#if defined(_WIN32)
  if (MoveFileExW(native_of(from).c_str(), native_of(to).c_str(), 0) == 0) {
    const DWORD code = GetLastError();
    if (code == ERROR_ALREADY_EXISTS || code == ERROR_FILE_EXISTS) {
      return Status::error(StatusCode::AlreadyExists, "the destination already exists");
    }
    return Status::error(StatusCode::IoFailure, "the rename failed");
  }
  return Status::success();
#else
  if (::link(native_of(from).c_str(), native_of(to).c_str()) != 0) {
    if (errno == EEXIST) {
      return Status::error(StatusCode::AlreadyExists, "the destination already exists");
    }
    return Status::error(StatusCode::IoFailure, "the exclusive rename failed");
  }
  if (::unlink(native_of(from).c_str()) != 0) {
    return Status::error(StatusCode::IoFailure, "the staging file could not be removed after the rename");
  }
  return Status::success();
#endif
}

Status remove_file(const std::filesystem::path& path) noexcept {
#if defined(_WIN32)
  if (DeleteFileW(native_of(path).c_str()) == 0) {
    const DWORD code = GetLastError();
    if (code == ERROR_FILE_NOT_FOUND || code == ERROR_PATH_NOT_FOUND) {
      return Status::success();
    }
    return Status::error(StatusCode::IoFailure, "the file could not be removed");
  }
  return Status::success();
#else
  if (::unlink(native_of(path).c_str()) != 0) {
    if (errno == ENOENT) {
      return Status::success();
    }
    return Status::error(StatusCode::IoFailure, "the file could not be removed");
  }
  return Status::success();
#endif
}

bool file_exists(const std::filesystem::path& path) noexcept {
#if defined(_WIN32)
  const DWORD attributes = GetFileAttributesW(native_of(path).c_str());
  return attributes != INVALID_FILE_ATTRIBUTES;
#else
  struct stat info {};
  return ::stat(native_of(path).c_str(), &info) == 0;
#endif
}

Result<std::vector<std::string>> list_directory_names(const std::filesystem::path& path,
                                                      std::uint32_t max_entries) {
  std::vector<std::string> names;
#if defined(_WIN32)
  WIN32_FIND_DATAW data{};
  std::wstring pattern = native_of(path) + L"\\*";
  HANDLE handle = FindFirstFileW(pattern.c_str(), &data);
  if (handle == INVALID_HANDLE_VALUE) {
    return Status::error(StatusCode::IoFailure, "the directory could not be listed");
  }
  do {
    const std::wstring name = data.cFileName;
    if (name == L"." || name == L"..") {
      continue;
    }
    if (names.size() >= max_entries) {
      FindClose(handle);
      return Status::error(StatusCode::LimitExceeded, "the directory holds more entries than the bound allows");
    }
    std::string narrow;
    narrow.reserve(name.size());
    for (const wchar_t character : name) {
      if (character < 0x20 || character > 0x7E) {
        narrow.push_back('?');
      } else {
        narrow.push_back(static_cast<char>(character));
      }
    }
    names.push_back(std::move(narrow));
  } while (FindNextFileW(handle, &data) != 0);
  FindClose(handle);
#else
  DIR* directory = ::opendir(native_of(path).c_str());
  if (directory == nullptr) {
    return Status::error(StatusCode::IoFailure, "the directory could not be listed");
  }
  while (true) {
    errno = 0;
    struct dirent* entry = ::readdir(directory);
    if (entry == nullptr) {
      break;
    }
    const std::string name = entry->d_name;
    if (name == "." || name == "..") {
      continue;
    }
    if (names.size() >= max_entries) {
      ::closedir(directory);
      return Status::error(StatusCode::LimitExceeded, "the directory holds more entries than the bound allows");
    }
    names.push_back(name);
  }
  ::closedir(directory);
#endif
  std::sort(names.begin(), names.end());
  return names;
}

Result<std::uint64_t> regular_file_size(const std::filesystem::path& path) {
#if defined(_WIN32)
  WIN32_FILE_ATTRIBUTE_DATA data{};
  if (GetFileAttributesExW(native_of(path).c_str(), GetFileExInfoStandard, &data) == 0) {
    return Status::error(StatusCode::NotFound, "the file does not exist");
  }
  if ((data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0) {
    return Status::error(StatusCode::PathRejected, "the path is a directory where a file is required");
  }
  if ((data.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0) {
    return Status::error(StatusCode::PathRejected, "the path is a reparse point, not a regular file");
  }
  const std::uint64_t size =
      (static_cast<std::uint64_t>(data.nFileSizeHigh) << 32u) | static_cast<std::uint64_t>(data.nFileSizeLow);
  return size;
#else
  struct stat info {};
  if (::stat(native_of(path).c_str(), &info) != 0) {
    return Status::error(StatusCode::NotFound, "the file does not exist");
  }
  if (S_ISDIR(info.st_mode)) {
    return Status::error(StatusCode::PathRejected, "the path is a directory where a file is required");
  }
  if (!S_ISREG(info.st_mode)) {
    return Status::error(StatusCode::PathRejected, "the path is not a regular file");
  }
  return static_cast<std::uint64_t>(info.st_size);
#endif
}

}  // namespace feed_authority::detail
