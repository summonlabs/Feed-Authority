#include "detail/file_lock.hpp"

#include <chrono>
#include <cstdint>
#include <thread>
#include <utility>

#if defined(_WIN32)
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#else
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#endif

namespace feed_authority::detail {
namespace {

void pause_briefly(std::uint32_t attempt) noexcept {
  // Bounded backoff: one millisecond doubling to eight milliseconds. The budget
  // bounds the wait; this only avoids a hot spin.
  std::uint32_t millis = 1u;
  for (std::uint32_t index = 0; index < attempt && millis < 8u; ++index) {
    millis *= 2u;
  }
  std::this_thread::sleep_for(std::chrono::milliseconds(millis));
}

}  // namespace

FileLock::FileLock(FileLock&& other) noexcept : native_(other.native_) {
  other.native_ = invalid_native();
}

FileLock& FileLock::operator=(FileLock&& other) noexcept {
  if (this != &other) {
    const Status released = release();
    (void)released;
    native_ = other.native_;
    other.native_ = invalid_native();
  }
  return *this;
}

FileLock::~FileLock() {
  const Status released = release();
  (void)released;
}

Status FileLock::release() noexcept {
  if (native_ == invalid_native()) {
    return Status::success();
  }
#if defined(_WIN32)
  OVERLAPPED overlapped{};
  UnlockFileEx(reinterpret_cast<HANDLE>(native_), 0, 1, 0, &overlapped);
  CloseHandle(reinterpret_cast<HANDLE>(native_));
#else
  struct flock lock {};
  lock.l_type = F_UNLCK;
  lock.l_whence = SEEK_SET;
  lock.l_start = 0;
  lock.l_len = 0;
  ::fcntl(static_cast<int>(native_), F_SETLK, &lock);
  ::close(static_cast<int>(native_));
#endif
  native_ = invalid_native();
  return Status::success();
}

Result<FileLock> FileLock::acquire(const std::filesystem::path& path, std::int64_t budget_nanos) {
  if (budget_nanos <= 0) {
    return Status::error(StatusCode::InvalidArgument, "the lock acquisition budget must be positive");
  }
  const auto start = std::chrono::steady_clock::now();
  std::uint32_t attempt = 0;
  while (true) {
#if defined(_WIN32)
    HANDLE handle = CreateFileW(path.native().c_str(), GENERIC_READ | GENERIC_WRITE,
                                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
                                OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (handle == INVALID_HANDLE_VALUE) {
      const DWORD code = GetLastError();
      if (code == ERROR_ACCESS_DENIED || code == ERROR_SHARING_VIOLATION) {
        return Status::error(StatusCode::PermissionDenied, "the lock file could not be opened");
      }
      return Status::error(StatusCode::IoFailure, "the lock file could not be opened");
    }
    OVERLAPPED overlapped{};
    if (LockFileEx(handle, LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, &overlapped) != 0) {
      return FileLock(reinterpret_cast<std::intptr_t>(handle));
    }
    const DWORD lock_error = GetLastError();
    CloseHandle(handle);
    if (lock_error != ERROR_LOCK_VIOLATION && lock_error != ERROR_IO_PENDING) {
      return Status::error(StatusCode::IoFailure, "the lock could not be acquired");
    }
#else
    const int descriptor = ::open(path.native().c_str(), O_RDWR | O_CREAT, 0644);
    if (descriptor < 0) {
      if (errno == EACCES || errno == EPERM) {
        return Status::error(StatusCode::PermissionDenied, "the lock file could not be opened");
      }
      return Status::error(StatusCode::IoFailure, "the lock file could not be opened");
    }
    struct flock lock {};
    lock.l_type = F_WRLCK;
    lock.l_whence = SEEK_SET;
    lock.l_start = 0;
    lock.l_len = 0;
    if (::fcntl(descriptor, F_SETLK, &lock) == 0) {
      return FileLock(static_cast<std::intptr_t>(descriptor));
    }
    const int lock_error = errno;
    ::close(descriptor);
    if (lock_error != EACCES && lock_error != EAGAIN) {
      return Status::error(StatusCode::IoFailure, "the lock could not be acquired");
    }
#endif
    const auto elapsed = std::chrono::steady_clock::now() - start;
    const auto elapsed_nanos =
        std::chrono::duration_cast<std::chrono::nanoseconds>(elapsed).count();
    if (elapsed_nanos >= budget_nanos) {
      return Status::error(StatusCode::LockConflict,
                           "another writer session holds the store lock");
    }
    pause_briefly(attempt);
    ++attempt;
  }
}

Result<bool> FileLock::is_held_by_any_process(const std::filesystem::path& path) {
#if defined(_WIN32)
  HANDLE handle = CreateFileW(path.native().c_str(), GENERIC_READ | GENERIC_WRITE,
                              FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
                              OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
  if (handle == INVALID_HANDLE_VALUE) {
    const DWORD code = GetLastError();
    if (code == ERROR_SHARING_VIOLATION || code == ERROR_ACCESS_DENIED) {
      return true;
    }
    return Status::error(StatusCode::IoFailure, "the lock file could not be opened");
  }
  OVERLAPPED overlapped{};
  const bool free = LockFileEx(handle, LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0,
                               &overlapped) != 0;
  if (free) {
    OVERLAPPED unlock{};
    UnlockFileEx(handle, 0, 1, 0, &unlock);
  }
  CloseHandle(handle);
  return !free;
#else
  const int descriptor = ::open(path.native().c_str(), O_RDWR | O_CREAT, 0644);
  if (descriptor < 0) {
    return Status::error(StatusCode::IoFailure, "the lock file could not be opened");
  }
  struct flock lock {};
  lock.l_type = F_WRLCK;
  lock.l_whence = SEEK_SET;
  lock.l_start = 0;
  lock.l_len = 0;
  const bool free = ::fcntl(descriptor, F_SETLK, &lock) == 0;
  if (free) {
    lock.l_type = F_UNLCK;
    ::fcntl(descriptor, F_SETLK, &lock);
  }
  ::close(descriptor);
  return !free;
#endif
}

}  // namespace feed_authority::detail
