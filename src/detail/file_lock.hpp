#pragma once

// Cross-process writer authority.
//
// The lock is an operating-system advisory lock on a dedicated lock file inside
// the store root. It is held only for the duration of one publication, never
// across a callback, and it is released by the operating system when the process
// dies, which is what makes an abruptly terminated writer safe.

#include <cstdint>
#include <filesystem>

#include "feed_authority/status.hpp"

namespace feed_authority::detail {

class FileLock {
 public:
  FileLock() noexcept = default;
  FileLock(FileLock&& other) noexcept;
  FileLock& operator=(FileLock&& other) noexcept;
  FileLock(const FileLock&) = delete;
  FileLock& operator=(const FileLock&) = delete;
  ~FileLock();

  /// Acquires the exclusive lock, waiting at most `budget_nanos` before refusing
  /// with `LockConflict`. The budget is an error bound: a mutation that cannot
  /// acquire authority reports a conflict instead of blocking forever.
  static Result<FileLock> acquire(const std::filesystem::path& path, std::int64_t budget_nanos);

  Status release() noexcept;
  bool held() const noexcept { return native_ != invalid_native(); }

  /// True when this process currently holds the lock for the given file. Used by
  /// the process-authority tests to prove exclusion without a second lock helper.
  static Result<bool> is_held_by_any_process(const std::filesystem::path& path);

 private:
  static std::intptr_t invalid_native() noexcept { return -1; }
  explicit FileLock(std::intptr_t native) noexcept : native_(native) {}
  std::intptr_t native_ = invalid_native();
};

}  // namespace feed_authority::detail
