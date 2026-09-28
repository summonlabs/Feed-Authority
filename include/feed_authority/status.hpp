#pragma once

#include <cstdint>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>

namespace feed_authority {

/// Stable machine-readable outcome codes.
///
/// The numeric values are part of the public contract and are never reused. The
/// textual tokens returned by `to_string` are also stable and are safe to match on.
enum class StatusCode : std::int32_t {
  Ok = 0,
  /// A caller-supplied argument is malformed, out of range, or self-inconsistent.
  InvalidArgument = 1,
  /// A referenced identity does not exist in the authoritative state.
  NotFound = 2,
  /// A create-only mutation found the identity already present.
  AlreadyExists = 3,
  /// The same identity was declared twice inside one input.
  DuplicateIdentity = 4,
  /// The request conflicts with another authoritative fact or authority binding.
  Conflict = 5,
  /// An explicit precondition supplied by the caller does not hold.
  PreconditionFailed = 6,
  /// The caller cited a decision generation that is no longer the current one.
  StaleGeneration = 7,
  /// The caller cited an authority epoch, incarnation, or writer session that is
  /// no longer authoritative.
  StaleAuthority = 8,
  /// The caller cited an external source generation (topology, policy, control or
  /// evidence revision) that has since advanced.
  StaleSourceGeneration = 9,
  /// The artifact is a recognizable but unsupported format version.
  IncompatibleVersion = 10,
  /// The artifact failed an integrity or structural check.
  Corruption = 11,
  /// A declared or observed size exceeds a configured bound.
  LimitExceeded = 12,
  /// The capability is deliberately outside this runtime's systems boundary.
  Unsupported = 13,
  /// The referenced object exists but cannot be used now.
  Unavailable = 14,
  /// The value cannot be determined from the available authority or evidence.
  Unknown = 15,
  /// Evidence exists but is contradictory or incomplete in a way that leaves the
  /// value indeterminate; it must not be treated as zero or as a known value.
  Indeterminate = 16,
  /// The operating system refused access to a required resource.
  PermissionDenied = 17,
  /// A file, directory, or device operation failed.
  IoFailure = 18,
  /// Another process or instance holds the store writer authority.
  LockConflict = 19,
  /// An internal consistency guarantee of the authority model was violated.
  InvariantViolation = 20,
  /// No explicit matching rule or authority path permits the load/feed pair.
  NotAuthorized = 21,
  /// An explicit rule or obligation denies the load/feed pair.
  Denied = 22,
  /// The grant was revoked and may not be used.
  Revoked = 23,
  /// The grant or authorization is outside its validity window.
  Expired = 24,
  /// Recovered state has not been revalidated against current inputs, so it may
  /// not authorize anything.
  NotRevalidated = 25,
  /// The store handle has been closed.
  Closed = 26,
  /// The artifact encodes multi-byte integers in the opposite byte order.
  EndianMismatch = 27,
  /// A mutating operation was refused because the store is read-only.
  ReadOnly = 28,
  /// The attempt identity was reused with a different request fingerprint.
  AttemptConflict = 29,
  /// The attempt identity is outside the retained idempotency window, so the prior
  /// result can no longer be replayed.
  AttemptEvicted = 30,
  /// Evidence exists but is outside its validity window at the requested instant.
  EvidenceStale = 31,
  /// A required evidence record was not supplied at all.
  EvidenceMissing = 32,
  /// The store head is older than generations present in the store, or older than
  /// the monotonic authority the caller requires.
  RollbackDetected = 33,
  /// A filesystem path was refused by the path-safety checks.
  PathRejected = 34,
};

/// Stable textual token for a status code, using lower_snake_case.
const char* to_string(StatusCode code) noexcept;

/// A status value: `Ok` or a typed error with a human-readable detail message.
class Status {
 public:
  Status() noexcept = default;

  static Status success() noexcept { return Status{}; }
  static Status error(StatusCode code, std::string message);

  bool ok() const noexcept { return code_ == StatusCode::Ok; }
  explicit operator bool() const noexcept { return ok(); }
  StatusCode code() const noexcept { return code_; }
  const std::string& message() const noexcept { return message_; }

  /// `token` or `token: message`.
  std::string to_string() const;

 private:
  StatusCode code_ = StatusCode::Ok;
  std::string message_;
};

/// A value or a typed error. Constructing from a non-Ok `Status` yields an error
/// result; the value is never observable in that case.
template <typename T>
class Result {
 public:
  Result(T value) : value_(std::move(value)) {}          // NOLINT(google-explicit-constructor)
  Result(Status status) : status_(std::move(status)) {}  // NOLINT(google-explicit-constructor)

  bool ok() const noexcept { return status_.ok(); }
  explicit operator bool() const noexcept { return ok(); }
  const Status& status() const noexcept { return status_; }

  const T& value() const {
    if (!status_.ok()) {
      throw std::logic_error("feed_authority::Result::value() on error: " + status_.to_string());
    }
    return *value_;
  }
  T& value() {
    if (!status_.ok()) {
      throw std::logic_error("feed_authority::Result::value() on error: " + status_.to_string());
    }
    return *value_;
  }
  const T& operator*() const { return value(); }
  T& operator*() { return value(); }
  const T* operator->() const { return &value(); }
  T* operator->() { return &value(); }

  /// The value when present, otherwise `fallback`.
  const T& value_or(const T& fallback) const noexcept { return value_ ? *value_ : fallback; }

 private:
  std::optional<T> value_{};
  Status status_{};
};

}  // namespace feed_authority
