#pragma once

// Explicit logical time.
//
// The library never reads a clock implicitly. Every evaluation, expiry check and
// freshness check takes the instant it must judge against, so results are
// reproducible and a test can place an observation and an evaluation at exactly
// the instants it wants.

#include <cstdint>
#include <iosfwd>
#include <string>
#include <string_view>

#include "feed_authority/status.hpp"

namespace feed_authority {

/// A non-negative span of time in nanoseconds.
class Duration {
 public:
  constexpr Duration() noexcept = default;

  static Result<Duration> FromNanos(std::int64_t nanos);
  static Result<Duration> FromMillis(std::int64_t millis);
  static Result<Duration> FromSeconds(std::int64_t seconds);
  static Result<Duration> FromMinutes(std::int64_t minutes);
  static Result<Duration> FromHours(std::int64_t hours);

  constexpr std::int64_t nanos() const noexcept { return nanos_; }
  constexpr std::int64_t millis_floor() const noexcept { return nanos_ / 1000000; }
  constexpr bool is_zero() const noexcept { return nanos_ == 0; }

  /// Renders the duration in the largest exact unit, for example "90s", "1500ms",
  /// "250ns".
  std::string to_string() const;

  friend constexpr bool operator==(Duration left, Duration right) noexcept {
    return left.nanos_ == right.nanos_;
  }
  friend constexpr bool operator!=(Duration left, Duration right) noexcept {
    return left.nanos_ != right.nanos_;
  }
  friend constexpr bool operator<(Duration left, Duration right) noexcept {
    return left.nanos_ < right.nanos_;
  }
  friend constexpr bool operator>(Duration left, Duration right) noexcept { return right < left; }
  friend constexpr bool operator<=(Duration left, Duration right) noexcept { return !(right < left); }
  friend constexpr bool operator>=(Duration left, Duration right) noexcept { return !(left < right); }

 private:
  explicit constexpr Duration(std::int64_t nanos) noexcept : nanos_(nanos) {}
  std::int64_t nanos_ = 0;
};

/// An instant on the Unix time line, in nanoseconds. It carries no time zone and
/// no calendar semantics beyond UTC rendering.
class AuthorityTime {
 public:
  /// The zero instant (1970-01-01T00:00:00Z).
  constexpr AuthorityTime() noexcept = default;

  static Result<AuthorityTime> FromUnixNanos(std::int64_t unix_nanos);
  static Result<AuthorityTime> FromUnixMillis(std::int64_t unix_millis);
  static Result<AuthorityTime> FromUnixSeconds(std::int64_t unix_seconds);

  constexpr std::int64_t unix_nanos() const noexcept { return unix_nanos_; }
  constexpr bool is_zero() const noexcept { return unix_nanos_ == 0; }

  /// Checked addition.
  Result<AuthorityTime> Plus(Duration delta) const;
  /// The span from `earlier` to this instant. Fails with `InvalidArgument` when
  /// `earlier` is in the future, because a negative age is not a duration.
  Result<Duration> Since(AuthorityTime earlier) const;

  /// RFC 3339 / ISO 8601 in UTC with nanosecond precision, for example
  /// "2026-03-01T12:00:00.000000000Z".
  std::string to_iso8601() const;
  /// Accepts `to_iso8601` output and the same form without a fractional part or
  /// with 1..9 fractional digits and a literal 'Z'.
  static Result<AuthorityTime> ParseIso8601(std::string_view text);

  friend constexpr bool operator==(AuthorityTime left, AuthorityTime right) noexcept {
    return left.unix_nanos_ == right.unix_nanos_;
  }
  friend constexpr bool operator!=(AuthorityTime left, AuthorityTime right) noexcept {
    return left.unix_nanos_ != right.unix_nanos_;
  }
  friend constexpr bool operator<(AuthorityTime left, AuthorityTime right) noexcept {
    return left.unix_nanos_ < right.unix_nanos_;
  }
  friend constexpr bool operator>(AuthorityTime left, AuthorityTime right) noexcept {
    return right < left;
  }
  friend constexpr bool operator<=(AuthorityTime left, AuthorityTime right) noexcept {
    return !(right < left);
  }
  friend constexpr bool operator>=(AuthorityTime left, AuthorityTime right) noexcept {
    return !(left < right);
  }

 private:
  explicit constexpr AuthorityTime(std::int64_t unix_nanos) noexcept : unix_nanos_(unix_nanos) {}
  std::int64_t unix_nanos_ = 0;
};

std::ostream& operator<<(std::ostream& stream, Duration duration);
std::ostream& operator<<(std::ostream& stream, AuthorityTime instant);

/// Reads the system clock. This is the only place in the library that touches a
/// clock, it is never called implicitly, and callers that need reproducibility
/// (tests, benchmarks, replay) inject their own instant instead.
Result<AuthorityTime> SystemAuthorityTime() noexcept;

}  // namespace feed_authority
