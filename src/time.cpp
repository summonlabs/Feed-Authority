#include "feed_authority/time.hpp"

#include <chrono>
#include <cstdio>
#include <cstddef>
#include <ostream>
#include <string>

#include "detail/checked.hpp"

namespace feed_authority {
namespace {

constexpr std::int64_t kNanosPerSecond = 1000000000ll;
constexpr std::int64_t kNanosPerMilli = 1000000ll;
constexpr std::int64_t kNanosPerMinute = 60ll * kNanosPerSecond;
constexpr std::int64_t kNanosPerHour = 60ll * kNanosPerMinute;
constexpr std::int64_t kNanosPerDay = 24ll * kNanosPerHour;

Result<Duration> scaled(std::int64_t count, std::int64_t unit) {
  if (count < 0) {
    return Status::error(StatusCode::InvalidArgument, "a duration cannot be negative");
  }
  std::int64_t nanos = 0;
  if (detail::mul_overflow(count, unit, nanos)) {
    return Status::error(StatusCode::LimitExceeded, "duration does not fit in nanoseconds");
  }
  return Duration::FromNanos(nanos);
}

/// Days from 1970-01-01 to a civil date (Howard Hinnant's algorithm).
std::int64_t days_from_civil(std::int64_t year, unsigned month, unsigned day) noexcept {
  year -= month <= 2u ? 1ll : 0ll;
  const std::int64_t era = (year >= 0 ? year : year - 399ll) / 400ll;
  const unsigned year_of_era = static_cast<unsigned>(year - era * 400ll);
  const unsigned day_of_year =
      (153u * (month > 2u ? month - 3u : month + 9u) + 2u) / 5u + day - 1u;
  const unsigned day_of_era =
      year_of_era * 365u + year_of_era / 4u - year_of_era / 100u + day_of_year;
  return era * 146097ll + static_cast<std::int64_t>(day_of_era) - 719468ll;
}

void civil_from_days(std::int64_t days, std::int64_t& year, unsigned& month, unsigned& day) noexcept {
  const std::int64_t shifted = days + 719468ll;
  const std::int64_t era = (shifted >= 0 ? shifted : shifted - 146096ll) / 146097ll;
  const unsigned day_of_era = static_cast<unsigned>(shifted - era * 146097ll);
  const unsigned year_of_era =
      (day_of_era - day_of_era / 1460u + day_of_era / 36524u - day_of_era / 146096u) / 365u;
  year = static_cast<std::int64_t>(year_of_era) + era * 400ll;
  const unsigned day_of_year =
      day_of_era - (365u * year_of_era + year_of_era / 4u - year_of_era / 100u);
  const unsigned month_prime = (5u * day_of_year + 2u) / 153u;
  day = day_of_year - (153u * month_prime + 2u) / 5u + 1u;
  month = month_prime < 10u ? month_prime + 3u : month_prime - 9u;
  year += month <= 2u ? 1ll : 0ll;
}

bool is_leap_year(std::int64_t year) noexcept {
  return (year % 4ll == 0ll && year % 100ll != 0ll) || year % 400ll == 0ll;
}

unsigned days_in_month(std::int64_t year, unsigned month) noexcept {
  static const unsigned table[12] = {31u, 28u, 31u, 30u, 31u, 30u, 31u, 31u, 30u, 31u, 30u, 31u};
  if (month == 2u && is_leap_year(year)) {
    return 29u;
  }
  return table[month - 1u];
}

}  // namespace

Result<Duration> Duration::FromNanos(std::int64_t nanos) {
  if (nanos < 0) {
    return Status::error(StatusCode::InvalidArgument, "a duration cannot be negative");
  }
  return Duration(nanos);
}

Result<Duration> Duration::FromMillis(std::int64_t millis) { return scaled(millis, kNanosPerMilli); }
Result<Duration> Duration::FromSeconds(std::int64_t seconds) { return scaled(seconds, kNanosPerSecond); }
Result<Duration> Duration::FromMinutes(std::int64_t minutes) { return scaled(minutes, kNanosPerMinute); }
Result<Duration> Duration::FromHours(std::int64_t hours) { return scaled(hours, kNanosPerHour); }

std::string Duration::to_string() const {
  const std::int64_t value = nanos_;
  if (value == 0) {
    return "0ns";
  }
  if (value % kNanosPerDay == 0) {
    return std::to_string(value / kNanosPerDay) + "d";
  }
  if (value % kNanosPerHour == 0) {
    return std::to_string(value / kNanosPerHour) + "h";
  }
  if (value % kNanosPerMinute == 0) {
    return std::to_string(value / kNanosPerMinute) + "m";
  }
  if (value % kNanosPerSecond == 0) {
    return std::to_string(value / kNanosPerSecond) + "s";
  }
  if (value % kNanosPerMilli == 0) {
    return std::to_string(value / kNanosPerMilli) + "ms";
  }
  return std::to_string(value) + "ns";
}

Result<AuthorityTime> AuthorityTime::FromUnixNanos(std::int64_t unix_nanos) {
  if (unix_nanos < 0) {
    return Status::error(StatusCode::InvalidArgument, "an instant cannot be negative");
  }
  return AuthorityTime(unix_nanos);
}

Result<AuthorityTime> AuthorityTime::FromUnixMillis(std::int64_t unix_millis) {
  std::int64_t nanos = 0;
  if (unix_millis < 0 || detail::mul_overflow(unix_millis, kNanosPerMilli, nanos)) {
    return Status::error(StatusCode::InvalidArgument, "milliseconds are out of range");
  }
  return AuthorityTime(nanos);
}

Result<AuthorityTime> AuthorityTime::FromUnixSeconds(std::int64_t unix_seconds) {
  std::int64_t nanos = 0;
  if (unix_seconds < 0 || detail::mul_overflow(unix_seconds, kNanosPerSecond, nanos)) {
    return Status::error(StatusCode::InvalidArgument, "seconds are out of range");
  }
  return AuthorityTime(nanos);
}

Result<AuthorityTime> AuthorityTime::Plus(Duration delta) const {
  std::int64_t result = 0;
  if (detail::add_overflow(unix_nanos_, delta.nanos(), result) || result < 0) {
    return Status::error(StatusCode::LimitExceeded, "instant addition overflows");
  }
  return AuthorityTime(result);
}

Result<Duration> AuthorityTime::Since(AuthorityTime earlier) const {
  if (earlier.unix_nanos_ > unix_nanos_) {
    return Status::error(StatusCode::InvalidArgument, "the earlier instant is in the future");
  }
  return Duration::FromNanos(unix_nanos_ - earlier.unix_nanos_);
}

std::string AuthorityTime::to_iso8601() const {
  const std::int64_t seconds = unix_nanos_ / kNanosPerSecond;
  const std::int64_t fraction = unix_nanos_ % kNanosPerSecond;
  std::int64_t days = seconds / 86400ll;
  std::int64_t remainder = seconds % 86400ll;
  if (remainder < 0) {
    remainder += 86400ll;
    days -= 1ll;
  }
  std::int64_t year = 0;
  unsigned month = 0;
  unsigned day = 0;
  civil_from_days(days, year, month, day);
  const unsigned hour = static_cast<unsigned>(remainder / 3600ll);
  const unsigned minute = static_cast<unsigned>((remainder % 3600ll) / 60ll);
  const unsigned second = static_cast<unsigned>(remainder % 60ll);

  char buffer[48];
  const int written = std::snprintf(buffer, sizeof(buffer), "%04lld-%02u-%02uT%02u:%02u:%02u.%09lldZ",
                                    static_cast<long long>(year), month, day, hour, minute, second,
                                    static_cast<long long>(fraction));
  if (written <= 0) {
    return std::string();
  }
  return std::string(buffer, static_cast<std::size_t>(written));
}

Result<AuthorityTime> AuthorityTime::ParseIso8601(std::string_view text) {
  if (text.size() < 20 || text.size() > 30) {
    return Status::error(StatusCode::InvalidArgument, "timestamp is not 20 to 30 characters");
  }
  const auto digit_at = [&](std::size_t index) -> Result<std::int64_t> {
    const char character = text[index];
    if (character < '0' || character > '9') {
      return Status::error(StatusCode::InvalidArgument, "timestamp contains a non-digit");
    }
    return static_cast<std::int64_t>(character - '0');
  };
  const auto read = [&](std::size_t offset, std::size_t count) -> Result<std::int64_t> {
    std::int64_t value = 0;
    for (std::size_t index = 0; index < count; ++index) {
      const Result<std::int64_t> part = digit_at(offset + index);
      if (!part.ok()) {
        return part.status();
      }
      value = value * 10 + part.value();
    }
    return value;
  };
  if (text[4] != '-' || text[7] != '-' || text[10] != 'T' || text[13] != ':' || text[16] != ':') {
    return Status::error(StatusCode::InvalidArgument, "timestamp separators are wrong");
  }
  const Result<std::int64_t> year = read(0, 4);
  const Result<std::int64_t> month = read(5, 2);
  const Result<std::int64_t> day = read(8, 2);
  const Result<std::int64_t> hour = read(11, 2);
  const Result<std::int64_t> minute = read(14, 2);
  const Result<std::int64_t> second = read(17, 2);
  for (const Result<std::int64_t>* part : {&year, &month, &day, &hour, &minute, &second}) {
    if (!part->ok()) {
      return part->status();
    }
  }

  std::size_t cursor = 19;
  std::int64_t subsecond = 0;
  if (cursor < text.size() && text[cursor] == '.') {
    ++cursor;
    std::size_t digits = 0;
    while (cursor < text.size() && text[cursor] >= '0' && text[cursor] <= '9') {
      if (digits >= 9) {
        return Status::error(StatusCode::InvalidArgument,
                             "timestamp has more than nine fractional digits");
      }
      subsecond = subsecond * 10 + static_cast<std::int64_t>(text[cursor] - '0');
      ++digits;
      ++cursor;
    }
    if (digits == 0) {
      return Status::error(StatusCode::InvalidArgument, "timestamp has an empty fraction");
    }
    for (std::size_t pad = digits; pad < 9; ++pad) {
      subsecond *= 10;
    }
  }
  if (cursor + 1 != text.size() || text[cursor] != 'Z') {
    return Status::error(StatusCode::InvalidArgument, "timestamp must end with Z");
  }
  if (month.value() < 1 || month.value() > 12) {
    return Status::error(StatusCode::InvalidArgument, "timestamp month is out of range");
  }
  if (day.value() < 1 ||
      static_cast<unsigned>(day.value()) >
          days_in_month(year.value(), static_cast<unsigned>(month.value()))) {
    return Status::error(StatusCode::InvalidArgument, "timestamp day is out of range");
  }
  if (hour.value() > 23 || minute.value() > 59 || second.value() > 59) {
    return Status::error(StatusCode::InvalidArgument, "timestamp time is out of range");
  }
  const std::int64_t days = days_from_civil(year.value(), static_cast<unsigned>(month.value()),
                                            static_cast<unsigned>(day.value()));
  std::int64_t seconds = 0;
  if (detail::mul_overflow(days, 86400ll, seconds)) {
    return Status::error(StatusCode::LimitExceeded, "timestamp is out of range");
  }
  const std::int64_t within_day = hour.value() * 3600ll + minute.value() * 60ll + second.value();
  if (detail::add_overflow(seconds, within_day, seconds)) {
    return Status::error(StatusCode::LimitExceeded, "timestamp is out of range");
  }
  std::int64_t nanos = 0;
  if (detail::mul_overflow(seconds, kNanosPerSecond, nanos) ||
      detail::add_overflow(nanos, subsecond, nanos)) {
    return Status::error(StatusCode::LimitExceeded, "timestamp is out of range");
  }
  if (nanos < 0) {
    return Status::error(StatusCode::InvalidArgument, "timestamp is before the Unix epoch");
  }
  return AuthorityTime(nanos);
}

std::ostream& operator<<(std::ostream& stream, Duration duration) {
  return stream << duration.to_string();
}

std::ostream& operator<<(std::ostream& stream, AuthorityTime instant) {
  return stream << instant.to_iso8601();
}

Result<AuthorityTime> SystemAuthorityTime() noexcept {
  try {
    const auto now = std::chrono::system_clock::now().time_since_epoch();
    const auto nanos = std::chrono::duration_cast<std::chrono::nanoseconds>(now).count();
    if (nanos < 0) {
      return Status::error(StatusCode::Unavailable, "the system clock is before the Unix epoch");
    }
    return AuthorityTime::FromUnixNanos(static_cast<std::int64_t>(nanos));
  } catch (...) {
    return Status::error(StatusCode::Unavailable, "the system clock could not be read");
  }
}

}  // namespace feed_authority
