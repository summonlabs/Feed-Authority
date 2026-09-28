#include "cli_json.hpp"

#include <cstdio>
#include <iostream>
#include <utility>

#if defined(_WIN32)
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#endif

namespace feed_authority::cli {

Result<Options> parse_options(const std::vector<std::string>& arguments,
                              const std::set<std::string>& value_options,
                              const std::set<std::string>& flag_options) {
  Options options;
  std::size_t index = 0;
  while (index < arguments.size()) {
    const std::string& argument = arguments[index];
    if (argument.size() < 2 || argument[0] != '-' || argument[1] != '-') {
      options.positionals.push_back(argument);
      ++index;
      continue;
    }
    std::string name = argument.substr(2);
    std::string value;
    const std::size_t equals = name.find('=');
    if (equals != std::string::npos) {
      value = name.substr(equals + 1);
      name = name.substr(0, equals);
    }
    if (value_options.count(name) != 0) {
      if (value.empty()) {
        if (index + 1 >= arguments.size()) {
          return Status::error(StatusCode::InvalidArgument, "option --" + name + " needs a value");
        }
        value = arguments[index + 1];
        ++index;
      }
      if (options.values.count(name) != 0) {
        return Status::error(StatusCode::InvalidArgument, "option --" + name + " was given twice");
      }
      options.values.emplace(name, value);
      ++index;
      continue;
    }
    if (flag_options.count(name) != 0) {
      if (!value.empty()) {
        return Status::error(StatusCode::InvalidArgument, "option --" + name + " takes no value");
      }
      options.flags.insert(name);
      ++index;
      continue;
    }
    return Status::error(StatusCode::InvalidArgument, "unrecognized option --" + name);
  }
  return options;
}

std::filesystem::path path_from_utf8(const std::string& text) {
#if defined(_WIN32)
  if (text.empty()) {
    return std::filesystem::path();
  }
  const int wide_length =
      MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text.c_str(),
                          static_cast<int>(text.size()), nullptr, 0);
  if (wide_length <= 0) {
    return std::filesystem::path();
  }
  std::wstring wide(static_cast<std::size_t>(wide_length), L'\0');
  MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text.c_str(), static_cast<int>(text.size()),
                      wide.data(), wide_length);
  return std::filesystem::path(wide);
#else
  return std::filesystem::path(text);
#endif
}

Result<AuthorityTime> parse_instant(const std::string& text) {
  if (text.empty()) {
    return Status::error(StatusCode::InvalidArgument, "an instant is empty");
  }
  if (text.find('-') != std::string::npos || text.find('T') != std::string::npos) {
    const Result<AuthorityTime> parsed = AuthorityTime::ParseIso8601(text);
    if (!parsed.ok()) {
      return Status::error(StatusCode::InvalidArgument, "an instant is not a valid ISO-8601 timestamp");
    }
    return parsed.value();
  }
  const Result<std::int64_t> seconds = parse_int(text);
  if (!seconds.ok()) {
    return Status::error(StatusCode::InvalidArgument, "an instant is neither a timestamp nor whole seconds");
  }
  const Result<AuthorityTime> parsed = AuthorityTime::FromUnixSeconds(seconds.value());
  if (!parsed.ok()) {
    return parsed.status();
  }
  return parsed.value();
}

Result<Duration> parse_duration(const std::string& text) {
  if (text.size() < 2) {
    return Status::error(StatusCode::InvalidArgument, "a duration needs a value and a unit");
  }
  std::string unit;
  std::size_t digits = 0;
  if (text.size() >= 2 && text.compare(text.size() - 2, 2, "ms") == 0) {
    unit = "ms";
    digits = text.size() - 2;
  } else {
    unit = text.substr(text.size() - 1);
    digits = text.size() - 1;
  }
  const Result<std::int64_t> value = parse_int(text.substr(0, digits));
  if (!value.ok()) {
    return Status::error(StatusCode::InvalidArgument, "a duration value is not an integer");
  }
  if (unit == "ns") return Duration::FromNanos(value.value());
  if (unit == "ms") return Duration::FromMillis(value.value());
  if (unit == "s") return Duration::FromSeconds(value.value());
  if (unit == "m") return Duration::FromMinutes(value.value());
  if (unit == "h") return Duration::FromHours(value.value());
  if (unit == "d") {
    const Result<Duration> hours = Duration::FromHours(value.value());
    if (!hours.ok()) {
      return hours.status();
    }
    return Duration::FromSeconds(value.value() * 86400);
  }
  return Status::error(StatusCode::InvalidArgument, "a duration unit must be one of ns, ms, s, m, h, d");
}

Result<AuthorityTime> resolve_now(const Options& options) {
  if (options.has("now")) {
    return parse_instant(options.value("now"));
  }
  return SystemAuthorityTime();
}

Result<std::vector<std::string>> parse_list(const std::string& text) {
  std::vector<std::string> items;
  if (text.empty()) {
    return items;
  }
  std::size_t start = 0;
  while (true) {
    const std::size_t comma = text.find(',', start);
    const std::string item =
        comma == std::string::npos ? text.substr(start) : text.substr(start, comma - start);
    if (item.empty()) {
      return Status::error(StatusCode::InvalidArgument, "a list contains an empty item");
    }
    items.push_back(item);
    if (items.size() > 4096u) {
      return Status::error(StatusCode::LimitExceeded, "a list is longer than the bound allows");
    }
    if (comma == std::string::npos) {
      break;
    }
    start = comma + 1;
  }
  return items;
}

Result<std::uint64_t> parse_uint(const std::string& text) {
  if (text.empty() || text.size() > 20) {
    return Status::error(StatusCode::InvalidArgument, "an unsigned value is empty or too long");
  }
  if (text.size() > 1 && text.front() == '0') {
    return Status::error(StatusCode::InvalidArgument, "an unsigned value has a leading zero");
  }
  std::uint64_t value = 0;
  for (const char character : text) {
    if (character < '0' || character > '9') {
      return Status::error(StatusCode::InvalidArgument, "an unsigned value is not decimal digits");
    }
    const std::uint64_t digit = static_cast<std::uint64_t>(character - '0');
    if (value > (0xFFFFFFFFFFFFFFFFull - digit) / 10ull) {
      return Status::error(StatusCode::LimitExceeded, "an unsigned value overflows 64 bits");
    }
    value = value * 10ull + digit;
  }
  return value;
}

Result<std::int64_t> parse_int(const std::string& text) {
  bool negative = false;
  std::string_view digits = text;
  if (!digits.empty() && digits.front() == '-') {
    negative = true;
    digits.remove_prefix(1);
  }
  if (digits.empty() || digits.size() > 19) {
    return Status::error(StatusCode::InvalidArgument, "a signed value is empty or too long");
  }
  if (digits.size() > 1 && digits.front() == '0') {
    return Status::error(StatusCode::InvalidArgument, "a signed value has a leading zero");
  }
  std::uint64_t magnitude = 0;
  for (const char character : digits) {
    if (character < '0' || character > '9') {
      return Status::error(StatusCode::InvalidArgument, "a signed value is not decimal digits");
    }
    magnitude = magnitude * 10ull + static_cast<std::uint64_t>(character - '0');
  }
  if (negative) {
    return -static_cast<std::int64_t>(magnitude);
  }
  return static_cast<std::int64_t>(magnitude);
}

int report(const Status& status) {
  if (status.ok()) {
    return 0;
  }
  std::cerr << "error: " << status.to_string() << "\n";
  return 1;
}

}  // namespace feed_authority::cli
