#include "detail/codec.hpp"

#include <cstddef>
#include <limits>
#include <string>

#include "feed_authority/digest.hpp"

namespace feed_authority::detail {

bool is_token_text(std::string_view text) noexcept {
  if (text.empty() || text.size() > 64u) {
    return false;
  }
  for (const char character : text) {
    const bool lower = character >= 'a' && character <= 'z';
    const bool digit = character >= '0' && character <= '9';
    if (!lower && !digit && character != '_') {
      return false;
    }
  }
  return true;
}

bool is_printable_ascii(std::string_view text) noexcept {
  for (const char character : text) {
    const unsigned char value = static_cast<unsigned char>(character);
    if (value < 0x20u || value > 0x7Eu) {
      return false;
    }
  }
  return true;
}

Result<std::uint64_t> parse_unsigned(std::string_view text, std::size_t max_digits) {
  if (text.empty()) {
    return Status::error(StatusCode::InvalidArgument, "an unsigned value is empty");
  }
  if (text.size() > max_digits) {
    return Status::error(StatusCode::LimitExceeded, "an unsigned value has too many digits");
  }
  if (text.size() > 1u && text.front() == '0') {
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

Result<std::int64_t> parse_signed(std::string_view text, std::size_t max_digits) {
  bool negative = false;
  if (!text.empty() && text.front() == '-') {
    negative = true;
    text.remove_prefix(1);
  }
  if (text.empty()) {
    return Status::error(StatusCode::InvalidArgument, "a signed value is empty");
  }
  if (text.size() > max_digits + 1u) {
    return Status::error(StatusCode::LimitExceeded, "a signed value has too many digits");
  }
  if (text.size() > 1u && text.front() == '0') {
    return Status::error(StatusCode::InvalidArgument, "a signed value has a leading zero");
  }
  std::uint64_t magnitude = 0;
  for (const char character : text) {
    if (character < '0' || character > '9') {
      return Status::error(StatusCode::InvalidArgument, "a signed value is not decimal digits");
    }
    const std::uint64_t digit = static_cast<std::uint64_t>(character - '0');
    if (magnitude > (0xFFFFFFFFFFFFFFFFull - digit) / 10ull) {
      return Status::error(StatusCode::LimitExceeded, "a signed value overflows 64 bits");
    }
    magnitude = magnitude * 10ull + digit;
  }
  constexpr std::uint64_t kMaxPositive = 0x7FFFFFFFFFFFFFFFull;
  constexpr std::uint64_t kMaxNegative = 0x8000000000000000ull;
  if (negative) {
    if (magnitude > kMaxNegative) {
      return Status::error(StatusCode::LimitExceeded, "a signed value underflows 64 bits");
    }
    if (magnitude == kMaxNegative) {
      return std::numeric_limits<std::int64_t>::min();
    }
    return -static_cast<std::int64_t>(magnitude);
  }
  if (magnitude > kMaxPositive) {
    return Status::error(StatusCode::LimitExceeded, "a signed value overflows 64 bits");
  }
  return static_cast<std::int64_t>(magnitude);
}

Result<bool> parse_boolean(std::string_view text) {
  if (text == "true") {
    return true;
  }
  if (text == "false") {
    return false;
  }
  return Status::error(StatusCode::InvalidArgument, "a boolean is exactly 'true' or 'false'");
}

Status escape_text(std::string_view text, std::string& out, std::uint32_t max_length) {
  if (text.size() > max_length) {
    return Status::error(StatusCode::LimitExceeded, "a text value exceeds the configured length bound");
  }
  out.push_back('"');
  for (const char character : text) {
    const unsigned char value = static_cast<unsigned char>(character);
    if (value < 0x20u || value > 0x7Eu) {
      return Status::error(StatusCode::InvalidArgument,
                           "a text value contains a character outside printable ASCII");
    }
    if (character == '"' || character == '\\') {
      out.push_back('\\');
    }
    out.push_back(character);
  }
  out.push_back('"');
  return Status::success();
}

Result<std::string> unescape_text(std::string_view text, std::size_t& cursor, std::uint32_t max_length) {
  if (cursor >= text.size() || text[cursor] != '"') {
    return Status::error(StatusCode::InvalidArgument, "a text value must start with a quote");
  }
  ++cursor;
  std::string value;
  while (true) {
    if (cursor >= text.size()) {
      return Status::error(StatusCode::InvalidArgument, "a text value is not terminated");
    }
    const char character = text[cursor];
    if (character == '"') {
      ++cursor;
      return value;
    }
    if (character == '\\') {
      ++cursor;
      if (cursor >= text.size()) {
        return Status::error(StatusCode::InvalidArgument, "a text value ends inside an escape");
      }
      const char escaped = text[cursor];
      if (escaped != '"' && escaped != '\\') {
        return Status::error(StatusCode::InvalidArgument, "a text value has an unsupported escape");
      }
      value.push_back(escaped);
      ++cursor;
      continue;
    }
    const unsigned char raw = static_cast<unsigned char>(character);
    if (raw < 0x20u || raw > 0x7Eu) {
      return Status::error(StatusCode::InvalidArgument,
                           "a text value contains a character outside printable ASCII");
    }
    value.push_back(character);
    ++cursor;
    if (value.size() > max_length) {
      return Status::error(StatusCode::LimitExceeded,
                           "a text value exceeds the configured length bound");
    }
  }
}

Result<std::vector<std::string>> split_fields(std::string_view line) {
  std::vector<std::string> fields;
  std::string current;
  bool in_quote = false;
  bool has_content = false;
  for (std::size_t index = 0; index < line.size(); ++index) {
    const char character = line[index];
    if (in_quote) {
      current.push_back(character);
      if (character == '\\') {
        if (index + 1 >= line.size()) {
          return Status::error(StatusCode::InvalidArgument, "a quoted field ends inside an escape");
        }
        current.push_back(line[index + 1]);
        ++index;
        continue;
      }
      if (character == '"') {
        in_quote = false;
      }
      continue;
    }
    if (character == '"') {
      in_quote = true;
      has_content = true;
      current.push_back(character);
      continue;
    }
    if (character == ' ' || character == '\t') {
      if (has_content) {
        fields.push_back(current);
        current.clear();
        has_content = false;
      }
      continue;
    }
    has_content = true;
    current.push_back(character);
  }
  if (in_quote) {
    return Status::error(StatusCode::InvalidArgument, "a quoted field is not terminated");
  }
  if (has_content) {
    fields.push_back(current);
  }
  return fields;
}

Status validate_line(std::string_view line, std::uint64_t max_length) {
  if (line.size() > max_length) {
    return Status::error(StatusCode::LimitExceeded, "a line exceeds the configured bound");
  }
  if (!is_printable_ascii(line)) {
    return Status::error(StatusCode::InvalidArgument,
                         "a line contains a character outside printable ASCII");
  }
  return Status::success();
}

Result<std::vector<std::string>> split_list(std::string_view text, std::size_t max_items) {
  std::vector<std::string> items;
  if (text.empty()) {
    return items;
  }
  std::size_t start = 0;
  while (true) {
    const std::size_t comma = text.find(',', start);
    const std::string_view item =
        comma == std::string_view::npos ? text.substr(start) : text.substr(start, comma - start);
    if (item.empty()) {
      return Status::error(StatusCode::InvalidArgument, "a list contains an empty item");
    }
    items.emplace_back(item);
    if (items.size() > max_items) {
      return Status::error(StatusCode::LimitExceeded, "a list exceeds the configured bound");
    }
    if (comma == std::string_view::npos) {
      break;
    }
    start = comma + 1;
  }
  return items;
}

std::string zero_padded(std::uint64_t value, std::size_t width) {
  std::string digits = std::to_string(value);
  if (digits.size() >= width) {
    return digits;
  }
  return std::string(width - digits.size(), '0') + digits;
}

}  // namespace feed_authority::detail
