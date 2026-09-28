#pragma once

// Strict text codecs shared by the canonical serializer and the scenario reader.
//
// Every parse here is exact: no leading or trailing whitespace tolerance beyond
// what the caller already split, no leading zeros, no '+' sign, no implicit
// decimal point, no locale, no case-insensitive tokens, and a hard bound on the
// result length. Anything else is an error, because a lenient parser is how a
// malformed artifact becomes accepted state.

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include "feed_authority/limits.hpp"
#include "feed_authority/status.hpp"

namespace feed_authority::detail {

/// True when the text is an enum token: 1..64 characters from [a-z0-9_].
bool is_token_text(std::string_view text) noexcept;

/// True when the text is printable ASCII without tab or newline.
bool is_printable_ascii(std::string_view text) noexcept;

/// Strict unsigned decimal: digits only, no sign, no whitespace, at most
/// `max_digits` characters, no leading zero unless the value is exactly "0".
Result<std::uint64_t> parse_unsigned(std::string_view text, std::size_t max_digits = 20);

/// Strict signed decimal: optional '-', digits, no '+', no whitespace, at most
/// `max_digits` digits, no leading zeros.
Result<std::int64_t> parse_signed(std::string_view text, std::size_t max_digits = 19);

/// Strict boolean: exactly "true" or "false".
Result<bool> parse_boolean(std::string_view text);

/// Appends `text` quoted with '"' and with '\\' and '"' escaped. Refuses text
/// longer than `max_length`, text containing characters outside printable ASCII,
/// and text containing a NUL.
Status escape_text(std::string_view text, std::string& out, std::uint32_t max_length);

/// Reads a quoted, escaped string. The input must start with '"'. Returns the
/// decoded text and advances `cursor` past the closing quote.
Result<std::string> unescape_text(std::string_view text, std::size_t& cursor,
                                  std::uint32_t max_length);

/// Splits a line on runs of spaces and tabs, honouring double-quoted sections and
/// backslash escapes inside them. An unterminated quote is an error.
Result<std::vector<std::string>> split_fields(std::string_view line);

/// Validates one raw line before it is parsed: printable ASCII, no CR, no NUL,
/// bounded length.
Status validate_line(std::string_view line, std::uint64_t max_length);

/// Bounded split of a comma-separated list; empty items are refused.
Result<std::vector<std::string>> split_list(std::string_view text, std::size_t max_items);

/// Renders an unsigned value as decimal into a fixed-width, zero-padded field.
std::string zero_padded(std::uint64_t value, std::size_t width);

}  // namespace feed_authority::detail
