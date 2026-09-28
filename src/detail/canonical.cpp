#include "detail/canonical.hpp"

#include <cstddef>
#include <string>
#include <utility>

#include "detail/codec.hpp"
#include "feed_authority/digest.hpp"

namespace feed_authority::detail {
namespace {

Status append_field_key(std::string& out, std::string_view key) {
  if (!is_token_text(key)) {
    return Status::error(StatusCode::InvariantViolation, "a canonical field key is not a token");
  }
  out.push_back(' ');
  out.append(key);
  out.push_back('=');
  return Status::success();
}

}  // namespace

RecordWriter::RecordWriter(std::string& out, std::string_view type) : out_(out) {
  out_.append(type);
}

RecordWriter& RecordWriter::num(std::string_view key, std::uint64_t value) {
  if (append_field_key(out_, key).ok()) {
    out_.append(std::to_string(value));
  }
  return *this;
}

RecordWriter& RecordWriter::snum(std::string_view key, std::int64_t value) {
  if (append_field_key(out_, key).ok()) {
    out_.append(std::to_string(value));
  }
  return *this;
}

RecordWriter& RecordWriter::boolean(std::string_view key, bool value) {
  if (append_field_key(out_, key).ok()) {
    out_.append(value ? "true" : "false");
  }
  return *this;
}

RecordWriter& RecordWriter::token(std::string_view key, std::string_view value) {
  if (append_field_key(out_, key).ok() && is_token_text(value)) {
    out_.append(value);
  }
  return *this;
}

RecordWriter& RecordWriter::text(std::string_view key, std::string_view value) {
  if (append_field_key(out_, key).ok()) {
    const Status status = escape_text(value, out_, kMaxTextLength);
    if (!status.ok()) {
      out_.append("\"\"");
    }
  }
  return *this;
}

RecordWriter& RecordWriter::digest(std::string_view key, const Digest& value) {
  if (append_field_key(out_, key).ok()) {
    out_.append(value.hex());
  }
  return *this;
}

void RecordWriter::end() { out_.push_back('\n'); }

RecordReader::RecordReader(std::string_view payload, Limits limits, std::string_view context)
    : payload_(payload), limits_(limits), context_(context) {}

Status RecordReader::fail(StatusCode code, std::string message) const {
  std::string text = context_;
  text += ":";
  text += std::to_string(line_number_);
  text += ": ";
  text += message;
  return Status::error(code, std::move(text));
}

Status RecordReader::next() {
  field_index_ = 0;
  fields_.clear();
  type_.clear();
  if (offset_ >= payload_.size()) {
    at_end_ = true;
    return Status::success();
  }
  at_end_ = false;
  const std::size_t newline = payload_.find('\n', offset_);
  if (newline == std::string_view::npos) {
    line_number_ += 1;
    return fail(StatusCode::Corruption, "the final record is not newline-terminated");
  }
  const std::string_view line = payload_.substr(offset_, newline - offset_);
  offset_ = newline + 1;
  line_number_ += 1;
  ++record_count_;
  if (line.empty()) {
    return fail(StatusCode::Corruption, "an empty record is not canonical");
  }
  const Status bounded = validate_line(line, limits_.max_payload_line_bytes);
  if (!bounded.ok()) {
    return fail(bounded.code(), bounded.message());
  }
  const Result<std::vector<std::string>> split = split_fields(line);
  if (!split.ok()) {
    return fail(split.status().code(), split.status().message());
  }
  const std::vector<std::string>& tokens = split.value();
  if (tokens.empty()) {
    return fail(StatusCode::Corruption, "a record has no type");
  }
  if (!is_token_text(tokens.front())) {
    return fail(StatusCode::Corruption, "a record type is not a token");
  }
  type_ = tokens.front();
  fields_.assign(tokens.begin() + 1, tokens.end());
  for (const std::string& field : fields_) {
    const std::size_t equals = field.find('=');
    if (equals == std::string::npos || equals == 0) {
      return fail(StatusCode::Corruption, "a record field is not key=value");
    }
    const std::string_view key(field.data(), equals);
    if (!is_token_text(key)) {
      return fail(StatusCode::Corruption, "a record field key is not a token");
    }
  }
  return Status::success();
}

Status RecordReader::take_field(std::string_view key, std::string_view& raw) {
  if (field_index_ >= fields_.size()) {
    std::string message = "record '";
    message.append(type_);
    message += "' is missing field '";
    message.append(key);
    message += "'";
    return fail(StatusCode::Corruption, std::move(message));
  }
  const std::string& field = fields_[field_index_];
  const std::size_t equals = field.find('=');
  const std::string_view actual_key(field.data(), equals);
  const std::string_view value(field.data() + equals + 1, field.size() - equals - 1);
  if (actual_key != key) {
    std::string message = "record '";
    message.append(type_);
    message += "' expected field '";
    message.append(key);
    message += "' in position ";
    message += std::to_string(field_index_ + 1);
    message += " but found '";
    message.append(actual_key);
    message += "'";
    return fail(StatusCode::Corruption, std::move(message));
  }
  raw = value;
  ++field_index_;
  return Status::success();
}

Result<std::uint64_t> RecordReader::expect_num(std::string_view key) {
  std::string_view raw;
  const Status taken = take_field(key, raw);
  if (!taken.ok()) {
    return taken;
  }
  const Result<std::uint64_t> parsed = parse_unsigned(raw);
  if (!parsed.ok()) {
    std::string message = "field '";
    message.append(key);
    message += "': ";
    message += parsed.status().message();
    return fail(parsed.status().code(), std::move(message));
  }
  return parsed.value();
}

Result<std::int64_t> RecordReader::expect_snum(std::string_view key) {
  std::string_view raw;
  const Status taken = take_field(key, raw);
  if (!taken.ok()) {
    return taken;
  }
  const Result<std::int64_t> parsed = parse_signed(raw);
  if (!parsed.ok()) {
    std::string message = "field '";
    message.append(key);
    message += "': ";
    message += parsed.status().message();
    return fail(parsed.status().code(), std::move(message));
  }
  return parsed.value();
}

Result<bool> RecordReader::expect_boolean(std::string_view key) {
  std::string_view raw;
  const Status taken = take_field(key, raw);
  if (!taken.ok()) {
    return taken;
  }
  const Result<bool> parsed = parse_boolean(raw);
  if (!parsed.ok()) {
    std::string message = "field '";
    message.append(key);
    message += "': ";
    message += parsed.status().message();
    return fail(parsed.status().code(), std::move(message));
  }
  return parsed.value();
}

Result<std::string> RecordReader::expect_token(std::string_view key) {
  std::string_view raw;
  const Status taken = take_field(key, raw);
  if (!taken.ok()) {
    return taken;
  }
  if (!is_token_text(raw)) {
    std::string message = "field '";
    message.append(key);
    message += "' is not a lowercase token";
    return fail(StatusCode::Corruption, std::move(message));
  }
  return std::string(raw);
}

Result<std::string> RecordReader::expect_text(std::string_view key) {
  std::string_view raw;
  const Status taken = take_field(key, raw);
  if (!taken.ok()) {
    return taken;
  }
  std::size_t cursor = 0;
  const Result<std::string> parsed = unescape_text(raw, cursor, limits_.max_text_length);
  if (!parsed.ok()) {
    std::string message = "field '";
    message.append(key);
    message += "': ";
    message += parsed.status().message();
    return fail(parsed.status().code(), std::move(message));
  }
  if (cursor != raw.size()) {
    std::string message = "field '";
    message.append(key);
    message += "' has trailing text after the closing quote";
    return fail(StatusCode::Corruption, std::move(message));
  }
  return parsed.value();
}

Result<Digest> RecordReader::expect_digest(std::string_view key) {
  std::string_view raw;
  const Status taken = take_field(key, raw);
  if (!taken.ok()) {
    return taken;
  }
  if (raw.size() != 64u) {
    std::string message = "field '";
    message.append(key);
    message += "' is not a 64-character digest";
    return fail(StatusCode::Corruption, std::move(message));
  }
  for (const char character : raw) {
    const bool lower_hex = (character >= '0' && character <= '9') || (character >= 'a' && character <= 'f');
    if (!lower_hex) {
      std::string message = "field '";
      message.append(key);
      message += "' is not lowercase hexadecimal";
      return fail(StatusCode::Corruption, std::move(message));
    }
  }
  const Result<Digest> parsed = Digest::ParseHex(raw);
  if (!parsed.ok()) {
    std::string message = "field '";
    message.append(key);
    message += "': ";
    message += parsed.status().message();
    return fail(StatusCode::Corruption, std::move(message));
  }
  return parsed.value();
}

Status RecordReader::expect_type_and_end(std::string_view expected_type) {
  if (at_end_) {
    return fail(StatusCode::Corruption, "the payload ended before the expected record");
  }
  if (type_ != expected_type) {
    std::string message = "expected record '";
    message.append(expected_type);
    message += "' but found '";
    message.append(type_);
    message += "'";
    return fail(StatusCode::Corruption, std::move(message));
  }
  if (field_index_ != fields_.size()) {
    std::string message = "record '";
    message.append(type_);
    message += "' has an unexpected extra field '";
    message.append(fields_[field_index_]);
    message += "'";
    return fail(StatusCode::Corruption, std::move(message));
  }
  return Status::success();
}

Status RecordReader::expect_payload_end() {
  // The reader sits *on* the last record it decoded, so advancing once is what
  // distinguishes "the payload ended" from "a record was left over".
  const Status advanced = next();
  if (!advanced.ok()) {
    return advanced;
  }
  if (!at_end_) {
    std::string message = "unexpected trailing record '";
    message.append(type_);
    message += "'";
    return fail(StatusCode::Corruption, std::move(message));
  }
  return Status::success();
}

}  // namespace feed_authority::detail
