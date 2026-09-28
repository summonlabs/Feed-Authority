#pragma once

// Canonical record serialization.
//
// The canonical form is line-oriented ASCII. Each line is a record type followed
// by positional `key=value` fields in a fixed order, separated by single spaces,
// terminated by a single '\n'. Values are strict unsigned/signed decimals,
// `true`/`false`, bare lowercase tokens, 64-character lowercase hexadecimal
// digests, or double-quoted strings in which only '\\' and '"' are escaped.
//
// The reader is positional and exact: it consumes fields in the written order and
// refuses a wrong key, a wrong type, a missing field, an extra field, a duplicate
// key, an unknown record type, a long line, too many records and a truncated
// payload. There is therefore exactly one byte sequence that decodes to a given
// logical value, which is what makes the content digest meaningful.

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include "feed_authority/digest.hpp"
#include "feed_authority/limits.hpp"
#include "feed_authority/status.hpp"

namespace feed_authority::detail {

class RecordWriter {
 public:
  /// Starts a record of `type`. `out` must outlive the writer.
  RecordWriter(std::string& out, std::string_view type);

  RecordWriter& num(std::string_view key, std::uint64_t value);
  RecordWriter& snum(std::string_view key, std::int64_t value);
  RecordWriter& boolean(std::string_view key, bool value);
  /// Writes a bare lowercase token without quoting.
  RecordWriter& token(std::string_view key, std::string_view value);
  /// Writes a quoted, escaped string.
  RecordWriter& text(std::string_view key, std::string_view value);
  RecordWriter& digest(std::string_view key, const Digest& value);
  /// Writes `key=0` or `key=1` for counters on Counter<...>; callers convert.
  void end();

 private:
  std::string& out_;
  bool ended_ = false;
};

class RecordReader {
 public:
  /// `payload` must outlive the reader.
  RecordReader(std::string_view payload, Limits limits, std::string_view context);

  /// Advances to the next record. Fails on a malformed line or an oversized
  /// payload.
  Status next();
  bool at_end() const noexcept { return at_end_; }
  /// The record type of the current record. Owned by the reader: a view into the
  /// field list would dangle as soon as the reader advanced.
  const std::string& type() const noexcept { return type_; }
  std::uint64_t line_number() const noexcept { return line_number_; }
  const std::string& context() const noexcept { return context_; }

  /// Consumes the next field, which must have the given key and the given form.
  Result<std::uint64_t> expect_num(std::string_view key);
  Result<std::int64_t> expect_snum(std::string_view key);
  Result<bool> expect_boolean(std::string_view key);
  Result<std::string> expect_token(std::string_view key);
  Result<std::string> expect_text(std::string_view key);
  Result<Digest> expect_digest(std::string_view key);

  /// Verifies the record type and that every field was consumed.
  Status expect_type_and_end(std::string_view expected_type);

  /// Fails when any record remains.
  Status expect_payload_end();

 private:
  Status fail(StatusCode code, std::string message) const;
  Status take_field(std::string_view key, std::string_view& raw);

  std::string_view payload_;
  Limits limits_;
  std::string context_;
  std::size_t offset_ = 0;
  std::uint64_t line_number_ = 0;
  std::uint64_t record_count_ = 0;
  bool at_end_ = true;
  std::string type_;
  std::vector<std::string> fields_;
  std::size_t field_index_ = 0;
};

}  // namespace feed_authority::detail
