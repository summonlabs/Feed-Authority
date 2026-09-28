#include "detail/store_format.hpp"

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "detail/canonical.hpp"
#include "detail/checked.hpp"
#include "detail/codec.hpp"
#include "detail/serialization.hpp"
#include "detail/state.hpp"
#include "feed_authority/emergency.hpp"
#include "feed_authority/event.hpp"
#include "feed_authority/grant.hpp"

namespace feed_authority::detail {
namespace {

constexpr std::size_t kDigestBytes = 32;

void put_u32(std::string& out, std::uint32_t value) {
  out.push_back(static_cast<char>(value & 0xFFu));
  out.push_back(static_cast<char>((value >> 8u) & 0xFFu));
  out.push_back(static_cast<char>((value >> 16u) & 0xFFu));
  out.push_back(static_cast<char>((value >> 24u) & 0xFFu));
}

void put_u64(std::string& out, std::uint64_t value) {
  for (unsigned shift = 0; shift < 64u; shift += 8u) {
    out.push_back(static_cast<char>((value >> shift) & 0xFFu));
  }
}

void put_i64(std::string& out, std::int64_t value) {
  put_u64(out, static_cast<std::uint64_t>(value));
}

std::uint32_t load_u32(std::string_view bytes, std::size_t offset) {
  return static_cast<std::uint32_t>(static_cast<unsigned char>(bytes[offset])) |
         (static_cast<std::uint32_t>(static_cast<unsigned char>(bytes[offset + 1])) << 8u) |
         (static_cast<std::uint32_t>(static_cast<unsigned char>(bytes[offset + 2])) << 16u) |
         (static_cast<std::uint32_t>(static_cast<unsigned char>(bytes[offset + 3])) << 24u);
}

std::uint64_t load_u64(std::string_view bytes, std::size_t offset) {
  std::uint64_t value = 0;
  for (unsigned index = 0; index < 8u; ++index) {
    value |= static_cast<std::uint64_t>(static_cast<unsigned char>(bytes[offset + index]))
             << (8u * index);
  }
  return value;
}

std::int64_t load_i64(std::string_view bytes, std::size_t offset) {
  return static_cast<std::int64_t>(load_u64(bytes, offset));
}

void put_digest(std::string& out, const Digest& digest) {
  const Digest::Bytes& bytes = digest.bytes();
  out.append(reinterpret_cast<const char*>(bytes.data()), bytes.size());
}

Digest load_digest(std::string_view bytes, std::size_t offset) {
  Digest::Bytes raw{};
  for (std::size_t index = 0; index < kDigestBytes; ++index) {
    raw[index] = static_cast<std::uint8_t>(bytes[offset + index]);
  }
  return Digest(raw);
}

Status check_version(std::uint32_t version) {
  if (version == kStoreFormatVersion) {
    return Status::success();
  }
  if (version == 0x01000000u) {
    return Status::error(StatusCode::EndianMismatch,
                         "the artifact was written with the opposite byte order");
  }
  return Status::error(StatusCode::IncompatibleVersion, "the artifact has an unsupported format version");
}

std::uint64_t state_payload_bound(const Limits& limits) {
  if (limits.max_generation_bytes <= kGenerationHeaderSize + kGenerationTrailerSize) {
    return 0;
  }
  return limits.max_generation_bytes - kGenerationHeaderSize - kGenerationTrailerSize;
}

Result<AuthorityBinding> read_binding(RecordReader& reader, std::string_view prefix) {
  AuthorityBinding binding;
  const std::string epoch_key = std::string(prefix) + "epoch";
  const std::string topology_key = std::string(prefix) + "topo";
  const std::string policy_key = std::string(prefix) + "pol";
  const std::string control_key = std::string(prefix) + "ctrl";
  const std::string evidence_key = std::string(prefix) + "ev";
  const std::string decision_key = std::string(prefix) + "dgen";

  const Result<std::uint64_t> epoch = reader.expect_num(epoch_key);
  if (!epoch.ok()) return epoch.status();
  binding.epoch = AuthorityEpoch::FromValue(epoch.value());
  const Result<std::uint64_t> topology = reader.expect_num(topology_key);
  if (!topology.ok()) return topology.status();
  binding.topology = TopologyRevision::FromValue(topology.value());
  const Result<std::uint64_t> policy = reader.expect_num(policy_key);
  if (!policy.ok()) return policy.status();
  binding.policy = PolicyRevision::FromValue(policy.value());
  const Result<std::uint64_t> control = reader.expect_num(control_key);
  if (!control.ok()) return control.status();
  binding.control = ControlRevision::FromValue(control.value());
  const Result<std::uint64_t> evidence = reader.expect_num(evidence_key);
  if (!evidence.ok()) return evidence.status();
  binding.evidence = EvidenceRevision::FromValue(evidence.value());
  const Result<std::uint64_t> decision = reader.expect_num(decision_key);
  if (!decision.ok()) return decision.status();
  binding.decision = DecisionGeneration::FromValue(decision.value());
  return binding;
}

void write_binding(RecordWriter& writer, std::string_view prefix, const AuthorityBinding& binding) {
  const std::string epoch_key = std::string(prefix) + "epoch";
  const std::string topology_key = std::string(prefix) + "topo";
  const std::string policy_key = std::string(prefix) + "pol";
  const std::string control_key = std::string(prefix) + "ctrl";
  const std::string evidence_key = std::string(prefix) + "ev";
  const std::string decision_key = std::string(prefix) + "dgen";
  writer.num(epoch_key, binding.epoch.value());
  writer.num(topology_key, binding.topology.value());
  writer.num(policy_key, binding.policy.value());
  writer.num(control_key, binding.control.value());
  writer.num(evidence_key, binding.evidence.value());
  writer.num(decision_key, binding.decision.value());
}

void write_grant(std::string& out, const Grant& grant) {
  RecordWriter writer(out, "grant");
  writer.num("id", grant.id.value());
  writer.text("load", grant.load.value());
  writer.text("feed", grant.feed.value());
  writer.text("path", grant.authority_path.value());
  write_binding(writer, "", grant.issued_binding);
  writer.digest("dfp", grant.decision_fingerprint);
  writer.num("issued", static_cast<std::uint64_t>(grant.issued_at.unix_nanos()));
  writer.num("expires", static_cast<std::uint64_t>(grant.expires_at.unix_nanos()));
  writer.boolean("revoked", grant.revoked);
  writer.num("rev_at", static_cast<std::uint64_t>(grant.revoked_at.unix_nanos()));
  writer.text("rev_by", grant.revoked_by.value());
  writer.text("rev_reason", grant.revocation_reason);
  writer.boolean("reval", grant.revalidated);
  write_binding(writer, "r_", grant.revalidated_binding);
  writer.num("r_at", static_cast<std::uint64_t>(grant.revalidated_at.unix_nanos()));
  writer.text("attempt", grant.attempt.value());
  writer.end();
}

Result<Grant> read_grant(RecordReader& reader, const Limits& limits) {
  Grant grant;
  const Result<std::uint64_t> id = reader.expect_num("id");
  if (!id.ok()) return id.status();
  if (id.value() == 0) {
    return Status::error(StatusCode::Corruption, "a grant identity is zero");
  }
  grant.id = GrantId::FromValue(id.value());
  const Result<std::string> load = reader.expect_text("load");
  if (!load.ok()) return load.status();
  const Result<LoadId> parsed_load = LoadId::Parse(load.value());
  if (!parsed_load.ok()) return Status::error(StatusCode::Corruption, "a grant load identity is not well-formed");
  grant.load = parsed_load.value();
  const Result<std::string> feed = reader.expect_text("feed");
  if (!feed.ok()) return feed.status();
  const Result<FeedId> parsed_feed = FeedId::Parse(feed.value());
  if (!parsed_feed.ok()) return Status::error(StatusCode::Corruption, "a grant feed identity is not well-formed");
  grant.feed = parsed_feed.value();
  const Result<std::string> path = reader.expect_text("path");
  if (!path.ok()) return path.status();
  const Result<AuthorityPathId> parsed_path = AuthorityPathId::Parse(path.value());
  if (!parsed_path.ok()) return Status::error(StatusCode::Corruption, "a grant authority path is not well-formed");
  grant.authority_path = parsed_path.value();
  const Result<AuthorityBinding> binding = read_binding(reader, "");
  if (!binding.ok()) return binding.status();
  grant.issued_binding = binding.value();
  const Result<Digest> fingerprint = reader.expect_digest("dfp");
  if (!fingerprint.ok()) return fingerprint.status();
  grant.decision_fingerprint = fingerprint.value();
  const Result<std::uint64_t> issued = reader.expect_num("issued");
  if (!issued.ok()) return issued.status();
  const Result<AuthorityTime> issued_at = AuthorityTime::FromUnixNanos(static_cast<std::int64_t>(issued.value()));
  if (!issued_at.ok()) return Status::error(StatusCode::Corruption, "a grant issue instant is out of range");
  grant.issued_at = issued_at.value();
  const Result<std::uint64_t> expires = reader.expect_num("expires");
  if (!expires.ok()) return expires.status();
  const Result<AuthorityTime> expires_at = AuthorityTime::FromUnixNanos(static_cast<std::int64_t>(expires.value()));
  if (!expires_at.ok()) return Status::error(StatusCode::Corruption, "a grant expiry instant is out of range");
  grant.expires_at = expires_at.value();
  const Result<bool> revoked = reader.expect_boolean("revoked");
  if (!revoked.ok()) return revoked.status();
  grant.revoked = revoked.value();
  const Result<std::uint64_t> revoked_at = reader.expect_num("rev_at");
  if (!revoked_at.ok()) return revoked_at.status();
  const Result<AuthorityTime> revoked_instant =
      AuthorityTime::FromUnixNanos(static_cast<std::int64_t>(revoked_at.value()));
  if (!revoked_instant.ok()) return Status::error(StatusCode::Corruption, "a grant revocation instant is out of range");
  grant.revoked_at = revoked_instant.value();
  const Result<std::string> revoked_by = reader.expect_text("rev_by");
  if (!revoked_by.ok()) return revoked_by.status();
  if (!revoked_by.value().empty()) {
    const Result<AuthorizerId> parsed = AuthorizerId::Parse(revoked_by.value());
    if (!parsed.ok()) return Status::error(StatusCode::Corruption, "a grant revoker identity is not well-formed");
    grant.revoked_by = parsed.value();
  }
  const Result<std::string> reason = reader.expect_text("rev_reason");
  if (!reason.ok()) return reason.status();
  grant.revocation_reason = reason.value();
  const Result<bool> revalidated = reader.expect_boolean("reval");
  if (!revalidated.ok()) return revalidated.status();
  grant.revalidated = revalidated.value();
  const Result<AuthorityBinding> revalidated_binding = read_binding(reader, "r_");
  if (!revalidated_binding.ok()) return revalidated_binding.status();
  grant.revalidated_binding = revalidated_binding.value();
  const Result<std::uint64_t> revalidated_at = reader.expect_num("r_at");
  if (!revalidated_at.ok()) return revalidated_at.status();
  const Result<AuthorityTime> revalidated_instant =
      AuthorityTime::FromUnixNanos(static_cast<std::int64_t>(revalidated_at.value()));
  if (!revalidated_instant.ok()) return Status::error(StatusCode::Corruption, "a grant revalidation instant is out of range");
  grant.revalidated_at = revalidated_instant.value();
  const Result<std::string> attempt = reader.expect_text("attempt");
  if (!attempt.ok()) return attempt.status();
  const Result<AttemptId> parsed_attempt = AttemptId::Parse(attempt.value());
  if (!parsed_attempt.ok()) return Status::error(StatusCode::Corruption, "a grant attempt identity is not well-formed");
  grant.attempt = parsed_attempt.value();
  const Status record = reader.expect_type_and_end("grant");
  if (!record.ok()) return record;
  if (grant.revoked && grant.revocation_reason.empty()) {
    return Status::error(StatusCode::Corruption, "a revoked grant has no revocation reason");
  }
  if (grant.revoked && !grant.revoked_by.valid()) {
    return Status::error(StatusCode::Corruption, "a revoked grant has no revoking authorizer");
  }
  if (grant.expires_at <= grant.issued_at) {
    return Status::error(StatusCode::Corruption, "a grant does not expire after it was issued");
  }
  (void)limits;
  return grant;
}

}  // namespace

std::string encode_generation(const std::string& payload) {
  std::string out;
  out.reserve(static_cast<std::size_t>(kGenerationHeaderSize) + payload.size() +
              static_cast<std::size_t>(kGenerationTrailerSize));
  out.append(kGenerationMagic);
  put_u32(out, kStoreFormatVersion);
  put_u32(out, static_cast<std::uint32_t>(kGenerationHeaderSize));
  put_u64(out, static_cast<std::uint64_t>(payload.size()));
  put_digest(out, Digest::Of(payload));
  out.append(16u, '\0');
  out.append(payload);
  out.append(kGenerationTrailerMagic);
  put_u64(out, static_cast<std::uint64_t>(payload.size()));
  return out;
}

Result<std::string> decode_generation(std::string_view bytes, const Limits& limits) {
  const std::uint64_t minimum = kGenerationHeaderSize + kGenerationTrailerSize;
  if (bytes.size() < minimum) {
    return Status::error(StatusCode::Corruption, "the generation file is shorter than its fixed framing");
  }
  if (bytes.substr(0, kGenerationMagic.size()) != kGenerationMagic) {
    return Status::error(StatusCode::Corruption, "the generation file has no magic");
  }
  const Status version = check_version(load_u32(bytes, 8));
  if (!version.ok()) {
    return version;
  }
  if (load_u32(bytes, 12) != kGenerationHeaderSize) {
    return Status::error(StatusCode::Corruption, "the generation header size is wrong");
  }
  const std::uint64_t payload_size = load_u64(bytes, 16);
  if (payload_size > state_payload_bound(limits)) {
    return Status::error(StatusCode::LimitExceeded, "the generation payload exceeds the configured bound");
  }
  std::uint64_t expected_total = 0;
  if (add_overflow(kGenerationHeaderSize, payload_size, expected_total) ||
      add_overflow(expected_total, kGenerationTrailerSize, expected_total)) {
    return Status::error(StatusCode::LimitExceeded, "the generation size overflows");
  }
  if (bytes.size() != expected_total) {
    return Status::error(StatusCode::Corruption, "the generation file size does not match its declared payload");
  }
  const std::size_t trailer_offset = static_cast<std::size_t>(kGenerationHeaderSize + payload_size);
  if (bytes.substr(trailer_offset, kGenerationTrailerMagic.size()) != kGenerationTrailerMagic) {
    return Status::error(StatusCode::Corruption, "the generation trailer magic is missing or truncated");
  }
  if (load_u64(bytes, trailer_offset + 8) != payload_size) {
    return Status::error(StatusCode::Corruption, "the generation trailer does not repeat the payload size");
  }
  const std::string_view payload = bytes.substr(static_cast<std::size_t>(kGenerationHeaderSize),
                                                static_cast<std::size_t>(payload_size));
  const Digest declared = load_digest(bytes, 24);
  if (!(Digest::Of(payload) == declared)) {
    return Status::error(StatusCode::Corruption, "the generation payload digest does not match");
  }
  return std::string(payload);
}

std::string encode_head(const HeadRecord& head) {
  std::string body;
  put_u64(body, head.sequence.value());
  put_u64(body, head.epoch.value());
  put_i64(body, head.committed_at.unix_nanos());
  std::string name = head.generation_file;
  if (name.size() > kGenerationNameBytes) {
    name.resize(static_cast<std::size_t>(kGenerationNameBytes));
  }
  name.resize(static_cast<std::size_t>(kGenerationNameBytes), '\0');
  body.append(name);
  put_digest(body, head.generation_digest);
  put_digest(body, head.previous_head_digest);

  std::string out;
  out.append(kHeadMagic);
  put_u32(out, kStoreFormatVersion);
  put_u32(out, static_cast<std::uint32_t>(kHeadHeaderSize));
  put_u64(out, kHeadBodySize);
  out.append(body);
  put_digest(out, Digest::Of(out));
  return out;
}

Result<HeadRecord> decode_head(std::string_view bytes) {
  if (bytes.size() != kHeadTotalSize) {
    return Status::error(StatusCode::Corruption, "the head marker is not exactly its fixed size");
  }
  if (bytes.substr(0, kHeadMagic.size()) != kHeadMagic) {
    return Status::error(StatusCode::Corruption, "the head marker has no magic");
  }
  const Status version = check_version(load_u32(bytes, 8));
  if (!version.ok()) {
    return version;
  }
  if (load_u32(bytes, 12) != kHeadHeaderSize) {
    return Status::error(StatusCode::Corruption, "the head marker header size is wrong");
  }
  if (load_u64(bytes, 16) != kHeadBodySize) {
    return Status::error(StatusCode::Corruption, "the head marker body size is wrong");
  }
  const std::string_view body = bytes.substr(static_cast<std::size_t>(kHeadHeaderSize));
  const Digest declared = load_digest(body, static_cast<std::size_t>(kHeadBodySize) - kDigestBytes);
  const std::string_view covered = bytes.substr(0, static_cast<std::size_t>(kHeadTotalSize) - kDigestBytes);
  if (!(Digest::Of(covered) == declared)) {
    return Status::error(StatusCode::Corruption, "the head marker self digest does not match");
  }

  HeadRecord head;
  head.sequence = StoreSequence::FromValue(load_u64(body, 0));
  head.epoch = AuthorityEpoch::FromValue(load_u64(body, 8));
  const Result<AuthorityTime> committed = AuthorityTime::FromUnixNanos(load_i64(body, 16));
  if (!committed.ok()) {
    return Status::error(StatusCode::Corruption, "the head marker commit instant is out of range");
  }
  head.committed_at = committed.value();
  const std::string_view raw_name = body.substr(24, static_cast<std::size_t>(kGenerationNameBytes));
  const std::size_t terminator = raw_name.find('\0');
  if (terminator == std::string_view::npos) {
    return Status::error(StatusCode::Corruption, "the generation file name is not terminated");
  }
  for (std::size_t index = terminator; index < raw_name.size(); ++index) {
    if (raw_name[index] != '\0') {
      return Status::error(StatusCode::Corruption, "the generation file name has trailing bytes");
    }
  }
  head.generation_file.assign(raw_name.substr(0, terminator));
  const std::size_t digest_offset = 24u + static_cast<std::size_t>(kGenerationNameBytes);
  head.generation_digest = load_digest(body, digest_offset);
  head.previous_head_digest = load_digest(body, digest_offset + kDigestBytes);
  head.head_digest = declared;
  return head;
}

std::string generation_file_name(StoreSequence sequence) {
  return "gen-" + zero_padded(sequence.value(), 19) + ".fas";
}

Result<StoreSequence> parse_generation_file_name(std::string_view name) {
  if (name.size() != kGenerationNameLength) {
    return Status::error(StatusCode::InvalidArgument, "a generation file name has the wrong length");
  }
  if (name.substr(0, 4) != "gen-" || name.substr(name.size() - 4) != ".fas") {
    return Status::error(StatusCode::InvalidArgument, "a generation file name has the wrong shape");
  }
  const std::string_view digits = name.substr(4, 19);
  // The name is zero-padded by construction, so the leading-zero rule that applies
  // to canonical field values does not apply here.
  std::uint64_t value = 0;
  for (const char character : digits) {
    if (character < '0' || character > '9') {
      return Status::error(StatusCode::InvalidArgument, "a generation file name has a non-digit");
    }
    const std::uint64_t digit = static_cast<std::uint64_t>(character - '0');
    if (value > (0xFFFFFFFFFFFFFFFFull - digit) / 10ull) {
      return Status::error(StatusCode::LimitExceeded, "a generation sequence overflows 64 bits");
    }
    value = value * 10ull + digit;
  }
  if (value == 0) {
    return Status::error(StatusCode::InvalidArgument, "a generation sequence is never zero");
  }
  return StoreSequence::FromValue(value);
}

namespace {

void write_emergency(std::string& out, const EmergencyAuthorization& authorization) {
  RecordWriter writer(out, "emergency");
  writer.num("id", authorization.id.value());
  writer.text("authorizer", authorization.authorizer.value());
  writer.text("justification", authorization.justification);
  write_binding(writer, "", authorization.binding);
  writer.num("issued", static_cast<std::uint64_t>(authorization.issued_at.unix_nanos()));
  writer.num("expires", static_cast<std::uint64_t>(authorization.expires_at.unix_nanos()));
  writer.boolean("revoked", authorization.revoked);
  writer.num("rev_at", static_cast<std::uint64_t>(authorization.revoked_at.unix_nanos()));
  writer.text("rev_by", authorization.revoked_by.value());
  writer.text("rev_reason", authorization.revocation_reason);
  writer.text("attempt", authorization.attempt.value());
  writer.num("classes_n", authorization.overridable_classes.size());
  writer.num("loads_n", authorization.loads.size());
  writer.num("feeds_n", authorization.feeds.size());
  writer.end();
  for (const PrecedenceClass value : authorization.overridable_classes) {
    RecordWriter item(out, "emergency_class");
    item.num("id", authorization.id.value());
    item.token("value", to_string(value));
    item.end();
  }
  for (const LoadId& value : authorization.loads) {
    RecordWriter item(out, "emergency_load");
    item.num("id", authorization.id.value());
    item.text("value", value.value());
    item.end();
  }
  for (const FeedId& value : authorization.feeds) {
    RecordWriter item(out, "emergency_feed");
    item.num("id", authorization.id.value());
    item.text("value", value.value());
    item.end();
  }
}

Result<EmergencyAuthorization> read_emergency(RecordReader& reader, const Limits& limits) {
  EmergencyAuthorization authorization;
  const Result<std::uint64_t> id = reader.expect_num("id");
  if (!id.ok()) return id.status();
  if (id.value() == 0) {
    return Status::error(StatusCode::Corruption, "an emergency authorization identity is zero");
  }
  authorization.id = EmergencyAuthorizationId::FromValue(id.value());
  const Result<std::string> authorizer = reader.expect_text("authorizer");
  if (!authorizer.ok()) return authorizer.status();
  const Result<AuthorizerId> parsed_authorizer = AuthorizerId::Parse(authorizer.value());
  if (!parsed_authorizer.ok()) {
    return Status::error(StatusCode::Corruption, "an emergency authorizer identity is not well-formed");
  }
  authorization.authorizer = parsed_authorizer.value();
  const Result<std::string> justification = reader.expect_text("justification");
  if (!justification.ok()) return justification.status();
  authorization.justification = justification.value();
  if (authorization.justification.empty()) {
    return Status::error(StatusCode::Corruption, "an emergency authorization has no justification");
  }
  const Result<AuthorityBinding> binding = read_binding(reader, "");
  if (!binding.ok()) return binding.status();
  authorization.binding = binding.value();
  const Result<std::uint64_t> issued = reader.expect_num("issued");
  if (!issued.ok()) return issued.status();
  const Result<AuthorityTime> issued_at = AuthorityTime::FromUnixNanos(static_cast<std::int64_t>(issued.value()));
  if (!issued_at.ok()) return Status::error(StatusCode::Corruption, "an authorization instant is out of range");
  authorization.issued_at = issued_at.value();
  const Result<std::uint64_t> expires = reader.expect_num("expires");
  if (!expires.ok()) return expires.status();
  const Result<AuthorityTime> expires_at = AuthorityTime::FromUnixNanos(static_cast<std::int64_t>(expires.value()));
  if (!expires_at.ok()) return Status::error(StatusCode::Corruption, "an authorization expiry is out of range");
  authorization.expires_at = expires_at.value();
  const Result<bool> revoked = reader.expect_boolean("revoked");
  if (!revoked.ok()) return revoked.status();
  authorization.revoked = revoked.value();
  const Result<std::uint64_t> revoked_at = reader.expect_num("rev_at");
  if (!revoked_at.ok()) return revoked_at.status();
  const Result<AuthorityTime> revoked_instant =
      AuthorityTime::FromUnixNanos(static_cast<std::int64_t>(revoked_at.value()));
  if (!revoked_instant.ok()) return Status::error(StatusCode::Corruption, "a revocation instant is out of range");
  authorization.revoked_at = revoked_instant.value();
  const Result<std::string> revoked_by = reader.expect_text("rev_by");
  if (!revoked_by.ok()) return revoked_by.status();
  if (!revoked_by.value().empty()) {
    const Result<AuthorizerId> parsed = AuthorizerId::Parse(revoked_by.value());
    if (!parsed.ok()) return Status::error(StatusCode::Corruption, "a revoking authorizer identity is not well-formed");
    authorization.revoked_by = parsed.value();
  }
  const Result<std::string> reason = reader.expect_text("rev_reason");
  if (!reason.ok()) return reason.status();
  authorization.revocation_reason = reason.value();
  const Result<std::string> attempt = reader.expect_text("attempt");
  if (!attempt.ok()) return attempt.status();
  const Result<AttemptId> parsed_attempt = AttemptId::Parse(attempt.value());
  if (!parsed_attempt.ok()) return Status::error(StatusCode::Corruption, "an authorization attempt identity is not well-formed");
  authorization.attempt = parsed_attempt.value();
  const Result<std::uint64_t> class_count = reader.expect_num("classes_n");
  if (!class_count.ok()) return class_count.status();
  const Result<std::uint64_t> load_count = reader.expect_num("loads_n");
  if (!load_count.ok()) return load_count.status();
  const Result<std::uint64_t> feed_count = reader.expect_num("feeds_n");
  if (!feed_count.ok()) return feed_count.status();
  const Status record = reader.expect_type_and_end("emergency");
  if (!record.ok()) return record;
  if (class_count.value() > limits.max_override_classes || load_count.value() > limits.max_loads ||
      feed_count.value() > limits.max_feeds) {
    return Status::error(StatusCode::LimitExceeded, "an emergency authorization declares too many values");
  }
  if (class_count.value() == 0 || load_count.value() == 0) {
    return Status::error(StatusCode::Corruption,
                         "an emergency authorization must name classes and loads");
  }
  for (std::uint64_t index = 0; index < class_count.value(); ++index) {
    const Status next = reader.next();
    if (!next.ok()) return next;
    const Result<std::uint64_t> subject = reader.expect_num("id");
    if (!subject.ok()) return subject.status();
    if (subject.value() != authorization.id.value()) {
      return Status::error(StatusCode::Corruption, "an emergency class record has the wrong subject");
    }
    const Result<std::string> value = reader.expect_token("value");
    if (!value.ok()) return value.status();
    const Result<PrecedenceClass> parsed = parse_precedence_class(value.value());
    if (!parsed.ok()) return Status::error(StatusCode::Corruption, "an override class token is not defined");
    const Status end = reader.expect_type_and_end("emergency_class");
    if (!end.ok()) return end;
    authorization.overridable_classes.push_back(parsed.value());
  }
  for (std::uint64_t index = 0; index < load_count.value(); ++index) {
    const Status next = reader.next();
    if (!next.ok()) return next;
    const Result<std::uint64_t> subject = reader.expect_num("id");
    if (!subject.ok()) return subject.status();
    if (subject.value() != authorization.id.value()) {
      return Status::error(StatusCode::Corruption, "an emergency load record has the wrong subject");
    }
    const Result<std::string> value = reader.expect_text("value");
    if (!value.ok()) return value.status();
    const Result<LoadId> parsed = LoadId::Parse(value.value());
    if (!parsed.ok()) return Status::error(StatusCode::Corruption, "an emergency load identity is not well-formed");
    const Status end = reader.expect_type_and_end("emergency_load");
    if (!end.ok()) return end;
    authorization.loads.push_back(parsed.value());
  }
  for (std::uint64_t index = 0; index < feed_count.value(); ++index) {
    const Status next = reader.next();
    if (!next.ok()) return next;
    const Result<std::uint64_t> subject = reader.expect_num("id");
    if (!subject.ok()) return subject.status();
    if (subject.value() != authorization.id.value()) {
      return Status::error(StatusCode::Corruption, "an emergency feed record has the wrong subject");
    }
    const Result<std::string> value = reader.expect_text("value");
    if (!value.ok()) return value.status();
    const Result<FeedId> parsed = FeedId::Parse(value.value());
    if (!parsed.ok()) return Status::error(StatusCode::Corruption, "an emergency feed identity is not well-formed");
    const Status end = reader.expect_type_and_end("emergency_feed");
    if (!end.ok()) return end;
    authorization.feeds.push_back(parsed.value());
  }
  if (authorization.expires_at <= authorization.issued_at) {
    return Status::error(StatusCode::Corruption, "an authorization does not expire after it was issued");
  }
  if (authorization.revoked &&
      (authorization.revocation_reason.empty() || !authorization.revoked_by.valid())) {
    return Status::error(StatusCode::Corruption, "a revoked authorization has no revoker or reason");
  }
  return authorization;
}

void write_attempt(std::string& out, const AttemptRecord& attempt) {
  RecordWriter writer(out, "attempt");
  writer.text("id", attempt.attempt.value());
  writer.token("kind", to_string(attempt.kind));
  writer.digest("fp", attempt.request_fingerprint);
  writer.num("grant", attempt.grant_id.value_or(0));
  writer.num("emergency", attempt.emergency_id.value_or(0));
  writer.num("at", attempt.recorded_at.value());
  writer.end();
}

Result<AttemptRecord> read_attempt(RecordReader& reader) {
  AttemptRecord attempt;
  const Result<std::string> id = reader.expect_text("id");
  if (!id.ok()) return id.status();
  const Result<AttemptId> parsed_id = AttemptId::Parse(id.value());
  if (!parsed_id.ok()) return Status::error(StatusCode::Corruption, "an attempt identity is not well-formed");
  attempt.attempt = parsed_id.value();
  const Result<std::string> kind = reader.expect_token("kind");
  if (!kind.ok()) return kind.status();
  const Result<AttemptKind> parsed_kind = parse_attempt_kind(kind.value());
  if (!parsed_kind.ok()) return Status::error(StatusCode::Corruption, "an attempt kind token is not defined");
  attempt.kind = parsed_kind.value();
  const Result<Digest> fingerprint = reader.expect_digest("fp");
  if (!fingerprint.ok()) return fingerprint.status();
  attempt.request_fingerprint = fingerprint.value();
  const Result<std::uint64_t> grant = reader.expect_num("grant");
  if (!grant.ok()) return grant.status();
  if (grant.value() != 0) {
    attempt.grant_id = grant.value();
  }
  const Result<std::uint64_t> emergency = reader.expect_num("emergency");
  if (!emergency.ok()) return emergency.status();
  if (emergency.value() != 0) {
    attempt.emergency_id = emergency.value();
  }
  const Result<std::uint64_t> at = reader.expect_num("at");
  if (!at.ok()) return at.status();
  attempt.recorded_at = StoreSequence::FromValue(at.value());
  const Status record = reader.expect_type_and_end("attempt");
  if (!record.ok()) return record;
  return attempt;
}

void write_event(std::string& out, const EventRecord& event) {
  RecordWriter writer(out, "event");
  writer.num("seq", event.sequence.value());
  writer.token("kind", to_string(event.kind));
  writer.num("at", static_cast<std::uint64_t>(event.at.unix_nanos()));
  writer.num("epoch", event.epoch.value());
  writer.text("detail", event.detail);
  writer.num("grant", event.grant ? event.grant->value() : 0);
  writer.num("emergency", event.emergency ? event.emergency->value() : 0);
  writer.num("decision", event.decision ? event.decision->value() : 0);
  writer.end();
}

Result<EventRecord> read_event(RecordReader& reader) {
  EventRecord event;
  const Result<std::uint64_t> sequence = reader.expect_num("seq");
  if (!sequence.ok()) return sequence.status();
  if (sequence.value() == 0) {
    return Status::error(StatusCode::Corruption, "an event sequence is zero");
  }
  event.sequence = EventSequence::FromValue(sequence.value());
  const Result<std::string> kind = reader.expect_token("kind");
  if (!kind.ok()) return kind.status();
  const Result<EventKind> parsed_kind = parse_event_kind(kind.value());
  if (!parsed_kind.ok()) return Status::error(StatusCode::Corruption, "an event kind token is not defined");
  event.kind = parsed_kind.value();
  const Result<std::uint64_t> at = reader.expect_num("at");
  if (!at.ok()) return at.status();
  const Result<AuthorityTime> instant = AuthorityTime::FromUnixNanos(static_cast<std::int64_t>(at.value()));
  if (!instant.ok()) return Status::error(StatusCode::Corruption, "an event instant is out of range");
  event.at = instant.value();
  const Result<std::uint64_t> epoch = reader.expect_num("epoch");
  if (!epoch.ok()) return epoch.status();
  event.epoch = AuthorityEpoch::FromValue(epoch.value());
  const Result<std::string> detail = reader.expect_text("detail");
  if (!detail.ok()) return detail.status();
  event.detail = detail.value();
  const Result<std::uint64_t> grant = reader.expect_num("grant");
  if (!grant.ok()) return grant.status();
  if (grant.value() != 0) {
    event.grant = GrantId::FromValue(grant.value());
  }
  const Result<std::uint64_t> emergency = reader.expect_num("emergency");
  if (!emergency.ok()) return emergency.status();
  if (emergency.value() != 0) {
    event.emergency = EmergencyAuthorizationId::FromValue(emergency.value());
  }
  const Result<std::uint64_t> decision = reader.expect_num("decision");
  if (!decision.ok()) return decision.status();
  if (decision.value() != 0) {
    event.decision = DecisionGeneration::FromValue(decision.value());
  }
  const Status record = reader.expect_type_and_end("event");
  if (!record.ok()) return record;
  return event;
}

}  // namespace

PersistedState make_initial_state(AuthorityTime now) {
  PersistedState state;
  state.sequence = StoreSequence::FromValue(1);
  state.epoch = AuthorityEpoch::FromValue(1);
  state.last_decision = DecisionGeneration::FromValue(0);
  state.decision_lease_ceiling = DecisionGeneration::FromValue(0);
  state.input_history.emplace_back();
  EventRecord event;
  event.sequence = EventSequence::FromValue(1);
  event.kind = EventKind::StoreCreated;
  event.at = now;
  event.epoch = state.epoch;
  event.detail = "store created";
  state.events.push_back(std::move(event));
  state.last_event = EventSequence::FromValue(1);
  return state;
}

Status encode_state(const PersistedState& state, const Limits& limits, std::string& out) {
  const Status limits_status = limits.validate();
  if (!limits_status.ok()) {
    return limits_status;
  }
  if (state.input_history.empty()) {
    return Status::error(StatusCode::InvariantViolation, "a state must carry at least one input generation");
  }
  if (state.input_history.size() > limits.max_policy_history ||
      state.input_history.size() > limits.max_topology_history) {
    return Status::error(StatusCode::LimitExceeded, "a state carries more input history than the bound allows");
  }
  if (state.grants.size() > limits.max_grants) {
    return Status::error(StatusCode::LimitExceeded, "a state carries more grants than the bound allows");
  }
  if (state.emergency.size() > limits.max_emergency_authorizations) {
    return Status::error(StatusCode::LimitExceeded, "a state carries more authorizations than the bound allows");
  }
  if (state.attempts.size() > limits.max_replay_entries) {
    return Status::error(StatusCode::LimitExceeded, "a state carries more attempts than the bound allows");
  }
  if (state.events.size() > limits.max_events) {
    return Status::error(StatusCode::LimitExceeded, "a state carries more events than the bound allows");
  }

  out.clear();
  RecordWriter header(out, "state");
  header.num("v", kStoreFormatVersion);
  header.end();

  RecordWriter counters(out, "counters");
  counters.num("seq", state.sequence.value());
  counters.num("epoch", state.epoch.value());
  counters.num("decision", state.last_decision.value());
  counters.num("lease", state.decision_lease_ceiling.value());
  counters.num("grant_seq", state.last_grant.value());
  counters.num("emergency_seq", state.last_emergency.value());
  counters.num("event_seq", state.last_event.value());
  counters.num("sections", state.input_history.size());
  counters.num("grants", state.grants.size());
  counters.num("emergencies", state.emergency.size());
  counters.num("attempts", state.attempts.size());
  counters.num("events", state.events.size());
  counters.end();

  for (std::size_t index = 0; index < state.input_history.size(); ++index) {
    RecordWriter begin(out, "section_begin");
    begin.num("h", index);
    begin.end();
    encode_input_records(out, state.input_history[index], limits);
    RecordWriter end(out, "section_end");
    end.num("h", index);
    end.end();
  }
  for (const Grant& grant : state.grants) {
    write_grant(out, grant);
  }
  for (const EmergencyAuthorization& authorization : state.emergency) {
    write_emergency(out, authorization);
  }
  for (const AttemptRecord& attempt : state.attempts) {
    write_attempt(out, attempt);
  }
  for (const EventRecord& event : state.events) {
    write_event(out, event);
  }

  const std::uint64_t bound = limits.max_generation_bytes > kGenerationHeaderSize + kGenerationTrailerSize
                                  ? limits.max_generation_bytes - kGenerationHeaderSize - kGenerationTrailerSize
                                  : 0;
  if (static_cast<std::uint64_t>(out.size()) > bound) {
    return Status::error(StatusCode::LimitExceeded,
                         "the encoded state exceeds the configured generation size bound");
  }
  return Status::success();
}

Result<PersistedState> decode_state(std::string_view payload, const Limits& limits) {
  const Status limits_status = limits.validate();
  if (!limits_status.ok()) {
    return limits_status;
  }
  if (payload.empty()) {
    return Status::error(StatusCode::Corruption, "the state payload is empty");
  }
  RecordReader reader(payload, limits, "state");

  Status status = reader.next();
  if (!status.ok()) return status;
  {
    const Result<std::uint64_t> version = reader.expect_num("v");
    if (!version.ok()) return version.status();
    if (version.value() != kStoreFormatVersion) {
      return Status::error(StatusCode::IncompatibleVersion, "the state payload has an unsupported version");
    }
    const Status record = reader.expect_type_and_end("state");
    if (!record.ok()) return record;
  }

  status = reader.next();
  if (!status.ok()) return status;
  PersistedState state;
  std::uint64_t section_count = 0;
  std::uint64_t grant_count = 0;
  std::uint64_t emergency_count = 0;
  std::uint64_t attempt_count = 0;
  std::uint64_t event_count = 0;
  {
    const Result<std::uint64_t> sequence = reader.expect_num("seq");
    if (!sequence.ok()) return sequence.status();
    state.sequence = StoreSequence::FromValue(sequence.value());
    const Result<std::uint64_t> epoch = reader.expect_num("epoch");
    if (!epoch.ok()) return epoch.status();
    state.epoch = AuthorityEpoch::FromValue(epoch.value());
    const Result<std::uint64_t> decision = reader.expect_num("decision");
    if (!decision.ok()) return decision.status();
    state.last_decision = DecisionGeneration::FromValue(decision.value());
    const Result<std::uint64_t> lease = reader.expect_num("lease");
    if (!lease.ok()) return lease.status();
    state.decision_lease_ceiling = DecisionGeneration::FromValue(lease.value());
    const Result<std::uint64_t> grant_sequence = reader.expect_num("grant_seq");
    if (!grant_sequence.ok()) return grant_sequence.status();
    state.last_grant = GrantSequence::FromValue(grant_sequence.value());
    const Result<std::uint64_t> emergency_sequence = reader.expect_num("emergency_seq");
    if (!emergency_sequence.ok()) return emergency_sequence.status();
    state.last_emergency = EmergencyAuthorizationId::FromValue(emergency_sequence.value());
    const Result<std::uint64_t> event_sequence = reader.expect_num("event_seq");
    if (!event_sequence.ok()) return event_sequence.status();
    state.last_event = EventSequence::FromValue(event_sequence.value());
    const Result<std::uint64_t> sections = reader.expect_num("sections");
    if (!sections.ok()) return sections.status();
    section_count = sections.value();
    const Result<std::uint64_t> grants = reader.expect_num("grants");
    if (!grants.ok()) return grants.status();
    grant_count = grants.value();
    const Result<std::uint64_t> emergencies = reader.expect_num("emergencies");
    if (!emergencies.ok()) return emergencies.status();
    emergency_count = emergencies.value();
    const Result<std::uint64_t> attempts = reader.expect_num("attempts");
    if (!attempts.ok()) return attempts.status();
    attempt_count = attempts.value();
    const Result<std::uint64_t> events = reader.expect_num("events");
    if (!events.ok()) return events.status();
    event_count = events.value();
    const Status record = reader.expect_type_and_end("counters");
    if (!record.ok()) return record;
  }

  if (state.sequence.is_zero() || state.epoch.is_zero()) {
    return Status::error(StatusCode::Corruption, "a state must carry a non-zero sequence and epoch");
  }
  if (state.decision_lease_ceiling < state.last_decision) {
    return Status::error(StatusCode::Corruption, "the decision lease ceiling is below the last decision");
  }
  if (section_count == 0 || section_count > limits.max_policy_history ||
      section_count > limits.max_topology_history) {
    return Status::error(StatusCode::Corruption, "a state carries an out-of-range number of input generations");
  }
  if (grant_count > limits.max_grants || emergency_count > limits.max_emergency_authorizations ||
      attempt_count > limits.max_replay_entries || event_count > limits.max_events) {
    return Status::error(StatusCode::LimitExceeded, "a state declares more records than the bound allows");
  }

  for (std::uint64_t index = 0; index < section_count; ++index) {
    status = reader.next();
    if (!status.ok()) return status;
    {
      const Result<std::uint64_t> ordinal = reader.expect_num("h");
      if (!ordinal.ok()) return ordinal.status();
      if (ordinal.value() != index) {
        return Status::error(StatusCode::Corruption, "input sections are not in ordinal order");
      }
      const Status record = reader.expect_type_and_end("section_begin");
      if (!record.ok()) return record;
    }
    AuthorityInputs inputs;
    status = decode_input_records(reader, limits, "section_end", inputs);
    if (!status.ok()) return status;
    // The input decoder stops *on* the boundary record without consuming it, so the
    // boundary fields are read here and the reader is left at the end of it.
    {
      const Result<std::uint64_t> ordinal = reader.expect_num("h");
      if (!ordinal.ok()) return ordinal.status();
      if (ordinal.value() != index) {
        return Status::error(StatusCode::Corruption, "an input section boundary has the wrong ordinal");
      }
      const Status record = reader.expect_type_and_end("section_end");
      if (!record.ok()) return record;
    }
    const Status valid = inputs.validate(limits);
    if (!valid.ok()) {
      return Status::error(StatusCode::Corruption,
                           "an input generation inside the state is invalid: " + valid.message());
    }
    AuthorityInputs::canonicalize(inputs);
    state.input_history.push_back(std::move(inputs));
  }

  for (std::uint64_t index = 0; index < grant_count; ++index) {
    status = reader.next();
    if (!status.ok()) return status;
    if (reader.type() != "grant") {
      return Status::error(StatusCode::Corruption, "a grant record is missing or out of order");
    }
    Result<Grant> grant = read_grant(reader, limits);
    if (!grant.ok()) return grant.status();
    if (!state.grants.empty() && !(state.grants.back().id < grant.value().id)) {
      return Status::error(StatusCode::Corruption, "grant records are not in increasing identity order");
    }
    state.grants.push_back(std::move(grant.value()));
  }

  for (std::uint64_t index = 0; index < emergency_count; ++index) {
    status = reader.next();
    if (!status.ok()) return status;
    if (reader.type() != "emergency") {
      return Status::error(StatusCode::Corruption, "an emergency authorization record is missing or out of order");
    }
    Result<EmergencyAuthorization> authorization = read_emergency(reader, limits);
    if (!authorization.ok()) return authorization.status();
    if (!state.emergency.empty() && !(state.emergency.back().id < authorization.value().id)) {
      return Status::error(StatusCode::Corruption,
                           "emergency authorization records are not in increasing identity order");
    }
    state.emergency.push_back(std::move(authorization.value()));
  }

  for (std::uint64_t index = 0; index < attempt_count; ++index) {
    status = reader.next();
    if (!status.ok()) return status;
    if (reader.type() != "attempt") {
      return Status::error(StatusCode::Corruption, "an attempt record is missing or out of order");
    }
    Result<AttemptRecord> attempt = read_attempt(reader);
    if (!attempt.ok()) return attempt.status();
    state.attempts.push_back(std::move(attempt.value()));
  }

  for (std::uint64_t index = 0; index < event_count; ++index) {
    status = reader.next();
    if (!status.ok()) return status;
    if (reader.type() != "event") {
      return Status::error(StatusCode::Corruption, "an event record is missing or out of order");
    }
    Result<EventRecord> event = read_event(reader);
    if (!event.ok()) return event.status();
    if (!state.events.empty() && !(state.events.back().sequence < event.value().sequence)) {
      return Status::error(StatusCode::Corruption, "event records are not in increasing sequence order");
    }
    state.events.push_back(std::move(event.value()));
  }

  status = reader.expect_payload_end();
  if (!status.ok()) return status;

  // Cross-record consistency.
  for (const Grant& grant : state.grants) {
    if (grant.id.value() > state.last_grant.value()) {
      return Status::error(StatusCode::Corruption, "a grant identity exceeds the grant sequence");
    }
    if (grant.issued_binding.epoch > state.epoch) {
      return Status::error(StatusCode::Corruption, "a grant binds an epoch newer than the state epoch");
    }
  }
  for (const EmergencyAuthorization& authorization : state.emergency) {
    if (authorization.id.value() > state.last_emergency.value()) {
      return Status::error(StatusCode::Corruption, "an authorization identity exceeds the authorization sequence");
    }
  }
  for (const EventRecord& event : state.events) {
    if (event.sequence.value() > state.last_event.value()) {
      return Status::error(StatusCode::Corruption, "an event sequence exceeds the event counter");
    }
    if (event.epoch > state.epoch) {
      return Status::error(StatusCode::Corruption, "an event carries an epoch newer than the state epoch");
    }
  }
  for (const AttemptRecord& attempt : state.attempts) {
    if (attempt.recorded_at.value() > state.sequence.value()) {
      return Status::error(StatusCode::Corruption, "an attempt was recorded after the state sequence");
    }
    // A retained attempt points at the record it produced. A dangling reference means
    // the state is not one whole state, so it is refused rather than carried forward.
    if (attempt.grant_id) {
      bool found = false;
      for (const Grant& grant : state.grants) {
        if (grant.id.value() == *attempt.grant_id) {
          found = true;
          break;
        }
      }
      if (!found) {
        return Status::error(StatusCode::Corruption,
                             "an attempt references a grant that the state does not contain");
      }
    }
    if (attempt.emergency_id) {
      bool found = false;
      for (const EmergencyAuthorization& authorization : state.emergency) {
        if (authorization.id.value() == *attempt.emergency_id) {
          found = true;
          break;
        }
      }
      if (!found) {
        return Status::error(StatusCode::Corruption,
                             "an attempt references an authorization that the state does not contain");
      }
    }
  }
  for (const EventRecord& event : state.events) {
    if (event.grant) {
      bool found = false;
      for (const Grant& grant : state.grants) {
        if (grant.id == *event.grant) {
          found = true;
          break;
        }
      }
      if (!found) {
        return Status::error(StatusCode::Corruption,
                             "an event references a grant that the state does not contain");
      }
    }
    if (event.emergency) {
      bool found = false;
      for (const EmergencyAuthorization& authorization : state.emergency) {
        if (authorization.id == *event.emergency) {
          found = true;
          break;
        }
      }
      if (!found) {
        return Status::error(StatusCode::Corruption,
                             "an event references an authorization that the state does not contain");
      }
    }
    if (event.decision && event.decision->value() > state.last_decision.value()) {
      return Status::error(StatusCode::Corruption,
                           "an event references a decision generation that was never handed out");
    }
  }

  // Canonical form is enforced by re-encoding: the decoder accepts only the exact
  // byte sequence the encoder produces for the decoded value, so record order,
  // field order, superfluous fields and non-canonical numbers are all refused.
  PersistedState canonical = state;
  canonical.canonicalize(limits);
  std::string reencoded;
  const Status encoded = encode_state(canonical, limits, reencoded);
  if (!encoded.ok()) {
    return Status::error(StatusCode::Corruption, "the decoded state cannot be re-encoded: " + encoded.message());
  }
  if (reencoded != payload) {
    return Status::error(StatusCode::Corruption, "the state payload is not in canonical form");
  }
  return state;
}

Result<Digest> PersistedState::content_digest() const {
  std::string payload;
  const Status encoded = encode_state(*this, Limits{}, payload);
  if (!encoded.ok()) {
    return encoded;
  }
  return Digest::Of(payload);
}

void PersistedState::canonicalize(const Limits& limits) {
  (void)limits;
  for (AuthorityInputs& inputs : input_history) {
    AuthorityInputs::canonicalize(inputs);
  }
  std::sort(grants.begin(), grants.end(),
            [](const Grant& left, const Grant& right) { return left.id < right.id; });
  std::sort(emergency.begin(), emergency.end(),
            [](const EmergencyAuthorization& left, const EmergencyAuthorization& right) {
              return left.id < right.id;
            });
  // Attempts and events keep insertion order: the oldest is evicted first, so the
  // order is part of the state rather than an artifact of it.
}

}  // namespace feed_authority::detail
