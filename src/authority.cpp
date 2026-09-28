#include "feed_authority/authority.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <string>
#include <string_view>
#include <unordered_set>
#include <utility>
#include <vector>

#include "detail/canonical.hpp"
#include "detail/checked.hpp"
#include "detail/evaluation.hpp"
#include "detail/file_lock.hpp"
#include "detail/platform_io.hpp"
#include "detail/serialization.hpp"
#include "detail/state.hpp"
#include "detail/store_format.hpp"
#include "detail/store_path.hpp"
#include "feed_authority/obligation.hpp"

namespace feed_authority {
namespace {

/// Bounded number of attempts to read a committed head and win the writer lock
/// without a concurrent publication racing the open.
constexpr std::size_t kOpenAttempts = 4;

}  // namespace

const char* to_string(FaultPoint point) noexcept {
  switch (point) {
    case FaultPoint::None: return "none";
    case FaultPoint::AfterStagingWrite: return "after_staging_write";
    case FaultPoint::AfterStagingReadback: return "after_staging_readback";
    case FaultPoint::AfterGenerationPublish: return "after_generation_publish";
    case FaultPoint::AfterHeadStagingWrite: return "after_head_staging_write";
    case FaultPoint::AfterHeadCommit: return "after_head_commit";
  }
  return "none";
}

namespace detail {

/// The private implementation of the runtime: one store root, one adopted state,
/// one writer session.
struct AuthorityImpl {
  OpenOptions options;
  Limits limits;
  std::filesystem::path root;
  OpenMode mode = OpenMode::ReadWrite;
  bool open = false;
  Incarnation incarnation;
  RecoveryReport recovery;
  PersistedState state;
  HeadRecord head;
  bool session_inputs_adopted = false;

  std::filesystem::path lock_path() const { return child_path(root, kLockFileName); }
  std::filesystem::path head_path() const { return child_path(root, kHeadFileName); }
  std::filesystem::path generations_path() const { return child_path(root, kGenerationsDirName); }
  std::filesystem::path staging_path() const { return child_path(root, kStagingDirName); }

  AuthorityBinding current_binding() const {
    AuthorityBinding binding;
    binding.epoch = state.epoch;
    const AuthorityInputs& inputs = state.current_inputs();
    binding.topology = inputs.topology.revision;
    binding.policy = inputs.policy.revision;
    binding.control = inputs.control.revision;
    binding.evidence = inputs.evidence;
    binding.decision = state.last_decision;
    return binding;
  }

  /// Invokes the configured fault callback, if the point matches. Exceptions from
  /// the callback are contained: they become a status rather than escaping through
  /// the publication protocol.
  /// Publications performed by this session, used to let a validation harness aim
  /// the fault at a chosen one.
  std::uint32_t publications_seen = 0;

  Status fault(FaultPoint point) const {
    if (options.fault_point != point || !options.on_fault) {
      return Status::success();
    }
    if (publications_seen <= options.fault_skip_publications) {
      return Status::success();
    }
    try {
      options.on_fault(point);
    } catch (const std::exception& error) {
      return Status::error(StatusCode::InvariantViolation,
                           std::string("the fault callback threw: ") + error.what());
    } catch (...) {
      return Status::error(StatusCode::InvariantViolation, "the fault callback threw");
    }
    return Status::success();
  }
};

}  // namespace detail

namespace {

using detail::AuthorityImpl;
using detail::PersistedState;

constexpr std::uint32_t kMaxEventDetailLength = 256;

std::string bounded_text(std::string_view text, std::uint32_t limit) {
  if (text.size() <= limit) {
    return std::string(text);
  }
  return std::string(text.substr(0, limit));
}

std::size_t history_bound(const Limits& limits) {
  return std::min<std::size_t>(limits.max_policy_history, limits.max_topology_history);
}

void trim_state(PersistedState& state, const Limits& limits) {
  const std::size_t bound = history_bound(limits);
  while (state.input_history.size() > bound) {
    state.input_history.erase(state.input_history.begin());
  }
  while (state.events.size() > limits.max_events) {
    state.events.erase(state.events.begin());
  }
  while (state.attempts.size() > limits.max_replay_entries) {
    state.attempts.erase(state.attempts.begin());
  }
}

void append_event(PersistedState& state, EventKind kind, AuthorityTime at, std::string detail) {
  const Result<EventSequence> next = state.last_event.next();
  if (!next.ok()) {
    return;
  }
  state.last_event = next.value();
  EventRecord event;
  event.sequence = state.last_event;
  event.kind = kind;
  event.at = at;
  event.epoch = state.epoch;
  event.detail = bounded_text(detail, kMaxEventDetailLength);
  state.events.push_back(std::move(event));
}

void record_attempt(PersistedState& state, const AttemptId& attempt, AttemptKind kind,
                    const Digest& fingerprint, std::optional<std::uint64_t> grant_id,
                    std::optional<std::uint64_t> emergency_id) {
  for (std::size_t index = 0; index < state.attempts.size(); ++index) {
    if (state.attempts[index].attempt == attempt) {
      state.attempts.erase(state.attempts.begin() + static_cast<std::ptrdiff_t>(index));
      break;
    }
  }
  AttemptRecord record;
  record.attempt = attempt;
  record.kind = kind;
  record.request_fingerprint = fingerprint;
  record.grant_id = grant_id;
  record.emergency_id = emergency_id;
  record.recorded_at = state.sequence;
  state.attempts.push_back(std::move(record));
}

const AttemptRecord* find_attempt(const PersistedState& state, const AttemptId& attempt) {
  for (const AttemptRecord& record : state.attempts) {
    if (record.attempt == attempt) {
      return &record;
    }
  }
  return nullptr;
}

const Grant* find_grant(const PersistedState& state, GrantId id) {
  for (const Grant& grant : state.grants) {
    if (grant.id == id) {
      return &grant;
    }
  }
  return nullptr;
}

Grant* find_grant(PersistedState& state, GrantId id) {
  for (Grant& grant : state.grants) {
    if (grant.id == id) {
      return &grant;
    }
  }
  return nullptr;
}

const EmergencyAuthorization* find_emergency(const PersistedState& state,
                                             EmergencyAuthorizationId id) {
  for (const EmergencyAuthorization& authorization : state.emergency) {
    if (authorization.id == id) {
      return &authorization;
    }
  }
  return nullptr;
}

EmergencyAuthorization* find_emergency(PersistedState& state, EmergencyAuthorizationId id) {
  for (EmergencyAuthorization& authorization : state.emergency) {
    if (authorization.id == id) {
      return &authorization;
    }
  }
  return nullptr;
}

Result<detail::HeadRecord> read_head_file(const std::filesystem::path& path) {
  if (!detail::file_exists(path)) {
    return Status::error(StatusCode::NotFound, "the store has no head marker");
  }
  const Result<std::string> bytes =
      detail::read_file_bounded(path, detail::kHeadTotalSize + 1u);
  if (!bytes.ok()) {
    return bytes.status();
  }
  return detail::decode_head(bytes.value());
}

/// Reads and fully verifies the state named by a head record.
Result<PersistedState> load_state_for_head(const std::filesystem::path& generations,
                                           const detail::HeadRecord& head, const Limits& limits) {
  const std::filesystem::path path = detail::child_path(generations, head.generation_file);
  const Result<std::string> bytes = detail::read_file_bounded(path, limits.max_generation_bytes);
  if (!bytes.ok()) {
    return Status::error(StatusCode::Corruption,
                         "the committed generation could not be read: " + bytes.status().message());
  }
  const Digest file_digest = Digest::Of(bytes.value());
  if (!(file_digest == head.generation_digest)) {
    return Status::error(StatusCode::Corruption,
                         "the committed generation does not match the head digest");
  }
  const Result<std::string> payload = detail::decode_generation(bytes.value(), limits);
  if (!payload.ok()) {
    return payload.status();
  }
  return detail::decode_state(payload.value(), limits);
}

Status write_head_and_publish(AuthorityImpl& impl, const std::string& generation_name,
                              const Digest& generation_digest, AuthorityTime committed_at,
                              detail::HeadRecord& out_head);

/// The transactional publication protocol. The caller must hold the writer lock.
Status publish_state(AuthorityImpl& impl, PersistedState& draft, AuthorityTime committed_at) {
  ++impl.publications_seen;
  const Result<StoreSequence> next = impl.head.sequence.next();
  if (!next.ok()) {
    return Status::error(StatusCode::LimitExceeded, "the store sequence is exhausted");
  }
  draft.sequence = next.value();
  draft.canonicalize(impl.limits);
  trim_state(draft, impl.limits);

  std::string payload;
  Status status = detail::encode_state(draft, impl.limits, payload);
  if (!status.ok()) {
    return status;
  }
  const std::string file_bytes = detail::encode_generation(payload);
  if (static_cast<std::uint64_t>(file_bytes.size()) > impl.limits.max_generation_bytes) {
    return Status::error(StatusCode::LimitExceeded, "the encoded generation exceeds the size bound");
  }
  const Status staging_ready = detail::ensure_directory(impl.staging_path());
  if (!staging_ready.ok()) {
    return staging_ready;
  }
  const Status generations_ready = detail::ensure_directory(impl.generations_path());
  if (!generations_ready.ok()) {
    return generations_ready;
  }

  const std::string name = detail::generation_file_name(draft.sequence);
  const std::filesystem::path staging_file =
      detail::child_path(impl.staging_path(), name + ".tmp");

  status = detail::write_file_durable(staging_file, file_bytes);
  if (!status.ok()) {
    return status;
  }
  status = impl.fault(FaultPoint::AfterStagingWrite);
  if (!status.ok()) {
    return status;
  }

  // Read the staging file back and verify it completely before it is published.
  const Result<std::string> readback =
      detail::read_file_bounded(staging_file, impl.limits.max_generation_bytes);
  if (!readback.ok()) {
    return Status::error(StatusCode::Corruption, "the staging file could not be read back");
  }
  if (readback.value() != file_bytes) {
    return Status::error(StatusCode::Corruption, "the staging file does not match what was written");
  }
  const Result<std::string> payload_check = detail::decode_generation(readback.value(), impl.limits);
  if (!payload_check.ok()) {
    return Status::error(StatusCode::Corruption, "the staging generation failed verification");
  }
  const Result<PersistedState> state_check = detail::decode_state(payload_check.value(), impl.limits);
  if (!state_check.ok()) {
    return Status::error(StatusCode::Corruption,
                         "the staging state failed verification: " + state_check.status().message());
  }
  status = impl.fault(FaultPoint::AfterStagingReadback);
  if (!status.ok()) {
    return status;
  }

  const std::filesystem::path published = detail::child_path(impl.generations_path(), name);
  // A generation file with this sequence number can only be residue: the head this
  // publication is planned against is one sequence behind, and a committed head
  // never names it. A crash between publishing a generation and committing the head
  // leaves exactly this file behind, so it is retired here, under the writer lock,
  // before the new generation takes its place.
  const Status retired = detail::remove_file(published);
  (void)retired;
  status = detail::rename_file_exclusive(staging_file, published);
  if (!status.ok()) {
    const Status removed = detail::remove_file(staging_file);
    (void)removed;
    return status;
  }
  status = impl.fault(FaultPoint::AfterGenerationPublish);
  if (!status.ok()) {
    return status;
  }

  detail::HeadRecord new_head;
  status = write_head_and_publish(impl, name, Digest::Of(file_bytes), committed_at, new_head);
  if (!status.ok()) {
    return status;
  }
  impl.head = new_head;

  // Retire safe residue: staging files, and generations beyond the retention
  // window. Failing to delete is not a failure of the publication.
  const Result<std::vector<std::string>> staging_names =
      detail::list_directory_names(impl.staging_path(), 64u);
  if (staging_names.ok()) {
    for (const std::string& leftover : staging_names.value()) {
      const Status removed = detail::remove_file(detail::child_path(impl.staging_path(), leftover));
      (void)removed;
    }
  }
  const Result<std::vector<std::string>> generation_names =
      detail::list_directory_names(impl.generations_path(), impl.limits.max_grants + 64u);
  if (generation_names.ok()) {
    std::vector<std::pair<std::uint64_t, std::string>> parsed;
    for (const std::string& candidate : generation_names.value()) {
      const Result<StoreSequence> sequence = detail::parse_generation_file_name(candidate);
      if (!sequence.ok()) {
        continue;
      }
      parsed.emplace_back(sequence.value().value(), candidate);
    }
    std::sort(parsed.begin(), parsed.end());
    while (parsed.size() > impl.limits.generation_retention) {
      const Status removed = detail::remove_file(detail::child_path(impl.generations_path(), parsed.front().second));
      (void)removed;
      parsed.erase(parsed.begin());
    }
  }
  return Status::success();
}

Status write_head_and_publish(AuthorityImpl& impl, const std::string& generation_name,
                              const Digest& generation_digest, AuthorityTime committed_at,
                              detail::HeadRecord& out_head) {
  detail::HeadRecord head;
  head.sequence = impl.head.sequence.next().value();
  head.epoch = impl.state.epoch;
  head.committed_at = committed_at;
  head.generation_file = generation_name;
  head.generation_digest = generation_digest;
  head.previous_head_digest = impl.head.head_digest;

  const std::string head_bytes = detail::encode_head(head);
  const std::filesystem::path staging_head =
      detail::child_path(impl.staging_path(), "head.marker.tmp");
  Status status = detail::write_file_durable(staging_head, head_bytes);
  if (!status.ok()) {
    return status;
  }
  const Result<std::string> readback = detail::read_file_bounded(staging_head, detail::kHeadTotalSize + 1u);
  if (!readback.ok()) {
    return Status::error(StatusCode::Corruption, "the head staging file could not be read back");
  }
  if (readback.value() != head_bytes) {
    return Status::error(StatusCode::Corruption, "the head staging file does not match what was written");
  }
  const Result<detail::HeadRecord> verified = detail::decode_head(readback.value());
  if (!verified.ok()) {
    return Status::error(StatusCode::Corruption, "the head staging file failed verification");
  }
  status = impl.fault(FaultPoint::AfterHeadStagingWrite);
  if (!status.ok()) {
    return status;
  }

  // The commit point: the atomic replacement of head.marker. Before it the
  // previous head is the whole state; after it this generation is.
  status = detail::atomic_replace_file(staging_head, impl.head_path());
  if (!status.ok()) {
    return Status::error(StatusCode::IoFailure,
                         "the head marker could not be committed: " + status.message());
  }
  status = impl.fault(FaultPoint::AfterHeadCommit);
  if (!status.ok()) {
    return status;
  }
  out_head = head;
  return Status::success();
}

Status require_open(const AuthorityImpl* impl) {
  if (impl == nullptr || !impl->open) {
    return Status::error(StatusCode::Closed, "the authority handle is closed");
  }
  return Status::success();
}

Status require_read_write(const AuthorityImpl* impl) {
  const Status open = require_open(impl);
  if (!open.ok()) {
    return open;
  }
  if (impl->mode != OpenMode::ReadWrite) {
    return Status::error(StatusCode::ReadOnly, "the store was opened read-only");
  }
  return Status::success();
}

/// Runs one mutation: acquire the writer lock, fence against a superseded session,
/// apply the change to a draft, publish it transactionally, then adopt it.
template <class Apply>
Status mutate(AuthorityImpl& impl, AuthorityTime committed_at, Apply&& apply) {
  const Status writable = require_read_write(&impl);
  if (!writable.ok()) {
    return writable;
  }
  Result<detail::FileLock> lock =
      detail::FileLock::acquire(impl.lock_path(), impl.limits.lock_acquire_budget_nanos);
  if (!lock.ok()) {
    return lock.status();
  }
  const Result<detail::HeadRecord> head = read_head_file(impl.head_path());
  if (!head.ok()) {
    return head.status();
  }
  if (!(head.value().sequence == impl.head.sequence)) {
    return Status::error(StatusCode::StaleAuthority,
                         "another writer session published a newer state; reload before mutating");
  }
  PersistedState draft = impl.state;
  const Status applied = apply(draft);
  if (!applied.ok()) {
    return applied;
  }
  const Status published = publish_state(impl, draft, committed_at);
  if (!published.ok()) {
    return published;
  }
  impl.state = std::move(draft);
  return Status::success();
}

/// Adopts a newer committed head when another session published one, so that a
/// retry of an already accepted attempt can be recognised before a stale
/// precondition is judged. Returns true when the state changed.
Result<bool> refresh_from_store(AuthorityImpl& impl) {
  const Result<detail::HeadRecord> head = read_head_file(impl.head_path());
  if (!head.ok()) {
    return head.status();
  }
  if (head.value().sequence == impl.head.sequence) {
    return false;
  }
  if (head.value().sequence < impl.head.sequence) {
    return Status::error(StatusCode::RollbackDetected,
                         "the committed head went backwards; refusing to adopt it");
  }
  Result<PersistedState> loaded = load_state_for_head(impl.generations_path(), head.value(), impl.limits);
  if (!loaded.ok()) {
    return loaded.status();
  }
  impl.session_inputs_adopted =
      impl.session_inputs_adopted && loaded.value().current_inputs().identical_to(impl.state.current_inputs());
  impl.state = std::move(loaded.value());
  impl.head = head.value();
  return true;
}

/// Looks up an attempt identity. A retry of an accepted attempt returns the prior
/// accepted record before any generation check runs.
Result<const AttemptRecord*> lookup_attempt(AuthorityImpl& impl, const AttemptId& attempt,
                                            const Digest& fingerprint) {
  const bool refreshed = refresh_from_store(impl).value_or(false);
  (void)refreshed;
  const AttemptRecord* record = find_attempt(impl.state, attempt);
  if (record == nullptr) {
    return record;
  }
  if (!(record->request_fingerprint == fingerprint)) {
    return Status::error(StatusCode::AttemptConflict,
                         "the attempt identity was reused with different content");
  }
  return record;
}

Status check_precondition(const AuthorityImpl& impl, const AuthorityBinding& expected) {
  const AuthorityBinding current = impl.current_binding();
  if (expected.epoch != current.epoch) {
    return Status::error(StatusCode::StaleAuthority,
                         "the request cites an authority epoch that is not current");
  }
  if (!expected.same_source_generations(current)) {
    return Status::error(StatusCode::StaleSourceGeneration,
                         "the request cites an input generation that is not current");
  }
  return Status::success();
}

Result<DecisionSet> evaluate_with(const AuthorityImpl& impl, const EvaluationRequest& request,
                                  std::vector<CandidateTrace>* traces) {
  detail::EvaluationEnvironment environment;
  environment.inputs = &impl.state.current_inputs();
  environment.binding = impl.current_binding();
  environment.emergency = &impl.state.emergency;
  environment.limits = &impl.limits;
  return detail::evaluate_load(environment, request, traces);
}

/// Evaluates the whole candidate set for a load and returns the entry for one feed.
/// The whole set is evaluated on purpose: a protected-load diversity obligation is
/// a property of the eligible set, so narrowing the request would change the answer.
Result<CandidateDecision> find_candidate(const Result<DecisionSet>& decision, const FeedId& feed) {
  if (!decision.ok()) {
    return decision.status();
  }
  for (const CandidateDecision& candidate : decision.value().candidates) {
    if (candidate.feed == feed) {
      return candidate;
    }
  }
  return Status::error(StatusCode::NotFound, "the feed has no declared path to the load");
}

std::string decision_detail(const CandidateDecision& candidate) {
  std::string detail = "outcome=";
  detail += to_string(candidate.outcome);
  detail += " reason=";
  detail += to_string(candidate.reason);
  return detail;
}

std::string display_path(const std::filesystem::path& path) {
  std::string out;
#if defined(_WIN32)
  for (const wchar_t character : path.native()) {
    out.push_back(character >= 0x20 && character <= 0x7E ? static_cast<char>(character) : '?');
  }
#else
  out = path.native();
#endif
  return out;
}

/// A single-line canonical summary of a rule, used by the diff commands.
std::string rule_summary(const EligibilityRule& rule) {
  std::string line;
  detail::RecordWriter writer(line, "rule");
  writer.text("id", rule.id.value());
  writer.token("prec", to_string(rule.precedence));
  writer.token("rank", to_string(rule.rank));
  writer.token("effect", to_string(rule.effect));
  writer.text("path", rule.authority_path.value());
  writer.token("reason", to_string(rule.reason));
  writer.text("feed", rule.scope.feed ? rule.scope.feed->value() : std::string());
  writer.text("load", rule.scope.load ? rule.scope.load->value() : std::string());
  writer.end();
  if (!line.empty() && line.back() == '\n') {
    line.pop_back();
  }
  return line;
}

std::string obligation_summary(const ProtectedObligation& obligation) {
  std::string line;
  detail::RecordWriter writer(line, "obligation");
  writer.text("id", obligation.id.value());
  writer.token("class", obligation.load_class ? to_string(*obligation.load_class) : "none");
  writer.boolean("protected_loads", obligation.applies_to_protected_loads);
  writer.num("domains", obligation.min_distinct_failure_domains);
  writer.num("loads", obligation.loads.size());
  writer.end();
  if (!line.empty() && line.back() == '\n') {
    line.pop_back();
  }
  return line;
}

Digest grant_request_fingerprint(const GrantRequest& request) {
  std::string payload;
  {
    detail::RecordWriter writer(payload, "issue_grant");
    writer.text("load", request.load.value());
    writer.text("feed", request.feed.value());
    // The decision *counter* is deliberately excluded: a retry that re-plans the
    // same logical decision carries a new counter but the same fingerprint, and it
    // must be recognised as the same intent. The decision fingerprint is included,
    // so a retry that planned against a different decision is a different request.
    writer.digest("dfp", request.decision_fingerprint);
    writer.num("validity", static_cast<std::uint64_t>(request.validity.nanos()));
    writer.num("now", static_cast<std::uint64_t>(request.now.unix_nanos()));
    writer.text("path", request.required_authority_path ? request.required_authority_path->value()
                                                        : std::string());
    writer.num("epoch", request.precondition.expected.epoch.value());
    writer.num("topology", request.precondition.expected.topology.value());
    writer.num("policy", request.precondition.expected.policy.value());
    writer.num("control", request.precondition.expected.control.value());
    writer.num("evidence", request.precondition.expected.evidence.value());
    writer.end();
  }
  return Digest::Of(payload);
}

Digest revoke_request_fingerprint(const RevokeGrantRequest& request) {
  std::string payload;
  {
    detail::RecordWriter writer(payload, "revoke_grant");
    writer.num("grant", request.grant.value());
    writer.text("authorizer", request.authorizer.value());
    writer.text("reason", request.reason);
    writer.num("now", static_cast<std::uint64_t>(request.now.unix_nanos()));
    writer.end();
  }
  return Digest::Of(payload);
}

Digest revalidate_request_fingerprint(const RevalidateGrantRequest& request) {
  std::string payload;
  {
    detail::RecordWriter writer(payload, "revalidate_grant");
    writer.num("grant", request.grant.value());
    writer.num("now", static_cast<std::uint64_t>(request.now.unix_nanos()));
    writer.end();
  }
  return Digest::Of(payload);
}

Digest adopt_request_fingerprint(const AuthorityInputs& inputs) {
  std::string payload;
  detail::encode_input_records(payload, inputs, Limits{});
  return Digest::Of(payload);
}

Digest emergency_request_fingerprint(const EmergencyAuthorizationRequest& request) {
  std::string payload;
  {
    detail::RecordWriter writer(payload, "authorize_emergency");
    writer.text("authorizer", request.authorizer.value());
    writer.text("justification", request.justification);
    writer.num("validity", static_cast<std::uint64_t>(request.validity.nanos()));
    writer.num("now", static_cast<std::uint64_t>(request.now.unix_nanos()));
    writer.num("loads", request.loads.size());
    writer.num("feeds", request.feeds.size());
    writer.num("classes", request.overridable_classes.size());
    writer.end();
    std::vector<LoadId> loads = request.loads;
    std::sort(loads.begin(), loads.end());
    for (const LoadId& load : loads) {
      detail::RecordWriter item(payload, "load");
      item.text("value", load.value());
      item.end();
    }
    std::vector<FeedId> feeds = request.feeds;
    std::sort(feeds.begin(), feeds.end());
    for (const FeedId& feed : feeds) {
      detail::RecordWriter item(payload, "feed");
      item.text("value", feed.value());
      item.end();
    }
    std::vector<PrecedenceClass> classes = request.overridable_classes;
    std::sort(classes.begin(), classes.end(),
              [](PrecedenceClass left, PrecedenceClass right) {
                return static_cast<std::int32_t>(left) < static_cast<std::int32_t>(right);
              });
    for (const PrecedenceClass value : classes) {
      detail::RecordWriter item(payload, "class");
      item.token("value", to_string(value));
      item.end();
    }
  }
  return Digest::Of(payload);
}

Digest revoke_emergency_request_fingerprint(const RevokeEmergencyAuthorizationRequest& request) {
  std::string payload;
  {
    detail::RecordWriter writer(payload, "revoke_emergency");
    writer.num("authorization", request.authorization.value());
    writer.text("authorizer", request.authorizer.value());
    writer.text("reason", request.reason);
    writer.num("now", static_cast<std::uint64_t>(request.now.unix_nanos()));
    writer.end();
  }
  return Digest::Of(payload);
}

/// The usability of a grant at an instant, before the evidence is re-checked.
struct GrantPrecheck {
  GrantUsability usability = GrantUsability::NeedsRevalidation;
  ReasonCode reason = ReasonCode::RequiredEvidenceNotFresh;
  std::string detail;
  bool requires_evaluation = false;
};

GrantPrecheck precheck_grant(const AuthorityImpl& impl, const Grant& grant, AuthorityTime now) {
  GrantPrecheck result;
  if (grant.revoked) {
    result.usability = GrantUsability::Revoked;
    result.reason = ReasonCode::RuleDenied;
    result.detail = "the grant was revoked";
    return result;
  }
  if (!(now < grant.expires_at)) {
    result.usability = GrantUsability::Expired;
    result.reason = ReasonCode::RuleDenied;
    result.detail = "the grant expired";
    return result;
  }
  if (!impl.session_inputs_adopted) {
    result.usability = GrantUsability::NeedsRevalidation;
    result.reason = ReasonCode::RequiredEvidenceNotFresh;
    result.detail = "no input generation was adopted by this writer session";
    return result;
  }
  const AuthorityBinding current = impl.current_binding();
  const bool revalidated_for_session = grant.revalidated && grant.revalidated_epoch == current.epoch;
  const bool issued_for_session = grant.issued_binding.epoch == current.epoch;
  // The binding that is in force is the revalidated one when a revalidation has
  // happened in this session, and the issued one otherwise.
  const AuthorityBinding& effective =
      revalidated_for_session ? grant.revalidated_binding : grant.issued_binding;
  if (effective.topology != current.topology || effective.policy != current.policy ||
      effective.control != current.control) {
    result.usability = GrantUsability::Superseded;
    result.reason = ReasonCode::RequiredEvidenceNotFresh;
    result.detail = "the topology, policy or control revision bound to the grant is no longer current";
    return result;
  }
  if (!revalidated_for_session && !issued_for_session) {
    result.usability = GrantUsability::NeedsRevalidation;
    result.reason = ReasonCode::RequiredEvidenceNotFresh;
    result.detail = "the grant was not issued or revalidated in this writer session";
    return result;
  }
  result.usability = GrantUsability::Usable;
  result.requires_evaluation = true;
  return result;
}

}  // namespace

FeedAuthority::FeedAuthority(std::unique_ptr<detail::AuthorityImpl> impl) noexcept
    : impl_(std::move(impl)) {}

FeedAuthority::FeedAuthority(FeedAuthority&& other) noexcept : impl_(std::move(other.impl_)) {}

FeedAuthority& FeedAuthority::operator=(FeedAuthority&& other) noexcept {
  if (this != &other) {
    Close();
    impl_ = std::move(other.impl_);
  }
  return *this;
}

FeedAuthority::~FeedAuthority() { Close(); }

void FeedAuthority::Close() noexcept {
  if (impl_) {
    impl_->open = false;
  }
}

bool FeedAuthority::is_open() const noexcept { return impl_ != nullptr && impl_->open; }

const std::filesystem::path& FeedAuthority::root() const noexcept { return impl_->root; }
const Limits& FeedAuthority::limits() const noexcept { return impl_->limits; }
const RecoveryReport& FeedAuthority::recovery() const noexcept { return impl_->recovery; }
AuthorityEpoch FeedAuthority::epoch() const noexcept { return impl_->state.epoch; }
Incarnation FeedAuthority::incarnation() const noexcept { return impl_->incarnation; }
AuthorityBinding FeedAuthority::current_binding() const { return impl_->current_binding(); }
const AuthorityInputs& FeedAuthority::inputs() const { return impl_->state.current_inputs(); }
bool FeedAuthority::session_inputs_adopted() const noexcept { return impl_->session_inputs_adopted; }

Result<FeedAuthority> FeedAuthority::Open(const OpenOptions& options) {
  const Status limits_status = options.limits.validate();
  if (!limits_status.ok()) {
    return limits_status;
  }
  if (options.root.empty()) {
    return Status::error(StatusCode::InvalidArgument, "no store root was supplied");
  }
  const Status prepared = detail::prepare_store_root(options.root, options.create_if_missing,
                                                     options.allow_reparse_root);
  if (!prepared.ok()) {
    return prepared;
  }

  AuthorityTime opened_at;
  if (options.opened_at) {
    opened_at = *options.opened_at;
  } else {
    const Result<AuthorityTime> system_now = SystemAuthorityTime();
    if (!system_now.ok()) {
      return system_now.status();
    }
    opened_at = system_now.value();
  }

  auto impl = std::make_unique<detail::AuthorityImpl>();
  impl->options = options;
  impl->limits = options.limits;
  impl->root = options.root;
  impl->mode = options.mode;

  bool opened = false;
  bool created = false;
  bool head_was_present = false;
  for (std::size_t attempt = 0; attempt < kOpenAttempts && !opened; ++attempt) {
    const Result<detail::HeadRecord> head = read_head_file(impl->head_path());
    if (!head.ok()) {
      if (head.status().code() != StatusCode::NotFound) {
        return head.status();
      }
      if (options.mode == OpenMode::ReadOnly) {
        return Status::error(StatusCode::NotFound, "the store does not exist");
      }
      if (!options.create_if_missing) {
        return Status::error(StatusCode::NotFound,
                             "the store does not exist and creation was not requested");
      }
      Result<detail::FileLock> lock =
          detail::FileLock::acquire(impl->lock_path(), impl->limits.lock_acquire_budget_nanos);
      if (!lock.ok()) {
        return lock.status();
      }
      const Result<detail::HeadRecord> recheck = read_head_file(impl->head_path());
      if (recheck.ok()) {
        continue;  // another session created the store first; retry against its head
      }
      if (recheck.status().code() != StatusCode::NotFound) {
        return recheck.status();
      }
      for (const std::string_view directory : {kGenerationsDirName, kStagingDirName}) {
        const Status ensured = detail::ensure_directory(detail::child_path(impl->root, directory));
        if (!ensured.ok()) {
          return ensured;
        }
      }
      detail::PersistedState initial = detail::make_initial_state(opened_at);
      const Status published = publish_state(*impl, initial, opened_at);
      if (!published.ok()) {
        return published;
      }
      impl->state = std::move(initial);
      created = true;
      opened = true;
      break;
    }

    head_was_present = true;
    if (options.required_min_sequence && head.value().sequence < *options.required_min_sequence) {
      return Status::error(StatusCode::RollbackDetected,
                           "the committed sequence is older than the caller requires");
    }
    if (options.required_min_epoch && head.value().epoch < *options.required_min_epoch) {
      return Status::error(StatusCode::RollbackDetected,
                           "the committed authority epoch is older than the caller requires");
    }

    // Rollback fence: the head must not be older than the generations present,
    // except for a single orphan generation, which is the expected residue of a
    // crash between publishing a generation and committing the head.
    std::uint64_t newest = 0;
    bool residue = false;
    {
      const Result<bool> generations_exist = detail::path_is_directory(impl->generations_path());
      if (!generations_exist.ok()) {
        return generations_exist.status();
      }
      if (generations_exist.value()) {
        const Result<std::vector<std::string>> names = detail::list_directory_names(
            impl->generations_path(), impl->limits.generation_retention + 64u);
        if (!names.ok()) {
          return names.status();
        }
        for (const std::string& candidate : names.value()) {
          const Result<StoreSequence> sequence = detail::parse_generation_file_name(candidate);
          if (!sequence.ok()) {
            continue;
          }
          newest = std::max(newest, sequence.value().value());
        }
      }
      if (newest > head.value().sequence.value() + 1u) {
        return Status::error(StatusCode::RollbackDetected,
                             "generations newer than the committed head are present");
      }
      residue = newest == head.value().sequence.value() + 1u;
    }

    const Result<detail::PersistedState> loaded =
        load_state_for_head(impl->generations_path(), head.value(), impl->limits);
    if (!loaded.ok()) {
      return loaded.status();
    }
    impl->head = head.value();
    impl->state = std::move(loaded.value());
    if (residue) {
      impl->recovery.residue_present = true;
      impl->recovery.residue.push_back("generation " + StoreSequence::FromValue(newest).str() +
                                       " is published but not committed");
    }
    // Record staging residue before this session publishes anything: a publication
    // retires it, and the report must describe what was found at open.
    if (detail::file_exists(impl->staging_path())) {
      const Result<std::vector<std::string>> staging =
          detail::list_directory_names(impl->staging_path(), 64u);
      if (staging.ok()) {
        for (const std::string& leftover : staging.value()) {
          impl->recovery.residue_present = true;
          impl->recovery.residue.push_back("staging residue: " + leftover);
        }
      }
    }

    if (options.mode == OpenMode::ReadOnly) {
      opened = true;
      break;
    }

    Result<detail::FileLock> lock =
        detail::FileLock::acquire(impl->lock_path(), impl->limits.lock_acquire_budget_nanos);
    if (!lock.ok()) {
      return lock.status();
    }
    const Result<detail::HeadRecord> verify = read_head_file(impl->head_path());
    if (!verify.ok()) {
      return verify.status();
    }
    if (!(verify.value().sequence == impl->head.sequence)) {
      continue;  // a writer published between the read and the lock; retry
    }

    detail::PersistedState draft = impl->state;
    const Result<AuthorityEpoch> next_epoch = draft.epoch.next();
    if (!next_epoch.ok()) {
      return Status::error(StatusCode::LimitExceeded, "the authority epoch is exhausted");
    }
    draft.epoch = next_epoch.value();
    if (draft.last_decision < draft.decision_lease_ceiling) {
      draft.last_decision = draft.decision_lease_ceiling;
    }
    append_event(draft, EventKind::WriterSessionOpened, opened_at, "writer session opened");
    const Status published = publish_state(*impl, draft, opened_at);
    if (!published.ok()) {
      return published;
    }
    impl->state = std::move(draft);
    opened = true;
    break;
  }

  if (!opened) {
    return Status::error(StatusCode::LockConflict,
                         "the store could not be opened after repeated publication races");
  }

  impl->incarnation = Incarnation::ForEpoch(impl->state.epoch);
  impl->session_inputs_adopted = false;
  impl->open = true;

  RecoveryReport& report = impl->recovery;
  report.sequence = impl->state.sequence;
  report.epoch = impl->state.epoch;
  report.incarnation = impl->incarnation;
  report.created_new_store = created;
  report.head_was_present = head_was_present;
  report.grants_loaded = static_cast<std::uint32_t>(impl->state.grants.size());
  report.emergency_loaded = static_cast<std::uint32_t>(impl->state.emergency.size());
  report.events_loaded = static_cast<std::uint32_t>(impl->state.events.size());
  report.replay_entries_loaded = static_cast<std::uint32_t>(impl->state.attempts.size());
  std::uint32_t needing = 0;
  for (const Grant& grant : impl->state.grants) {
    const GrantPrecheck precheck = precheck_grant(*impl, grant, opened_at);
    if (!precheck.requires_evaluation) {
      ++needing;
    }
  }
  report.grants_needing_revalidation = needing;

  return FeedAuthority(std::move(impl));
}

namespace {

Result<DecisionGeneration> allocate_decision_generation(detail::AuthorityImpl& impl,
                                                        AuthorityTime now) {
  const Result<DecisionGeneration> next = impl.state.last_decision.next();
  if (!next.ok()) {
    return Status::error(StatusCode::LimitExceeded, "the decision generation is exhausted");
  }
  if (!(next.value() <= impl.state.decision_lease_ceiling)) {
    // Extend the durable lease so generations stay monotonic across restarts
    // without a write per evaluation.
    const Status extended = mutate(impl, now, [&](detail::PersistedState& draft) {
      const Result<DecisionGeneration> ceiling = next.value().next();
      if (!ceiling.ok()) {
        return Status::error(StatusCode::LimitExceeded, "the decision generation is exhausted");
      }
      const std::uint64_t lease = impl.limits.decision_lease == 0 ? 1u : impl.limits.decision_lease;
      DecisionGeneration target = ceiling.value();
      for (std::uint64_t index = 1; index < lease; ++index) {
        const Result<DecisionGeneration> advanced = target.next();
        if (!advanced.ok()) {
          break;
        }
        target = advanced.value();
      }
      draft.decision_lease_ceiling = target;
      draft.last_decision = next.value();
      return Status::success();
    });
    if (!extended.ok()) {
      return extended;
    }
  } else {
    impl.state.last_decision = next.value();
  }
  return next.value();
}

}  // namespace

Status FeedAuthority::AdoptInputs(const AdoptInputsRequest& request) {
  const Status open = require_read_write(impl_.get());
  if (!open.ok()) {
    return open;
  }
  if (!request.attempt.valid()) {
    return Status::error(StatusCode::InvalidArgument, "adopting inputs requires an attempt identity");
  }
  AuthorityInputs inputs = request.inputs;
  AuthorityInputs::canonicalize(inputs);
  const Status valid = inputs.validate(impl_->limits);
  if (!valid.ok()) {
    return valid;
  }
  const Digest fingerprint = adopt_request_fingerprint(inputs);

  const Result<const AttemptRecord*> prior = lookup_attempt(*impl_, request.attempt, fingerprint);
  if (!prior.ok()) {
    return prior.status();
  }
  if (prior.value() != nullptr) {
    impl_->session_inputs_adopted = true;
    return Status::success();
  }

  const AuthorityInputs& current = impl_->state.current_inputs();
  if (inputs.identical_to(current)) {
    // Adopting the generation that is already in force is a successful no-op: it is
    // how a fresh process re-adopts the inputs its owner supplies.
    impl_->session_inputs_adopted = true;
    return Status::success();
  }

  const struct {
    const char* name;
    std::uint64_t incoming;
    std::uint64_t current_revision;
    Digest incoming_fingerprint;
    Digest current_fingerprint;
  } components[4] = {
      {"topology", inputs.topology.revision.value(), current.topology.revision.value(),
       inputs.topology_fingerprint(), current.topology_fingerprint()},
      {"policy", inputs.policy.revision.value(), current.policy.revision.value(),
       inputs.policy_fingerprint(), current.policy_fingerprint()},
      {"control", inputs.control.revision.value(), current.control.revision.value(),
       inputs.control_fingerprint(), current.control_fingerprint()},
      {"evidence", inputs.evidence.value(), current.evidence.value(), Digest(), Digest()},
  };
  for (const auto& component : components) {
    if (component.incoming < component.current_revision) {
      return Status::error(StatusCode::StaleSourceGeneration,
                           std::string("the ") + component.name + " revision went backwards");
    }
    if (component.incoming == component.current_revision && component.name[0] != 'e') {
      if (!(component.incoming_fingerprint == component.current_fingerprint)) {
        return Status::error(StatusCode::Conflict, std::string("the ") + component.name +
                                                       " revision was reused with different content");
      }
    }
  }

  if (request.precondition) {
    const Status precondition = check_precondition(*impl_, request.precondition->expected);
    if (!precondition.ok()) {
      return precondition;
    }
  }

  const Status applied = mutate(*impl_, request.now, [&](detail::PersistedState& draft) {
    draft.input_history.push_back(inputs);
    append_event(draft, EventKind::InputsAdopted, request.now,
                 "topology=" + inputs.topology.revision.str() + " policy=" +
                     inputs.policy.revision.str() + " control=" + inputs.control.revision.str() +
                     " evidence=" + inputs.evidence.str());
    record_attempt(draft, request.attempt, AttemptKind::AdoptInputs, fingerprint, std::nullopt,
                   std::nullopt);
    return Status::success();
  });
  if (!applied.ok()) {
    return applied;
  }
  impl_->session_inputs_adopted = true;
  return Status::success();
}

Result<DecisionSet> FeedAuthority::Evaluate(const EvaluationRequest& request) {
  const Status open = require_open(impl_.get());
  if (!open.ok()) {
    return open;
  }
  std::vector<CandidateTrace> traces;
  Result<DecisionSet> decision =
      evaluate_with(*impl_, request, request.record_event ? &traces : nullptr);
  if (!decision.ok()) {
    return decision;
  }
  const Result<DecisionGeneration> generation = allocate_decision_generation(*impl_, request.now);
  if (!generation.ok()) {
    return generation.status();
  }
  decision.value().generation = generation.value();
  if (request.record_event) {
    const std::string detail = "load=" + request.load.value() + " eligible=" +
                               std::to_string(decision.value().eligible.size()) + " fingerprint=" +
                               decision.value().fingerprint.hex();
    const Status recorded = mutate(*impl_, request.now, [&](detail::PersistedState& draft) {
      append_event(draft, EventKind::DecisionRecorded, request.now, detail);
      draft.events.back().decision = generation.value();
      return Status::success();
    });
    if (!recorded.ok()) {
      return recorded;
    }
  }
  return decision;
}

Result<Explanation> FeedAuthority::Explain(const EvaluationRequest& request) {
  const Status open = require_open(impl_.get());
  if (!open.ok()) {
    return open;
  }
  Explanation explanation;
  Result<DecisionSet> decision = evaluate_with(*impl_, request, &explanation.traces);
  if (!decision.ok()) {
    return decision.status();
  }
  const Result<DecisionGeneration> generation = allocate_decision_generation(*impl_, request.now);
  if (!generation.ok()) {
    return generation.status();
  }
  decision.value().generation = generation.value();
  explanation.decision = std::move(decision.value());
  return explanation;
}

Result<Grant> FeedAuthority::IssueGrant(const GrantRequest& request) {
  const Status open = require_read_write(impl_.get());
  if (!open.ok()) {
    return open;
  }
  if (!request.attempt.valid()) {
    return Status::error(StatusCode::InvalidArgument, "issuing a grant requires an attempt identity");
  }
  if (!request.load.valid() || !request.feed.valid()) {
    return Status::error(StatusCode::InvalidArgument, "the grant request names no load or no feed");
  }
  if (request.validity.is_zero()) {
    return Status::error(StatusCode::InvalidArgument, "a grant must be valid for a positive time");
  }
  if (request.validity.nanos() > impl_->limits.max_grant_validity_nanos) {
    return Status::error(StatusCode::LimitExceeded, "the requested grant validity exceeds the bound");
  }
  const Digest fingerprint = grant_request_fingerprint(request);
  const Result<const AttemptRecord*> prior = lookup_attempt(*impl_, request.attempt, fingerprint);
  if (!prior.ok()) {
    return prior.status();
  }
  if (prior.value() != nullptr) {
    if (!prior.value()->grant_id) {
      return Status::error(StatusCode::AttemptConflict,
                           "the attempt identity was used for a different operation");
    }
    const Grant* existing = find_grant(impl_->state, GrantId::FromValue(*prior.value()->grant_id));
    if (existing == nullptr) {
      return Status::error(StatusCode::NotFound, "the grant recorded for this attempt no longer exists");
    }
    return *existing;
  }

  const Status precondition = check_precondition(*impl_, request.precondition.expected);
  if (!precondition.ok()) {
    return precondition;
  }
  if (!impl_->session_inputs_adopted) {
    return Status::error(StatusCode::NotRevalidated,
                         "the current input generation has not been adopted by this writer session");
  }

  EvaluationRequest evaluation;
  evaluation.load = request.load;
  evaluation.now = request.now;
  evaluation.required_authority_path = request.required_authority_path;
  const Result<DecisionSet> decision = evaluate_with(*impl_, evaluation, nullptr);
  if (!decision.ok()) {
    return decision.status();
  }
  if (!(decision.value().fingerprint == request.decision_fingerprint)) {
    return Status::error(StatusCode::StaleGeneration,
                         "the cited decision is not the current decision for this pair");
  }
  if (request.decision.is_zero() || request.decision > impl_->state.last_decision) {
    return Status::error(StatusCode::StaleGeneration, "the cited decision generation is not current");
  }
  const Result<CandidateDecision> candidate = find_candidate(decision, request.feed);
  if (!candidate.ok()) {
    return candidate.status();
  }
  if (candidate.value().outcome != DecisionOutcome::Allow) {
    const StatusCode code = candidate.value().outcome == DecisionOutcome::Deny ? StatusCode::Denied
                                                                              : StatusCode::Indeterminate;
    return Status::error(code, std::string("the pair is not admissible: ") +
                                   decision_detail(candidate.value()));
  }
  if (!candidate.value().authority_path.valid()) {
    return Status::error(StatusCode::NotAuthorized,
                         "the permit carries no authority path, so no grant may be issued");
  }

  const Result<AuthorityTime> expires = request.now.Plus(request.validity);
  if (!expires.ok()) {
    return Status::error(StatusCode::LimitExceeded, "the grant expiry overflows");
  }
  Grant issued;
  const Status applied = mutate(*impl_, request.now, [&](detail::PersistedState& draft) {
    if (draft.grants.size() >= impl_->limits.max_grants) {
      return Status::error(StatusCode::LimitExceeded,
                           "the store holds as many grants as its bound allows");
    }
    const Result<GrantSequence> next = draft.last_grant.next();
    if (!next.ok()) {
      return Status::error(StatusCode::LimitExceeded, "the grant sequence is exhausted");
    }
    draft.last_grant = next.value();
    Grant grant;
    grant.id = GrantId::FromValue(next.value().value());
    grant.load = request.load;
    grant.feed = request.feed;
    grant.authority_path = candidate.value().authority_path;
    grant.issued_binding = impl_->current_binding();
    grant.issued_binding.decision = request.decision;
    grant.decision_fingerprint = decision.value().fingerprint;
    grant.issued_at = request.now;
    grant.expires_at = expires.value();
    grant.attempt = request.attempt;
    draft.grants.push_back(grant);
    append_event(draft, EventKind::GrantIssued, request.now,
                 "grant " + grant.id.str() + " load=" + request.load.value() + " feed=" +
                     request.feed.value() + " path=" + grant.authority_path.value());
    draft.events.back().grant = grant.id;
    draft.events.back().decision = request.decision;
    record_attempt(draft, request.attempt, AttemptKind::IssueGrant, fingerprint,
                   grant.id.value(), std::nullopt);
    issued = grant;
    return Status::success();
  });
  if (!applied.ok()) {
    return applied;
  }
  return issued;
}

Result<GrantAuthorization> FeedAuthority::Authorize(const CheckGrantRequest& request) {
  const Status open = require_open(impl_.get());
  if (!open.ok()) {
    return open;
  }
  const Grant* grant = find_grant(impl_->state, request.grant);
  if (grant == nullptr) {
    return Status::error(StatusCode::NotFound, "no such grant");
  }
  GrantAuthorization authorization;
  authorization.grant = *grant;
  authorization.authority_path = grant->authority_path;
  const GrantPrecheck precheck = precheck_grant(*impl_, *grant, request.now);
  authorization.usability = precheck.usability;
  authorization.reason = precheck.reason;
  authorization.detail = precheck.detail;
  authorization.authorized = false;
  if (!precheck.requires_evaluation) {
    return authorization;
  }

  EvaluationRequest evaluation;
  evaluation.load = grant->load;
  evaluation.now = request.now;
  if (grant->authority_path.valid()) {
    evaluation.required_authority_path = grant->authority_path;
  }
  const Result<DecisionSet> decision = evaluate_with(*impl_, evaluation, nullptr);
  if (!decision.ok()) {
    authorization.usability = GrantUsability::EvidenceWithdrawn;
    authorization.reason = ReasonCode::RequiredEvidenceNotFresh;
    authorization.detail = decision.status().message();
    return authorization;
  }
  const Result<CandidateDecision> candidate = find_candidate(decision, grant->feed);
  if (!candidate.ok()) {
    authorization.usability = GrantUsability::EvidenceWithdrawn;
    authorization.reason = ReasonCode::PathNotEstablished;
    authorization.detail = candidate.status().message();
    return authorization;
  }
  if (candidate.value().outcome != DecisionOutcome::Allow) {
    authorization.usability = GrantUsability::EvidenceWithdrawn;
    authorization.reason = candidate.value().reason;
    authorization.detail = decision_detail(candidate.value());
    return authorization;
  }
  if (!(candidate.value().authority_path == grant->authority_path)) {
    authorization.usability = GrantUsability::EvidenceWithdrawn;
    authorization.reason = ReasonCode::AuthorityPathMismatch;
    authorization.detail = "the pair is admissible under a different authority path";
    return authorization;
  }
  authorization.authorized = true;
  authorization.usability = GrantUsability::Usable;
  authorization.reason = candidate.value().reason;
  authorization.detail = "current evidence supports the bound authority path";
  return authorization;
}

Result<Grant> FeedAuthority::RevalidateGrant(const RevalidateGrantRequest& request) {
  const Status open = require_read_write(impl_.get());
  if (!open.ok()) {
    return open;
  }
  if (!request.attempt.valid()) {
    return Status::error(StatusCode::InvalidArgument, "revalidating a grant requires an attempt identity");
  }
  const Digest fingerprint = revalidate_request_fingerprint(request);
  const Result<const AttemptRecord*> prior = lookup_attempt(*impl_, request.attempt, fingerprint);
  if (!prior.ok()) {
    return prior.status();
  }
  if (prior.value() != nullptr) {
    if (!prior.value()->grant_id) {
      return Status::error(StatusCode::AttemptConflict,
                           "the attempt identity was used for a different operation");
    }
    const Grant* existing = find_grant(impl_->state, GrantId::FromValue(*prior.value()->grant_id));
    if (existing == nullptr) {
      return Status::error(StatusCode::NotFound, "the grant recorded for this attempt no longer exists");
    }
    return *existing;
  }
  const Status precondition = check_precondition(*impl_, request.precondition.expected);
  if (!precondition.ok()) {
    return precondition;
  }
  const Grant* grant = find_grant(impl_->state, request.grant);
  if (grant == nullptr) {
    return Status::error(StatusCode::NotFound, "no such grant");
  }
  if (grant->revoked) {
    return Status::error(StatusCode::Revoked, "a revoked grant can never be revalidated");
  }
  if (!(request.now < grant->expires_at)) {
    return Status::error(StatusCode::Expired, "an expired grant can never be revalidated");
  }
  if (!impl_->session_inputs_adopted) {
    return Status::error(StatusCode::NotRevalidated,
                         "the current input generation has not been adopted by this writer session");
  }

  EvaluationRequest evaluation;
  evaluation.load = grant->load;
  evaluation.now = request.now;
  if (grant->authority_path.valid()) {
    evaluation.required_authority_path = grant->authority_path;
  }
  const Result<DecisionSet> decision = evaluate_with(*impl_, evaluation, nullptr);
  if (!decision.ok()) {
    return decision.status();
  }
  const Result<CandidateDecision> candidate = find_candidate(decision, grant->feed);
  const bool admissible = candidate.ok() && candidate.value().outcome == DecisionOutcome::Allow &&
                          candidate.value().authority_path == grant->authority_path;
  const Result<DecisionGeneration> generation = allocate_decision_generation(*impl_, request.now);
  if (!generation.ok()) {
    return generation.status();
  }

  if (!admissible) {
    const StatusCode code = candidate.ok()
                                ? (candidate.value().outcome == DecisionOutcome::Deny
                                       ? StatusCode::Denied
                                       : StatusCode::Indeterminate)
                                : candidate.status().code();
    const std::string detail = candidate.ok() ? decision_detail(candidate.value())
                                              : candidate.status().message();
    const Status recorded = mutate(*impl_, request.now, [&](detail::PersistedState& draft) {
      append_event(draft, EventKind::GrantRevalidationRefused, request.now,
                   "grant " + request.grant.str() + " " + detail);
      draft.events.back().grant = request.grant;
      return Status::success();
    });
    if (!recorded.ok()) {
      return recorded;
    }
    return Status::error(code, "the grant could not be revalidated: " + detail);
  }

  Grant revalidated;
  const Status applied = mutate(*impl_, request.now, [&](detail::PersistedState& draft) {
    Grant* target = find_grant(draft, request.grant);
    if (target == nullptr) {
      return Status::error(StatusCode::NotFound, "no such grant");
    }
    target->revalidated = true;
    target->revalidated_epoch = draft.epoch;
    target->revalidated_binding = impl_->current_binding();
    target->revalidated_binding.decision = generation.value();
    target->revalidated_at = request.now;
    append_event(draft, EventKind::GrantRevalidated, request.now,
                 "grant " + request.grant.str() + " revalidated against topology=" +
                     draft.current_inputs().topology.revision.str() + " policy=" +
                     draft.current_inputs().policy.revision.str() + " control=" +
                     draft.current_inputs().control.revision.str());
    draft.events.back().grant = request.grant;
    draft.events.back().decision = generation.value();
    record_attempt(draft, request.attempt, AttemptKind::RevalidateGrant, fingerprint,
                   request.grant.value(), std::nullopt);
    revalidated = *target;
    return Status::success();
  });
  if (!applied.ok()) {
    return applied;
  }
  return revalidated;
}

Result<Grant> FeedAuthority::RevokeGrant(const RevokeGrantRequest& request) {
  const Status open = require_read_write(impl_.get());
  if (!open.ok()) {
    return open;
  }
  if (!request.attempt.valid()) {
    return Status::error(StatusCode::InvalidArgument, "revoking a grant requires an attempt identity");
  }
  if (!request.authorizer.valid()) {
    return Status::error(StatusCode::InvalidArgument, "revoking a grant requires an identified authorizer");
  }
  if (request.reason.empty() || request.reason.size() > impl_->limits.max_text_length) {
    return Status::error(StatusCode::InvalidArgument,
                         "revoking a grant requires a bounded non-empty reason");
  }
  const Digest fingerprint = revoke_request_fingerprint(request);
  const Result<const AttemptRecord*> prior = lookup_attempt(*impl_, request.attempt, fingerprint);
  if (!prior.ok()) {
    return prior.status();
  }
  if (prior.value() != nullptr) {
    if (!prior.value()->grant_id) {
      return Status::error(StatusCode::AttemptConflict,
                           "the attempt identity was used for a different operation");
    }
    const Grant* existing = find_grant(impl_->state, GrantId::FromValue(*prior.value()->grant_id));
    if (existing == nullptr) {
      return Status::error(StatusCode::NotFound, "the grant recorded for this attempt no longer exists");
    }
    return *existing;
  }
  const Status precondition = check_precondition(*impl_, request.precondition.expected);
  if (!precondition.ok()) {
    return precondition;
  }
  const Grant* grant = find_grant(impl_->state, request.grant);
  if (grant == nullptr) {
    return Status::error(StatusCode::NotFound, "no such grant");
  }
  if (grant->revoked) {
    return Status::error(StatusCode::AlreadyExists, "the grant is already revoked");
  }
  Grant revoked;
  const Status applied = mutate(*impl_, request.now, [&](detail::PersistedState& draft) {
    Grant* target = find_grant(draft, request.grant);
    if (target == nullptr) {
      return Status::error(StatusCode::NotFound, "no such grant");
    }
    target->revoked = true;
    target->revoked_at = request.now;
    target->revoked_by = request.authorizer;
    target->revocation_reason = request.reason;
    append_event(draft, EventKind::GrantRevoked, request.now,
                 "grant " + request.grant.str() + " by=" + request.authorizer.value() +
                     " reason=" + request.reason);
    draft.events.back().grant = request.grant;
    record_attempt(draft, request.attempt, AttemptKind::RevokeGrant, fingerprint,
                   request.grant.value(), std::nullopt);
    revoked = *target;
    return Status::success();
  });
  if (!applied.ok()) {
    return applied;
  }
  return revoked;
}

Result<EmergencyAuthorization> FeedAuthority::AuthorizeEmergency(
    const EmergencyAuthorizationRequest& request) {
  const Status open = require_read_write(impl_.get());
  if (!open.ok()) {
    return open;
  }
  if (!request.attempt.valid()) {
    return Status::error(StatusCode::InvalidArgument, "authorizing requires an attempt identity");
  }
  if (!request.authorizer.valid()) {
    return Status::error(StatusCode::InvalidArgument, "an emergency authorization requires an authorizer");
  }
  if (request.justification.empty() || request.justification.size() > impl_->limits.max_text_length) {
    return Status::error(StatusCode::InvalidArgument,
                         "an emergency authorization requires a bounded non-empty justification");
  }
  if (request.loads.empty()) {
    return Status::error(StatusCode::InvalidArgument,
                         "an emergency authorization must name the loads it covers");
  }
  if (request.loads.size() > impl_->limits.max_loads || request.feeds.size() > impl_->limits.max_feeds) {
    return Status::error(StatusCode::LimitExceeded, "the authorization names more subjects than the bound allows");
  }
  if (request.overridable_classes.empty() ||
      request.overridable_classes.size() > impl_->limits.max_override_classes) {
    return Status::error(StatusCode::InvalidArgument,
                         "an emergency authorization must name the precedence classes it overrides");
  }
  {
    std::unordered_set<std::string> seen;
    for (const LoadId& load : request.loads) {
      if (!load.valid() || !seen.insert(load.value()).second) {
        return Status::error(StatusCode::DuplicateIdentity, "the authorization names a load twice");
      }
    }
    seen.clear();
    for (const FeedId& feed : request.feeds) {
      if (!feed.valid() || !seen.insert(feed.value()).second) {
        return Status::error(StatusCode::DuplicateIdentity, "the authorization names a feed twice");
      }
    }
    std::unordered_set<std::int32_t> classes;
    for (const PrecedenceClass value : request.overridable_classes) {
      const std::int32_t raw = static_cast<std::int32_t>(value);
      if (raw < 0 || raw >= kPrecedenceClassCount) {
        return Status::error(StatusCode::InvalidArgument, "the authorization names an undefined class");
      }
      if (!precedence_class_is_overridable_by_design(value)) {
        return Status::error(StatusCode::NotAuthorized,
                             "a safety interlock can never be overridden");
      }
      if (!classes.insert(raw).second) {
        return Status::error(StatusCode::DuplicateIdentity, "the authorization names a class twice");
      }
    }
  }
  if (request.validity.is_zero() || request.validity.nanos() > impl_->limits.max_emergency_validity_nanos) {
    return Status::error(StatusCode::InvalidArgument,
                         "the requested authorization validity is outside the supported range");
  }

  const Digest fingerprint = emergency_request_fingerprint(request);
  const Result<const AttemptRecord*> prior = lookup_attempt(*impl_, request.attempt, fingerprint);
  if (!prior.ok()) {
    return prior.status();
  }
  if (prior.value() != nullptr) {
    if (!prior.value()->emergency_id) {
      return Status::error(StatusCode::AttemptConflict,
                           "the attempt identity was used for a different operation");
    }
    const EmergencyAuthorization* existing = find_emergency(
        impl_->state, EmergencyAuthorizationId::FromValue(*prior.value()->emergency_id));
    if (existing == nullptr) {
      return Status::error(StatusCode::NotFound, "the authorization recorded for this attempt no longer exists");
    }
    return *existing;
  }

  const Status precondition = check_precondition(*impl_, request.precondition.expected);
  if (!precondition.ok()) {
    return precondition;
  }
  if (!impl_->state.current_inputs().policy.options.emergency_override_enabled) {
    return Status::error(StatusCode::Unsupported,
                         "the adopted policy does not enable emergency overrides");
  }
  for (const LoadId& load : request.loads) {
    if (impl_->state.current_inputs().topology.find_load(load) == nullptr) {
      return Status::error(StatusCode::NotFound, "the authorization names a load the topology does not declare");
    }
  }
  for (const FeedId& feed : request.feeds) {
    if (impl_->state.current_inputs().topology.find_feed(feed) == nullptr) {
      return Status::error(StatusCode::NotFound, "the authorization names a feed the topology does not declare");
    }
  }
  const Result<AuthorityTime> expires = request.now.Plus(request.validity);
  if (!expires.ok()) {
    return Status::error(StatusCode::LimitExceeded, "the authorization expiry overflows");
  }

  EmergencyAuthorization issued;
  const Status applied = mutate(*impl_, request.now, [&](detail::PersistedState& draft) {
    if (draft.emergency.size() >= impl_->limits.max_emergency_authorizations) {
      return Status::error(StatusCode::LimitExceeded,
                           "the store holds as many authorizations as its bound allows");
    }
    const Result<EmergencyAuthorizationId> next = draft.last_emergency.next();
    if (!next.ok()) {
      return Status::error(StatusCode::LimitExceeded, "the authorization sequence is exhausted");
    }
    draft.last_emergency = next.value();
    EmergencyAuthorization authorization;
    authorization.id = next.value();
    authorization.authorizer = request.authorizer;
    authorization.justification = request.justification;
    authorization.loads = request.loads;
    std::sort(authorization.loads.begin(), authorization.loads.end());
    authorization.feeds = request.feeds;
    std::sort(authorization.feeds.begin(), authorization.feeds.end());
    authorization.overridable_classes = request.overridable_classes;
    std::sort(authorization.overridable_classes.begin(), authorization.overridable_classes.end(),
              [](PrecedenceClass left, PrecedenceClass right) {
                return static_cast<std::int32_t>(left) < static_cast<std::int32_t>(right);
              });
    authorization.binding = impl_->current_binding();
    authorization.issued_at = request.now;
    authorization.expires_at = expires.value();
    authorization.attempt = request.attempt;
    draft.emergency.push_back(authorization);
    append_event(draft, EventKind::EmergencyAuthorized, request.now,
                 "authorization " + authorization.id.str() + " by=" + request.authorizer.value() +
                     " loads=" + std::to_string(authorization.loads.size()) + " classes=" +
                     std::to_string(authorization.overridable_classes.size()));
    draft.events.back().emergency = authorization.id;
    record_attempt(draft, request.attempt, AttemptKind::AuthorizeEmergency, fingerprint,
                   std::nullopt, authorization.id.value());
    issued = authorization;
    return Status::success();
  });
  if (!applied.ok()) {
    return applied;
  }
  return issued;
}

Result<EmergencyAuthorization> FeedAuthority::RevokeEmergency(
    const RevokeEmergencyAuthorizationRequest& request) {
  const Status open = require_read_write(impl_.get());
  if (!open.ok()) {
    return open;
  }
  if (!request.attempt.valid()) {
    return Status::error(StatusCode::InvalidArgument, "revoking requires an attempt identity");
  }
  if (!request.authorizer.valid()) {
    return Status::error(StatusCode::InvalidArgument, "revoking requires an identified authorizer");
  }
  if (request.reason.empty() || request.reason.size() > impl_->limits.max_text_length) {
    return Status::error(StatusCode::InvalidArgument, "revoking requires a bounded non-empty reason");
  }
  const Digest fingerprint = revoke_emergency_request_fingerprint(request);
  const Result<const AttemptRecord*> prior = lookup_attempt(*impl_, request.attempt, fingerprint);
  if (!prior.ok()) {
    return prior.status();
  }
  if (prior.value() != nullptr) {
    if (!prior.value()->emergency_id) {
      return Status::error(StatusCode::AttemptConflict,
                           "the attempt identity was used for a different operation");
    }
    const EmergencyAuthorization* existing = find_emergency(
        impl_->state, EmergencyAuthorizationId::FromValue(*prior.value()->emergency_id));
    if (existing == nullptr) {
      return Status::error(StatusCode::NotFound, "the authorization recorded for this attempt no longer exists");
    }
    return *existing;
  }
  const Status precondition = check_precondition(*impl_, request.precondition.expected);
  if (!precondition.ok()) {
    return precondition;
  }
  const EmergencyAuthorization* authorization = find_emergency(impl_->state, request.authorization);
  if (authorization == nullptr) {
    return Status::error(StatusCode::NotFound, "no such emergency authorization");
  }
  if (authorization->revoked) {
    return Status::error(StatusCode::AlreadyExists, "the authorization is already revoked");
  }
  EmergencyAuthorization revoked;
  const Status applied = mutate(*impl_, request.now, [&](detail::PersistedState& draft) {
    EmergencyAuthorization* target = find_emergency(draft, request.authorization);
    if (target == nullptr) {
      return Status::error(StatusCode::NotFound, "no such emergency authorization");
    }
    target->revoked = true;
    target->revoked_at = request.now;
    target->revoked_by = request.authorizer;
    target->revocation_reason = request.reason;
    append_event(draft, EventKind::EmergencyRevoked, request.now,
                 "authorization " + request.authorization.str() + " by=" +
                     request.authorizer.value() + " reason=" + request.reason);
    draft.events.back().emergency = request.authorization;
    record_attempt(draft, request.attempt, AttemptKind::RevokeEmergency, fingerprint, std::nullopt,
                   request.authorization.value());
    revoked = *target;
    return Status::success();
  });
  if (!applied.ok()) {
    return applied;
  }
  return revoked;
}

Result<Grant> FeedAuthority::FindGrant(GrantId id) const {
  const Status open = require_open(impl_.get());
  if (!open.ok()) {
    return open;
  }
  const Grant* grant = find_grant(impl_->state, id);
  if (grant == nullptr) {
    return Status::error(StatusCode::NotFound, "no such grant");
  }
  return *grant;
}

std::vector<Grant> FeedAuthority::Grants() const {
  if (impl_ == nullptr) {
    return {};
  }
  return impl_->state.grants;
}

Result<EmergencyAuthorization> FeedAuthority::FindEmergency(EmergencyAuthorizationId id) const {
  const Status open = require_open(impl_.get());
  if (!open.ok()) {
    return open;
  }
  const EmergencyAuthorization* authorization = find_emergency(impl_->state, id);
  if (authorization == nullptr) {
    return Status::error(StatusCode::NotFound, "no such emergency authorization");
  }
  return *authorization;
}

std::vector<EmergencyAuthorization> FeedAuthority::EmergencyAuthorizations() const {
  if (impl_ == nullptr) {
    return {};
  }
  return impl_->state.emergency;
}

std::vector<EventRecord> FeedAuthority::History(std::size_t limit) const {
  std::vector<EventRecord> history;
  if (impl_ == nullptr) {
    return history;
  }
  const std::size_t bound = std::min<std::size_t>(limit, impl_->state.events.size());
  history.reserve(bound);
  for (std::size_t index = 0; index < bound; ++index) {
    history.push_back(impl_->state.events[impl_->state.events.size() - 1u - index]);
  }
  return history;
}

std::vector<AttemptRecord> FeedAuthority::RetainedAttempts() const {
  if (impl_ == nullptr) {
    return {};
  }
  return impl_->state.attempts;
}

Result<StoreAuditReport> FeedAuthority::AuditStore() const {
  const Status open = require_open(impl_.get());
  if (!open.ok()) {
    return open;
  }
  StoreAuditReport report;
  report.root = display_path(impl_->root);

  const Result<detail::HeadRecord> head = read_head_file(impl_->head_path());
  if (head.ok()) {
    report.head_present = true;
    report.head_valid = true;
    report.head_sequence = head.value().sequence;
    report.epoch = head.value().epoch;
    report.head_generation_digest = head.value().generation_digest;
    report.head_detail = "head " + head.value().sequence.str() + " -> " + head.value().generation_file;
  } else {
    report.head_present = detail::file_exists(impl_->head_path());
    report.head_valid = false;
    report.head_detail = head.status().to_string();
  }

  if (detail::file_exists(impl_->generations_path())) {
    const Result<std::vector<std::string>> names =
        detail::list_directory_names(impl_->generations_path(), impl_->limits.generation_retention + 64u);
    if (names.ok()) {
      for (const std::string& name : names.value()) {
        GenerationAudit entry;
        entry.name = name;
        const Result<StoreSequence> sequence = detail::parse_generation_file_name(name);
        if (!sequence.ok()) {
          entry.classification = "unexpected";
          entry.detail = "the file name is not a generation name";
          report.generations.push_back(std::move(entry));
          continue;
        }
        entry.sequence = sequence.value();
        report.newest_generation_sequence =
            std::max(report.newest_generation_sequence, sequence.value().value());
        const std::filesystem::path path = detail::child_path(impl_->generations_path(), name);
        const Result<std::string> bytes =
            detail::read_file_bounded(path, impl_->limits.max_generation_bytes);
        if (!bytes.ok()) {
          entry.classification = "corrupt";
          entry.detail = bytes.status().message();
          report.generations.push_back(std::move(entry));
          continue;
        }
        entry.bytes = static_cast<std::uint64_t>(bytes.value().size());
        report.total_bytes += entry.bytes;
        const Digest file_digest = Digest::Of(bytes.value());
        entry.header_ok = true;
        const Result<std::string> payload = detail::decode_generation(bytes.value(), impl_->limits);
        if (!payload.ok()) {
          entry.classification = "corrupt";
          entry.detail = payload.status().message();
          report.generations.push_back(std::move(entry));
          continue;
        }
        entry.digest_ok = true;
        const Result<detail::PersistedState> state =
            detail::decode_state(payload.value(), impl_->limits);
        if (!state.ok()) {
          entry.classification = "corrupt";
          entry.detail = state.status().message();
          report.generations.push_back(std::move(entry));
          continue;
        }
        entry.payload_ok = true;
        if (report.head_valid && sequence.value() == report.head_sequence) {
          entry.classification = "head";
          if (!(file_digest == report.head_generation_digest)) {
            entry.classification = "corrupt";
            entry.detail = "the head generation does not match the head digest";
          } else {
            report.granted = static_cast<std::uint32_t>(state.value().grants.size());
            report.emergency_authorizations =
                static_cast<std::uint32_t>(state.value().emergency.size());
            report.events = static_cast<std::uint32_t>(state.value().events.size());
            report.replay_entries = static_cast<std::uint32_t>(state.value().attempts.size());
            for (const Grant& grant : state.value().grants) {
              if (grant.revoked) {
                ++report.revoked;
              }
            }
          }
        } else if (report.head_valid && sequence.value().value() == report.head_sequence.value() + 1u) {
          entry.classification = "orphan";
          entry.detail = "published but not committed, the residue of an interrupted publication";
        } else if (report.head_valid && sequence.value() < report.head_sequence) {
          entry.classification = "retained";
        } else {
          entry.classification = "unexpected";
          entry.detail = "the generation is newer than the committed head";
        }
        report.generations.push_back(std::move(entry));
      }
    }
  }

  if (detail::file_exists(impl_->staging_path())) {
    const Result<std::vector<std::string>> staging =
        detail::list_directory_names(impl_->staging_path(), 64u);
    if (staging.ok()) {
      report.staging_residue = staging.value();
    }
  }

  const Result<std::vector<std::string>> root_entries =
      detail::list_directory_names(impl_->root, 64u);
  if (root_entries.ok()) {
    for (const std::string& entry : root_entries.value()) {
      if (entry != kLockFileName && entry != kHeadFileName && entry != kGenerationsDirName &&
          entry != kStagingDirName) {
        report.unexpected_entries.push_back(entry);
      }
    }
  }

  report.rollback_suspected = report.head_valid &&
                              report.newest_generation_sequence > report.head_sequence.value() + 1u;
  return report;
}

Result<PolicyDiff> FeedAuthority::DiffPolicy(PolicyRevision from, PolicyRevision to) const {
  const Status open = require_open(impl_.get());
  if (!open.ok()) {
    return open;
  }
  const PolicySet* before = nullptr;
  const PolicySet* after = nullptr;
  for (const AuthorityInputs& inputs : impl_->state.input_history) {
    if (inputs.policy.revision == from) {
      before = &inputs.policy;
    }
    if (inputs.policy.revision == to) {
      after = &inputs.policy;
    }
  }
  if (before == nullptr) {
    return Status::error(StatusCode::NotFound, "the policy revision is not retained in this store");
  }
  if (after == nullptr) {
    return Status::error(StatusCode::NotFound, "the policy revision is not retained in this store");
  }

  PolicyDiff diff;
  diff.from = from;
  diff.to = to;
  diff.identical = from == to;
  for (const EligibilityRule& rule : before->rules) {
    const EligibilityRule* other = after->find_rule(rule.id);
    if (other == nullptr) {
      diff.rules.push_back(RuleDelta{rule.id, "removed", rule_summary(rule), std::string()});
    } else if (!(*other == rule)) {
      diff.rules.push_back(RuleDelta{rule.id, "changed", rule_summary(rule), rule_summary(*other)});
      diff.identical = false;
    }
  }
  for (const EligibilityRule& rule : after->rules) {
    if (before->find_rule(rule.id) == nullptr) {
      diff.rules.push_back(RuleDelta{rule.id, "added", std::string(), rule_summary(rule)});
      diff.identical = false;
    }
  }
  std::sort(diff.rules.begin(), diff.rules.end(),
            [](const RuleDelta& left, const RuleDelta& right) { return left.id < right.id; });

  for (const ProtectedObligation& obligation : before->obligations) {
    const ProtectedObligation* other = nullptr;
    for (const ProtectedObligation& candidate : after->obligations) {
      if (candidate.id == obligation.id) {
        other = &candidate;
        break;
      }
    }
    if (other == nullptr) {
      diff.obligations.push_back(
          ObligationDelta{obligation.id, "removed", obligation_summary(obligation), std::string()});
    } else if (!(*other == obligation)) {
      diff.obligations.push_back(ObligationDelta{obligation.id, "changed",
                                                 obligation_summary(obligation),
                                                 obligation_summary(*other)});
      diff.identical = false;
    }
  }
  for (const ProtectedObligation& obligation : after->obligations) {
    bool found = false;
    for (const ProtectedObligation& candidate : before->obligations) {
      if (candidate.id == obligation.id) {
        found = true;
        break;
      }
    }
    if (!found) {
      diff.obligations.push_back(
          ObligationDelta{obligation.id, "added", std::string(), obligation_summary(obligation)});
      diff.identical = false;
    }
  }
  std::sort(diff.obligations.begin(), diff.obligations.end(),
            [](const ObligationDelta& left, const ObligationDelta& right) { return left.id < right.id; });

  if (!(before->options == after->options)) {
    diff.identical = false;
    diff.option_changes.push_back(std::string("ranking enabled ") +
                                  (before->options.ranking.enabled ? "true" : "false") + " -> " +
                                  (after->options.ranking.enabled ? "true" : "false"));
    diff.option_changes.push_back(std::string("emergency overrides ") +
                                  (before->options.emergency_override_enabled ? "true" : "false") +
                                  " -> " +
                                  (after->options.emergency_override_enabled ? "true" : "false"));
    std::string before_roles;
    for (const RedundancyRole role : before->options.ranking.role_order) {
      before_roles += std::string(to_string(role)) + " ";
    }
    std::string after_roles;
    for (const RedundancyRole role : after->options.ranking.role_order) {
      after_roles += std::string(to_string(role)) + " ";
    }
    if (before_roles != after_roles) {
      diff.option_changes.push_back("ranking order " + before_roles + "-> " + after_roles);
    }
  }
  return diff;
}

Result<InputsDiff> FeedAuthority::DiffInputs(TopologyRevision from, TopologyRevision to) const {
  const Status open = require_open(impl_.get());
  if (!open.ok()) {
    return open;
  }
  const AuthorityInputs* before = nullptr;
  const AuthorityInputs* after = nullptr;
  for (const AuthorityInputs& inputs : impl_->state.input_history) {
    if (inputs.topology.revision == from) {
      before = &inputs;
    }
    if (inputs.topology.revision == to) {
      after = &inputs;
    }
  }
  if (before == nullptr || after == nullptr) {
    return Status::error(StatusCode::NotFound, "the topology revision is not retained in this store");
  }

  InputsDiff diff;
  diff.identical = before->identical_to(*after);
  diff.from_topology = before->topology.revision;
  diff.to_topology = after->topology.revision;
  diff.from_policy = before->policy.revision;
  diff.to_policy = after->policy.revision;
  diff.from_control = before->control.revision;
  diff.to_control = after->control.revision;
  diff.from_evidence = before->evidence;
  diff.to_evidence = after->evidence;

  for (const FeedDescriptor& feed : before->topology.feeds) {
    const FeedDescriptor* other = after->topology.find_feed(feed.id);
    if (other == nullptr) {
      diff.changes.push_back("feed removed " + feed.id.value());
    } else if (!(*other == feed)) {
      diff.changes.push_back("feed changed " + feed.id.value() + " source " +
                             to_string(feed.source_class) + "->" + to_string(other->source_class) +
                             " role " + to_string(feed.role) + "->" + to_string(other->role));
    }
  }
  for (const FeedDescriptor& feed : after->topology.feeds) {
    if (before->topology.find_feed(feed.id) == nullptr) {
      diff.changes.push_back("feed added " + feed.id.value());
    }
  }
  for (const LoadDescriptor& load : before->topology.loads) {
    const LoadDescriptor* other = after->topology.find_load(load.id);
    if (other == nullptr) {
      diff.changes.push_back("load removed " + load.id.value());
    } else if (!(*other == load)) {
      diff.changes.push_back("load changed " + load.id.value());
    }
  }
  for (const LoadDescriptor& load : after->topology.loads) {
    if (before->topology.find_load(load.id) == nullptr) {
      diff.changes.push_back("load added " + load.id.value());
    }
  }
  for (const FeedLink& link : before->topology.links) {
    bool found = false;
    for (const FeedLink& other : after->topology.links) {
      if (other.feed == link.feed && other.load == link.load) {
        found = true;
        if (!(other == link)) {
          diff.changes.push_back("path changed " + link.feed.value() + " -> " + link.load.value());
        }
        break;
      }
    }
    if (!found) {
      diff.changes.push_back("path removed " + link.feed.value() + " -> " + link.load.value());
    }
  }
  for (const FeedLink& link : after->topology.links) {
    bool found = false;
    for (const FeedLink& other : before->topology.links) {
      if (other.feed == link.feed && other.load == link.load) {
        found = true;
        break;
      }
    }
    if (!found) {
      diff.changes.push_back("path added " + link.feed.value() + " -> " + link.load.value());
    }
  }
  if (!(before->control == after->control)) {
    diff.changes.push_back("control revision " + before->control.revision.str() + " -> " +
                           after->control.revision.str());
  }
  if (!(before->policy == after->policy)) {
    diff.changes.push_back("policy revision " + before->policy.revision.str() + " -> " +
                           after->policy.revision.str());
  }
  std::sort(diff.changes.begin(), diff.changes.end());
  std::sort(diff.changes.begin(), diff.changes.end());
  const Result<PolicyDiff> policy_diff = DiffPolicy(before->policy.revision, after->policy.revision);
  if (policy_diff.ok()) {
    diff.policy_diff = policy_diff.value();
  }
  return diff;
}

Status FeedAuthority::Verify() const {
  const Status open = require_open(impl_.get());
  if (!open.ok()) {
    return open;
  }
  std::string payload;
  Status status = detail::encode_state(impl_->state, impl_->limits, payload);
  if (!status.ok()) {
    return Status::error(StatusCode::InvariantViolation,
                         "the adopted state cannot be encoded: " + status.message());
  }
  const Result<detail::PersistedState> decoded = detail::decode_state(payload, impl_->limits);
  if (!decoded.ok()) {
    return Status::error(StatusCode::InvariantViolation,
                         "the adopted state does not round trip: " + decoded.status().message());
  }
  std::string second;
  status = detail::encode_state(decoded.value(), impl_->limits, second);
  if (!status.ok() || second != payload) {
    return Status::error(StatusCode::InvariantViolation,
                         "the canonical encoding of the adopted state is not stable");
  }

  for (std::size_t index = 0; index < impl_->state.input_history.size(); ++index) {
    const Status valid = impl_->state.input_history[index].validate(impl_->limits);
    if (!valid.ok()) {
      return Status::error(StatusCode::InvariantViolation,
                           "an adopted input generation is invalid: " + valid.message());
    }
  }
  for (std::size_t index = 0; index < impl_->state.grants.size(); ++index) {
    const Grant& grant = impl_->state.grants[index];
    if (!grant.id.value()) {
      return Status::error(StatusCode::InvariantViolation, "a grant has a zero identity");
    }
    if (index > 0 && !(impl_->state.grants[index - 1].id < grant.id)) {
      return Status::error(StatusCode::InvariantViolation, "grants are not in increasing identity order");
    }
    if (!(grant.issued_at < grant.expires_at)) {
      return Status::error(StatusCode::InvariantViolation, "a grant does not expire after it was issued");
    }
  }
  for (std::size_t index = 0; index < impl_->state.emergency.size(); ++index) {
    const EmergencyAuthorization& authorization = impl_->state.emergency[index];
    if (index > 0 && !(impl_->state.emergency[index - 1].id < authorization.id)) {
      return Status::error(StatusCode::InvariantViolation,
                           "emergency authorizations are not in increasing identity order");
    }
    if (authorization.loads.empty() || authorization.overridable_classes.empty()) {
      return Status::error(StatusCode::InvariantViolation,
                           "an emergency authorization has no scope");
    }
    for (const PrecedenceClass value : authorization.overridable_classes) {
      if (!precedence_class_is_overridable_by_design(value)) {
        return Status::error(StatusCode::InvariantViolation,
                             "an emergency authorization names a safety interlock");
      }
    }
  }
  for (std::size_t index = 0; index < impl_->state.events.size(); ++index) {
    if (index > 0 && !(impl_->state.events[index - 1].sequence < impl_->state.events[index].sequence)) {
      return Status::error(StatusCode::InvariantViolation, "events are not in increasing sequence order");
    }
  }
  return Status::success();
}

Status FeedAuthority::Reload() {
  const Status open = require_read_write(impl_.get());
  if (!open.ok()) {
    return open;
  }
  Result<bool> changed = refresh_from_store(*impl_);
  if (!changed.ok()) {
    return changed.status();
  }
  if (!changed.value()) {
    return Status::success();
  }
  AuthorityTime now;
  const Result<AuthorityTime> system_now = SystemAuthorityTime();
  if (!system_now.ok()) {
    return system_now.status();
  }
  now = system_now.value();
  const Status applied = mutate(*impl_, now, [&](detail::PersistedState& draft) {
    const Result<AuthorityEpoch> next_epoch = draft.epoch.next();
    if (!next_epoch.ok()) {
      return Status::error(StatusCode::LimitExceeded, "the authority epoch is exhausted");
    }
    draft.epoch = next_epoch.value();
    if (draft.last_decision < draft.decision_lease_ceiling) {
      draft.last_decision = draft.decision_lease_ceiling;
    }
    append_event(draft, EventKind::StoreReloaded, now,
                 "adopted sequence " + draft.sequence.str() + " from another writer session");
    return Status::success();
  });
  if (!applied.ok()) {
    return applied;
  }
  impl_->incarnation = Incarnation::ForEpoch(impl_->state.epoch);
  return Status::success();
}

}  // namespace feed_authority
