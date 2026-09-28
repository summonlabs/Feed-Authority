#pragma once

// The persisted authority state: exactly what one generation file contains.

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include "feed_authority/emergency.hpp"
#include "feed_authority/event.hpp"
#include "feed_authority/grant.hpp"
#include "feed_authority/idempotency.hpp"
#include "feed_authority/inputs.hpp"
#include "feed_authority/limits.hpp"
#include "feed_authority/status.hpp"
#include "feed_authority/store.hpp"

namespace feed_authority::detail {

struct PersistedState {
  StoreSequence sequence{};
  AuthorityEpoch epoch{};
  /// The highest decision generation handed out so far.
  DecisionGeneration last_decision{};
  /// The highest decision generation reserved durably. Generations up to this
  /// ceiling may be handed out without another publication.
  DecisionGeneration decision_lease_ceiling{};
  GrantSequence last_grant{};
  EmergencyAuthorizationId last_emergency{};
  EventSequence last_event{};

  /// Adopted input generations, oldest first. The last entry is the current one;
  /// a new store starts with one empty generation at revision zero.
  std::vector<AuthorityInputs> input_history;

  std::vector<Grant> grants;
  std::vector<EmergencyAuthorization> emergency;
  /// Retained idempotency records, oldest first.
  std::vector<AttemptRecord> attempts;
  /// Audit events, oldest first.
  std::vector<EventRecord> events;

  const AuthorityInputs& current_inputs() const noexcept { return input_history.back(); }

  /// SHA-256 over the canonical payload of this state.
  Result<Digest> content_digest() const;

  /// Sorts every collection into canonical order so that logically equal states
  /// encode to identical bytes.
  void canonicalize(const Limits& limits);
};

/// Encodes the whole state as canonical payload bytes.
Status encode_state(const PersistedState& state, const Limits& limits, std::string& out);

/// Decodes canonical payload bytes. Strict: unknown records, missing or extra
/// fields, out-of-order records, out-of-range values, counts above the limits and
/// cross-reference failures are refused.
Result<PersistedState> decode_state(std::string_view payload, const Limits& limits);

/// The state of a store that has just been created.
PersistedState make_initial_state(AuthorityTime now);

}  // namespace feed_authority::detail
