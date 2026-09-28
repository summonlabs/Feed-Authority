#pragma once

// The Feed Authority runtime.
//
// One instance owns one store root and one adopted input generation. The instance
// is confined to one thread: the library holds no internal mutex, adds no worker
// threads and spawns nothing. Cross-process authority is enforced by an operating
// system advisory lock on the store root plus generation fencing, so two processes
// cannot publish over each other and a writer whose in-memory state was superseded
// refuses to mutate rather than merging.
//
// The public surface answers exactly one question: which feed may serve which load
// now, under which mode, redundancy, maintenance, failure and policy constraints,
// and why. It never switches anything.

#include <cstdint>
#include <filesystem>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "feed_authority/decision.hpp"
#include "feed_authority/diff.hpp"
#include "feed_authority/emergency.hpp"
#include "feed_authority/event.hpp"
#include "feed_authority/grant.hpp"
#include "feed_authority/idempotency.hpp"
#include "feed_authority/inputs.hpp"
#include "feed_authority/store.hpp"
#include "feed_authority/time.hpp"

namespace feed_authority {

namespace detail {
/// The private implementation of the runtime. Declared here so that helpers in the
/// implementation file can reach it, and defined only in the library.
struct AuthorityImpl;
}  // namespace detail

/// A mutation states the binding it was planned against. The runtime refuses the
/// mutation with `StaleAuthority` or `StaleSourceGeneration` when the current
/// binding no longer matches.
struct AuthorityPrecondition {
  AuthorityBinding expected;

  friend bool operator==(const AuthorityPrecondition& left,
                         const AuthorityPrecondition& right) noexcept {
    return left.expected == right.expected;
  }
};

struct AdoptInputsRequest {
  AuthorityInputs inputs;
  AttemptId attempt;
  /// Optional. When supplied, the adoption is refused when the current generation
  /// binding differs. The first adoption in a session may omit it.
  std::optional<AuthorityPrecondition> precondition;
  /// The instant recorded in the audit event.
  AuthorityTime now;
};

struct GrantRequest {
  LoadId load;
  FeedId feed;
  /// The decision generation and fingerprint that authorized this pair. The
  /// runtime re-evaluates and refuses the grant when the pair is not admissible.
  DecisionGeneration decision{};
  Digest decision_fingerprint;
  /// How long the grant stays valid from `now`. Bounded by the limits.
  Duration validity;
  /// When set, the deciding permit rule must name exactly this authority path.
  std::optional<AuthorityPathId> required_authority_path;
  AuthorityTime now;
  AttemptId attempt;
  AuthorityPrecondition precondition;
};

struct RevokeGrantRequest {
  GrantId grant;
  AuthorizerId authorizer;
  std::string reason;
  AuthorityTime now;
  AttemptId attempt;
  AuthorityPrecondition precondition;
};

struct RevalidateGrantRequest {
  GrantId grant;
  AuthorityTime now;
  AttemptId attempt;
  AuthorityPrecondition precondition;
};

struct CheckGrantRequest {
  GrantId grant;
  AuthorityTime now;
};

struct EmergencyAuthorizationRequest {
  AuthorizerId authorizer;
  std::string justification;
  std::vector<LoadId> loads;
  std::vector<FeedId> feeds;
  std::vector<PrecedenceClass> overridable_classes;
  Duration validity;
  AuthorityTime now;
  AttemptId attempt;
  AuthorityPrecondition precondition;
};

struct RevokeEmergencyAuthorizationRequest {
  EmergencyAuthorizationId authorization;
  AuthorizerId authorizer;
  std::string reason;
  AuthorityTime now;
  AttemptId attempt;
  AuthorityPrecondition precondition;
};

/// The runtime handle. Move-only: the store lock and the adopted generation belong
/// to exactly one holder.
class FeedAuthority {
 public:
  static Result<FeedAuthority> Open(const OpenOptions& options);

  FeedAuthority(FeedAuthority&& other) noexcept;
  FeedAuthority& operator=(FeedAuthority&& other) noexcept;
  ~FeedAuthority();

  FeedAuthority(const FeedAuthority&) = delete;
  FeedAuthority& operator=(const FeedAuthority&) = delete;

  /// Releases the writer lock and detaches from the store. Idempotent.
  void Close() noexcept;
  bool is_open() const noexcept;

  const std::filesystem::path& root() const noexcept;
  const Limits& limits() const noexcept;
  const RecoveryReport& recovery() const noexcept;
  AuthorityEpoch epoch() const noexcept;
  Incarnation incarnation() const noexcept;
  /// The binding every mutation must be planned against.
  AuthorityBinding current_binding() const;
  /// The adopted input generation. After recovery this is the generation read
  /// from disk; its evidence is not made fresh by recovery.
  const AuthorityInputs& inputs() const;
  /// True once this writer session adopted inputs. Grant issuance, revalidation
  /// and grant authorization require it, so a recovered grant cannot authorize
  /// anything before the current inputs were supplied by their owner.
  bool session_inputs_adopted() const noexcept;

  /// Adopts a newer or equal input generation. Refuses a revision that went
  /// backwards, a revision reused with different content, and a stale
  /// precondition. A logically identical generation is a successful no-op.
  Status AdoptInputs(const AdoptInputsRequest& request);

  /// Evaluates every admissible candidate for one load. Pure read of adopted
  /// state: it takes no store lock and mutates nothing unless the request asks for
  /// an audit event.
  Result<DecisionSet> Evaluate(const EvaluationRequest& request);
  /// Evaluation with the ordered per-candidate trace.
  Result<Explanation> Explain(const EvaluationRequest& request);

  Result<Grant> IssueGrant(const GrantRequest& request);
  /// The authorization question: may this grant authorize anything now?
  Result<GrantAuthorization> Authorize(const CheckGrantRequest& request);
  Result<Grant> RevalidateGrant(const RevalidateGrantRequest& request);
  Result<Grant> RevokeGrant(const RevokeGrantRequest& request);

  Result<EmergencyAuthorization> AuthorizeEmergency(const EmergencyAuthorizationRequest& request);
  Result<EmergencyAuthorization> RevokeEmergency(
      const RevokeEmergencyAuthorizationRequest& request);

  Result<Grant> FindGrant(GrantId id) const;
  std::vector<Grant> Grants() const;
  Result<EmergencyAuthorization> FindEmergency(EmergencyAuthorizationId id) const;
  std::vector<EmergencyAuthorization> EmergencyAuthorizations() const;

  /// The most recent events, newest first, bounded by `limit`.
  std::vector<EventRecord> History(std::size_t limit) const;
  /// The retained idempotency records, oldest first.
  std::vector<AttemptRecord> RetainedAttempts() const;

  /// A structural and integrity audit of the store directory. Never mutates it.
  Result<StoreAuditReport> AuditStore() const;

  Result<PolicyDiff> DiffPolicy(PolicyRevision from, PolicyRevision to) const;
  Result<InputsDiff> DiffInputs(TopologyRevision from, TopologyRevision to) const;

  /// Recomputes every digest and checks every documented internal invariant.
  Status Verify() const;

  /// Adopts a newer head published by another session, refusing a head that went
  /// backwards. Does not make evidence fresh and does not revalidate grants.
  Status Reload();

 private:
  friend struct detail::AuthorityImpl;
  explicit FeedAuthority(std::unique_ptr<detail::AuthorityImpl> impl) noexcept;
  std::unique_ptr<detail::AuthorityImpl> impl_;
};

}  // namespace feed_authority
