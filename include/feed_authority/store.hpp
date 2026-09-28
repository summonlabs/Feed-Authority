#pragma once

// Durable, integrity-checked store of authority state.
//
// Layout (all inside the store root directory):
//
//   authority.lock          advisory cross-process writer lock, never written to
//   head.marker             the committed head: sequence, generation file name,
//                           generation digest, previous head digest, epoch
//   generations/gen-<19 digits>.fas
//                           verified generations, oldest first, bounded retention
//   staging/                staging files, never authoritative, always removable
//
// Publication is transactional: a mutation is planned in memory, validated, its
// generation is written to a staging file and flushed, read back and verified
// byte for byte, published by an atomic rename into `generations/`, and only then
// committed by atomically replacing `head.marker`. The commit point is the
// successful atomic replacement of `head.marker`: before it, the previous head is
// still the whole state; after it, the new generation is. A crash before the
// commit leaves a staging file or an orphan generation, both of which are residue
// that recovery ignores and `store-audit` reports. A crash after the commit leaves
// the new generation as the whole state.

#include <cstdint>
#include <filesystem>
#include <functional>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "feed_authority/digest.hpp"
#include "feed_authority/generations.hpp"
#include "feed_authority/limits.hpp"
#include "feed_authority/status.hpp"
#include "feed_authority/time.hpp"

namespace feed_authority {

enum class OpenMode : std::int32_t {
  /// Reads the committed state, takes no lock and advances no epoch. No mutation
  /// is possible.
  ReadOnly = 0,
  /// Takes the writer lock, advances the authority epoch and permits mutation.
  ReadWrite = 1,
};

/// A durable stage of the publication protocol. A validation harness may inject a
/// fault at one of these points to prove what recovery does with the artifacts a
/// crash at that stage leaves behind. See docs/artifact-format.md.
enum class FaultPoint : std::int32_t {
  None = 0,
  /// The staging file was written and flushed, and the generation was not yet
  /// published.
  AfterStagingWrite = 1,
  /// The staging file was read back and verified, and the generation was not yet
  /// published.
  AfterStagingReadback = 2,
  /// The generation was published into `generations/`, and the head marker was
  /// not yet committed: the crash leaves an orphan generation.
  AfterGenerationPublish = 3,
  /// The head staging file was written, and the head marker was not yet replaced.
  AfterHeadStagingWrite = 4,
  /// The head marker was committed: the crash leaves the new state as the whole
  /// state.
  AfterHeadCommit = 5,
};

const char* to_string(FaultPoint point) noexcept;

struct OpenOptions {
  std::filesystem::path root;
  OpenMode mode = OpenMode::ReadWrite;
  /// Create an empty store when the root contains no head marker. When false, a
  /// root without a head is refused with `NotFound`.
  bool create_if_missing = false;
  /// The minimum committed sequence this caller accepts. A store whose head is
  /// older is refused with `RollbackDetected`. This is the caller-side fence
  /// against restoring an older whole state.
  std::optional<StoreSequence> required_min_sequence;
  /// The minimum authority epoch this caller accepts, with the same refusal.
  std::optional<AuthorityEpoch> required_min_epoch;
  /// Accept a store root that is itself a symbolic link, junction or other reparse
  /// point. Refused by default, because the trust model treats the root as a
  /// caller-chosen directory and a substituted root would silently redirect writes.
  bool allow_reparse_root = false;
  /// The instant recorded in the events this session writes while opening. When
  /// unset, the system clock is read once at open. Every later operation takes its
  /// instant from the caller, so this is the only implicit clock use in the
  /// library.
  std::optional<AuthorityTime> opened_at;
  /// The durable stage at which `on_fault` is invoked. Inert by default. The
  /// callback runs with the writer lock held and no other internal resource
  /// acquired, so a callback that terminates the process leaves exactly the
  /// durable artifacts of that stage behind.
  FaultPoint fault_point = FaultPoint::None;
  /// How many publications of this session to let through before the fault point is
  /// honoured. Zero means the fault is live from the first publication, which is the
  /// session-opening one; one means the first publication completes and the next one
  /// (typically the mutation under test) is the one that faults.
  std::uint32_t fault_skip_publications = 0;
  std::function<void(FaultPoint)> on_fault;
  Limits limits{};
};

/// The result of reading one generation file during an audit.
struct GenerationAudit {
  std::string name;
  std::uint64_t bytes = 0;
  StoreSequence sequence{};
  bool header_ok = false;
  bool digest_ok = false;
  bool payload_ok = false;
  /// "head", "retained", "orphan", "corrupt", or "unexpected".
  std::string classification;
  std::string detail;
};

/// A structural and integrity audit of a store directory. The audit never
/// modifies the store.
struct StoreAuditReport {
  std::string root;
  bool head_present = false;
  bool head_valid = false;
  std::string head_detail;
  StoreSequence head_sequence{};
  AuthorityEpoch epoch{};
  Digest head_generation_digest;
  std::vector<GenerationAudit> generations;
  std::vector<std::string> staging_residue;
  std::vector<std::string> unexpected_entries;
  std::uint64_t newest_generation_sequence = 0;
  bool rollback_suspected = false;
  std::uint64_t total_bytes = 0;
  std::uint32_t granted = 0;
  std::uint32_t revoked = 0;
  std::uint32_t expiring = 0;
  std::uint32_t emergency_authorizations = 0;
  std::uint32_t events = 0;
  std::uint32_t replay_entries = 0;

  /// True when every generation that must be readable is readable, the head is
  /// valid, and no rollback is suspected. Residue does not make an audit fail: it
  /// is reported and may be removed by the next successful publication.
  bool ok() const noexcept;
  std::string to_string() const;
};

/// What recovery adopted at open.
struct RecoveryReport {
  StoreSequence sequence{};
  AuthorityEpoch epoch{};
  Incarnation incarnation{};
  bool created_new_store = false;
  bool head_was_present = false;
  bool residue_present = false;
  std::vector<std::string> residue;
  std::uint32_t grants_loaded = 0;
  /// Grants that are present on disk but may not authorize anything until this
  /// writer session revalidates them.
  std::uint32_t grants_needing_revalidation = 0;
  std::uint32_t emergency_loaded = 0;
  std::uint32_t events_loaded = 0;
  std::uint32_t replay_entries_loaded = 0;

  std::string to_string() const;
};

/// Fixed file and directory names inside a store root.
inline constexpr std::string_view kLockFileName = "authority.lock";
inline constexpr std::string_view kHeadFileName = "head.marker";
inline constexpr std::string_view kGenerationsDirName = "generations";
inline constexpr std::string_view kStagingDirName = "staging";

}  // namespace feed_authority
