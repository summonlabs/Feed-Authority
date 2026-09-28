// Proof obligations: authority state is published transactionally and reopened as
// exactly one whole verified state; recovery distinguishes persisted grants from
// usable grants; a rolled-back or truncated store is refused; identical logical state
// produces identical bytes.

#include <fstream>

#include "support/test_harness.hpp"
#include "support/fixtures.hpp"

#include "detail/platform_io.hpp"
#include "detail/state.hpp"
#include "detail/store_format.hpp"

using namespace feed_authority;

namespace {

const char* kScenario = R"(revisions topology=10 policy=4 control=7 evidence=9
feed F1 source=utility role=primary domain=D1 protected=yes
feed F2 source=generator role=secondary domain=D2 protected=yes
load L1 class=critical protected=yes
link F1 L1 role=primary domain=D1
link F2 L1 role=secondary domain=D2
obs feed F1 condition=energized at=1735689600 max_age=300s source=S1
obs feed F2 condition=energized at=1735689600 max_age=300s source=S1
obs link F1 L1 present=yes at=1735689600 max_age=300s source=S1
obs link F2 L1 present=yes at=1735689600 max_age=300s source=S1
obs state condition=normal at=1735689600 max_age=300s source=S1
rule R1 effect=permit precedence=ordinary_policy feed=F1 load=L1 path=AUTH-PRIMARY
rule R2 effect=permit precedence=ordinary_policy feed=F2 load=L1 path=AUTH-SECONDARY
)";

std::filesystem::path head_path(const std::filesystem::path& root) {
  return root / std::string(kHeadFileName);
}

std::filesystem::path generations_path(const std::filesystem::path& root) {
  return root / std::string(kGenerationsDirName);
}

std::string read_all(const std::filesystem::path& path) {
  std::ifstream stream(path, std::ios::binary);
  return std::string((std::istreambuf_iterator<char>(stream)), std::istreambuf_iterator<char>());
}

void write_all(const std::filesystem::path& path, const std::string& bytes) {
  std::ofstream stream(path, std::ios::binary | std::ios::trunc);
  stream.write(bytes.data(), static_cast<std::streamsize>(bytes.size()));
}

std::filesystem::path newest_generation(const std::filesystem::path& root) {
  std::filesystem::path newest;
  std::uint64_t highest = 0;
  for (const auto& entry : std::filesystem::directory_iterator(generations_path(root))) {
    const Result<StoreSequence> sequence =
        detail::parse_generation_file_name(entry.path().filename().string());
    if (!sequence.ok()) {
      continue;
    }
    if (sequence.value().value() >= highest) {
      highest = sequence.value().value();
      newest = entry.path();
    }
  }
  return newest;
}

}  // namespace

FA_TEST(persistence, close_and_reopen_adopts_one_whole_state) {
  const std::filesystem::path root = fa_test::fresh_store("persistence-reopen");
  GrantId issued;
  StoreSequence first_sequence;
  AuthorityEpoch first_epoch;
  {
    Result<FeedAuthority> authority = fa_test::open_store(root, true);
    FA_REQUIRE_OK(authority);
    FA_REQUIRE_OK(fa_test::adopt(authority.value(), fa_test::inputs(kScenario), "adopt-1",
                                 fa_test::at(1735689600)));
    const Result<Grant> grant =
        fa_test::issue_grant(authority.value(), "L1", "F1", fa_test::at(1735689600), "attempt-1");
    FA_REQUIRE_OK(grant);
    issued = grant.value().id;
    first_sequence = authority.value().recovery().sequence;
    first_epoch = authority.value().epoch();
    FA_CHECK(authority.value().session_inputs_adopted());
  }
  {
    Result<FeedAuthority> authority = fa_test::open_store(root, false);
    FA_REQUIRE_OK(authority);
    FA_CHECK(authority.value().recovery().sequence > first_sequence);
    FA_CHECK(authority.value().epoch() > first_epoch);
    FA_CHECK(authority.value().recovery().head_was_present);
    FA_CHECK(!authority.value().recovery().created_new_store);
    FA_CHECK_EQ(authority.value().recovery().grants_loaded, 1u);
    FA_CHECK_EQ(authority.value().recovery().grants_needing_revalidation, 1u);
    // Recovery does not make anything usable: no inputs were adopted yet.
    FA_CHECK(!authority.value().session_inputs_adopted());
    CheckGrantRequest check;
    check.grant = issued;
    check.now = fa_test::at(1735689700);
    const Result<GrantAuthorization> authorization = authority.value().Authorize(check);
    FA_REQUIRE_OK(authorization);
    FA_CHECK(!authorization.value().authorized);
    FA_CHECK_EQ(authorization.value().usability, GrantUsability::NeedsRevalidation);
    // The inputs the store holds are still the ones that were adopted before, and
    // the caller can re-adopt them to make them current for this session.
    FA_REQUIRE_OK(fa_test::adopt(authority.value(), authority.value().inputs(), "adopt-again",
                                 fa_test::at(1735689700)));
    FA_CHECK(authority.value().session_inputs_adopted());
    RevalidateGrantRequest revalidate;
    revalidate.grant = issued;
    revalidate.now = fa_test::at(1735689700);
    revalidate.attempt = fa_test::attempt("revalidate-after-restart");
    revalidate.precondition.expected = authority.value().current_binding();
    FA_REQUIRE_OK(authority.value().RevalidateGrant(revalidate));
    const Result<GrantAuthorization> usable = authority.value().Authorize(check);
    FA_REQUIRE_OK(usable);
    FA_CHECK(usable.value().authorized);
  }
}

FA_TEST(persistence, read_only_open_does_not_advance_authority) {
  const std::filesystem::path root = fa_test::fresh_store("persistence-read-only");
  StoreSequence sequence;
  AuthorityEpoch epoch;
  {
    Result<FeedAuthority> authority = fa_test::open_store(root, true);
    FA_REQUIRE_OK(authority);
    sequence = authority.value().recovery().sequence;
    epoch = authority.value().epoch();
  }
  {
    Result<FeedAuthority> authority = fa_test::open_store_read_only(root);
    FA_REQUIRE_OK(authority);
    FA_CHECK_EQ(authority.value().recovery().sequence.value(), sequence.value());
    FA_CHECK_EQ(authority.value().epoch().value(), epoch.value());
    AdoptInputsRequest request;
    request.inputs = fa_test::inputs(kScenario);
    request.now = fa_test::at(1735689600);
    request.attempt = fa_test::attempt("adopt-readonly");
    FA_REQUIRE_ERR(authority.value().AdoptInputs(request), StatusCode::ReadOnly);
  }
}

FA_TEST(persistence, store_audit_and_verify_agree_on_a_healthy_store) {
  const std::filesystem::path root = fa_test::fresh_store("persistence-audit");
  Result<FeedAuthority> authority = fa_test::open_store(root, true);
  FA_REQUIRE_OK(authority);
  FA_REQUIRE_OK(fa_test::adopt(authority.value(), fa_test::inputs(kScenario), "adopt-1",
                               fa_test::at(1735689600)));
  FA_REQUIRE_OK(fa_test::issue_grant(authority.value(), "L1", "F1", fa_test::at(1735689600), "a1"));
  const Result<StoreAuditReport> audit = authority.value().AuditStore();
  FA_REQUIRE_OK(audit);
  FA_CHECK(audit.value().ok());
  FA_CHECK(audit.value().head_valid);
  // The audit reads the store as it is now; the recovery report describes the state
  // adopted at open, so the audit's head can only be newer or equal.
  FA_CHECK(audit.value().head_sequence.value() >= authority.value().recovery().sequence.value());
  FA_CHECK_EQ(audit.value().granted, 1u);
  FA_CHECK_EQ(audit.value().staging_residue.size(), 0u);
  FA_CHECK(!audit.value().rollback_suspected);
  bool saw_head = false;
  for (const GenerationAudit& entry : audit.value().generations) {
    if (entry.classification == "head") {
      saw_head = true;
      FA_CHECK(entry.payload_ok);
      FA_CHECK(entry.digest_ok);
    }
  }
  FA_CHECK(saw_head);
  FA_REQUIRE_OK(authority.value().Verify());
}

FA_TEST(persistence, identical_logical_state_produces_identical_bytes) {
  const std::filesystem::path first = fa_test::fresh_store("persistence-bytes-a");
  const std::filesystem::path second = fa_test::fresh_store("persistence-bytes-b");
  for (const std::filesystem::path& root : {first, second}) {
    Result<FeedAuthority> authority = fa_test::open_store(root, true, true, 1735689600);
    FA_REQUIRE_OK(authority);
    FA_REQUIRE_OK(fa_test::adopt(authority.value(), fa_test::inputs(kScenario), "adopt-1",
                                 fa_test::at(1735689600)));
    FA_REQUIRE_OK(
        fa_test::issue_grant(authority.value(), "L1", "F1", fa_test::at(1735689600), "attempt-1"));
  }
  const std::string first_bytes = read_all(newest_generation(first));
  const std::string second_bytes = read_all(newest_generation(second));
  FA_CHECK(!first_bytes.empty());
  FA_CHECK_EQ(first_bytes.size(), second_bytes.size());
  FA_CHECK(first_bytes == second_bytes);
  FA_CHECK_EQ(Digest::Of(first_bytes).hex(), Digest::Of(second_bytes).hex());
}

FA_TEST(persistence, a_corrupted_generation_is_refused) {
  const std::filesystem::path root = fa_test::fresh_store("persistence-corrupt");
  {
    Result<FeedAuthority> authority = fa_test::open_store(root, true);
    FA_REQUIRE_OK(authority);
    FA_REQUIRE_OK(fa_test::adopt(authority.value(), fa_test::inputs(kScenario), "adopt-1",
                                 fa_test::at(1735689600)));
  }
  const std::filesystem::path generation = newest_generation(root);
  const std::string original = read_all(generation);
  FA_CHECK(!original.empty());

  // One flipped bit in the payload must be detected by the digest.
  std::string flipped = original;
  flipped[flipped.size() / 2] = static_cast<char>(flipped[flipped.size() / 2] ^ 0x01);
  write_all(generation, flipped);
  {
    Result<FeedAuthority> authority = fa_test::open_store(root, false);
    FA_REQUIRE_ERR(authority, StatusCode::Corruption);
  }

  // A truncated file must be refused, never partially adopted.
  write_all(generation, original.substr(0, original.size() - 1));
  {
    Result<FeedAuthority> authority = fa_test::open_store(root, false);
    FA_REQUIRE_ERR(authority, StatusCode::Corruption);
  }
  write_all(generation, original.substr(0, detail::kGenerationHeaderSize + 4));
  {
    Result<FeedAuthority> authority = fa_test::open_store(root, false);
    FA_REQUIRE_ERR(authority, StatusCode::Corruption);
  }

  // Restoring the bytes restores the store.
  write_all(generation, original);
  Result<FeedAuthority> authority = fa_test::open_store(root, false);
  FA_REQUIRE_OK(authority);
}

FA_TEST(persistence, a_newer_generation_than_the_head_is_a_rollback_signal) {
  const std::filesystem::path root = fa_test::fresh_store("persistence-rollback");
  {
    Result<FeedAuthority> authority = fa_test::open_store(root, true);
    FA_REQUIRE_OK(authority);
    FA_REQUIRE_OK(fa_test::adopt(authority.value(), fa_test::inputs(kScenario), "adopt-1",
                                 fa_test::at(1735689600)));
  }
  const std::string head_bytes = read_all(head_path(root));
  const detail::HeadRecord head = detail::decode_head(head_bytes).value();
  const std::string generation_bytes = read_all(newest_generation(root));
  // A generation three sequences beyond the committed head cannot be crash residue:
  // at most one orphan is a legitimate publication that did not commit.
  const std::filesystem::path far_ahead =
      generations_path(root) / detail::generation_file_name(StoreSequence::FromValue(head.sequence.value() + 3));
  write_all(far_ahead, generation_bytes);
  {
    Result<FeedAuthority> authority = fa_test::open_store(root, false);
    FA_REQUIRE_ERR(authority, StatusCode::RollbackDetected);
  }
  std::error_code error;
  std::filesystem::remove(far_ahead, error);

  // A single orphan is residue and must be ignored, not adopted.
  const std::filesystem::path orphan =
      generations_path(root) / detail::generation_file_name(StoreSequence::FromValue(head.sequence.value() + 1));
  write_all(orphan, generation_bytes);
  {
    Result<FeedAuthority> authority = fa_test::open_store(root, false);
    FA_REQUIRE_OK(authority);
    FA_CHECK(authority.value().recovery().residue_present);
    FA_CHECK_EQ(authority.value().recovery().sequence.value(), head.sequence.value() + 1u);
  }
}

FA_TEST(persistence, the_caller_side_rollback_fence_is_honoured) {
  const std::filesystem::path root = fa_test::fresh_store("persistence-fence");
  {
    Result<FeedAuthority> authority = fa_test::open_store(root, true);
    FA_REQUIRE_OK(authority);
    FA_REQUIRE_OK(fa_test::adopt(authority.value(), fa_test::inputs(kScenario), "adopt-1",
                                 fa_test::at(1735689600)));
  }
  OpenOptions options;
  options.root = root;
  options.mode = OpenMode::ReadOnly;
  Result<FeedAuthority> current = FeedAuthority::Open(options);
  FA_REQUIRE_OK(current);
  options.required_min_sequence = StoreSequence::FromValue(current.value().recovery().sequence.value() + 1);
  FA_REQUIRE_ERR(FeedAuthority::Open(options), StatusCode::RollbackDetected);
  options.required_min_sequence.reset();
  options.required_min_epoch = AuthorityEpoch::FromValue(current.value().epoch().value() + 1);
  FA_REQUIRE_ERR(FeedAuthority::Open(options), StatusCode::RollbackDetected);
}

FA_TEST(persistence, staging_residue_is_reported_and_never_adopted) {
  const std::filesystem::path root = fa_test::fresh_store("persistence-staging");
  {
    Result<FeedAuthority> authority = fa_test::open_store(root, true);
    FA_REQUIRE_OK(authority);
  }
  const std::filesystem::path staging = root / std::string(kStagingDirName);
  std::error_code error;
  std::filesystem::create_directories(staging, error);
  write_all(staging / "gen-0000000000000000099.fas.tmp", "leftover staging bytes");
  // A read-only open reports the residue without touching it; a publication retires
  // it, which is why the write path below is checked separately.
  Result<FeedAuthority> authority = fa_test::open_store_read_only(root);
  FA_REQUIRE_OK(authority);
  FA_CHECK(authority.value().recovery().residue_present);
  FA_CHECK(!authority.value().recovery().residue.empty());
  const Result<StoreAuditReport> audit = authority.value().AuditStore();
  FA_REQUIRE_OK(audit);
  FA_CHECK_EQ(audit.value().staging_residue.size(), 1u);
  FA_CHECK(authority.value().Verify().ok());

  // A writer session retires the residue as part of its publication, and reports
  // that it saw it.
  Result<FeedAuthority> writer = fa_test::open_store(root, false);
  FA_REQUIRE_OK(writer);
  FA_CHECK(writer.value().recovery().residue_present);
  const Result<StoreAuditReport> after = writer.value().AuditStore();
  FA_REQUIRE_OK(after);
  FA_CHECK_EQ(after.value().staging_residue.size(), 0u);
}

FA_TEST(persistence, an_unexpected_entry_in_the_root_is_reported) {
  const std::filesystem::path root = fa_test::fresh_store("persistence-unexpected");
  {
    Result<FeedAuthority> authority = fa_test::open_store(root, true);
    FA_REQUIRE_OK(authority);
  }
  write_all(root / "stray.txt", "not part of the store");
  Result<FeedAuthority> authority = fa_test::open_store(root, false);
  FA_REQUIRE_OK(authority);
  const Result<StoreAuditReport> audit = authority.value().AuditStore();
  FA_REQUIRE_OK(audit);
  FA_CHECK_EQ(audit.value().unexpected_entries.size(), 1u);
  FA_CHECK_EQ(audit.value().unexpected_entries.front(), std::string("stray.txt"));
}

FA_TEST(persistence, generation_retention_is_bounded) {
  const std::filesystem::path root = fa_test::fresh_store("persistence-retention");
  OpenOptions options;
  options.root = root;
  options.create_if_missing = true;
  options.opened_at = fa_test::at(1735689600);
  options.limits.generation_retention = 2;
  Result<FeedAuthority> authority = FeedAuthority::Open(options);
  FA_REQUIRE_OK(authority);
  for (int index = 0; index < 6; ++index) {
    const AuthorityInputs inputs = fa_test::inputs(kScenario);
    const Status adopted = fa_test::adopt(authority.value(), inputs,
                                          "adopt-" + std::to_string(index),
                                          fa_test::at(1735689600 + index));
    FA_REQUIRE_OK(adopted);
  }
  std::size_t generations = 0;
  for (const auto& entry : std::filesystem::directory_iterator(generations_path(root))) {
    if (detail::parse_generation_file_name(entry.path().filename().string()).ok()) {
      ++generations;
    }
  }
  FA_CHECK(generations <= 2u);
  FA_CHECK(authority.value().Verify().ok());
}

FA_TEST(persistence, policy_and_topology_history_support_diff) {
  const std::filesystem::path root = fa_test::fresh_store("persistence-diff");
  Result<FeedAuthority> authority = fa_test::open_store(root, true);
  FA_REQUIRE_OK(authority);
  FA_REQUIRE_OK(fa_test::adopt(authority.value(), fa_test::inputs(kScenario), "adopt-1",
                               fa_test::at(1735689600)));
  const AuthorityInputs newer = fa_test::inputs(R"(revisions topology=11 policy=5 control=8 evidence=10
feed F1 source=utility role=primary domain=D1 protected=yes
load L1 class=critical protected=yes
link F1 L1 role=primary domain=D1
obs feed F1 condition=energized at=1735689600 max_age=300s source=S1
obs link F1 L1 present=yes at=1735689600 max_age=300s source=S1
rule R1 effect=permit precedence=ordinary_policy feed=F1 load=L1 path=AUTH-PRIMARY
)");
  FA_REQUIRE_OK(fa_test::adopt(authority.value(), newer, "adopt-2", fa_test::at(1735689610)));
  const Result<PolicyDiff> policy_diff =
      authority.value().DiffPolicy(PolicyRevision::FromValue(4), PolicyRevision::FromValue(5));
  FA_REQUIRE_OK(policy_diff);
  FA_CHECK(!policy_diff.value().identical);
  FA_CHECK(!policy_diff.value().rules.empty());
  const Result<InputsDiff> inputs_diff =
      authority.value().DiffInputs(TopologyRevision::FromValue(10), TopologyRevision::FromValue(11));
  FA_REQUIRE_OK(inputs_diff);
  FA_CHECK(!inputs_diff.value().identical);
  FA_CHECK(!inputs_diff.value().changes.empty());
  // A revision the retention window no longer holds is reported as not found rather
  // than guessed.
  FA_REQUIRE_ERR(authority.value().DiffPolicy(PolicyRevision::FromValue(1), PolicyRevision::FromValue(5)),
                 StatusCode::NotFound);
}
