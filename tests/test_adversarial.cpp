// Proof obligations for adversarial input: every malformed, truncated, oversized,
// wrong-version, wrong-endian, non-canonical or path-manipulated artifact is refused
// whole, with the documented status code, and never partially adopted.

#include <fstream>
#include <iostream>

#include "feed_authority/scenario.hpp"
#include "support/fixtures.hpp"
#include "support/proc.hpp"
#include "support/test_harness.hpp"

#include "detail/platform_io.hpp"
#include "detail/serialization.hpp"
#include "detail/state.hpp"
#include "detail/store_format.hpp"

using namespace feed_authority;

namespace {

const char* kScenario = R"(revisions topology=10 policy=4 control=7 evidence=9
feed F1 source=utility role=primary domain=D1
load L1 class=critical
link F1 L1 role=primary domain=D1
obs feed F1 condition=energized at=1735689600 max_age=300s source=S1
obs link F1 L1 present=yes at=1735689600 max_age=300s source=S1
rule R1 effect=permit precedence=ordinary_policy feed=F1 load=L1 path=AUTH-PRIMARY
)";

std::filesystem::path head_path(const std::filesystem::path& root) {
  return root / std::string(kHeadFileName);
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
  for (const auto& entry : std::filesystem::directory_iterator(root / std::string(kGenerationsDirName))) {
    const Result<StoreSequence> sequence =
        detail::parse_generation_file_name(entry.path().filename().string());
    if (sequence.ok() && sequence.value().value() >= highest) {
      highest = sequence.value().value();
      newest = entry.path();
    }
  }
  return newest;
}

/// Creates a store with one adopted generation and returns its root.
std::filesystem::path seeded_store(const char* name) {
  const std::filesystem::path root = fa_test::fresh_store(name);
  Result<FeedAuthority> authority = fa_test::open_store(root, true);
  if (!authority.ok()) {
    fa_test::report_failure(__FILE__, __LINE__, "seeded_store", authority.status().to_string());
    return root;
  }
  const Status adopted = fa_test::adopt(authority.value(), fa_test::inputs(kScenario), "adopt-1",
                                        fa_test::at(1735689600));
  if (!adopted.ok()) {
    fa_test::report_failure(__FILE__, __LINE__, "seeded_store", adopted.to_string());
  }
  return root;
}

}  // namespace

FA_TEST(adversarial, generation_framing_is_refused_whole) {
  const std::filesystem::path root = seeded_store("adversarial-framing");
  const std::filesystem::path generation = newest_generation(root);
  const std::string original = read_all(generation);
  FA_CHECK(!original.empty());
  const Limits limits;

  // Directly: the decoder refuses every malformed framing.
  FA_REQUIRE_ERR(detail::decode_generation(std::string(), limits), StatusCode::Corruption);
  FA_REQUIRE_ERR(detail::decode_generation(original.substr(0, 4), limits), StatusCode::Corruption);
  FA_REQUIRE_ERR(detail::decode_generation(original.substr(0, detail::kGenerationHeaderSize), limits),
                 StatusCode::Corruption);
  FA_REQUIRE_ERR(detail::decode_generation(original + "x", limits), StatusCode::Corruption);
  {
    std::string swapped = original;
    swapped[8] = 0;
    swapped[9] = 0;
    swapped[10] = 0;
    swapped[11] = 1;
    FA_REQUIRE_ERR(detail::decode_generation(swapped, limits), StatusCode::EndianMismatch);
  }
  {
    std::string unsupported = original;
    unsupported[8] = 9;
    FA_REQUIRE_ERR(detail::decode_generation(unsupported, limits), StatusCode::IncompatibleVersion);
  }
  {
    std::string bad_magic = original;
    bad_magic[0] = 'X';
    FA_REQUIRE_ERR(detail::decode_generation(bad_magic, limits), StatusCode::Corruption);
  }
  {
    std::string oversized = original;
    // Declare a payload eight bytes larger than the file can hold.
    const std::uint64_t declared = static_cast<std::uint64_t>(original.size());
    for (unsigned index = 0; index < 8; ++index) {
      oversized[16 + index] = static_cast<char>((declared + 8u) >> (8u * index) & 0xFFu);
    }
    FA_REQUIRE_ERR(detail::decode_generation(oversized, limits), StatusCode::Corruption);
  }
  {
    std::string trailer = original;
    trailer[trailer.size() - 1] = 'X';
    FA_REQUIRE_ERR(detail::decode_generation(trailer, limits), StatusCode::Corruption);
  }
  {
    // A declared payload above the configured bound is refused before anything is
    // read or allocated.
    std::string huge = original;
    const std::uint64_t enormous = 0xFFFFFFFFull;
    for (unsigned index = 0; index < 8; ++index) {
      huge[16 + index] = static_cast<char>((enormous >> (8u * index)) & 0xFFu);
    }
    FA_REQUIRE_ERR(detail::decode_generation(huge, limits), StatusCode::LimitExceeded);
  }

  // Through the runtime: a corrupted committed generation refuses the open.
  write_all(generation, original.substr(0, original.size() / 2));
  FA_REQUIRE_ERR(fa_test::open_store(root, false), StatusCode::Corruption);
  write_all(generation, original);
  FA_REQUIRE_OK(fa_test::open_store(root, false));
}

FA_TEST(adversarial, head_marker_is_refused_whole) {
  const std::filesystem::path root = seeded_store("adversarial-head");
  const std::string original = read_all(head_path(root));
  FA_CHECK_EQ(original.size(), static_cast<std::size_t>(detail::kHeadTotalSize));

  FA_REQUIRE_ERR(detail::decode_head(original.substr(0, 8)), StatusCode::Corruption);
  FA_REQUIRE_ERR(detail::decode_head(original + "x"), StatusCode::Corruption);
  {
    std::string magic = original;
    magic[0] = 'X';
    FA_REQUIRE_ERR(detail::decode_head(magic), StatusCode::Corruption);
  }
  {
    std::string digest = original;
    digest[digest.size() - 1] = static_cast<char>(digest[digest.size() - 1] ^ 0x01);
    FA_REQUIRE_ERR(detail::decode_head(digest), StatusCode::Corruption);
  }
  {
    std::string body = original;
    // A sequence of zero is never a committed head.
    for (unsigned index = 0; index < 8; ++index) {
      body[detail::kHeadHeaderSize + index] = 0;
    }
    FA_REQUIRE_ERR(detail::decode_head(body), StatusCode::Corruption);
  }

  write_all(head_path(root), original.substr(0, 10));
  FA_REQUIRE_ERR(fa_test::open_store(root, false), StatusCode::Corruption);
  write_all(head_path(root), original);
  FA_REQUIRE_OK(fa_test::open_store(root, false));
}

FA_TEST(adversarial, a_non_canonical_payload_is_refused) {
  const Limits limits;
  const AuthorityInputs inputs = fa_test::inputs(kScenario);
  std::string payload;
  detail::encode_input_records(payload, inputs, limits);
  // A payload that is valid but not canonical must be refused by the state decoder,
  // which re-encodes what it decoded and compares bytes.
  detail::PersistedState state;
  state.sequence = StoreSequence::FromValue(1);
  state.epoch = AuthorityEpoch::FromValue(1);
  state.input_history.push_back(inputs);
  std::string encoded;
  FA_REQUIRE_OK(detail::encode_state(state, limits, encoded));
  detail::PersistedState decoded = detail::decode_state(encoded, limits).value();

  std::string padded = encoded;
  padded.insert(0, "\n");
  FA_CHECK(!detail::decode_state(padded, limits).ok());

  std::string reordered = encoded;
  const std::size_t first_newline = reordered.find('\n');
  const std::size_t second_newline = reordered.find('\n', first_newline + 1);
  if (second_newline != std::string::npos) {
    // Duplicate the first record after the second: the record order is then wrong.
    const std::string first_record = reordered.substr(0, first_newline + 1);
    reordered.insert(second_newline + 1, first_record);
    FA_CHECK(!detail::decode_state(reordered, limits).ok());
  }

  std::string trailing_space = encoded;
  trailing_space.insert(trailing_space.find('\n'), " ");
  FA_CHECK(!detail::decode_state(trailing_space, limits).ok());

  std::string nul_byte = encoded;
  nul_byte.insert(nul_byte.begin() + 3, '\0');
  FA_CHECK(!detail::decode_state(nul_byte, limits).ok());

  // A record with an unknown type is refused.
  std::string unknown = encoded;
  unknown += "mystery field=1\n";
  FA_CHECK(!detail::decode_state(unknown, limits).ok());
}

FA_TEST(adversarial, duplicate_identities_inside_a_state_are_refused) {
  const Limits limits;
  const AuthorityInputs inputs = fa_test::inputs(kScenario);
  std::string payload;
  detail::encode_input_records(payload, inputs, limits);
  // Duplicate the feed record verbatim: the section then declares F1 twice.
  const std::size_t feed_start = payload.find("feed id=\"F1\"");
  FA_REQUIRE(feed_start != std::string::npos);
  const std::size_t feed_end = payload.find('\n', feed_start);
  const std::string feed_record = payload.substr(feed_start, feed_end - feed_start + 1);
  payload.insert(feed_end + 1, feed_record);

  detail::PersistedState state;
  state.sequence = StoreSequence::FromValue(1);
  state.epoch = AuthorityEpoch::FromValue(1);
  state.input_history.push_back(inputs);
  std::string encoded;
  FA_REQUIRE_OK(detail::encode_state(state, limits, encoded));
  // Splice the duplicated feed into the real state payload as well.
  const std::size_t real_feed = encoded.find("feed id=\"F1\"");
  FA_REQUIRE(real_feed != std::string::npos);
  const std::size_t real_end = encoded.find('\n', real_feed);
  encoded.insert(real_end + 1, encoded.substr(real_feed, real_end - real_feed + 1));
  FA_CHECK(!detail::decode_state(encoded, limits).ok());
}

FA_TEST(adversarial, path_attacks_are_refused) {
  const std::filesystem::path base = fa_test::fresh_store("adversarial-paths");
  {
    OpenOptions options;
    options.root = base / ".." / "escape";
    options.create_if_missing = true;
    FA_REQUIRE_ERR(FeedAuthority::Open(options), StatusCode::PathRejected);
  }
  {
    OpenOptions options;
    options.root = base / "CON";
    options.create_if_missing = true;
    FA_REQUIRE_ERR(FeedAuthority::Open(options), StatusCode::PathRejected);
  }
  {
    OpenOptions options;
    options.root = base / "trailing.";
    options.create_if_missing = true;
    FA_REQUIRE_ERR(FeedAuthority::Open(options), StatusCode::PathRejected);
  }
  {
    // A file where the store root should be a directory.
    const std::filesystem::path file = base / "a-file";
    write_all(file, "not a directory");
    OpenOptions options;
    options.root = file;
    options.create_if_missing = true;
    FA_REQUIRE_ERR(FeedAuthority::Open(options), StatusCode::PathRejected);
  }
  {
    // A directory where the head marker file must be.
    const std::filesystem::path root = fa_test::fresh_store("adversarial-head-dir");
    std::error_code error;
    std::filesystem::create_directories(root / std::string(kHeadFileName), error);
    OpenOptions options;
    options.root = root;
    FA_REQUIRE_ERR(FeedAuthority::Open(options), StatusCode::PathRejected);
  }
  {
    // A missing store without create permission is a not-found, never a silent
    // creation.
    OpenOptions options;
    options.root = base / "absent";
    FA_REQUIRE_ERR(FeedAuthority::Open(options), StatusCode::NotFound);
  }
}

FA_TEST(adversarial, a_head_that_names_a_missing_generation_is_refused) {
  const std::filesystem::path root = seeded_store("adversarial-missing-generation");
  const std::filesystem::path generation = newest_generation(root);
  std::error_code error;
  std::filesystem::remove(generation, error);
  FA_REQUIRE_ERR(fa_test::open_store(root, false), StatusCode::Corruption);
}

FA_TEST(adversarial, a_missing_generations_directory_is_refused) {
  const std::filesystem::path root = seeded_store("adversarial-missing-directory");
  std::error_code error;
  std::filesystem::remove_all(root / std::string(kGenerationsDirName), error);
  Result<FeedAuthority> authority = fa_test::open_store(root, false);
  FA_CHECK(!authority.ok());
  if (!authority.ok()) {
    FA_CHECK(authority.status().code() == StatusCode::Corruption ||
             authority.status().code() == StatusCode::NotFound ||
             authority.status().code() == StatusCode::IoFailure);
  }
}

FA_TEST(adversarial, a_lock_file_that_is_not_a_file_is_refused) {
  const std::filesystem::path root = fa_test::fresh_store("adversarial-lock-directory");
  {
    Result<FeedAuthority> authority = fa_test::open_store(root, true);
    FA_REQUIRE_OK(authority);
  }
  std::error_code error;
  std::filesystem::remove(root / std::string(kLockFileName), error);
  std::filesystem::create_directories(root / std::string(kLockFileName), error);
  Result<FeedAuthority> authority = fa_test::open_store(root, false);
  FA_CHECK(!authority.ok());
  if (!authority.ok()) {
    FA_CHECK(authority.status().code() == StatusCode::PermissionDenied ||
             authority.status().code() == StatusCode::IoFailure ||
             authority.status().code() == StatusCode::PathRejected);
  }
}

FA_TEST(adversarial, reparse_point_roots_are_refused_when_the_host_can_create_one) {
  const std::filesystem::path base = fa_test::fresh_store("adversarial-reparse");
  const std::filesystem::path target = base / "target";
  const std::filesystem::path link = base / "link";
  std::error_code error;
  std::filesystem::create_directories(target, error);
  bool created = false;
#if defined(_WIN32)
  // A junction needs no elevation, so this normally succeeds; when the host refuses
  // it the check is reported as unsupported rather than silently passing.
  int exit_code = 0;
  std::string spawn_error;
  const bool spawned = fa_test::spawn_wait(
      "cmd.exe", {"/c", "mklink", "/J", link.string(), target.string()},
      base / "mklink-output.txt", exit_code, spawn_error);
  created = spawned && exit_code == 0 && std::filesystem::exists(link, error);
#else
  created = std::filesystem::create_directory_symlink(target, link, error) && !error;
#endif
  if (!created) {
    std::cout << "note: this host could not create a junction or symlink; the "
                 "reparse-point refusal was not exercised here\n";
    FA_CHECK(true);
    return;
  }
  OpenOptions options;
  options.root = link;
  options.create_if_missing = true;
  FA_REQUIRE_ERR(FeedAuthority::Open(options), StatusCode::PathRejected);
  options.allow_reparse_root = true;
  FA_REQUIRE_OK(FeedAuthority::Open(options));
}

FA_TEST(adversarial, oversized_and_malformed_scenarios_are_refused) {
  const Limits limits;
  {
    // More feeds than the bound allows.
    std::string text = "revisions topology=1 policy=1 control=1 evidence=1\n";
    for (std::uint32_t index = 0; index < limits.max_feeds + 1u; ++index) {
      text += "feed F" + std::to_string(index) + " source=utility role=primary\n";
    }
    FA_REQUIRE_ERR(parse_scenario(text, limits, "oversized"), StatusCode::LimitExceeded);
  }
  {
    // An identity longer than the bound.
    const std::string long_id(65, 'a');
    const std::string text = "revisions topology=1 policy=1 control=1 evidence=1\nfeed " + long_id +
                             " source=utility role=primary\n";
    FA_REQUIRE_ERR(parse_scenario(text, limits, "long-id"), StatusCode::InvalidArgument);
  }
  {
    // A control character inside a line.
    std::string text = "revisions topology=1 policy=1 control=1 evidence=1\nfeed F1 source=utility";
    text.push_back('\001');
    text += " role=primary\n";
    FA_REQUIRE_ERR(parse_scenario(text, limits, "control-char"), StatusCode::InvalidArgument);
  }
  {
    // A NUL byte inside a line.
    std::string text = "revisions topology=1 policy=1 control=1 evidence=1\nfeed F1 source=utility";
    text.push_back('\0');
    text += " role=primary\n";
    FA_REQUIRE_ERR(parse_scenario(text, limits, "nul"), StatusCode::InvalidArgument);
  }
  {
    // An unknown record type, an unknown key and a duplicate key are all errors.
    FA_REQUIRE_ERR(parse_scenario("revisions topology=1 policy=1 control=1 evidence=1\nmystery 1\n",
                                  limits, "unknown-record"),
                   StatusCode::InvalidArgument);
    FA_REQUIRE_ERR(parse_scenario(
                       "revisions topology=1 policy=1 control=1 evidence=1\nfeed F1 source=utility "
                       "role=primary colour=red\n",
                       limits, "unknown-key"),
                   StatusCode::InvalidArgument);
    FA_REQUIRE_ERR(parse_scenario(
                       "revisions topology=1 policy=1 control=1 evidence=1\nfeed F1 source=utility "
                       "source=generator role=primary\n",
                       limits, "duplicate-key"),
                   StatusCode::InvalidArgument);
  }
  {
    // A rule that names a feed the topology does not declare is refused at adoption.
    FA_REQUIRE_ERR(parse_scenario(
                       "revisions topology=1 policy=1 control=1 evidence=1\nfeed F1 source=utility "
                       "role=primary\nload L1 class=critical\nlink F1 L1 role=primary\n"
                       "rule R1 effect=permit feed=F9 load=L1 path=AUTH-1\n",
                       limits, "dangling-rule"),
                   StatusCode::NotFound);
  }
  {
    // Observations that name an absent subject are refused.
    FA_REQUIRE_ERR(parse_scenario(
                       "revisions topology=1 policy=1 control=1 evidence=1\nfeed F1 source=utility "
                       "role=primary\nobs feed F9 condition=energized at=1 max_age=1s source=S1\n",
                       limits, "dangling-observation"),
                   StatusCode::InvalidArgument);
  }
}

FA_TEST(adversarial, limits_are_validated_before_they_are_used) {
  OpenOptions options;
  options.root = fa_test::fresh_store("adversarial-limits");
  options.create_if_missing = true;
  options.limits.max_replay_entries = 0;
  FA_REQUIRE_ERR(FeedAuthority::Open(options), StatusCode::InvalidArgument);
  options.limits = Limits{};
  options.limits.max_generation_bytes = 64;
  FA_REQUIRE_ERR(FeedAuthority::Open(options), StatusCode::InvalidArgument);
  options.limits = Limits{};
  options.limits.max_feeds = 0;
  FA_REQUIRE_ERR(FeedAuthority::Open(options), StatusCode::InvalidArgument);
}

FA_TEST(adversarial, candidate_bounds_are_enforced) {
  const std::filesystem::path root = seeded_store("adversarial-candidates");
  Result<FeedAuthority> authority = fa_test::open_store(root, false);
  FA_REQUIRE_OK(authority);
  EvaluationRequest request;
  request.load = fa_test::load("L1");
  request.now = fa_test::at(1735689600);
  for (std::uint32_t index = 0; index < authority.value().limits().max_candidates + 1u; ++index) {
    request.candidate_feeds.push_back(fa_test::feed("F" + std::to_string(index)));
  }
  FA_REQUIRE_ERR(authority.value().Evaluate(request), StatusCode::LimitExceeded);

  request.candidate_feeds.clear();
  request.candidate_feeds.push_back(fa_test::feed("F1"));
  request.candidate_feeds.push_back(fa_test::feed("F1"));
  FA_REQUIRE_ERR(authority.value().Evaluate(request), StatusCode::DuplicateIdentity);
}
