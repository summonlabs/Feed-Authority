// Feed Authority administration and inspection tool.
//
// Every answer this tool prints comes from the library: it parses arguments, opens
// or creates a store, adopts the scenario the operator names, calls the authority
// and renders the result. It decides nothing on its own, and it never switches
// anything: it reports which feeds are permitted to serve which loads, and why.

#include <cstddef>
#include <cstdint>
#include <exception>
#include <iostream>
#include <set>
#include <string>
#include <vector>

#include "cli_json.hpp"
#include "feed_authority/authority.hpp"
#include "feed_authority/render.hpp"
#include "feed_authority/scenario.hpp"
#include "feed_authority/version.hpp"

#if defined(_WIN32)
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#endif

namespace feed_authority::cli {
namespace {

constexpr int kUsageExit = 2;

int usage() {
  std::cout <<
      "feed-authority " << version_string() << "\n"
      "\n"
      "Usage: feed-authority <command> [subcommand] [options]\n"
      "\n"
      "Commands:\n"
      "  store create    --store DIR [--json]\n"
      "  store audit     --store DIR [--json]\n"
      "  store verify    --store DIR [--json]\n"
      "  store history   --store DIR [--limit N] [--json]\n"
      "  store attempts  --store DIR [--json]\n"
      "  store limits    [--json]\n"
      "  inputs adopt    --store DIR --scenario FILE [--attempt ID] [--now TIME] [--json]\n"
      "  inputs show     --store DIR [--json]\n"
      "  policy show     --store DIR [--json] | --scenario FILE [--json]\n"
      "  evaluate        --store DIR --load ID [--feeds A,B] [--scenario FILE] [--path P]\n"
      "                  [--record] [--now TIME] [--json]\n"
      "  explain         --store DIR --load ID [--feeds A,B] [--scenario FILE] [--path P]\n"
      "                  [--now TIME] [--json]\n"
      "  grant issue     --store DIR --load ID --feed ID --validity D [--decision N]\n"
      "                  [--fingerprint HEX] [--attempt ID] [--scenario FILE] [--now TIME] [--json]\n"
      "  grant list      --store DIR [--json]\n"
      "  grant show      --store DIR --id N [--json]\n"
      "  grant check     --store DIR --id N [--scenario FILE] [--now TIME] [--json]\n"
      "  grant revoke    --store DIR --id N --authorizer ID --reason TEXT --attempt ID\n"
      "                  [--now TIME] [--json]\n"
      "  grant revalidate --store DIR --id N --attempt ID [--scenario FILE] [--now TIME] [--json]\n"
      "  emergency authorize --store DIR --authorizer ID --justification TEXT --loads A,B\n"
      "                  --classes C,D [--feeds A,B] --validity D --attempt ID [--now TIME] [--json]\n"
      "  emergency list  --store DIR [--json]\n"
      "  emergency show  --store DIR --id N [--json]\n"
      "  emergency revoke --store DIR --id N --authorizer ID --reason TEXT --attempt ID\n"
      "                  [--now TIME] [--json]\n"
      "  diff policy     --store DIR --from N --to N [--json]\n"
      "  diff inputs     --store DIR --from N --to N [--json]\n"
      "  version\n"
      "\n"
      "Times are ISO-8601 UTC timestamps or whole Unix seconds. Durations use ns, ms,\n"
      "s, m, h or d. Exit codes: 0 success, 1 refusal or failure, 2 usage error.\n";
  return kUsageExit;
}

RenderOptions render_options(const Options& options) {
  RenderOptions render;
  render.json = options.flag("json");
  return render;
}

Result<std::uint64_t> require_uint(const Options& options, std::string_view name) {
  if (!options.has(name)) {
    return Status::error(StatusCode::InvalidArgument, "option --" + std::string(name) + " is required");
  }
  const Result<std::uint64_t> value = parse_uint(options.value(name));
  if (!value.ok()) {
    return Status::error(StatusCode::InvalidArgument,
                         "option --" + std::string(name) + " is not an unsigned decimal");
  }
  return value.value();
}

Result<std::string> require_text(const Options& options, std::string_view name) {
  if (!options.has(name) || options.value(name).empty()) {
    return Status::error(StatusCode::InvalidArgument, "option --" + std::string(name) + " is required");
  }
  return options.value(name);
}

Result<std::string> require_store(const Options& options) {
  return require_text(options, "store");
}

Result<FeedAuthority> open_store(const Options& options, bool read_write, bool create) {
  const Result<std::string> root = require_store(options);
  if (!root.ok()) {
    return root.status();
  }
  OpenOptions open;
  open.root = path_from_utf8(root.value());
  if (open.root.empty()) {
    return Status::error(StatusCode::InvalidArgument, "the store path is not valid UTF-8");
  }
  open.mode = read_write ? OpenMode::ReadWrite : OpenMode::ReadOnly;
  open.create_if_missing = create;
  return FeedAuthority::Open(open);
}

/// Adopts the scenario named by --scenario, when one was given. Adoption is what
/// makes an input generation current for this writer session; without it a
/// recovered grant cannot authorize anything and the tool says so.
///
/// `use_option_attempt` is true only for the `inputs adopt` command, where the
/// caller's --attempt belongs to the adoption itself. Every other command owns its
/// --attempt, so the convenience adoption derives its own identity and cannot
/// collide with the operation under test.
Status adopt_scenario(FeedAuthority& authority, const Options& options, AuthorityTime now,
                      bool use_option_attempt = false) {
  if (!options.has("scenario")) {
    return Status::success();
  }
  const Result<AuthorityInputs> inputs =
      load_scenario_file(path_from_utf8(options.value("scenario")), authority.limits());
  if (!inputs.ok()) {
    return inputs.status();
  }
  AdoptInputsRequest request;
  request.inputs = inputs.value();
  request.now = now;
  if (use_option_attempt && options.has("attempt")) {
    const Result<AttemptId> attempt = AttemptId::Parse(options.value("attempt"));
    if (!attempt.ok()) {
      return Status::error(StatusCode::InvalidArgument, "the attempt identity is not well-formed");
    }
    request.attempt = attempt.value();
  } else {
    const Result<AttemptId> attempt =
        AttemptId::Parse("adopt-" + inputs.value().fingerprint().hex().substr(0, 16));
    if (!attempt.ok()) {
      return attempt.status();
    }
    request.attempt = attempt.value();
  }
  return authority.AdoptInputs(request);
}

Result<EvaluationRequest> build_request(const FeedAuthority& authority, const Options& options,
                                        AuthorityTime now) {
  EvaluationRequest request;
  const Result<std::string> load = require_text(options, "load");
  if (!load.ok()) {
    return load.status();
  }
  const Result<LoadId> parsed_load = LoadId::Parse(load.value());
  if (!parsed_load.ok()) {
    return Status::error(StatusCode::InvalidArgument, "the load identity is not well-formed");
  }
  request.load = parsed_load.value();
  request.now = now;
  request.record_event = options.flag("record");
  if (options.has("feeds")) {
    const Result<std::vector<std::string>> feeds = parse_list(options.value("feeds"));
    if (!feeds.ok()) {
      return feeds.status();
    }
    for (const std::string& feed : feeds.value()) {
      const Result<FeedId> parsed = FeedId::Parse(feed);
      if (!parsed.ok()) {
        return Status::error(StatusCode::InvalidArgument, "a candidate feed identity is not well-formed");
      }
      request.candidate_feeds.push_back(parsed.value());
    }
  }
  if (options.has("path")) {
    const Result<AuthorityPathId> path = AuthorityPathId::Parse(options.value("path"));
    if (!path.ok()) {
      return Status::error(StatusCode::InvalidArgument, "the authority path is not well-formed");
    }
    request.required_authority_path = path.value();
  }
  (void)authority;
  return request;
}

int command_store(const std::vector<std::string>& arguments) {
  const std::set<std::string> value_options = {"store", "limit"};
  const std::set<std::string> flag_options = {"json", "help"};
  const Result<Options> parsed = parse_options(arguments, value_options, flag_options);
  if (!parsed.ok()) {
    std::cerr << "error: " << parsed.status().to_string() << "\n";
    return kUsageExit;
  }
  const Options& options = parsed.value();
  const std::string sub = options.positionals.empty() ? std::string() : options.positionals.front();
  if (sub == "limits") {
    std::cout << render_limits(Limits{}, render_options(options));
    return 0;
  }
  if (sub == "create") {
    Result<FeedAuthority> authority = open_store(options, true, true);
    if (!authority.ok()) {
      return report(authority.status());
    }
    std::cout << render_recovery(authority.value().recovery(), render_options(options));
    return 0;
  }
  if (sub == "audit") {
    Result<FeedAuthority> authority = open_store(options, false, false);
    if (!authority.ok()) {
      return report(authority.status());
    }
    const Result<StoreAuditReport> audit = authority.value().AuditStore();
    if (!audit.ok()) {
      return report(audit.status());
    }
    std::cout << render_audit(audit.value(), render_options(options));
    return audit.value().ok() ? 0 : 1;
  }
  if (sub == "verify") {
    Result<FeedAuthority> authority = open_store(options, false, false);
    if (!authority.ok()) {
      return report(authority.status());
    }
    const Result<StoreAuditReport> audit = authority.value().AuditStore();
    if (!audit.ok()) {
      return report(audit.status());
    }
    const Status verified = authority.value().Verify();
    std::cout << render_audit(audit.value(), render_options(options));
    std::cout << render_status(verified, render_options(options));
    return verified.ok() && audit.value().ok() ? 0 : 1;
  }
  if (sub == "history") {
    Result<FeedAuthority> authority = open_store(options, false, false);
    if (!authority.ok()) {
      return report(authority.status());
    }
    std::size_t limit = 32;
    if (options.has("limit")) {
      const Result<std::uint64_t> parsed_limit = parse_uint(options.value("limit"));
      if (!parsed_limit.ok()) {
        return report(parsed_limit.status());
      }
      limit = static_cast<std::size_t>(parsed_limit.value());
    }
    std::cout << render_history(authority.value().History(limit), render_options(options));
    return 0;
  }
  if (sub == "attempts") {
    Result<FeedAuthority> authority = open_store(options, false, false);
    if (!authority.ok()) {
      return report(authority.status());
    }
    std::cout << render_attempts(authority.value().RetainedAttempts(), render_options(options));
    return 0;
  }
  return usage();
}

int command_inputs(const std::vector<std::string>& arguments) {
  const std::set<std::string> value_options = {"store", "scenario", "attempt", "now"};
  const std::set<std::string> flag_options = {"json"};
  const Result<Options> parsed = parse_options(arguments, value_options, flag_options);
  if (!parsed.ok()) {
    std::cerr << "error: " << parsed.status().to_string() << "\n";
    return kUsageExit;
  }
  const Options& options = parsed.value();
  const std::string sub = options.positionals.empty() ? std::string() : options.positionals.front();
  const Result<AuthorityTime> now = resolve_now(options);
  if (!now.ok()) {
    return report(now.status());
  }
  if (sub == "adopt") {
    Result<FeedAuthority> authority = open_store(options, true, true);
    if (!authority.ok()) {
      return report(authority.status());
    }
    if (!options.has("scenario")) {
      std::cerr << "error: --scenario is required\n";
      return kUsageExit;
    }
    const Status adopted = adopt_scenario(authority.value(), options, now.value(), true);
    if (!adopted.ok()) {
      return report(adopted);
    }
    std::cout << render_recovery(authority.value().recovery(), render_options(options));
    std::cout << render_inputs(authority.value().inputs(), render_options(options));
    return 0;
  }
  if (sub == "show") {
    Result<FeedAuthority> authority = open_store(options, false, false);
    if (!authority.ok()) {
      return report(authority.status());
    }
    std::cout << render_inputs(authority.value().inputs(), render_options(options));
    return 0;
  }
  return usage();
}

int command_policy(const std::vector<std::string>& arguments) {
  const std::set<std::string> value_options = {"store", "scenario"};
  const std::set<std::string> flag_options = {"json"};
  const Result<Options> parsed = parse_options(arguments, value_options, flag_options);
  if (!parsed.ok()) {
    std::cerr << "error: " << parsed.status().to_string() << "\n";
    return kUsageExit;
  }
  const Options& options = parsed.value();
  if (!options.positionals.empty() && options.positionals.front() != "show") {
    return usage();
  }
  if (options.has("scenario")) {
    const Result<AuthorityInputs> inputs =
        load_scenario_file(path_from_utf8(options.value("scenario")), Limits{});
    if (!inputs.ok()) {
      return report(inputs.status());
    }
    std::cout << render_policy(inputs.value().policy, render_options(options));
    return 0;
  }
  Result<FeedAuthority> authority = open_store(options, false, false);
  if (!authority.ok()) {
    return report(authority.status());
  }
  std::cout << render_policy(authority.value().inputs().policy, render_options(options));
  return 0;
}

int command_evaluate(const std::vector<std::string>& arguments, bool explain) {
  const std::set<std::string> value_options = {"store", "load", "feeds", "scenario", "path", "now"};
  const std::set<std::string> flag_options = {"json", "record"};
  const Result<Options> parsed = parse_options(arguments, value_options, flag_options);
  if (!parsed.ok()) {
    std::cerr << "error: " << parsed.status().to_string() << "\n";
    return kUsageExit;
  }
  const Options& options = parsed.value();
  const Result<AuthorityTime> now = resolve_now(options);
  if (!now.ok()) {
    return report(now.status());
  }
  Result<FeedAuthority> authority = open_store(options, true, true);
  if (!authority.ok()) {
    return report(authority.status());
  }
  const Status adopted = adopt_scenario(authority.value(), options, now.value());
  if (!adopted.ok()) {
    return report(adopted);
  }
  const Result<EvaluationRequest> request = build_request(authority.value(), options, now.value());
  if (!request.ok()) {
    return report(request.status());
  }
  if (explain) {
    const Result<Explanation> explanation = authority.value().Explain(request.value());
    if (!explanation.ok()) {
      return report(explanation.status());
    }
    std::cout << render_explanation(explanation.value(), render_options(options));
    return 0;
  }
  const Result<DecisionSet> decision = authority.value().Evaluate(request.value());
  if (!decision.ok()) {
    return report(decision.status());
  }
  std::cout << render_decision(decision.value(), render_options(options));
  return 0;
}

int command_grant(const std::vector<std::string>& arguments) {
  const std::set<std::string> value_options = {"store",  "load",      "feed",      "validity",
                                              "decision", "fingerprint", "attempt", "scenario",
                                              "now",     "id",        "authorizer", "reason"};
  const std::set<std::string> flag_options = {"json", "check"};
  const Result<Options> parsed = parse_options(arguments, value_options, flag_options);
  if (!parsed.ok()) {
    std::cerr << "error: " << parsed.status().to_string() << "\n";
    return kUsageExit;
  }
  const Options& options = parsed.value();
  const std::string sub = options.positionals.empty() ? std::string() : options.positionals.front();
  const Result<AuthorityTime> now = resolve_now(options);
  if (!now.ok()) {
    return report(now.status());
  }

  if (sub == "list") {
    Result<FeedAuthority> authority = open_store(options, false, false);
    if (!authority.ok()) {
      return report(authority.status());
    }
    for (const Grant& grant : authority.value().Grants()) {
      std::cout << render_grant(grant, render_options(options));
    }
    return 0;
  }

  if (sub == "show") {
    Result<FeedAuthority> authority = open_store(options, false, false);
    if (!authority.ok()) {
      return report(authority.status());
    }
    const Result<std::uint64_t> id = require_uint(options, "id");
    if (!id.ok()) {
      return report(id.status());
    }
    const Result<Grant> grant = authority.value().FindGrant(GrantId::FromValue(id.value()));
    if (!grant.ok()) {
      return report(grant.status());
    }
    std::cout << render_grant(grant.value(), render_options(options));
    return 0;
  }

  if (sub == "check") {
    Result<FeedAuthority> authority = open_store(options, true, true);
    if (!authority.ok()) {
      return report(authority.status());
    }
    const Status adopted = adopt_scenario(authority.value(), options, now.value());
    if (!adopted.ok()) {
      return report(adopted);
    }
    const Result<std::uint64_t> id = require_uint(options, "id");
    if (!id.ok()) {
      return report(id.status());
    }
    CheckGrantRequest request;
    request.grant = GrantId::FromValue(id.value());
    request.now = now.value();
    const Result<GrantAuthorization> authorization = authority.value().Authorize(request);
    if (!authorization.ok()) {
      return report(authorization.status());
    }
    std::cout << render_grant_authorization(authorization.value(), render_options(options));
    return authorization.value().authorized ? 0 : 1;
  }

  if (sub == "issue") {
    Result<FeedAuthority> authority = open_store(options, true, true);
    if (!authority.ok()) {
      return report(authority.status());
    }
    const Status adopted = adopt_scenario(authority.value(), options, now.value());
    if (!adopted.ok()) {
      return report(adopted);
    }
    const Result<std::string> load = require_text(options, "load");
    if (!load.ok()) return report(load.status());
    const Result<std::string> feed = require_text(options, "feed");
    if (!feed.ok()) return report(feed.status());
    const Result<std::string> validity = require_text(options, "validity");
    if (!validity.ok()) return report(validity.status());
    const Result<Duration> window = parse_duration(validity.value());
    if (!window.ok()) return report(window.status());
    const Result<LoadId> parsed_load = LoadId::Parse(load.value());
    if (!parsed_load.ok()) return report(parsed_load.status());
    const Result<FeedId> parsed_feed = FeedId::Parse(feed.value());
    if (!parsed_feed.ok()) return report(parsed_feed.status());

    // The grant binds the decision that authorized it. When the caller does not
    // name one, the tool evaluates at the same instant and uses that decision, so
    // the binding check in the library still runs against a real decision.
    Digest fingerprint;
    DecisionGeneration generation{};
    if (options.has("decision") || options.has("fingerprint")) {
      const Result<std::uint64_t> decision = require_uint(options, "decision");
      if (!decision.ok()) return report(decision.status());
      const Result<std::string> text = require_text(options, "fingerprint");
      if (!text.ok()) return report(text.status());
      const Result<Digest> parsed_fingerprint = Digest::ParseHex(text.value());
      if (!parsed_fingerprint.ok()) return report(parsed_fingerprint.status());
      generation = DecisionGeneration::FromValue(decision.value());
      fingerprint = parsed_fingerprint.value();
    } else {
      EvaluationRequest evaluation;
      evaluation.load = parsed_load.value();
      evaluation.now = now.value();
      const Result<DecisionSet> decision = authority.value().Evaluate(evaluation);
      if (!decision.ok()) return report(decision.status());
      generation = decision.value().generation;
      fingerprint = decision.value().fingerprint;
    }

    GrantRequest request;
    request.load = parsed_load.value();
    request.feed = parsed_feed.value();
    request.decision = generation;
    request.decision_fingerprint = fingerprint;
    request.validity = window.value();
    request.now = now.value();
    request.precondition.expected = authority.value().current_binding();
    const std::string attempt_text =
        options.has("attempt")
            ? options.value("attempt")
            : "grant-" + parsed_load.value().value() + "-" + parsed_feed.value().value() + "-" +
                  generation.str();
    const Result<AttemptId> attempt = AttemptId::Parse(attempt_text);
    if (!attempt.ok()) {
      return report(Status::error(StatusCode::InvalidArgument, "the attempt identity is not well-formed"));
    }
    request.attempt = attempt.value();
    const Result<Grant> grant = authority.value().IssueGrant(request);
    if (!grant.ok()) {
      return report(grant.status());
    }
    std::cout << render_grant(grant.value(), render_options(options));
    return 0;
  }

  if (sub == "revoke") {
    Result<FeedAuthority> authority = open_store(options, true, true);
    if (!authority.ok()) {
      return report(authority.status());
    }
    const Result<std::uint64_t> id = require_uint(options, "id");
    if (!id.ok()) return report(id.status());
    const Result<std::string> authorizer = require_text(options, "authorizer");
    if (!authorizer.ok()) return report(authorizer.status());
    const Result<std::string> reason = require_text(options, "reason");
    if (!reason.ok()) return report(reason.status());
    const Result<std::string> attempt = require_text(options, "attempt");
    if (!attempt.ok()) return report(attempt.status());
    RevokeGrantRequest request;
    request.grant = GrantId::FromValue(id.value());
    const Result<AuthorizerId> parsed_authorizer = AuthorizerId::Parse(authorizer.value());
    if (!parsed_authorizer.ok()) return report(parsed_authorizer.status());
    request.authorizer = parsed_authorizer.value();
    request.reason = reason.value();
    const Result<AttemptId> parsed_attempt = AttemptId::Parse(attempt.value());
    if (!parsed_attempt.ok()) return report(parsed_attempt.status());
    request.attempt = parsed_attempt.value();
    request.now = now.value();
    request.precondition.expected = authority.value().current_binding();
    const Result<Grant> grant = authority.value().RevokeGrant(request);
    if (!grant.ok()) {
      return report(grant.status());
    }
    std::cout << render_grant(grant.value(), render_options(options));
    return 0;
  }

  if (sub == "revalidate") {
    Result<FeedAuthority> authority = open_store(options, true, true);
    if (!authority.ok()) {
      return report(authority.status());
    }
    const Status adopted = adopt_scenario(authority.value(), options, now.value());
    if (!adopted.ok()) {
      return report(adopted);
    }
    const Result<std::uint64_t> id = require_uint(options, "id");
    if (!id.ok()) return report(id.status());
    RevalidateGrantRequest request;
    request.grant = GrantId::FromValue(id.value());
    request.now = now.value();
    request.precondition.expected = authority.value().current_binding();
    const std::string attempt_text = options.has("attempt")
                                         ? options.value("attempt")
                                         : "revalidate-" + std::to_string(id.value());
    const Result<AttemptId> attempt = AttemptId::Parse(attempt_text);
    if (!attempt.ok()) return report(attempt.status());
    request.attempt = attempt.value();
    const Result<Grant> grant = authority.value().RevalidateGrant(request);
    if (!grant.ok()) {
      return report(grant.status());
    }
    std::cout << render_grant(grant.value(), render_options(options));
    if (options.flag("check")) {
      // Revalidation and the check happen in one session on purpose: a grant
      // authorizes only in the session that revalidated it.
      CheckGrantRequest check;
      check.grant = request.grant;
      check.now = now.value();
      const Result<GrantAuthorization> authorization = authority.value().Authorize(check);
      if (!authorization.ok()) {
        return report(authorization.status());
      }
      std::cout << render_grant_authorization(authorization.value(), render_options(options));
      return authorization.value().authorized ? 0 : 1;
    }
    return 0;
  }
  return usage();
}

int command_emergency(const std::vector<std::string>& arguments) {
  const std::set<std::string> value_options = {"store",     "authorizer", "justification",
                                              "loads",     "feeds",      "classes",
                                              "validity",  "attempt",    "now",
                                              "id",        "reason",     "scenario"};
  const std::set<std::string> flag_options = {"json"};
  const Result<Options> parsed = parse_options(arguments, value_options, flag_options);
  if (!parsed.ok()) {
    std::cerr << "error: " << parsed.status().to_string() << "\n";
    return kUsageExit;
  }
  const Options& options = parsed.value();
  const std::string sub = options.positionals.empty() ? std::string() : options.positionals.front();
  const Result<AuthorityTime> now = resolve_now(options);
  if (!now.ok()) {
    return report(now.status());
  }

  if (sub == "list") {
    Result<FeedAuthority> authority = open_store(options, false, false);
    if (!authority.ok()) {
      return report(authority.status());
    }
    for (const EmergencyAuthorization& authorization : authority.value().EmergencyAuthorizations()) {
      std::cout << render_emergency(authorization, render_options(options));
    }
    return 0;
  }
  if (sub == "show") {
    Result<FeedAuthority> authority = open_store(options, false, false);
    if (!authority.ok()) {
      return report(authority.status());
    }
    const Result<std::uint64_t> id = require_uint(options, "id");
    if (!id.ok()) return report(id.status());
    const Result<EmergencyAuthorization> authorization =
        authority.value().FindEmergency(EmergencyAuthorizationId::FromValue(id.value()));
    if (!authorization.ok()) {
      return report(authorization.status());
    }
    std::cout << render_emergency(authorization.value(), render_options(options));
    return 0;
  }
  if (sub == "authorize") {
    Result<FeedAuthority> authority = open_store(options, true, true);
    if (!authority.ok()) {
      return report(authority.status());
    }
    const Status adopted = adopt_scenario(authority.value(), options, now.value());
    if (!adopted.ok()) {
      return report(adopted);
    }
    const Result<std::string> authorizer = require_text(options, "authorizer");
    if (!authorizer.ok()) return report(authorizer.status());
    const Result<std::string> justification = require_text(options, "justification");
    if (!justification.ok()) return report(justification.status());
    const Result<std::string> loads = require_text(options, "loads");
    if (!loads.ok()) return report(loads.status());
    const Result<std::string> classes = require_text(options, "classes");
    if (!classes.ok()) return report(classes.status());
    const Result<std::string> validity = require_text(options, "validity");
    if (!validity.ok()) return report(validity.status());
    const Result<std::string> attempt = require_text(options, "attempt");
    if (!attempt.ok()) return report(attempt.status());
    const Result<Duration> window = parse_duration(validity.value());
    if (!window.ok()) return report(window.status());

    EmergencyAuthorizationRequest request;
    const Result<AuthorizerId> parsed_authorizer = AuthorizerId::Parse(authorizer.value());
    if (!parsed_authorizer.ok()) return report(parsed_authorizer.status());
    request.authorizer = parsed_authorizer.value();
    request.justification = justification.value();
    const Result<std::vector<std::string>> load_list = parse_list(loads.value());
    if (!load_list.ok()) return report(load_list.status());
    for (const std::string& item : load_list.value()) {
      const Result<LoadId> parsed_load = LoadId::Parse(item);
      if (!parsed_load.ok()) return report(parsed_load.status());
      request.loads.push_back(parsed_load.value());
    }
    if (options.has("feeds")) {
      const Result<std::vector<std::string>> feed_list = parse_list(options.value("feeds"));
      if (!feed_list.ok()) return report(feed_list.status());
      for (const std::string& item : feed_list.value()) {
        const Result<FeedId> parsed_feed = FeedId::Parse(item);
        if (!parsed_feed.ok()) return report(parsed_feed.status());
        request.feeds.push_back(parsed_feed.value());
      }
    }
    const Result<std::vector<std::string>> class_list = parse_list(classes.value());
    if (!class_list.ok()) return report(class_list.status());
    for (const std::string& item : class_list.value()) {
      const Result<PrecedenceClass> parsed_class = parse_precedence_class(item);
      if (!parsed_class.ok()) return report(parsed_class.status());
      request.overridable_classes.push_back(parsed_class.value());
    }
    request.validity = window.value();
    request.now = now.value();
    const Result<AttemptId> parsed_attempt = AttemptId::Parse(attempt.value());
    if (!parsed_attempt.ok()) return report(parsed_attempt.status());
    request.attempt = parsed_attempt.value();
    request.precondition.expected = authority.value().current_binding();
    const Result<EmergencyAuthorization> authorization =
        authority.value().AuthorizeEmergency(request);
    if (!authorization.ok()) {
      return report(authorization.status());
    }
    std::cout << render_emergency(authorization.value(), render_options(options));
    return 0;
  }
  if (sub == "revoke") {
    Result<FeedAuthority> authority = open_store(options, true, true);
    if (!authority.ok()) {
      return report(authority.status());
    }
    const Result<std::uint64_t> id = require_uint(options, "id");
    if (!id.ok()) return report(id.status());
    const Result<std::string> authorizer = require_text(options, "authorizer");
    if (!authorizer.ok()) return report(authorizer.status());
    const Result<std::string> reason = require_text(options, "reason");
    if (!reason.ok()) return report(reason.status());
    const Result<std::string> attempt = require_text(options, "attempt");
    if (!attempt.ok()) return report(attempt.status());
    RevokeEmergencyAuthorizationRequest request;
    request.authorization = EmergencyAuthorizationId::FromValue(id.value());
    const Result<AuthorizerId> parsed_authorizer = AuthorizerId::Parse(authorizer.value());
    if (!parsed_authorizer.ok()) return report(parsed_authorizer.status());
    request.authorizer = parsed_authorizer.value();
    request.reason = reason.value();
    const Result<AttemptId> parsed_attempt = AttemptId::Parse(attempt.value());
    if (!parsed_attempt.ok()) return report(parsed_attempt.status());
    request.attempt = parsed_attempt.value();
    request.now = now.value();
    request.precondition.expected = authority.value().current_binding();
    const Result<EmergencyAuthorization> authorization =
        authority.value().RevokeEmergency(request);
    if (!authorization.ok()) {
      return report(authorization.status());
    }
    std::cout << render_emergency(authorization.value(), render_options(options));
    return 0;
  }
  return usage();
}

int command_diff(const std::vector<std::string>& arguments) {
  const std::set<std::string> value_options = {"store", "from", "to"};
  const std::set<std::string> flag_options = {"json"};
  const Result<Options> parsed = parse_options(arguments, value_options, flag_options);
  if (!parsed.ok()) {
    std::cerr << "error: " << parsed.status().to_string() << "\n";
    return kUsageExit;
  }
  const Options& options = parsed.value();
  const std::string sub = options.positionals.empty() ? std::string() : options.positionals.front();
  Result<FeedAuthority> authority = open_store(options, false, false);
  if (!authority.ok()) {
    return report(authority.status());
  }
  const Result<std::uint64_t> from = require_uint(options, "from");
  if (!from.ok()) return report(from.status());
  const Result<std::uint64_t> to = require_uint(options, "to");
  if (!to.ok()) return report(to.status());
  if (sub == "policy") {
    const Result<PolicyDiff> diff = authority.value().DiffPolicy(PolicyRevision::FromValue(from.value()),
                                                                PolicyRevision::FromValue(to.value()));
    if (!diff.ok()) {
      return report(diff.status());
    }
    std::cout << render_policy_diff(diff.value(), render_options(options));
    return 0;
  }
  if (sub == "inputs") {
    const Result<InputsDiff> diff = authority.value().DiffInputs(TopologyRevision::FromValue(from.value()),
                                                                 TopologyRevision::FromValue(to.value()));
    if (!diff.ok()) {
      return report(diff.status());
    }
    std::cout << render_inputs_diff(diff.value(), render_options(options));
    return 0;
  }
  return usage();
}

int run(const std::vector<std::string>& arguments) {
  if (arguments.empty()) {
    return usage();
  }
  const std::string& command = arguments.front();
  std::vector<std::string> rest(arguments.begin() + 1, arguments.end());
  if (command == "help" || command == "--help" || command == "-h") {
    return usage();
  }
  if (command == "version") {
    std::cout << version_string() << "\n";
    return 0;
  }
  if (command == "store") return command_store(rest);
  if (command == "inputs") return command_inputs(rest);
  if (command == "policy") return command_policy(rest);
  if (command == "evaluate") return command_evaluate(rest, false);
  if (command == "explain") return command_evaluate(rest, true);
  if (command == "grant") return command_grant(rest);
  if (command == "emergency") return command_emergency(rest);
  if (command == "diff") return command_diff(rest);
  std::cerr << "error: unrecognized command '" << command << "'\n";
  return kUsageExit;
}

}  // namespace
}  // namespace feed_authority::cli

#if defined(_WIN32)
int wmain(int argc, wchar_t** argv) {
  std::vector<std::string> arguments;
  for (int index = 1; index < argc; ++index) {
    const int length = WideCharToMultiByte(CP_UTF8, 0, argv[index], -1, nullptr, 0, nullptr, nullptr);
    if (length <= 1) {
      arguments.emplace_back();
      continue;
    }
    std::string text(static_cast<std::size_t>(length - 1), '\0');
    WideCharToMultiByte(CP_UTF8, 0, argv[index], -1, text.data(), length, nullptr, nullptr);
    arguments.push_back(std::move(text));
  }
  return feed_authority::cli::run(arguments);
}
#else
int main(int argc, char** argv) {
  std::vector<std::string> arguments;
  for (int index = 1; index < argc; ++index) {
    arguments.emplace_back(argv[index]);
  }
  return feed_authority::cli::run(arguments);
}
#endif
