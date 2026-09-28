// An out-of-tree consumer of the installed Feed Authority package.
//
// It exercises the public surface only: open a durable store, adopt an input
// generation, evaluate a load, issue a grant, close, reopen, revalidate the grant
// against the current generation, verify the state and audit the store. Every step
// checks its own result, so a broken package fails the build of this program.

#include <cstdint>
#include <filesystem>
#include <iostream>
#include <string>

#include "feed_authority/authority.hpp"
#include "feed_authority/render.hpp"
#include "feed_authority/scenario.hpp"
#include "feed_authority/version.hpp"

namespace {

using namespace feed_authority;

int fail(const std::string& step, const Status& status) {
  std::cerr << "consumer: " << step << " failed: " << status.to_string() << "\n";
  return 1;
}

AuthorityTime at(std::int64_t seconds) { return AuthorityTime::FromUnixSeconds(seconds).value(); }

}  // namespace

int main(int argc, char** argv) {
  const std::filesystem::path root =
      argc > 1 ? std::filesystem::path(argv[1])
               : std::filesystem::current_path() / "consumer-store";
  std::error_code error;
  std::filesystem::remove_all(root, error);

  std::cout << "consumer: feed_authority " << version_string() << " from an installed package\n";

  const char* scenario_text = R"(revisions topology=10 policy=4 control=7 evidence=9
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

  {
    OpenOptions options;
    options.root = root;
    options.create_if_missing = true;
    options.opened_at = at(1735689600);
    Result<FeedAuthority> authority = FeedAuthority::Open(options);
    if (!authority.ok()) {
      return fail("open", authority.status());
    }
    const Result<AuthorityInputs> inputs =
        parse_scenario(scenario_text, authority.value().limits(), "consumer");
    if (!inputs.ok()) {
      return fail("parse_scenario", inputs.status());
    }
    AdoptInputsRequest adopt;
    adopt.inputs = inputs.value();
    adopt.now = at(1735689600);
    adopt.attempt = AttemptId::Parse("consumer-adopt-1").value();
    if (Status status = authority.value().AdoptInputs(adopt); !status.ok()) {
      return fail("adopt", status);
    }

    EvaluationRequest request;
    request.load = LoadId::Parse("L1").value();
    request.now = at(1735689600);
    const Result<DecisionSet> decision = authority.value().Evaluate(request);
    if (!decision.ok()) {
      return fail("evaluate", decision.status());
    }
    std::cout << render_decision(decision.value());
    if (decision.value().eligible.size() != 2u) {
      std::cerr << "consumer: expected two eligible feeds\n";
      return 1;
    }

    GrantRequest issue;
    issue.load = request.load;
    issue.feed = FeedId::Parse("F1").value();
    issue.decision = decision.value().generation;
    issue.decision_fingerprint = decision.value().fingerprint;
    issue.validity = Duration::FromHours(1).value();
    issue.now = request.now;
    issue.attempt = AttemptId::Parse("consumer-grant-1").value();
    issue.precondition.expected = authority.value().current_binding();
    const Result<Grant> grant = authority.value().IssueGrant(issue);
    if (!grant.ok()) {
      return fail("issue_grant", grant.status());
    }
    std::cout << render_grant(grant.value());
  }

  {
    // Reopening is a new writer session: the grant is persisted but not usable until
    // it is revalidated against the current generation.
    OpenOptions options;
    options.root = root;
    options.opened_at = at(1735689700);
    Result<FeedAuthority> authority = FeedAuthority::Open(options);
    if (!authority.ok()) {
      return fail("reopen", authority.status());
    }
    std::cout << render_recovery(authority.value().recovery());
    if (authority.value().recovery().grants_loaded != 1u) {
      std::cerr << "consumer: the persisted grant was not recovered\n";
      return 1;
    }
    CheckGrantRequest check;
    check.grant = GrantId::FromValue(1);
    check.now = at(1735689700);
    const Result<GrantAuthorization> before = authority.value().Authorize(check);
    if (!before.ok()) {
      return fail("authorize before revalidation", before.status());
    }
    if (before.value().authorized) {
      std::cerr << "consumer: a recovered grant authorized something before revalidation\n";
      return 1;
    }

    const Result<AuthorityInputs> inputs =
        parse_scenario(scenario_text, authority.value().limits(), "consumer");
    if (!inputs.ok()) {
      return fail("parse_scenario", inputs.status());
    }
    AdoptInputsRequest adopt;
    adopt.inputs = inputs.value();
    adopt.now = at(1735689700);
    adopt.attempt = AttemptId::Parse("consumer-adopt-2").value();
    if (Status status = authority.value().AdoptInputs(adopt); !status.ok()) {
      return fail("re-adopt", status);
    }
    RevalidateGrantRequest revalidate;
    revalidate.grant = GrantId::FromValue(1);
    revalidate.now = at(1735689700);
    revalidate.attempt = AttemptId::Parse("consumer-revalidate-1").value();
    revalidate.precondition.expected = authority.value().current_binding();
    const Result<Grant> revalidated = authority.value().RevalidateGrant(revalidate);
    if (!revalidated.ok()) {
      return fail("revalidate", revalidated.status());
    }
    const Result<GrantAuthorization> after = authority.value().Authorize(check);
    if (!after.ok()) {
      return fail("authorize after revalidation", after.status());
    }
    std::cout << render_grant_authorization(after.value());
    if (!after.value().authorized) {
      std::cerr << "consumer: the revalidated grant did not authorize\n";
      return 1;
    }
    if (Status status = authority.value().Verify(); !status.ok()) {
      return fail("verify", status);
    }
    const Result<StoreAuditReport> audit = authority.value().AuditStore();
    if (!audit.ok()) {
      return fail("audit", audit.status());
    }
    std::cout << render_audit(audit.value());
    if (!audit.value().ok()) {
      std::cerr << "consumer: the store audit did not pass\n";
      return 1;
    }
  }

  std::cout << "consumer: lifecycle complete, installed package is usable\n";
  std::filesystem::remove_all(root, error);
  return 0;
}
