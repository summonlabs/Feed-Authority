// Stale authority: a grant is issued against one policy generation, then the policy
// advances. The persisted grant is not silently reused: it is superseded, and it
// authorizes nothing until it is revalidated against the current generation. A
// revoked grant can never be revalidated at all.

#include "support.hpp"

int main() {
  using namespace example;
  heading("a superseded grant is refused until it is revalidated");
  const std::filesystem::path root = scratch("stale-grant");
  Result<FeedAuthority> authority = open(root, 1735689600);
  if (!authority.ok()) {
    line("store error: " + authority.status().to_string());
    return 1;
  }
  const char* first = R"(revisions topology=10 policy=4 control=7 evidence=9
feed F1 source=utility role=primary domain=D1 protected=yes
load L1 class=critical protected=yes
link F1 L1 role=primary domain=D1
obs feed F1 condition=energized at=1735689600 max_age=300s source=S1
obs link F1 L1 present=yes at=1735689600 max_age=300s source=S1
obs state condition=normal at=1735689600 max_age=300s source=S1
rule R1 effect=permit precedence=ordinary_policy feed=F1 load=L1 path=AUTH-PRIMARY
)";
  if (!adopt(authority.value(), first, "example-adopt-1", 1735689600).ok()) {
    line("adoption refused");
    std::filesystem::remove_all(root);
    return 1;
  }

  EvaluationRequest request;
  request.load = LoadId::Parse("L1").value();
  request.now = at(1735689600);
  const Result<DecisionSet> decision = authority.value().Evaluate(request);
  if (!decision.ok()) {
    line("evaluation refused: " + decision.status().to_string());
    return 1;
  }
  GrantRequest issue;
  issue.load = request.load;
  issue.feed = FeedId::Parse("F1").value();
  issue.decision = decision.value().generation;
  issue.decision_fingerprint = decision.value().fingerprint;
  issue.validity = Duration::FromHours(1).value();
  issue.now = request.now;
  issue.attempt = AttemptId::Parse("example-grant-1").value();
  issue.precondition.expected = authority.value().current_binding();
  const Result<Grant> grant = authority.value().IssueGrant(issue);
  if (!grant.ok()) {
    line("grant refused: " + grant.status().to_string());
    std::filesystem::remove_all(root);
    return 1;
  }
  line("grant " + grant.value().id.str() + " issued against policy revision " +
       grant.value().issued_binding.policy.str());

  // The policy advances: the same path is permitted by a new revision.
  const char* second = R"(revisions topology=10 policy=5 control=7 evidence=10
feed F1 source=utility role=primary domain=D1 protected=yes
load L1 class=critical protected=yes
link F1 L1 role=primary domain=D1
obs feed F1 condition=energized at=1735689600 max_age=300s source=S1
obs link F1 L1 present=yes at=1735689600 max_age=300s source=S1
obs state condition=normal at=1735689600 max_age=300s source=S1
rule R9 effect=permit precedence=ordinary_policy feed=F1 load=L1 path=AUTH-PRIMARY
)";
  if (!adopt(authority.value(), second, "example-adopt-2", 1735689700).ok()) {
    line("adoption refused");
    std::filesystem::remove_all(root);
    return 1;
  }

  CheckGrantRequest check;
  check.grant = grant.value().id;
  check.now = at(1735689700);
  const Result<GrantAuthorization> superseded = authority.value().Authorize(check);
  if (!superseded.ok()) {
    line("authorization refused: " + superseded.status().to_string());
    return 1;
  }
  line("after the policy advanced:");
  std::cout << render_grant_authorization(superseded.value());

  RevalidateGrantRequest revalidate;
  revalidate.grant = grant.value().id;
  revalidate.now = at(1735689700);
  revalidate.attempt = AttemptId::Parse("example-revalidate-1").value();
  revalidate.precondition.expected = authority.value().current_binding();
  const Result<Grant> restored = authority.value().RevalidateGrant(revalidate);
  if (!restored.ok()) {
    line("revalidation refused: " + restored.status().to_string());
    std::filesystem::remove_all(root);
    return 1;
  }
  const Result<GrantAuthorization> usable = authority.value().Authorize(check);
  if (!usable.ok()) {
    line("authorization refused: " + usable.status().to_string());
    return 1;
  }
  line("after revalidation against the current generation:");
  std::cout << render_grant_authorization(usable.value());

  // Revocation is final: a revoked grant can never be revalidated.
  RevokeGrantRequest revoke;
  revoke.grant = grant.value().id;
  revoke.authorizer = AuthorizerId::Parse("OPERATOR-1").value();
  revoke.reason = "planned transfer";
  revoke.now = at(1735689750);
  revoke.attempt = AttemptId::Parse("example-revoke-1").value();
  revoke.precondition.expected = authority.value().current_binding();
  if (!authority.value().RevokeGrant(revoke).ok()) {
    line("revocation refused");
    return 1;
  }
  RevalidateGrantRequest after_revoke = revalidate;
  after_revoke.attempt = AttemptId::Parse("example-revalidate-2").value();
  after_revoke.now = at(1735689800);
  const Result<Grant> revived = authority.value().RevalidateGrant(after_revoke);
  line("revalidating a revoked grant: " + revived.status().to_string());
  std::filesystem::remove_all(root);
  return 0;
}
