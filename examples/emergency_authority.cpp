// Explicit emergency authority: a maintenance denial that policy marked
// emergency-overridable is overturned by an authorization that names its authorizer,
// its justification, the loads it covers and the precedence class it overrides. The
// decision records both the denial and the authorization, and the audit history
// records the authorization itself.

#include "support.hpp"

int main() {
  using namespace example;
  heading("explicit emergency authority over an overridable denial");
  const std::filesystem::path root = scratch("emergency");
  Result<FeedAuthority> authority = open(root, 1735689600);
  if (!authority.ok()) {
    line("store error: " + authority.status().to_string());
    return 1;
  }
  const Status adopted = adopt(authority.value(), R"(revisions topology=10 policy=4 control=7 evidence=9
option emergency=on
feed F1 source=utility role=primary domain=D1 protected=yes
load L1 class=critical protected=yes
link F1 L1 role=primary domain=D1
obs feed F1 condition=energized at=1735689600 max_age=300s source=S1
obs link F1 L1 present=yes at=1735689600 max_age=300s source=S1
obs state condition=emergency at=1735689600 max_age=300s source=S1
obs maintenance F1 exposure=withdrawn at=1735689600 max_age=300s source=S1
rule R1 effect=permit precedence=ordinary_policy feed=F1 load=L1 path=AUTH-PRIMARY
rule R2 effect=deny precedence=maintenance_restriction rank=emergency overridable=yes feed=F1 load=L1 reason=maintenance_withdrawn
)", "example-adopt-1", 1735689600);
  if (!adopted.ok()) {
    line("adoption refused: " + adopted.to_string());
    std::filesystem::remove_all(root);
    return 1;
  }

  EvaluationRequest request;
  request.load = LoadId::Parse("L1").value();
  request.now = at(1735689600);
  const Result<DecisionSet> before = authority.value().Evaluate(request);
  if (!before.ok()) {
    line("evaluation refused: " + before.status().to_string());
    return 1;
  }
  line("before the authorization:");
  std::cout << render_decision(before.value());

  EmergencyAuthorizationRequest authorization;
  authorization.authorizer = AuthorizerId::Parse("INCIDENT-COMMANDER-7").value();
  authorization.justification = "single path during a declared incident, transfer blocked";
  authorization.loads.push_back(LoadId::Parse("L1").value());
  authorization.overridable_classes.push_back(PrecedenceClass::MaintenanceRestriction);
  authorization.validity = Duration::FromMinutes(30).value();
  authorization.now = at(1735689600);
  authorization.attempt = AttemptId::Parse("emergency-1").value();
  authorization.precondition.expected = authority.value().current_binding();
  const Result<EmergencyAuthorization> issued = authority.value().AuthorizeEmergency(authorization);
  if (!issued.ok()) {
    line("authorization refused: " + issued.status().to_string());
    std::filesystem::remove_all(root);
    return 1;
  }
  line("authorization " + issued.value().id.str() + " issued by " +
       issued.value().authorizer.value());

  request.now = at(1735689700);
  const Result<Explanation> after = authority.value().Explain(request);
  if (!after.ok()) {
    line("evaluation refused: " + after.status().to_string());
    return 1;
  }
  line("after the authorization:");
  std::cout << render_explanation(after.value());
  line("audit history:");
  std::cout << render_history(authority.value().History(4));
  std::filesystem::remove_all(root);
  return 0;
}
