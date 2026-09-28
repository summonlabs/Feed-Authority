// Normal operation: one protected critical load served by a primary and a secondary
// feed. Both are admissible. Feed Authority does not choose between them: ranking is
// not part of this policy, so the eligible set is returned and selection is left to
// the controller that owns switching.

#include "support.hpp"

int main() {
  using namespace example;
  heading("primary and secondary feeds under normal operating conditions");
  const std::filesystem::path root = scratch("primary-secondary");
  Result<FeedAuthority> authority = open(root, 1735689600);
  if (!authority.ok()) {
    line("store error: " + authority.status().to_string());
    return 1;
  }
  const Status adopted = adopt(authority.value(), R"(revisions topology=10 policy=4 control=7 evidence=9
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
rule R1 effect=permit precedence=ordinary_policy feed=F1 load=L1 path=AUTH-PRIMARY reason=rule_permitted
rule R2 effect=permit precedence=ordinary_policy feed=F2 load=L1 path=AUTH-SECONDARY reason=rule_permitted
)", "example-adopt-1", 1735689600);
  if (!adopted.ok()) {
    line("adoption refused: " + adopted.to_string());
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
  std::cout << render_decision(decision.value());
  line("both feeds are admissible; this runtime issues no switching decision");
  std::filesystem::remove_all(root);
  return 0;
}
