// Maintenance: the primary feed is withdrawn for a maintenance window. The policy
// denies it at the maintenance precedence class, which decides before ordinary
// policy, so the ordinary permit for the primary feed cannot outrank it. The
// secondary feed is unaffected.

#include "support.hpp"

int main() {
  using namespace example;
  heading("maintenance withdrawal of the primary feed");
  const std::filesystem::path root = scratch("maintenance");
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
obs state condition=maintenance at=1735689600 max_age=300s source=S1
obs maintenance F1 window=MW-2026-01 exposure=withdrawn at=1735689600 max_age=300s source=S1
rule R1 effect=permit precedence=ordinary_policy feed=F1 load=L1 path=AUTH-PRIMARY
rule R2 effect=permit precedence=ordinary_policy feed=F2 load=L1 path=AUTH-SECONDARY
rule R3 effect=deny precedence=maintenance_restriction rank=emergency exposures=withdrawn feed=F1 load=L1 reason=maintenance_withdrawn
)", "example-adopt-1", 1735689600);
  if (!adopted.ok()) {
    line("adoption refused: " + adopted.to_string());
    return 1;
  }
  EvaluationRequest request;
  request.load = LoadId::Parse("L1").value();
  request.now = at(1735689600);
  const Result<Explanation> explanation = authority.value().Explain(request);
  if (!explanation.ok()) {
    line("evaluation refused: " + explanation.status().to_string());
    return 1;
  }
  std::cout << render_explanation(explanation.value());
  std::filesystem::remove_all(root);
  return 0;
}
