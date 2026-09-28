#pragma once

// The eligibility engine. Pure: it reads an adopted input generation, an explicit
// instant and the durable authority records it is given, and returns a decision set
// with no side effects.

#include <vector>

#include "feed_authority/decision.hpp"
#include "feed_authority/emergency.hpp"
#include "feed_authority/generations.hpp"
#include "feed_authority/inputs.hpp"
#include "feed_authority/limits.hpp"
#include "feed_authority/status.hpp"

namespace feed_authority::detail {

struct EvaluationEnvironment {
  const AuthorityInputs* inputs = nullptr;
  /// The current generation binding: the epoch, the four source revisions and the
  /// decision generation being handed out.
  AuthorityBinding binding{};
  /// Live and historical emergency authorizations. Authorization liveness is
  /// decided by the engine, not by the caller.
  const std::vector<EmergencyAuthorization>* emergency = nullptr;
  const Limits* limits = nullptr;
};

/// Evaluates every candidate for the request's load. `traces`, when supplied,
/// receives one ordered trace per candidate in the same order as the decision.
Result<DecisionSet> evaluate_load(const EvaluationEnvironment& environment,
                                  const EvaluationRequest& request,
                                  std::vector<CandidateTrace>* traces);

}  // namespace feed_authority::detail
