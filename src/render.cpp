#include "feed_authority/render.hpp"

#include <cstddef>
#include <string>
#include <string_view>
#include <vector>

#include "feed_authority/obligation.hpp"

namespace feed_authority {
namespace {

std::string quote(std::string_view text) {
  std::string out;
  out.push_back('"');
  for (const char character : text) {
    const unsigned char value = static_cast<unsigned char>(character);
    switch (character) {
      case '"': out += "\\\""; break;
      case '\\': out += "\\\\"; break;
      case '\n': out += "\\n"; break;
      case '\r': out += "\\r"; break;
      case '\t': out += "\\t"; break;
      default:
        if (value < 0x20u) {
          static const char kHex[] = "0123456789abcdef";
          out += "\\u00";
          out.push_back(kHex[(value >> 4u) & 0x0Fu]);
          out.push_back(kHex[value & 0x0Fu]);
        } else {
          out.push_back(character);
        }
        break;
    }
  }
  out.push_back('"');
  return out;
}

std::string join_ids(const std::vector<RuleId>& ids) {
  std::string out;
  for (const RuleId& id : ids) {
    if (!out.empty()) {
      out += ",";
    }
    out += id.value();
  }
  return out.empty() ? std::string("-") : out;
}

std::string join_obligations(const std::vector<ObligationId>& ids) {
  std::string out;
  for (const ObligationId& id : ids) {
    if (!out.empty()) {
      out += ",";
    }
    out += id.value();
  }
  return out.empty() ? std::string("-") : out;
}

std::string join_reasons(const std::vector<ReasonCode>& codes) {
  std::string out;
  for (const ReasonCode code : codes) {
    if (!out.empty()) {
      out += ",";
    }
    out += to_string(code);
  }
  return out.empty() ? std::string("-") : out;
}

std::string join_evidence(const std::vector<EvidenceRef>& refs) {
  std::string out;
  for (const EvidenceRef& reference : refs) {
    if (!out.empty()) {
      out += ",";
    }
    out += reference.source.value();
    out += ":";
    out += to_string(reference.state);
  }
  return out.empty() ? std::string("-") : out;
}

std::string join_feeds(const std::vector<FeedId>& feeds) {
  std::string out;
  for (const FeedId& feed : feeds) {
    if (!out.empty()) {
      out += ",";
    }
    out += feed.value();
  }
  return out.empty() ? std::string("-") : out;
}

std::string candidate_line(const CandidateDecision& candidate) {
  std::string text = "candidate ";
  text += candidate.feed.valid() ? candidate.feed.value() : std::string("<unset>");
  text += " outcome=";
  text += to_string(candidate.outcome);
  text += " reason=";
  text += to_string(candidate.reason);
  text += " decided_at=";
  text += to_string(candidate.decided_at);
  text += " role=";
  text += to_string(candidate.role);
  text += " domain=";
  text += candidate.failure_domain.valid() ? candidate.failure_domain.value() : std::string("-");
  text += " path=";
  text += candidate.authority_path.valid() ? candidate.authority_path.value() : std::string("-");
  text += " emergency=";
  text += candidate.emergency_override ? candidate.emergency_authorization : std::string("false");
  return text;
}

std::string candidate_json(const CandidateDecision& candidate) {
  std::string out = "{";
  out += "\"feed\":" + quote(candidate.feed.value());
  out += ",\"outcome\":" + quote(to_string(candidate.outcome));
  out += ",\"reason\":" + quote(to_string(candidate.reason));
  out += ",\"decided_at\":" + quote(to_string(candidate.decided_at));
  out += ",\"role\":" + quote(to_string(candidate.role));
  out += ",\"failure_domain\":" + quote(candidate.failure_domain.value());
  out += ",\"authority_path\":" + quote(candidate.authority_path.value());
  out += ",\"emergency_override\":";
  out += candidate.emergency_override ? "true" : "false";
  out += ",\"emergency_authorization\":" + quote(candidate.emergency_authorization);
  out += ",\"reasons\":[";
  for (std::size_t index = 0; index < candidate.reasons.size(); ++index) {
    if (index != 0) {
      out += ",";
    }
    out += quote(to_string(candidate.reasons[index]));
  }
  out += "],\"rules\":[";
  for (std::size_t index = 0; index < candidate.matched_rules.size(); ++index) {
    if (index != 0) {
      out += ",";
    }
    out += quote(candidate.matched_rules[index].value());
  }
  out += "],\"obligations\":[";
  for (std::size_t index = 0; index < candidate.matched_obligations.size(); ++index) {
    if (index != 0) {
      out += ",";
    }
    out += quote(candidate.matched_obligations[index].value());
  }
  out += "],\"evidence\":[";
  for (std::size_t index = 0; index < candidate.evidence.size(); ++index) {
    if (index != 0) {
      out += ",";
    }
    out += "{\"source\":" + quote(candidate.evidence[index].source.value()) +
           ",\"state\":" + quote(to_string(candidate.evidence[index].state)) + "}";
  }
  out += "]}";
  return out;
}

std::string decision_header_text(const DecisionSet& decision) {
  std::string text = "decision load=";
  text += decision.load.value();
  text += " condition=";
  text += to_string(decision.condition);
  text += " generation=";
  text += decision.generation.str();
  text += " epoch=";
  text += decision.epoch.str();
  text += " topology=";
  text += decision.topology.str();
  text += " policy=";
  text += decision.policy.str();
  text += " control=";
  text += decision.control.str();
  text += " evidence=";
  text += decision.evidence.str();
  text += "\n";
  text += "candidates=";
  text += std::to_string(decision.candidates.size());
  text += " eligible=";
  text += std::to_string(decision.eligible.size());
  text += " denied=";
  text += std::to_string(decision.denied.size());
  text += " indeterminate=";
  text += std::to_string(decision.indeterminate.size());
  text += " obligation_blocked=";
  text += decision.obligation_blocked ? "true" : "false";
  text += " narrowed=";
  text += decision.candidate_set_narrowed ? "true" : "false";
  text += "\nfingerprint=";
  text += decision.fingerprint.hex();
  text += "\n";
  return text;
}

std::string decision_header_json(const DecisionSet& decision) {
  std::string out = "{";
  out += "\"kind\":\"decision\"";
  out += ",\"load\":" + quote(decision.load.value());
  out += ",\"condition\":" + quote(to_string(decision.condition));
  out += ",\"generation\":" + decision.generation.str();
  out += ",\"epoch\":" + decision.epoch.str();
  out += ",\"topology\":" + decision.topology.str();
  out += ",\"policy\":" + decision.policy.str();
  out += ",\"control\":" + decision.control.str();
  out += ",\"evidence\":" + decision.evidence.str();
  out += ",\"fingerprint\":" + quote(decision.fingerprint.hex());
  out += ",\"evaluated_at\":" + quote(decision.evaluated_at.to_iso8601());
  out += ",\"obligation_blocked\":";
  out += decision.obligation_blocked ? "true" : "false";
  out += ",\"candidate_set_narrowed\":";
  out += decision.candidate_set_narrowed ? "true" : "false";
  out += ",\"blocking_obligations\":[";
  for (std::size_t index = 0; index < decision.blocking_obligations.size(); ++index) {
    if (index != 0) {
      out += ",";
    }
    out += quote(decision.blocking_obligations[index].value());
  }
  out += "]";
  return out;
}

}  // namespace

std::string render_status(const Status& status, const RenderOptions& options) {
  if (options.json) {
    std::string out = "{\"kind\":\"status\",\"ok\":";
    out += status.ok() ? "true" : "false";
    out += ",\"code\":" + quote(to_string(status.code()));
    out += ",\"message\":" + quote(status.message());
    out += "}\n";
    return out;
  }
  return status.to_string() + "\n";
}

std::string render_decision(const DecisionSet& decision, const RenderOptions& options) {
  if (options.json) {
    std::string out = decision_header_json(decision);
    out += ",\"candidates\":[";
    for (std::size_t index = 0; index < decision.candidates.size(); ++index) {
      if (index != 0) {
        out += ",";
      }
      out += candidate_json(decision.candidates[index]);
    }
    out += "],\"eligible\":[";
    for (std::size_t index = 0; index < decision.eligible.size(); ++index) {
      if (index != 0) {
        out += ",";
      }
      out += quote(decision.eligible[index].value());
    }
    out += "],\"denied\":[";
    for (std::size_t index = 0; index < decision.denied.size(); ++index) {
      if (index != 0) {
        out += ",";
      }
      out += quote(decision.denied[index].value());
    }
    out += "],\"indeterminate\":[";
    for (std::size_t index = 0; index < decision.indeterminate.size(); ++index) {
      if (index != 0) {
        out += ",";
      }
      out += quote(decision.indeterminate[index].value());
    }
    out += "],\"ranking\":{\"applied\":";
    out += decision.ranking.applied ? "true" : "false";
    out += ",\"selection_deferred_to_controller\":";
    out += decision.ranking.selection_deferred_to_controller ? "true" : "false";
    out += ",\"reason\":" + quote(to_string(decision.ranking.reason));
    out += ",\"preferred\":" + quote(decision.ranking.preferred.value());
    out += ",\"order\":[";
    for (std::size_t index = 0; index < decision.ranking.order.size(); ++index) {
      if (index != 0) {
        out += ",";
      }
      out += quote(decision.ranking.order[index].value());
    }
    out += "]}}\n";
    return out;
  }

  std::string text = decision_header_text(decision);
  for (const CandidateDecision& candidate : decision.candidates) {
    text += candidate_line(candidate);
    text += "\n  reasons=";
    text += join_reasons(candidate.reasons);
    text += "\n  rules=";
    text += join_ids(candidate.matched_rules);
    text += " obligations=";
    text += join_obligations(candidate.matched_obligations);
    text += "\n  evidence=";
    text += join_evidence(candidate.evidence);
    text += "\n";
  }
  text += "eligible=";
  text += join_feeds(decision.eligible);
  text += "\ndenied=";
  text += join_feeds(decision.denied);
  text += "\nindeterminate=";
  text += join_feeds(decision.indeterminate);
  text += "\nranking applied=";
  text += decision.ranking.applied ? "true" : "false";
  text += " selection_deferred_to_controller=";
  text += decision.ranking.selection_deferred_to_controller ? "true" : "false";
  text += " reason=";
  text += to_string(decision.ranking.reason);
  text += " preferred=";
  text += decision.ranking.preferred.valid() ? decision.ranking.preferred.value() : std::string("-");
  text += " order=";
  text += join_feeds(decision.ranking.order);
  text += "\n";
  if (decision.obligation_blocked) {
    text += "blocking_obligations=";
    text += join_obligations(decision.blocking_obligations);
    text += "\n";
  }
  return text;
}

std::string render_explanation(const Explanation& explanation, const RenderOptions& options) {
  std::string text = render_decision(explanation.decision, options);
  if (options.json) {
    return text;
  }
  for (const CandidateTrace& trace : explanation.traces) {
    text += "trace ";
    text += trace.feed.valid() ? trace.feed.value() : std::string("<unset>");
    text += "\n";
    for (const TraceStep& step : trace.steps) {
      text += "  step ";
      text += step.stage;
      text += " decisive=";
      text += step.decisive ? "true" : "false";
      text += " outcome=";
      text += to_string(step.outcome);
      text += " reason=";
      text += to_string(step.reason);
      text += "\n";
    }
  }
  return text;
}

std::string render_grant(const Grant& grant, const RenderOptions& options) {
  if (options.json) {
    std::string out = "{\"kind\":\"grant\",\"id\":" + grant.id.str();
    out += ",\"load\":" + quote(grant.load.value());
    out += ",\"feed\":" + quote(grant.feed.value());
    out += ",\"authority_path\":" + quote(grant.authority_path.value());
    out += ",\"issued_at\":" + quote(grant.issued_at.to_iso8601());
    out += ",\"expires_at\":" + quote(grant.expires_at.to_iso8601());
    out += ",\"revoked\":" + std::string(grant.revoked ? "true" : "false");
    out += ",\"revoked_by\":" + quote(grant.revoked_by.value());
    out += ",\"revocation_reason\":" + quote(grant.revocation_reason);
    out += ",\"revalidated\":" + std::string(grant.revalidated ? "true" : "false");
    out += ",\"revalidated_epoch\":" + grant.revalidated_epoch.str();
    out += ",\"issued_binding\":{\"epoch\":" + grant.issued_binding.epoch.str() +
           ",\"topology\":" + grant.issued_binding.topology.str() +
           ",\"policy\":" + grant.issued_binding.policy.str() +
           ",\"control\":" + grant.issued_binding.control.str() +
           ",\"evidence\":" + grant.issued_binding.evidence.str() +
           ",\"decision\":" + grant.issued_binding.decision.str() + "}";
    out += ",\"decision_fingerprint\":" + quote(grant.decision_fingerprint.hex());
    out += ",\"attempt\":" + quote(grant.attempt.value());
    out += "}\n";
    return out;
  }
  std::string text = "grant ";
  text += grant.id.str();
  text += " load=";
  text += grant.load.value();
  text += " feed=";
  text += grant.feed.value();
  text += " path=";
  text += grant.authority_path.value();
  text += "\n  issued=";
  text += grant.issued_at.to_iso8601();
  text += " expires=";
  text += grant.expires_at.to_iso8601();
  text += "\n  bound ";
  text += grant.issued_binding.to_string();
  text += "\n  decision_fingerprint=";
  text += grant.decision_fingerprint.hex();
  text += "\n  revoked=";
  text += grant.revoked ? "true" : "false";
  if (grant.revoked) {
    text += " at=";
    text += grant.revoked_at.to_iso8601();
    text += " by=";
    text += grant.revoked_by.value();
    text += " reason=";
    text += grant.revocation_reason;
  }
  text += "\n  revalidated=";
  text += grant.revalidated ? "true" : "false";
  if (grant.revalidated) {
    text += " epoch=";
    text += grant.revalidated_epoch.str();
    text += " at=";
    text += grant.revalidated_at.to_iso8601();
  }
  text += "\n";
  return text;
}

std::string render_grant_authorization(const GrantAuthorization& authorization,
                                       const RenderOptions& options) {
  if (options.json) {
    std::string out = "{\"kind\":\"grant_authorization\",\"authorized\":";
    out += authorization.authorized ? "true" : "false";
    out += ",\"usability\":" + quote(to_string(authorization.usability));
    out += ",\"reason\":" + quote(to_string(authorization.reason));
    out += ",\"detail\":" + quote(authorization.detail);
    out += ",\"grant\":" + std::to_string(authorization.grant.id.value());
    out += ",\"load\":" + quote(authorization.grant.load.value());
    out += ",\"feed\":" + quote(authorization.grant.feed.value());
    out += ",\"authority_path\":" + quote(authorization.authority_path.value());
    out += "}\n";
    return out;
  }
  std::string text = "authorization grant=";
  text += authorization.grant.id.str();
  text += " load=";
  text += authorization.grant.load.value();
  text += " feed=";
  text += authorization.grant.feed.value();
  text += " authorized=";
  text += authorization.authorized ? "true" : "false";
  text += " usability=";
  text += to_string(authorization.usability);
  text += " reason=";
  text += to_string(authorization.reason);
  text += " path=";
  text += authorization.authority_path.valid() ? authorization.authority_path.value()
                                               : std::string("-");
  text += "\n  detail=";
  text += authorization.detail;
  text += "\n";
  return text;
}

std::string render_emergency(const EmergencyAuthorization& authorization,
                             const RenderOptions& options) {
  if (options.json) {
    std::string out = "{\"kind\":\"emergency_authorization\",\"id\":" + authorization.id.str();
    out += ",\"authorizer\":" + quote(authorization.authorizer.value());
    out += ",\"justification\":" + quote(authorization.justification);
    out += ",\"issued_at\":" + quote(authorization.issued_at.to_iso8601());
    out += ",\"expires_at\":" + quote(authorization.expires_at.to_iso8601());
    out += ",\"revoked\":" + std::string(authorization.revoked ? "true" : "false");
    out += ",\"loads\":[";
    for (std::size_t index = 0; index < authorization.loads.size(); ++index) {
      if (index != 0) {
        out += ",";
      }
      out += quote(authorization.loads[index].value());
    }
    out += "],\"feeds\":[";
    for (std::size_t index = 0; index < authorization.feeds.size(); ++index) {
      if (index != 0) {
        out += ",";
      }
      out += quote(authorization.feeds[index].value());
    }
    out += "],\"overridable_classes\":[";
    for (std::size_t index = 0; index < authorization.overridable_classes.size(); ++index) {
      if (index != 0) {
        out += ",";
      }
      out += quote(to_string(authorization.overridable_classes[index]));
    }
    out += "]}\n";
    return out;
  }
  std::string text = "emergency ";
  text += authorization.id.str();
  text += " authorizer=";
  text += authorization.authorizer.value();
  text += "\n  justification=";
  text += authorization.justification;
  text += "\n  issued=";
  text += authorization.issued_at.to_iso8601();
  text += " expires=";
  text += authorization.expires_at.to_iso8601();
  text += " revoked=";
  text += authorization.revoked ? "true" : "false";
  text += "\n  loads=";
  for (std::size_t index = 0; index < authorization.loads.size(); ++index) {
    if (index != 0) {
      text += ",";
    }
    text += authorization.loads[index].value();
  }
  text += " feeds=";
  if (authorization.feeds.empty()) {
    text += "<any linked>";
  }
  for (std::size_t index = 0; index < authorization.feeds.size(); ++index) {
    if (index != 0) {
      text += ",";
    }
    text += authorization.feeds[index].value();
  }
  text += "\n  overridable_classes=";
  for (std::size_t index = 0; index < authorization.overridable_classes.size(); ++index) {
    if (index != 0) {
      text += ",";
    }
    text += to_string(authorization.overridable_classes[index]);
  }
  text += "\n";
  return text;
}

std::string render_policy(const PolicySet& policy, const RenderOptions& options) {
  if (options.json) {
    std::string out = "{\"kind\":\"policy\",\"revision\":" + policy.revision.str();
    out += ",\"rules\":[";
    for (std::size_t index = 0; index < policy.rules.size(); ++index) {
      const EligibilityRule& rule = policy.rules[index];
      if (index != 0) {
        out += ",";
      }
      out += "{\"id\":" + quote(rule.id.value());
      out += ",\"precedence\":" + quote(to_string(rule.precedence));
      out += ",\"rank\":" + quote(to_string(rule.rank));
      out += ",\"effect\":" + quote(to_string(rule.effect));
      out += ",\"authority_path\":" + quote(rule.authority_path.value());
      out += ",\"reason\":" + quote(to_string(rule.reason));
      out += ",\"overridable\":" + std::string(rule.emergency_overridable ? "true" : "false");
      out += ",\"feed\":" + quote(rule.scope.feed ? rule.scope.feed->value() : std::string());
      out += ",\"load\":" + quote(rule.scope.load ? rule.scope.load->value() : std::string());
      out += "}";
    }
    out += "],\"obligations\":[";
    for (std::size_t index = 0; index < policy.obligations.size(); ++index) {
      if (index != 0) {
        out += ",";
      }
      out += "{\"id\":" + quote(policy.obligations[index].id.value());
      out += ",\"min_distinct_failure_domains\":" +
             std::to_string(policy.obligations[index].min_distinct_failure_domains);
      out += "}";
    }
    out += "],\"ranking_enabled\":";
    out += policy.options.ranking.enabled ? "true" : "false";
    out += ",\"emergency_override_enabled\":";
    out += policy.options.emergency_override_enabled ? "true" : "false";
    out += "}\n";
    return out;
  }
  std::string text = "policy revision=";
  text += policy.revision.str();
  text += " rules=";
  text += std::to_string(policy.rules.size());
  text += " obligations=";
  text += std::to_string(policy.obligations.size());
  text += " ranking=";
  text += policy.options.ranking.enabled ? "on" : "off";
  text += " emergency_override=";
  text += policy.options.emergency_override_enabled ? "on" : "off";
  text += "\n";
  for (const EligibilityRule& rule : policy.rules) {
    text += "  rule ";
    text += rule.id.value();
    text += " effect=";
    text += to_string(rule.effect);
    text += " precedence=";
    text += to_string(rule.precedence);
    text += " rank=";
    text += to_string(rule.rank);
    text += " reason=";
    text += to_string(rule.reason);
    if (rule.authority_path.valid()) {
      text += " path=";
      text += rule.authority_path.value();
    }
    if (rule.scope.feed) {
      text += " feed=";
      text += rule.scope.feed->value();
    }
    if (rule.scope.load) {
      text += " load=";
      text += rule.scope.load->value();
    }
    if (!rule.conditions.empty()) {
      text += " conditions=";
      for (std::size_t index = 0; index < rule.conditions.size(); ++index) {
        if (index != 0) {
          text += ",";
        }
        text += to_string(rule.conditions[index]);
      }
    }
    if (rule.emergency_overridable) {
      text += " overridable=true";
    }
    text += "\n";
  }
  for (const ProtectedObligation& obligation : policy.obligations) {
    text += "  obligation ";
    text += obligation.id.value();
    text += " min_distinct_failure_domains=";
    text += std::to_string(obligation.min_distinct_failure_domains);
    text += " protected_loads=";
    text += obligation.applies_to_protected_loads ? "true" : "false";
    text += " loads=";
    text += std::to_string(obligation.loads.size());
    text += "\n";
  }
  return text;
}

std::string render_topology(const TopologyView& topology, const RenderOptions& options) {
  if (options.json) {
    std::string out = "{\"kind\":\"topology\",\"revision\":" + topology.revision.str();
    out += ",\"feeds\":[";
    for (std::size_t index = 0; index < topology.feeds.size(); ++index) {
      if (index != 0) {
        out += ",";
      }
      out += "{\"id\":" + quote(topology.feeds[index].id.value());
      out += ",\"source\":" + quote(to_string(topology.feeds[index].source_class));
      out += ",\"role\":" + quote(to_string(topology.feeds[index].role));
      out += ",\"failure_domain\":" + quote(topology.feeds[index].failure_domain.value());
      out += "}";
    }
    out += "],\"loads\":[";
    for (std::size_t index = 0; index < topology.loads.size(); ++index) {
      if (index != 0) {
        out += ",";
      }
      out += "{\"id\":" + quote(topology.loads[index].id.value());
      out += ",\"class\":" + quote(to_string(topology.loads[index].load_class));
      out += ",\"protected\":";
      out += topology.loads[index].protected_load ? "true" : "false";
      out += "}";
    }
    out += "],\"paths\":[";
    for (std::size_t index = 0; index < topology.links.size(); ++index) {
      if (index != 0) {
        out += ",";
      }
      out += "{\"feed\":" + quote(topology.links[index].feed.value());
      out += ",\"load\":" + quote(topology.links[index].load.value());
      out += ",\"role\":" + quote(to_string(topology.links[index].role));
      out += ",\"failure_domain\":" + quote(topology.links[index].failure_domain.value());
      out += "}";
    }
    out += "]}\n";
    return out;
  }
  std::string text = "topology revision=";
  text += topology.revision.str();
  text += " feeds=";
  text += std::to_string(topology.feeds.size());
  text += " loads=";
  text += std::to_string(topology.loads.size());
  text += " paths=";
  text += std::to_string(topology.links.size());
  text += "\n";
  for (const FeedDescriptor& feed : topology.feeds) {
    text += "  feed ";
    text += feed.id.value();
    text += " source=";
    text += to_string(feed.source_class);
    text += " role=";
    text += to_string(feed.role);
    text += " domain=";
    text += feed.failure_domain.valid() ? feed.failure_domain.value() : std::string("-");
    text += " protected_capable=";
    text += feed.may_serve_protected_loads ? "true" : "false";
    text += " observations=";
    text += std::to_string(feed.condition.size());
    text += "\n";
  }
  for (const LoadDescriptor& load : topology.loads) {
    text += "  load ";
    text += load.id.value();
    text += " class=";
    text += to_string(load.load_class);
    text += " protected=";
    text += load.protected_load ? "true" : "false";
    text += "\n";
  }
  for (const FeedLink& link : topology.links) {
    text += "  path ";
    text += link.feed.value();
    text += " -> ";
    text += link.load.value();
    text += " role=";
    text += to_string(link.role);
    text += " domain=";
    text += link.failure_domain.valid() ? link.failure_domain.value() : std::string("-");
    text += " observations=";
    text += std::to_string(link.observed.size());
    text += "\n";
  }
  return text;
}

std::string render_inputs(const AuthorityInputs& inputs, const RenderOptions& options) {
  std::string text = render_topology(inputs.topology, options);
  for (const MaintenanceRecord& record : inputs.control.maintenance) {
    text += "maintenance ";
    text += record.feed.value();
    text += " observations=";
    text += std::to_string(record.exposure.size());
    text += "\n";
  }
  text += "control revision=";
  text += inputs.control.revision.str();
  text += " condition_observations=";
  text += std::to_string(inputs.control.condition.size());
  text += "\n";
  text += render_policy(inputs.policy, options);
  text += "evidence revision=";
  text += inputs.evidence.str();
  text += "\n";
  return text;
}

std::string render_recovery(const RecoveryReport& report, const RenderOptions& options) {
  if (options.json) {
    std::string out = "{\"kind\":\"recovery\",\"sequence\":" + report.sequence.str();
    out += ",\"epoch\":" + report.epoch.str();
    out += ",\"incarnation\":" + quote(report.incarnation.str());
    out += ",\"created_new_store\":";
    out += report.created_new_store ? "true" : "false";
    out += ",\"head_was_present\":";
    out += report.head_was_present ? "true" : "false";
    out += ",\"residue_present\":";
    out += report.residue_present ? "true" : "false";
    out += ",\"grants_loaded\":" + std::to_string(report.grants_loaded);
    out += ",\"grants_needing_revalidation\":" + std::to_string(report.grants_needing_revalidation);
    out += ",\"emergency_loaded\":" + std::to_string(report.emergency_loaded);
    out += ",\"events_loaded\":" + std::to_string(report.events_loaded);
    out += ",\"replay_entries_loaded\":" + std::to_string(report.replay_entries_loaded);
    out += "}\n";
    return out;
  }
  std::string text = "recovery sequence=";
  text += report.sequence.str();
  text += " epoch=";
  text += report.epoch.str();
  text += " incarnation=";
  text += report.incarnation.str();
  text += " created=";
  text += report.created_new_store ? "true" : "false";
  text += " head_present=";
  text += report.head_was_present ? "true" : "false";
  text += "\n  grants_loaded=";
  text += std::to_string(report.grants_loaded);
  text += " grants_needing_revalidation=";
  text += std::to_string(report.grants_needing_revalidation);
  text += " emergency_loaded=";
  text += std::to_string(report.emergency_loaded);
  text += " events_loaded=";
  text += std::to_string(report.events_loaded);
  text += " replay_entries=";
  text += std::to_string(report.replay_entries_loaded);
  text += "\n";
  for (const std::string& residue : report.residue) {
    text += "  residue ";
    text += residue;
    text += "\n";
  }
  return text;
}

std::string render_audit(const StoreAuditReport& report, const RenderOptions& options) {
  if (options.json) {
    std::string out = "{\"kind\":\"store_audit\",\"root\":" + quote(report.root);
    out += ",\"ok\":";
    out += report.ok() ? "true" : "false";
    out += ",\"head_present\":";
    out += report.head_present ? "true" : "false";
    out += ",\"head_valid\":";
    out += report.head_valid ? "true" : "false";
    out += ",\"head_sequence\":" + report.head_sequence.str();
    out += ",\"epoch\":" + report.epoch.str();
    out += ",\"head_generation_digest\":" + quote(report.head_generation_digest.hex());
    out += ",\"rollback_suspected\":";
    out += report.rollback_suspected ? "true" : "false";
    out += ",\"newest_generation_sequence\":" + std::to_string(report.newest_generation_sequence);
    out += ",\"total_bytes\":" + std::to_string(report.total_bytes);
    out += ",\"generations\":[";
    for (std::size_t index = 0; index < report.generations.size(); ++index) {
      if (index != 0) {
        out += ",";
      }
      out += "{\"name\":" + quote(report.generations[index].name);
      out += ",\"sequence\":" + report.generations[index].sequence.str();
      out += ",\"bytes\":" + std::to_string(report.generations[index].bytes);
      out += ",\"header_ok\":";
      out += report.generations[index].header_ok ? "true" : "false";
      out += ",\"digest_ok\":";
      out += report.generations[index].digest_ok ? "true" : "false";
      out += ",\"payload_ok\":";
      out += report.generations[index].payload_ok ? "true" : "false";
      out += ",\"classification\":" + quote(report.generations[index].classification);
      out += ",\"detail\":" + quote(report.generations[index].detail);
      out += "}";
    }
    out += "]}\n";
    return out;
  }
  std::string text = "store-audit root=";
  text += report.root;
  text += " ok=";
  text += report.ok() ? "true" : "false";
  text += "\n  head present=";
  text += report.head_present ? "true" : "false";
  text += " valid=";
  text += report.head_valid ? "true" : "false";
  text += " sequence=";
  text += report.head_sequence.str();
  text += " epoch=";
  text += report.epoch.str();
  text += "\n  head_detail=";
  text += report.head_detail;
  text += "\n  generations=";
  text += std::to_string(report.generations.size());
  text += " newest=";
  text += std::to_string(report.newest_generation_sequence);
  text += " rollback_suspected=";
  text += report.rollback_suspected ? "true" : "false";
  text += "\n";
  for (const GenerationAudit& entry : report.generations) {
    text += "  generation ";
    text += entry.name;
    text += " sequence=";
    text += entry.sequence.str();
    text += " bytes=";
    text += std::to_string(entry.bytes);
    text += " header=";
    text += entry.header_ok ? "ok" : "bad";
    text += " digest=";
    text += entry.digest_ok ? "ok" : "bad";
    text += " payload=";
    text += entry.payload_ok ? "ok" : "bad";
    text += " class=";
    text += entry.classification;
    if (!entry.detail.empty()) {
      text += " detail=";
      text += entry.detail;
    }
    text += "\n";
  }
  for (const std::string& residue : report.staging_residue) {
    text += "  staging-residue ";
    text += residue;
    text += "\n";
  }
  for (const std::string& entry : report.unexpected_entries) {
    text += "  unexpected ";
    text += entry;
    text += "\n";
  }
  text += "  grants=";
  text += std::to_string(report.granted);
  text += " revoked=";
  text += std::to_string(report.revoked);
  text += " emergency=";
  text += std::to_string(report.emergency_authorizations);
  text += " events=";
  text += std::to_string(report.events);
  text += " replay_entries=";
  text += std::to_string(report.replay_entries);
  text += "\n";
  return text;
}

std::string render_history(const std::vector<EventRecord>& events, const RenderOptions& options) {
  std::string text;
  for (const EventRecord& event : events) {
    if (options.json) {
      text += "{\"kind\":\"event\",\"sequence\":" + event.sequence.str();
      text += ",\"event\":" + quote(to_string(event.kind));
      text += ",\"at\":" + quote(event.at.to_iso8601());
      text += ",\"epoch\":" + event.epoch.str();
      text += ",\"detail\":" + quote(event.detail);
      text += ",\"grant\":" + (event.grant ? event.grant->str() : std::string("0"));
      text += ",\"emergency\":" + (event.emergency ? event.emergency->str() : std::string("0"));
      text += ",\"decision\":" + (event.decision ? event.decision->str() : std::string("0"));
      text += "}\n";
      continue;
    }
    text += "event ";
    text += event.sequence.str();
    text += " ";
    text += to_string(event.kind);
    text += " at=";
    text += event.at.to_iso8601();
    text += " epoch=";
    text += event.epoch.str();
    if (event.grant) {
      text += " grant=";
      text += event.grant->str();
    }
    if (event.emergency) {
      text += " emergency=";
      text += event.emergency->str();
    }
    if (event.decision) {
      text += " decision=";
      text += event.decision->str();
    }
    text += " detail=";
    text += event.detail;
    text += "\n";
  }
  return text;
}

std::string render_attempts(const std::vector<AttemptRecord>& attempts,
                            const RenderOptions& options) {
  std::string text;
  for (const AttemptRecord& attempt : attempts) {
    if (options.json) {
      text += "{\"kind\":\"attempt\",\"id\":" + quote(attempt.attempt.value());
      text += ",\"operation\":" + quote(to_string(attempt.kind));
      text += ",\"fingerprint\":" + quote(attempt.request_fingerprint.hex());
      text += ",\"grant\":" + (attempt.grant_id ? std::to_string(*attempt.grant_id) : std::string("0"));
      text += ",\"emergency\":" +
              (attempt.emergency_id ? std::to_string(*attempt.emergency_id) : std::string("0"));
      text += ",\"recorded_at\":" + attempt.recorded_at.str();
      text += "}\n";
      continue;
    }
    text += "attempt ";
    text += attempt.attempt.value();
    text += " operation=";
    text += to_string(attempt.kind);
    text += " fingerprint=";
    text += attempt.request_fingerprint.hex();
    text += " grant=";
    text += attempt.grant_id ? std::to_string(*attempt.grant_id) : std::string("-");
    text += " emergency=";
    text += attempt.emergency_id ? std::to_string(*attempt.emergency_id) : std::string("-");
    text += " recorded_at=";
    text += attempt.recorded_at.str();
    text += "\n";
  }
  return text;
}

std::string render_policy_diff(const PolicyDiff& diff, const RenderOptions& options) {
  if (options.json) {
    std::string out = "{\"kind\":\"policy_diff\",\"from\":" + diff.from.str();
    out += ",\"to\":" + diff.to.str();
    out += ",\"identical\":";
    out += diff.identical ? "true" : "false";
    out += ",\"rules\":[";
    for (std::size_t index = 0; index < diff.rules.size(); ++index) {
      if (index != 0) {
        out += ",";
      }
      out += "{\"id\":" + quote(diff.rules[index].id.value());
      out += ",\"change\":" + quote(diff.rules[index].change);
      out += "}";
    }
    out += "]}\n";
    return out;
  }
  return diff.to_string();
}

std::string render_inputs_diff(const InputsDiff& diff, const RenderOptions& options) {
  if (options.json) {
    std::string out = "{\"kind\":\"inputs_diff\",\"identical\":";
    out += diff.identical ? "true" : "false";
    out += ",\"from_topology\":" + diff.from_topology.str();
    out += ",\"to_topology\":" + diff.to_topology.str();
    out += ",\"changes\":[";
    for (std::size_t index = 0; index < diff.changes.size(); ++index) {
      if (index != 0) {
        out += ",";
      }
      out += quote(diff.changes[index]);
    }
    out += "]}\n";
    return out;
  }
  return diff.to_string();
}

std::string render_limits(const Limits& limits, const RenderOptions& options) {
  std::string text;
  if (options.json) {
    text = "{\"kind\":\"limits\"";
    text += ",\"max_feeds\":" + std::to_string(limits.max_feeds);
    text += ",\"max_loads\":" + std::to_string(limits.max_loads);
    text += ",\"max_links\":" + std::to_string(limits.max_links);
    text += ",\"max_rules\":" + std::to_string(limits.max_rules);
    text += ",\"max_obligations\":" + std::to_string(limits.max_obligations);
    text += ",\"max_candidates\":" + std::to_string(limits.max_candidates);
    text += ",\"max_grants\":" + std::to_string(limits.max_grants);
    text += ",\"max_emergency_authorizations\":" + std::to_string(limits.max_emergency_authorizations);
    text += ",\"max_events\":" + std::to_string(limits.max_events);
    text += ",\"max_replay_entries\":" + std::to_string(limits.max_replay_entries);
    text += ",\"generation_retention\":" + std::to_string(limits.generation_retention);
    text += ",\"max_generation_bytes\":" + std::to_string(limits.max_generation_bytes);
    text += "}\n";
    return text;
  }
  text += "limits max_feeds=" + std::to_string(limits.max_feeds);
  text += " max_loads=" + std::to_string(limits.max_loads);
  text += " max_links=" + std::to_string(limits.max_links);
  text += " max_rules=" + std::to_string(limits.max_rules);
  text += " max_obligations=" + std::to_string(limits.max_obligations);
  text += " max_candidates=" + std::to_string(limits.max_candidates);
  text += " max_grants=" + std::to_string(limits.max_grants);
  text += " max_emergency_authorizations=" + std::to_string(limits.max_emergency_authorizations);
  text += " max_events=" + std::to_string(limits.max_events);
  text += " max_replay_entries=" + std::to_string(limits.max_replay_entries);
  text += " generation_retention=" + std::to_string(limits.generation_retention);
  text += " max_generation_bytes=" + std::to_string(limits.max_generation_bytes);
  text += "\n";
  return text;
}

std::string render_recovery_json_helper(const RecoveryReport& report) {
  return render_recovery(report, RenderOptions{true, false});
}

}  // namespace feed_authority
