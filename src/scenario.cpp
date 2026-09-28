#include "feed_authority/scenario.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <map>
#include <set>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "detail/codec.hpp"
#include "detail/platform_io.hpp"
#include "feed_authority/obligation.hpp"

namespace feed_authority {
namespace {

using detail::parse_boolean;
using detail::parse_signed;
using detail::parse_unsigned;
using detail::split_fields;
using detail::split_list;
using detail::validate_line;

std::string_view trim(std::string_view text) {
  while (!text.empty() && (text.front() == ' ' || text.front() == '\t')) {
    text.remove_prefix(1);
  }
  while (!text.empty() && (text.back() == ' ' || text.back() == '\t' || text.back() == '\r')) {
    text.remove_suffix(1);
  }
  return text;
}

Status fail(std::string_view source, std::size_t line, std::string message) {
  std::string text(source);
  text += ":";
  text += std::to_string(line);
  text += ": ";
  text += std::move(message);
  return Status::error(StatusCode::InvalidArgument, std::move(text));
}

/// A strict key=value view over one record. Every declared key must be consumed
/// exactly once, so an unknown key, a duplicate key or a misspelled key is an
/// error rather than a silently ignored field.
class FieldMap {
 public:
  static Result<FieldMap> parse(const std::vector<std::string>& fields, std::size_t first,
                                std::string_view source, std::size_t line) {
    FieldMap map;
    map.source_ = source;
    map.line_ = line;
    for (std::size_t index = first; index < fields.size(); ++index) {
      const std::string& field = fields[index];
      const std::size_t equals = field.find('=');
      if (equals == std::string::npos || equals == 0) {
        return fail(source, line, "a field is not key=value");
      }
      const std::string key = field.substr(0, equals);
      if (!detail::is_token_text(key)) {
        return fail(source, line, "a field key is not a lowercase token");
      }
      if (!map.values_.emplace(key, field.substr(equals + 1)).second) {
        return fail(source, line, "the field '" + key + "' appears twice");
      }
    }
    return map;
  }

  bool has(std::string_view key) const { return values_.find(std::string(key)) != values_.end(); }

  Result<std::string> take_text(std::string_view key, bool required) {
    const auto found = values_.find(std::string(key));
    if (found == values_.end()) {
      if (required) {
        return fail(source_, line_, "the field '" + std::string(key) + "' is required");
      }
      return std::string();
    }
    used_.insert(found->first);
    const std::string& raw = found->second;
    if (raw.empty()) {
      return std::string();
    }
    if (raw.front() != '"') {
      return raw;
    }
    std::size_t cursor = 0;
    const Result<std::string> decoded = detail::unescape_text(raw, cursor, kMaxTextLength);
    if (!decoded.ok()) {
      return fail(source_, line_, "the field '" + std::string(key) + "' is not a valid string");
    }
    if (cursor != raw.size()) {
      return fail(source_, line_, "the field '" + std::string(key) + "' has trailing characters");
    }
    return decoded.value();
  }

  Result<std::uint64_t> take_uint(std::string_view key, bool required) {
    const Result<std::string> text = take_text(key, required);
    if (!text.ok()) {
      return text.status();
    }
    if (text.value().empty() && !required) {
      return 0u;
    }
    const Result<std::uint64_t> value = parse_unsigned(text.value());
    if (!value.ok()) {
      return fail(source_, line_, "the field '" + std::string(key) + "' is not an unsigned decimal");
    }
    return value.value();
  }

  Result<bool> take_bool(std::string_view key, bool fallback) {
    if (!has(key)) {
      return fallback;
    }
    const Result<std::string> text = take_text(key, true);
    if (!text.ok()) {
      return text.status();
    }
    if (text.value() == "yes" || text.value() == "true" || text.value() == "on") {
      return true;
    }
    if (text.value() == "no" || text.value() == "false" || text.value() == "off") {
      return false;
    }
    return fail(source_, line_, "the field '" + std::string(key) + "' is not yes, no, on or off");
  }

  Status finish() {
    for (const auto& entry : values_) {
      if (used_.find(entry.first) == used_.end()) {
        return fail(source_, line_, "the field '" + entry.first + "' is not recognized");
      }
    }
    return Status::success();
  }

 private:
  std::map<std::string, std::string> values_;
  std::set<std::string> used_;
  std::string source_;
  std::size_t line_ = 0;
};

Result<AuthorityTime> parse_instant(std::string_view text, std::string_view source, std::size_t line) {
  if (text.find('-') != std::string_view::npos || text.find('T') != std::string_view::npos) {
    const Result<AuthorityTime> parsed = AuthorityTime::ParseIso8601(text);
    if (!parsed.ok()) {
      return fail(source, line, "an instant is not a valid ISO-8601 timestamp");
    }
    return parsed.value();
  }
  const Result<std::int64_t> seconds = detail::parse_signed(text);
  if (!seconds.ok()) {
    return fail(source, line, "an instant is neither a timestamp nor whole seconds");
  }
  const Result<AuthorityTime> parsed = AuthorityTime::FromUnixSeconds(seconds.value());
  if (!parsed.ok()) {
    return fail(source, line, parsed.status().message());
  }
  return parsed.value();
}

Result<Duration> parse_duration(std::string_view text, std::string_view source, std::size_t line) {
  if (text.size() < 2) {
    return fail(source, line, "a duration needs a value and a unit");
  }
  std::string_view unit = text.substr(text.size() - 2);
  std::size_t digits = text.size() - 2;
  if (unit == "ms") {
    unit = "ms";
  } else {
    unit = text.substr(text.size() - 1);
    digits = text.size() - 1;
  }
  const Result<std::int64_t> value = detail::parse_signed(text.substr(0, digits));
  if (!value.ok()) {
    return fail(source, line, "a duration value is not an integer");
  }
  if (unit == "ns") return Duration::FromNanos(value.value());
  if (unit == "ms") return Duration::FromMillis(value.value());
  if (unit == "s") return Duration::FromSeconds(value.value());
  if (unit == "m") return Duration::FromMinutes(value.value());
  if (unit == "h") return Duration::FromHours(value.value());
  return fail(source, line, "a duration unit must be one of ns, ms, s, m, h");
}

Result<FeedId> parse_feed_id(std::string_view text, std::string_view source, std::size_t line) {
  const Result<FeedId> parsed = FeedId::Parse(text);
  if (!parsed.ok()) {
    return fail(source, line, "a feed identity is not well-formed");
  }
  return parsed.value();
}

Result<LoadId> parse_load_id(std::string_view text, std::string_view source, std::size_t line) {
  const Result<LoadId> parsed = LoadId::Parse(text);
  if (!parsed.ok()) {
    return fail(source, line, "a load identity is not well-formed");
  }
  return parsed.value();
}

struct PendingObservation {
  enum class Subject : std::int32_t { Feed, Link, Maintenance, State };
  Subject subject = Subject::Feed;
  FeedId feed;
  LoadId load;
  MaintenanceWindowId window;
  bool known = false;
  std::string value_token;
  std::string declaration;
  AuthorityTime at;
  Duration max_age;
  EvidenceSourceId source;
  std::size_t line = 0;
};

/// Builds one observation record from a pending declaration.
template <class Value, class ParseValue>
Result<Observation<Value>> build_pending_observation(const PendingObservation& pending,
                                                     ParseValue parse_value,
                                                     std::string_view source) {
  if (pending.known) {
    const Result<Value> parsed = parse_value(pending.value_token);
    if (!parsed.ok()) {
      return fail(source, pending.line, "an observation value token is not defined");
    }
    const Result<Observation<Value>> known = Observation<Value>::Known(
        parsed.value(), pending.at, pending.max_age, pending.source);
    if (!known.ok()) {
      return fail(source, pending.line, known.status().message());
    }
    return known.value();
  }
  if (pending.declaration == "unsupported") {
    return Observation<Value>::Unsupported(pending.source);
  }
  if (pending.declaration == "unavailable") {
    return Observation<Value>::Unavailable(pending.source);
  }
  return Observation<Value>::Unknown(pending.source);
}

}  // namespace

Result<AuthorityInputs> parse_scenario(std::string_view text, const Limits& limits,
                                       std::string_view source_name) {
  const Status limits_status = limits.validate();
  if (!limits_status.ok()) {
    return limits_status;
  }
  if (text.size() > kMaxScenarioBytes) {
    return Status::error(StatusCode::LimitExceeded, "the scenario is larger than the supported bound");
  }

  AuthorityInputs inputs;
  std::vector<PendingObservation> observations;
  bool saw_revisions = false;
  bool saw_option = false;
  bool saw_ranking_roles = false;

  std::size_t line_number = 0;
  std::size_t offset = 0;
  while (offset <= text.size()) {
    std::size_t end = text.find('\n', offset);
    if (end == std::string_view::npos) {
      end = text.size();
    }
    const std::string_view raw = text.substr(offset, end - offset);
    offset = end + 1;
    ++line_number;
    const std::string_view line = trim(raw);
    if (line.empty() || line.front() == '#') {
      if (end >= text.size()) {
        break;
      }
      continue;
    }
    const Status bounded = validate_line(line, limits.max_payload_line_bytes);
    if (!bounded.ok()) {
      return fail(source_name, line_number, bounded.message());
    }
    const Result<std::vector<std::string>> split = split_fields(line);
    if (!split.ok()) {
      return fail(source_name, line_number, split.status().message());
    }
    const std::vector<std::string>& fields = split.value();
    const std::string& type = fields.front();

    if (type == "revisions") {
      if (saw_revisions) {
        return fail(source_name, line_number, "the scenario declares revisions twice");
      }
      saw_revisions = true;
      Result<FieldMap> map = FieldMap::parse(fields, 1, source_name, line_number);
      if (!map.ok()) return map.status();
      const Result<std::uint64_t> topology = map.value().take_uint("topology", true);
      if (!topology.ok()) return topology.status();
      const Result<std::uint64_t> policy = map.value().take_uint("policy", true);
      if (!policy.ok()) return policy.status();
      const Result<std::uint64_t> control = map.value().take_uint("control", true);
      if (!control.ok()) return control.status();
      const Result<std::uint64_t> evidence = map.value().take_uint("evidence", true);
      if (!evidence.ok()) return evidence.status();
      const Status finished = map.value().finish();
      if (!finished.ok()) return finished;
      inputs.topology.revision = TopologyRevision::FromValue(topology.value());
      inputs.policy.revision = PolicyRevision::FromValue(policy.value());
      inputs.control.revision = ControlRevision::FromValue(control.value());
      inputs.evidence = EvidenceRevision::FromValue(evidence.value());
    } else if (type == "name") {
      continue;  // informational only
    } else if (type == "option") {
      Result<FieldMap> map = FieldMap::parse(fields, 1, source_name, line_number);
      if (!map.ok()) return map.status();
      if (map.value().has("ranking")) {
        const Result<bool> ranking = map.value().take_bool("ranking", false);
        if (!ranking.ok()) return ranking.status();
        inputs.policy.options.ranking.enabled = ranking.value();
        saw_option = true;
      }
      if (map.value().has("emergency")) {
        const Result<bool> emergency = map.value().take_bool("emergency", false);
        if (!emergency.ok()) return emergency.status();
        inputs.policy.options.emergency_override_enabled = emergency.value();
        saw_option = true;
      }
      if (map.value().has("roles")) {
        if (saw_ranking_roles) {
          return fail(source_name, line_number, "the scenario declares a ranking order twice");
        }
        saw_ranking_roles = true;
        const Result<std::string> roles = map.value().take_text("roles", true);
        if (!roles.ok()) return roles.status();
        const Result<std::vector<std::string>> items = split_list(roles.value(), 4u);
        if (!items.ok()) return fail(source_name, line_number, items.status().message());
        for (const std::string& item : items.value()) {
          const Result<RedundancyRole> role = parse_redundancy_role(item);
          if (!role.ok()) return fail(source_name, line_number, "a ranking role token is not defined");
          inputs.policy.options.ranking.role_order.push_back(role.value());
        }
        saw_option = true;
      }
      const Status finished = map.value().finish();
      if (!finished.ok()) return finished;
    } else if (type == "feed") {
      if (fields.size() < 2) {
        return fail(source_name, line_number, "a feed record needs an identity");
      }
      const Result<FeedId> id = parse_feed_id(fields[1], source_name, line_number);
      if (!id.ok()) return id.status();
      Result<FieldMap> map = FieldMap::parse(fields, 2, source_name, line_number);
      if (!map.ok()) return map.status();
      FeedDescriptor feed;
      feed.id = id.value();
      const Result<std::string> source = map.value().take_text("source", true);
      if (!source.ok()) return source.status();
      const Result<SourceClass> parsed_source = parse_source_class(source.value());
      if (!parsed_source.ok()) return fail(source_name, line_number, "a source class token is not defined");
      feed.source_class = parsed_source.value();
      const Result<std::string> role = map.value().take_text("role", true);
      if (!role.ok()) return role.status();
      const Result<RedundancyRole> parsed_role = parse_redundancy_role(role.value());
      if (!parsed_role.ok()) return fail(source_name, line_number, "a redundancy role token is not defined");
      feed.role = parsed_role.value();
      const Result<std::string> domain = map.value().take_text("domain", false);
      if (!domain.ok()) return domain.status();
      if (!domain.value().empty()) {
        const Result<FailureDomainId> parsed_domain = FailureDomainId::Parse(domain.value());
        if (!parsed_domain.ok()) return fail(source_name, line_number, "a failure domain identity is not well-formed");
        feed.failure_domain = parsed_domain.value();
      }
      const Result<bool> capability = map.value().take_bool("protected", false);
      if (!capability.ok()) return capability.status();
      feed.may_serve_protected_loads = capability.value();
      const Status finished = map.value().finish();
      if (!finished.ok()) return finished;
      inputs.topology.feeds.push_back(std::move(feed));
    } else if (type == "load") {
      if (fields.size() < 2) {
        return fail(source_name, line_number, "a load record needs an identity");
      }
      const Result<LoadId> id = parse_load_id(fields[1], source_name, line_number);
      if (!id.ok()) return id.status();
      Result<FieldMap> map = FieldMap::parse(fields, 2, source_name, line_number);
      if (!map.ok()) return map.status();
      LoadDescriptor load;
      load.id = id.value();
      const Result<std::string> load_class = map.value().take_text("class", true);
      if (!load_class.ok()) return load_class.status();
      const Result<LoadClass> parsed_class = parse_load_class(load_class.value());
      if (!parsed_class.ok()) return fail(source_name, line_number, "a load class token is not defined");
      load.load_class = parsed_class.value();
      const Result<bool> is_protected = map.value().take_bool("protected", false);
      if (!is_protected.ok()) return is_protected.status();
      load.protected_load = is_protected.value();
      const Status finished = map.value().finish();
      if (!finished.ok()) return finished;
      inputs.topology.loads.push_back(std::move(load));
    } else if (type == "link") {
      if (fields.size() < 3) {
        return fail(source_name, line_number, "a path record needs a feed and a load");
      }
      const Result<FeedId> feed = parse_feed_id(fields[1], source_name, line_number);
      if (!feed.ok()) return feed.status();
      const Result<LoadId> load = parse_load_id(fields[2], source_name, line_number);
      if (!load.ok()) return load.status();
      Result<FieldMap> map = FieldMap::parse(fields, 3, source_name, line_number);
      if (!map.ok()) return map.status();
      FeedLink link;
      link.feed = feed.value();
      link.load = load.value();
      const Result<std::string> role = map.value().take_text("role", true);
      if (!role.ok()) return role.status();
      const Result<RedundancyRole> parsed_role = parse_redundancy_role(role.value());
      if (!parsed_role.ok()) return fail(source_name, line_number, "a path role token is not defined");
      link.role = parsed_role.value();
      const Result<std::string> domain = map.value().take_text("domain", false);
      if (!domain.ok()) return domain.status();
      if (!domain.value().empty()) {
        const Result<FailureDomainId> parsed_domain = FailureDomainId::Parse(domain.value());
        if (!parsed_domain.ok()) return fail(source_name, line_number, "a path failure domain identity is not well-formed");
        link.failure_domain = parsed_domain.value();
      }
      const Status finished = map.value().finish();
      if (!finished.ok()) return finished;
      inputs.topology.links.push_back(std::move(link));
    } else if (type == "obs") {
      if (fields.size() < 2) {
        return fail(source_name, line_number, "an observation record needs a subject");
      }
      PendingObservation pending;
      pending.line = line_number;
      const std::string& subject = fields[1];
      std::size_t first_key = 2;
      if (subject == "feed") {
        if (fields.size() < 3) return fail(source_name, line_number, "an observation needs a feed");
        const Result<FeedId> feed = parse_feed_id(fields[2], source_name, line_number);
        if (!feed.ok()) return feed.status();
        pending.subject = PendingObservation::Subject::Feed;
        pending.feed = feed.value();
        first_key = 3;
      } else if (subject == "link") {
        if (fields.size() < 4) return fail(source_name, line_number, "an observation needs a feed and a load");
        const Result<FeedId> feed = parse_feed_id(fields[2], source_name, line_number);
        if (!feed.ok()) return feed.status();
        const Result<LoadId> load = parse_load_id(fields[3], source_name, line_number);
        if (!load.ok()) return load.status();
        pending.subject = PendingObservation::Subject::Link;
        pending.feed = feed.value();
        pending.load = load.value();
        first_key = 4;
      } else if (subject == "maintenance") {
        if (fields.size() < 3) return fail(source_name, line_number, "an observation needs a feed");
        const Result<FeedId> feed = parse_feed_id(fields[2], source_name, line_number);
        if (!feed.ok()) return feed.status();
        pending.subject = PendingObservation::Subject::Maintenance;
        pending.feed = feed.value();
        first_key = 3;
      } else if (subject == "state") {
        pending.subject = PendingObservation::Subject::State;
        first_key = 2;
      } else {
        return fail(source_name, line_number, "an observation subject must be feed, link, maintenance or state");
      }

      // A bare declaration token ("obs feed F1 unavailable source=S1") is accepted
      // as shorthand for decl=<token>.
      std::string shorthand_declaration;
      if (first_key < fields.size() && fields[first_key].find('=') == std::string::npos) {
        shorthand_declaration = fields[first_key];
        ++first_key;
      }
      Result<FieldMap> map = FieldMap::parse(fields, first_key, source_name, line_number);
      if (!map.ok()) return map.status();
      if (pending.subject == PendingObservation::Subject::Maintenance) {
        const Result<std::string> window = map.value().take_text("window", false);
        if (!window.ok()) return window.status();
        if (!window.value().empty()) {
          const Result<MaintenanceWindowId> parsed_window = MaintenanceWindowId::Parse(window.value());
          if (!parsed_window.ok()) return fail(source_name, line_number, "a maintenance window identity is not well-formed");
          pending.window = parsed_window.value();
        }
      }
      const Result<std::string> declaration = map.value().take_text("decl", false);
      if (!declaration.ok()) return declaration.status();
      std::string declaration_token = declaration.value();
      if (!shorthand_declaration.empty()) {
        if (!declaration_token.empty()) {
          return fail(source_name, line_number, "an observation declares its state twice");
        }
        declaration_token = shorthand_declaration;
      }
      if (declaration_token.empty()) {
        declaration_token = map.value().has("condition") || map.value().has("exposure") ||
                                    map.value().has("present")
                                ? "known"
                                : "unknown";
      }
      if (declaration_token == "known") {
        pending.known = true;
        std::string value_token;
        if (pending.subject == PendingObservation::Subject::Feed) {
          const Result<std::string> condition = map.value().take_text("condition", true);
          if (!condition.ok()) return condition.status();
          value_token = condition.value();
          const Result<FeedCondition> parsed = parse_feed_condition(value_token);
          if (!parsed.ok()) return fail(source_name, line_number, "a feed condition token is not defined");
        } else if (pending.subject == PendingObservation::Subject::Link) {
          const Result<bool> present = map.value().take_bool("present", true);
          if (!present.ok()) return present.status();
          value_token = present.value() ? "present" : "absent";
        } else if (pending.subject == PendingObservation::Subject::Maintenance) {
          const Result<std::string> exposure = map.value().take_text("exposure", true);
          if (!exposure.ok()) return exposure.status();
          value_token = exposure.value();
          const Result<MaintenanceExposure> parsed = parse_maintenance_exposure(value_token);
          if (!parsed.ok()) return fail(source_name, line_number, "a maintenance exposure token is not defined");
        } else {
          const Result<std::string> condition = map.value().take_text("condition", true);
          if (!condition.ok()) return condition.status();
          value_token = condition.value();
          const Result<OperatingCondition> parsed = parse_operating_condition(value_token);
          if (!parsed.ok()) return fail(source_name, line_number, "an operating condition token is not defined");
        }
        const Result<std::string> at = map.value().take_text("at", true);
        if (!at.ok()) return at.status();
        const Result<AuthorityTime> instant = parse_instant(at.value(), source_name, line_number);
        if (!instant.ok()) return instant.status();
        pending.at = instant.value();
        const Result<std::string> max_age = map.value().take_text("max_age", true);
        if (!max_age.ok()) return max_age.status();
        const Result<Duration> window = parse_duration(max_age.value(), source_name, line_number);
        if (!window.ok()) return window.status();
        pending.max_age = window.value();
        pending.value_token = value_token;
      } else {
        const Result<EvidenceDeclaration> parsed = parse_evidence_declaration(declaration_token);
        if (!parsed.ok()) {
          return fail(source_name, line_number, "an observation declaration must be known, unknown, unsupported or unavailable");
        }
        if (parsed.value() == EvidenceDeclaration::Known) {
          return fail(source_name, line_number, "a known observation must carry a value");
        }
        pending.known = false;
        pending.declaration = declaration_token;
      }
      const Result<std::string> source = map.value().take_text("source", true);
      if (!source.ok()) return source.status();
      const Result<EvidenceSourceId> parsed_source = EvidenceSourceId::Parse(source.value());
      if (!parsed_source.ok()) return fail(source_name, line_number, "an evidence source identity is not well-formed");
      pending.source = parsed_source.value();
      const Status finished = map.value().finish();
      if (!finished.ok()) return finished;
      if (observations.size() >= limits.max_links + limits.max_feeds + limits.max_maintenance_records) {
        return fail(source_name, line_number, "the scenario declares more observations than the bound allows");
      }
      observations.push_back(std::move(pending));
    } else if (type == "rule") {
      if (fields.size() < 2) {
        return fail(source_name, line_number, "a rule record needs an identity");
      }
      const Result<RuleId> id = RuleId::Parse(fields[1]);
      if (!id.ok()) return fail(source_name, line_number, "a rule identity is not well-formed");
      Result<FieldMap> map = FieldMap::parse(fields, 2, source_name, line_number);
      if (!map.ok()) return map.status();
      EligibilityRule rule;
      rule.id = id.value();
      const Result<std::string> effect = map.value().take_text("effect", true);
      if (!effect.ok()) return effect.status();
      const Result<RuleEffect> parsed_effect = parse_rule_effect(effect.value());
      if (!parsed_effect.ok()) return fail(source_name, line_number, "a rule effect token is not defined");
      rule.effect = parsed_effect.value();
      const Result<std::string> precedence = map.value().take_text("precedence", false);
      if (!precedence.ok()) return precedence.status();
      if (!precedence.value().empty()) {
        const Result<PrecedenceClass> parsed = parse_precedence_class(precedence.value());
        if (!parsed.ok()) return fail(source_name, line_number, "a precedence class token is not defined");
        rule.precedence = parsed.value();
      }
      const Result<std::string> rank = map.value().take_text("rank", false);
      if (!rank.ok()) return rank.status();
      if (!rank.value().empty()) {
        const Result<AuthorityRank> parsed = parse_authority_rank(rank.value());
        if (!parsed.ok()) return fail(source_name, line_number, "an authority rank token is not defined");
        rule.rank = parsed.value();
      }
      const Result<std::string> reason = map.value().take_text("reason", false);
      if (!reason.ok()) return reason.status();
      if (!reason.value().empty()) {
        const Result<ReasonCode> parsed = parse_reason_code(reason.value());
        if (!parsed.ok()) return fail(source_name, line_number, "a reason code token is not defined");
        rule.reason = parsed.value();
      } else {
        rule.reason = rule.effect == RuleEffect::Permit ? ReasonCode::RulePermitted : ReasonCode::RuleDenied;
      }
      const Result<std::string> path = map.value().take_text("path", false);
      if (!path.ok()) return path.status();
      if (!path.value().empty()) {
        const Result<AuthorityPathId> parsed = AuthorityPathId::Parse(path.value());
        if (!parsed.ok()) return fail(source_name, line_number, "an authority path identity is not well-formed");
        rule.authority_path = parsed.value();
      }
      const Result<std::string> feed = map.value().take_text("feed", false);
      if (!feed.ok()) return feed.status();
      if (!feed.value().empty()) {
        const Result<FeedId> parsed = FeedId::Parse(feed.value());
        if (!parsed.ok()) return fail(source_name, line_number, "a rule scope feed identity is not well-formed");
        rule.scope.feed = parsed.value();
      }
      const Result<std::string> load = map.value().take_text("load", false);
      if (!load.ok()) return load.status();
      if (!load.value().empty()) {
        const Result<LoadId> parsed = LoadId::Parse(load.value());
        if (!parsed.ok()) return fail(source_name, line_number, "a rule scope load identity is not well-formed");
        rule.scope.load = parsed.value();
      }
      const Result<std::string> source_class = map.value().take_text("source_class", false);
      if (!source_class.ok()) return source_class.status();
      if (!source_class.value().empty()) {
        const Result<SourceClass> parsed = parse_source_class(source_class.value());
        if (!parsed.ok()) return fail(source_name, line_number, "a rule scope source class token is not defined");
        rule.scope.source_class = parsed.value();
      }
      const Result<std::string> load_class = map.value().take_text("load_class", false);
      if (!load_class.ok()) return load_class.status();
      if (!load_class.value().empty()) {
        const Result<LoadClass> parsed = parse_load_class(load_class.value());
        if (!parsed.ok()) return fail(source_name, line_number, "a rule scope load class token is not defined");
        rule.scope.load_class = parsed.value();
      }
      const Result<std::string> role = map.value().take_text("role", false);
      if (!role.ok()) return role.status();
      if (!role.value().empty()) {
        const Result<RedundancyRole> parsed = parse_redundancy_role(role.value());
        if (!parsed.ok()) return fail(source_name, line_number, "a rule scope role token is not defined");
        rule.scope.role = parsed.value();
      }
      const Result<std::string> domains = map.value().take_text("domains", false);
      if (!domains.ok()) return domains.status();
      if (!domains.value().empty()) {
        const Result<std::vector<std::string>> items =
            split_list(domains.value(), limits.max_scope_failure_domains);
        if (!items.ok()) return fail(source_name, line_number, items.status().message());
        for (const std::string& item : items.value()) {
          const Result<FailureDomainId> parsed = FailureDomainId::Parse(item);
          if (!parsed.ok()) return fail(source_name, line_number, "a rule failure domain identity is not well-formed");
          rule.scope.failure_domains.push_back(parsed.value());
        }
      }
      const Result<std::string> conditions = map.value().take_text("conditions", false);
      if (!conditions.ok()) return conditions.status();
      if (!conditions.value().empty()) {
        const Result<std::vector<std::string>> items =
            split_list(conditions.value(), limits.max_conditions_per_rule);
        if (!items.ok()) return fail(source_name, line_number, items.status().message());
        for (const std::string& item : items.value()) {
          const Result<OperatingCondition> parsed = parse_operating_condition(item);
          if (!parsed.ok()) return fail(source_name, line_number, "a rule condition token is not defined");
          rule.conditions.push_back(parsed.value());
        }
      }
      const Result<std::string> exposures = map.value().take_text("exposures", false);
      if (!exposures.ok()) return exposures.status();
      if (!exposures.value().empty()) {
        const Result<std::vector<std::string>> items = split_list(exposures.value(), 4u);
        if (!items.ok()) return fail(source_name, line_number, items.status().message());
        for (const std::string& item : items.value()) {
          const Result<MaintenanceExposure> parsed = parse_maintenance_exposure(item);
          if (!parsed.ok()) return fail(source_name, line_number, "a rule exposure token is not defined");
          rule.maintenance_exposures.push_back(parsed.value());
        }
      }
      const Result<bool> fresh = map.value().take_bool("fresh", true);
      if (!fresh.ok()) return fresh.status();
      rule.requires_fresh_evidence = fresh.value();
      const Result<bool> overridable = map.value().take_bool("overridable", false);
      if (!overridable.ok()) return overridable.status();
      rule.emergency_overridable = overridable.value();
      const Result<std::string> note = map.value().take_text("note", false);
      if (!note.ok()) return note.status();
      rule.note = note.value();
      const Status finished = map.value().finish();
      if (!finished.ok()) return finished;
      inputs.policy.rules.push_back(std::move(rule));
    } else if (type == "obligation") {
      if (fields.size() < 2) {
        return fail(source_name, line_number, "an obligation record needs an identity");
      }
      const Result<ObligationId> id = ObligationId::Parse(fields[1]);
      if (!id.ok()) return fail(source_name, line_number, "an obligation identity is not well-formed");
      Result<FieldMap> map = FieldMap::parse(fields, 2, source_name, line_number);
      if (!map.ok()) return map.status();
      ProtectedObligation obligation;
      obligation.id = id.value();
      const Result<std::string> load_class = map.value().take_text("class", false);
      if (!load_class.ok()) return load_class.status();
      if (!load_class.value().empty()) {
        const Result<LoadClass> parsed = parse_load_class(load_class.value());
        if (!parsed.ok()) return fail(source_name, line_number, "an obligation load class token is not defined");
        obligation.load_class = parsed.value();
      }
      const Result<bool> protected_loads = map.value().take_bool("protected_loads", false);
      if (!protected_loads.ok()) return protected_loads.status();
      obligation.applies_to_protected_loads = protected_loads.value();
      const Result<bool> capability = map.value().take_bool("capability", true);
      if (!capability.ok()) return capability.status();
      obligation.requires_feed_protected_capability = capability.value();
      const Result<std::uint64_t> domains = map.value().take_uint("min_domains", false);
      if (!domains.ok()) return domains.status();
      obligation.min_distinct_failure_domains = static_cast<std::uint32_t>(domains.value());
      const Result<bool> overridable = map.value().take_bool("overridable", false);
      if (!overridable.ok()) return overridable.status();
      obligation.emergency_overridable = overridable.value();
      const Result<std::string> reason = map.value().take_text("reason", false);
      if (!reason.ok()) return reason.status();
      if (!reason.value().empty()) {
        const Result<ReasonCode> parsed = parse_reason_code(reason.value());
        if (!parsed.ok()) return fail(source_name, line_number, "an obligation reason code token is not defined");
        obligation.reason = parsed.value();
      }
      const Result<std::string> note = map.value().take_text("note", false);
      if (!note.ok()) return note.status();
      obligation.note = note.value();
      const Result<std::string> loads = map.value().take_text("loads", false);
      if (!loads.ok()) return loads.status();
      if (!loads.value().empty()) {
        const Result<std::vector<std::string>> items = split_list(loads.value(), limits.max_loads);
        if (!items.ok()) return fail(source_name, line_number, items.status().message());
        for (const std::string& item : items.value()) {
          const Result<LoadId> parsed = LoadId::Parse(item);
          if (!parsed.ok()) return fail(source_name, line_number, "an obligation load identity is not well-formed");
          obligation.loads.push_back(parsed.value());
        }
      }
      const Result<std::string> roles = map.value().take_text("roles", false);
      if (!roles.ok()) return roles.status();
      if (!roles.value().empty()) {
        const Result<std::vector<std::string>> items = split_list(roles.value(), 4u);
        if (!items.ok()) return fail(source_name, line_number, items.status().message());
        for (const std::string& item : items.value()) {
          const Result<RedundancyRole> parsed = parse_redundancy_role(item);
          if (!parsed.ok()) return fail(source_name, line_number, "an obligation role token is not defined");
          obligation.permitted_roles.push_back(parsed.value());
        }
      }
      const Result<std::string> sources = map.value().take_text("source_classes", false);
      if (!sources.ok()) return sources.status();
      if (!sources.value().empty()) {
        const Result<std::vector<std::string>> items = split_list(sources.value(), 8u);
        if (!items.ok()) return fail(source_name, line_number, items.status().message());
        for (const std::string& item : items.value()) {
          const Result<SourceClass> parsed = parse_source_class(item);
          if (!parsed.ok()) return fail(source_name, line_number, "an obligation source class token is not defined");
          obligation.permitted_source_classes.push_back(parsed.value());
        }
      }
      const Status finished = map.value().finish();
      if (!finished.ok()) return finished;
      inputs.policy.obligations.push_back(std::move(obligation));
    } else {
      return fail(source_name, line_number, "unrecognized record type '" + type + "'");
    }

    if (end >= text.size()) {
      break;
    }
  }

  if (!saw_revisions) {
    return fail(source_name, 0, "the scenario does not declare the four revisions");
  }
  if (!saw_option) {
    inputs.policy.options.ranking.enabled = false;
    inputs.policy.options.emergency_override_enabled = false;
  }

  // Attach the observations to their subjects.
  for (const PendingObservation& pending : observations) {
    switch (pending.subject) {
      case PendingObservation::Subject::Feed: {
        FeedDescriptor* target = nullptr;
        for (FeedDescriptor& feed : inputs.topology.feeds) {
          if (feed.id == pending.feed) {
            target = &feed;
            break;
          }
        }
        if (target == nullptr) {
          return fail(source_name, pending.line, "an observation names a feed the scenario does not declare");
        }
        const auto parser = [](const std::string& token) { return parse_feed_condition(token); };
        const Result<Observation<FeedCondition>> record =
            build_pending_observation<FeedCondition>(pending, parser, source_name);
        if (!record.ok()) return record.status();
        target->condition.push_back(record.value());
        break;
      }
      case PendingObservation::Subject::Link: {
        FeedLink* target = nullptr;
        for (FeedLink& link : inputs.topology.links) {
          if (link.feed == pending.feed && link.load == pending.load) {
            target = &link;
            break;
          }
        }
        if (target == nullptr) {
          return fail(source_name, pending.line, "an observation names a path the scenario does not declare");
        }
        const auto parser = [](const std::string& token) -> Result<bool> {
          if (token == "present") return true;
          if (token == "absent") return false;
          if (token.empty()) return false;
          return Status::error(StatusCode::InvalidArgument, "a path observation token is not defined");
        };
        const Result<Observation<bool>> record =
            build_pending_observation<bool>(pending, parser, source_name);
        if (!record.ok()) return record.status();
        target->observed.push_back(record.value());
        break;
      }
      case PendingObservation::Subject::Maintenance: {
        MaintenanceRecord* target = nullptr;
        for (MaintenanceRecord& record : inputs.control.maintenance) {
          if (record.feed == pending.feed && record.window == pending.window) {
            target = &record;
            break;
          }
        }
        if (target == nullptr) {
          MaintenanceRecord record;
          record.feed = pending.feed;
          record.window = pending.window;
          inputs.control.maintenance.push_back(std::move(record));
          target = &inputs.control.maintenance.back();
        }
        const auto parser = [](const std::string& token) { return parse_maintenance_exposure(token); };
        const Result<Observation<MaintenanceExposure>> record =
            build_pending_observation<MaintenanceExposure>(pending, parser, source_name);
        if (!record.ok()) return record.status();
        target->exposure.push_back(record.value());
        break;
      }
      case PendingObservation::Subject::State: {
        const auto parser = [](const std::string& token) { return parse_operating_condition(token); };
        const Result<Observation<OperatingCondition>> record =
            build_pending_observation<OperatingCondition>(pending, parser, source_name);
        if (!record.ok()) return record.status();
        inputs.control.condition.push_back(record.value());
        break;
      }
    }
  }

  AuthorityInputs::canonicalize(inputs);
  const Status valid = inputs.validate(limits);
  if (!valid.ok()) {
    return Status::error(valid.code(), std::string(source_name) + ": " + valid.message());
  }
  return inputs;
}

Result<AuthorityInputs> load_scenario_file(const std::filesystem::path& path, const Limits& limits) {
  const Result<std::string> bytes = detail::read_file_bounded(path, kMaxScenarioBytes);
  if (!bytes.ok()) {
    return bytes.status();
  }
  return parse_scenario(bytes.value(), limits, path.filename().string());
}

}  // namespace feed_authority
