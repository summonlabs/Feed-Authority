#include "detail/serialization.hpp"

#include <algorithm>
#include <cstdint>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "detail/codec.hpp"
#include "feed_authority/obligation.hpp"

namespace feed_authority::detail {
namespace {

constexpr std::string_view kUnsetToken = "none";

Result<AuthorityTime> instant_from_nanos(std::uint64_t nanos) {
  if (nanos > static_cast<std::uint64_t>(INT64_MAX)) {
    return Status::error(StatusCode::Corruption, "an instant does not fit in a signed 64-bit value");
  }
  return AuthorityTime::FromUnixNanos(static_cast<std::int64_t>(nanos));
}

Result<Duration> duration_from_nanos(std::uint64_t nanos) {
  if (nanos > static_cast<std::uint64_t>(INT64_MAX)) {
    return Status::error(StatusCode::Corruption, "a duration does not fit in a signed 64-bit value");
  }
  return Duration::FromNanos(static_cast<std::int64_t>(nanos));
}

std::uint64_t nanos_of(AuthorityTime instant) {
  return static_cast<std::uint64_t>(instant.unix_nanos());
}

std::uint64_t nanos_of(Duration duration) {
  return static_cast<std::uint64_t>(duration.nanos());
}

template <class SubjectWriter>
void write_observation(std::string& out, std::string_view type, SubjectWriter subject_writer,
                       std::string_view value_token, EvidenceDeclaration declaration,
                       AuthorityTime observed_at, Duration max_age, const EvidenceSourceId& source) {
  RecordWriter writer(out, type);
  subject_writer(writer);
  writer.token("decl", to_string(declaration));
  writer.token("value", declaration == EvidenceDeclaration::Known ? value_token : "unknown");
  writer.num("at", nanos_of(observed_at));
  writer.num("max_age", nanos_of(max_age));
  writer.text("src", source.value());
  writer.end();
}

struct RawObservation {
  EvidenceDeclaration declaration = EvidenceDeclaration::Unknown;
  std::string value_token;
  AuthorityTime observed_at{};
  Duration max_age{};
  EvidenceSourceId source;
};

Result<RawObservation> read_observation_tail(RecordReader& reader) {
  RawObservation raw;
  const Result<std::string> declaration = reader.expect_token("decl");
  if (!declaration.ok()) return declaration.status();
  const Result<EvidenceDeclaration> parsed_declaration = parse_evidence_declaration(declaration.value());
  if (!parsed_declaration.ok()) {
    return Status::error(StatusCode::Corruption, "an observation declaration token is not defined");
  }
  raw.declaration = parsed_declaration.value();

  const Result<std::string> value = reader.expect_token("value");
  if (!value.ok()) return value.status();
  raw.value_token = value.value();

  const Result<std::uint64_t> at = reader.expect_num("at");
  if (!at.ok()) return at.status();
  const Result<AuthorityTime> instant = instant_from_nanos(at.value());
  if (!instant.ok()) return instant.status();
  raw.observed_at = instant.value();

  const Result<std::uint64_t> max_age = reader.expect_num("max_age");
  if (!max_age.ok()) return max_age.status();
  const Result<Duration> window = duration_from_nanos(max_age.value());
  if (!window.ok()) return window.status();
  raw.max_age = window.value();

  const Result<std::string> source = reader.expect_text("src");
  if (!source.ok()) return source.status();
  if (source.value().empty()) {
    return Status::error(StatusCode::Corruption, "an observation has no evidence source");
  }
  const Result<EvidenceSourceId> parsed_source = EvidenceSourceId::Parse(source.value());
  if (!parsed_source.ok()) {
    return Status::error(StatusCode::Corruption, "an observation source is not a well-formed identity");
  }
  raw.source = parsed_source.value();

  if (raw.declaration != EvidenceDeclaration::Known) {
    if (raw.value_token != "unknown" || !raw.observed_at.is_zero() || !raw.max_age.is_zero()) {
      return Status::error(StatusCode::Corruption,
                           "an observation that is not known must carry no value, instant or window");
    }
    return raw;
  }
  if (raw.value_token == "unknown") {
    return Status::error(StatusCode::Corruption, "a known observation must carry a value token");
  }
  if (raw.max_age.is_zero()) {
    return Status::error(StatusCode::Corruption, "a known observation must carry a non-zero window");
  }
  return raw;
}

template <class Value, class ParseValue>
Result<Observation<Value>> build_observation(const RawObservation& raw, ParseValue parse_value) {
  switch (raw.declaration) {
    case EvidenceDeclaration::Unknown:
      return Observation<Value>::Unknown(raw.source);
    case EvidenceDeclaration::Unsupported:
      return Observation<Value>::Unsupported(raw.source);
    case EvidenceDeclaration::Unavailable:
      return Observation<Value>::Unavailable(raw.source);
    case EvidenceDeclaration::Known:
      break;
  }
  const Result<Value> value = parse_value(raw.value_token);
  if (!value.ok()) {
    return Status::error(StatusCode::Corruption, "an observation value token is not defined");
  }
  const Result<Observation<Value>> known =
      Observation<Value>::Known(value.value(), raw.observed_at, raw.max_age, raw.source);
  if (!known.ok()) {
    return known.status();
  }
  return known.value();
}

Result<std::string> expect_matching_text(RecordReader& reader, std::string_view key,
                                         std::string_view expected) {
  const Result<std::string> value = reader.expect_text(key);
  if (!value.ok()) {
    return value.status();
  }
  if (value.value() != expected) {
    return Status::error(StatusCode::Corruption, "a record does not belong to the preceding subject");
  }
  return value.value();
}

}  // namespace

void encode_topology_records(std::string& out, const TopologyView& topology, const Limits& limits) {
  for (const FeedDescriptor& feed : topology.feeds) {
    RecordWriter writer(out, "feed");
    writer.text("id", feed.id.value());
    writer.token("source", to_string(feed.source_class));
    writer.token("role", to_string(feed.role));
    writer.text("domain", feed.failure_domain.value());
    writer.boolean("protected", feed.may_serve_protected_loads);
    writer.num("obs_n", feed.condition.size());
    writer.end();
    for (const Observation<FeedCondition>& observation : feed.condition) {
      write_observation(
          out, "obs_feed",
          [&feed](RecordWriter& target) { target.text("feed", feed.id.value()); },
          to_string(observation.value()), observation.declaration(), observation.observed_at(),
          observation.max_age(), observation.source());
    }
  }
  for (const LoadDescriptor& load : topology.loads) {
    RecordWriter writer(out, "load");
    writer.text("id", load.id.value());
    writer.token("class", to_string(load.load_class));
    writer.boolean("protected", load.protected_load);
    writer.end();
  }
  for (const FeedLink& link : topology.links) {
    RecordWriter writer(out, "link");
    writer.text("feed", link.feed.value());
    writer.text("load", link.load.value());
    writer.token("role", to_string(link.role));
    writer.text("domain", link.failure_domain.value());
    writer.num("obs_n", link.observed.size());
    writer.end();
    for (const Observation<bool>& observation : link.observed) {
      write_observation(
          out, "obs_link",
          [&link](RecordWriter& target) {
            target.text("load", link.load.value());
            target.text("feed", link.feed.value());
          },
          observation.value() ? "present" : "absent", observation.declaration(),
          observation.observed_at(), observation.max_age(), observation.source());
    }
  }
  (void)limits;
}

void encode_control_records(std::string& out, const ControlState& control, const Limits& limits) {
  for (const MaintenanceRecord& record : control.maintenance) {
    RecordWriter writer(out, "maint");
    writer.text("feed", record.feed.value());
    writer.text("window", record.window.value());
    writer.num("obs_n", record.exposure.size());
    writer.end();
    for (const Observation<MaintenanceExposure>& observation : record.exposure) {
      write_observation(
          out, "obs_maint",
          [&record](RecordWriter& target) {
            target.text("feed", record.feed.value());
            target.text("window", record.window.value());
          },
          to_string(observation.value()), observation.declaration(), observation.observed_at(),
          observation.max_age(), observation.source());
    }
  }
  for (const Observation<OperatingCondition>& observation : control.condition) {
    write_observation(out, "obs_state", [](RecordWriter&) {}, to_string(observation.value()),
                      observation.declaration(), observation.observed_at(), observation.max_age(),
                      observation.source());
  }
  (void)limits;
}

void encode_policy_records(std::string& out, const PolicySet& policy, const Limits& limits) {
  for (const EligibilityRule& rule : policy.rules) {
    RecordWriter writer(out, "rule");
    writer.text("id", rule.id.value());
    writer.token("prec", to_string(rule.precedence));
    writer.token("rank", to_string(rule.rank));
    writer.token("effect", to_string(rule.effect));
    writer.text("path", rule.authority_path.value());
    writer.token("reason", to_string(rule.reason));
    writer.boolean("fresh", rule.requires_fresh_evidence);
    writer.boolean("overridable", rule.emergency_overridable);
    writer.text("note", rule.note);
    writer.text("feed", rule.scope.feed ? rule.scope.feed->value() : std::string());
    writer.text("load", rule.scope.load ? rule.scope.load->value() : std::string());
    writer.token("source", rule.scope.source_class ? to_string(*rule.scope.source_class) : kUnsetToken);
    writer.token("class", rule.scope.load_class ? to_string(*rule.scope.load_class) : kUnsetToken);
    writer.token("role", rule.scope.role ? to_string(*rule.scope.role) : kUnsetToken);
    writer.num("cond_n", rule.conditions.size());
    writer.num("expo_n", rule.maintenance_exposures.size());
    writer.num("dom_n", rule.scope.failure_domains.size());
    writer.end();
    for (const OperatingCondition condition : rule.conditions) {
      RecordWriter item(out, "rule_cond");
      item.text("id", rule.id.value());
      item.token("value", to_string(condition));
      item.end();
    }
    for (const MaintenanceExposure exposure : rule.maintenance_exposures) {
      RecordWriter item(out, "rule_expo");
      item.text("id", rule.id.value());
      item.token("value", to_string(exposure));
      item.end();
    }
    for (const FailureDomainId& domain : rule.scope.failure_domains) {
      RecordWriter item(out, "rule_dom");
      item.text("id", rule.id.value());
      item.text("value", domain.value());
      item.end();
    }
  }
  for (const ProtectedObligation& obligation : policy.obligations) {
    RecordWriter writer(out, "obligation");
    writer.text("id", obligation.id.value());
    writer.token("class", obligation.load_class ? to_string(*obligation.load_class) : kUnsetToken);
    writer.boolean("protected_loads", obligation.applies_to_protected_loads);
    writer.boolean("capability", obligation.requires_feed_protected_capability);
    writer.num("domains", obligation.min_distinct_failure_domains);
    writer.boolean("overridable", obligation.emergency_overridable);
    writer.token("reason", to_string(obligation.reason));
    writer.text("note", obligation.note);
    writer.num("loads_n", obligation.loads.size());
    writer.num("roles_n", obligation.permitted_roles.size());
    writer.num("sources_n", obligation.permitted_source_classes.size());
    writer.end();
    for (const LoadId& load : obligation.loads) {
      RecordWriter item(out, "obligation_load");
      item.text("id", obligation.id.value());
      item.text("value", load.value());
      item.end();
    }
    for (const RedundancyRole role : obligation.permitted_roles) {
      RecordWriter item(out, "obligation_role");
      item.text("id", obligation.id.value());
      item.token("value", to_string(role));
      item.end();
    }
    for (const SourceClass source : obligation.permitted_source_classes) {
      RecordWriter item(out, "obligation_source");
      item.text("id", obligation.id.value());
      item.token("value", to_string(source));
      item.end();
    }
  }
  RecordWriter options(out, "option");
  options.boolean("ranking", policy.options.ranking.enabled);
  options.boolean("emergency", policy.options.emergency_override_enabled);
  options.end();
  std::uint64_t ordinal = 0;
  for (const RedundancyRole role : policy.options.ranking.role_order) {
    RecordWriter item(out, "rank_role");
    item.num("ordinal", ordinal);
    item.token("value", to_string(role));
    item.end();
    ++ordinal;
  }
  (void)limits;
}

void encode_input_records(std::string& out, const AuthorityInputs& inputs, const Limits& limits) {
  RecordWriter generation(out, "generation");
  generation.num("topology", inputs.topology.revision.value());
  generation.num("policy", inputs.policy.revision.value());
  generation.num("control", inputs.control.revision.value());
  generation.num("evidence", inputs.evidence.value());
  generation.end();
  encode_topology_records(out, inputs.topology, limits);
  encode_control_records(out, inputs.control, limits);
  encode_policy_records(out, inputs.policy, limits);
}

Status decode_input_records(RecordReader& reader, const Limits& limits, std::string_view boundary,
                            AuthorityInputs& inputs) {
  bool saw_generation = false;
  bool saw_option = false;
  std::uint64_t expected_rank_ordinal = 0;

  while (true) {
    const Status status = reader.next();
    if (!status.ok()) {
      return status;
    }
    if (reader.at_end()) {
      return Status::error(StatusCode::Corruption, "the payload ended before the section boundary");
    }
    const std::string_view type = reader.type();
    if (type == boundary) {
      if (!saw_generation) {
        return Status::error(StatusCode::Corruption, "an input section has no generation record");
      }
      if (!saw_option) {
        return Status::error(StatusCode::Corruption, "an input section has no option record");
      }
      return Status::success();
    }

    if (type == "generation") {
      if (saw_generation) {
        return Status::error(StatusCode::Corruption, "an input section has more than one generation record");
      }
      const Result<std::uint64_t> topology = reader.expect_num("topology");
      if (!topology.ok()) return topology.status();
      const Result<std::uint64_t> policy = reader.expect_num("policy");
      if (!policy.ok()) return policy.status();
      const Result<std::uint64_t> control = reader.expect_num("control");
      if (!control.ok()) return control.status();
      const Result<std::uint64_t> evidence = reader.expect_num("evidence");
      if (!evidence.ok()) return evidence.status();
      const Status record = reader.expect_type_and_end("generation");
      if (!record.ok()) return record;
      inputs.topology.revision = TopologyRevision::FromValue(topology.value());
      inputs.policy.revision = PolicyRevision::FromValue(policy.value());
      inputs.control.revision = ControlRevision::FromValue(control.value());
      inputs.evidence = EvidenceRevision::FromValue(evidence.value());
      saw_generation = true;
      continue;
    }

    if (type == "feed") {
      if (inputs.topology.feeds.size() >= limits.max_feeds) {
        return Status::error(StatusCode::LimitExceeded, "the payload declares too many feeds");
      }
      FeedDescriptor feed;
      const Result<std::string> id = reader.expect_text("id");
      if (!id.ok()) return id.status();
      const Result<FeedId> parsed_id = FeedId::Parse(id.value());
      if (!parsed_id.ok()) {
        return Status::error(StatusCode::Corruption, "a feed identity is not well-formed");
      }
      feed.id = parsed_id.value();
      const Result<std::string> source = reader.expect_token("source");
      if (!source.ok()) return source.status();
      const Result<SourceClass> parsed_source = parse_source_class(source.value());
      if (!parsed_source.ok()) {
        return Status::error(StatusCode::Corruption, "a source class token is not defined");
      }
      feed.source_class = parsed_source.value();
      const Result<std::string> role = reader.expect_token("role");
      if (!role.ok()) return role.status();
      const Result<RedundancyRole> parsed_role = parse_redundancy_role(role.value());
      if (!parsed_role.ok()) {
        return Status::error(StatusCode::Corruption, "a redundancy role token is not defined");
      }
      feed.role = parsed_role.value();
      const Result<std::string> domain = reader.expect_text("domain");
      if (!domain.ok()) return domain.status();
      if (!domain.value().empty()) {
        const Result<FailureDomainId> parsed_domain = FailureDomainId::Parse(domain.value());
        if (!parsed_domain.ok()) {
          return Status::error(StatusCode::Corruption, "a failure domain identity is not well-formed");
        }
        feed.failure_domain = parsed_domain.value();
      }
      const Result<bool> capability = reader.expect_boolean("protected");
      if (!capability.ok()) return capability.status();
      feed.may_serve_protected_loads = capability.value();
      const Result<std::uint64_t> observations = reader.expect_num("obs_n");
      if (!observations.ok()) return observations.status();
      const Status record = reader.expect_type_and_end("feed");
      if (!record.ok()) return record;
      if (observations.value() > kMaxObservationsPerSubject) {
        return Status::error(StatusCode::Corruption, "a feed declares too many observations");
      }
      for (std::uint64_t index = 0; index < observations.value(); ++index) {
        const Status next = reader.next();
        if (!next.ok()) return next;
        const Result<std::string> subject = expect_matching_text(reader, "feed", feed.id.value());
        if (!subject.ok()) return subject.status();
        const Result<RawObservation> raw = read_observation_tail(reader);
        if (!raw.ok()) return raw.status();
        const Status end = reader.expect_type_and_end("obs_feed");
        if (!end.ok()) return end;
        const Result<Observation<FeedCondition>> observation =
            build_observation<FeedCondition>(raw.value(), [](const std::string& token) {
              return parse_feed_condition(token);
            });
        if (!observation.ok()) return observation.status();
        feed.condition.push_back(observation.value());
      }
      inputs.topology.feeds.push_back(std::move(feed));
      continue;
    }

    if (type == "load") {
      if (inputs.topology.loads.size() >= limits.max_loads) {
        return Status::error(StatusCode::LimitExceeded, "the payload declares too many loads");
      }
      LoadDescriptor load;
      const Result<std::string> id = reader.expect_text("id");
      if (!id.ok()) return id.status();
      const Result<LoadId> parsed_id = LoadId::Parse(id.value());
      if (!parsed_id.ok()) {
        return Status::error(StatusCode::Corruption, "a load identity is not well-formed");
      }
      load.id = parsed_id.value();
      const Result<std::string> load_class = reader.expect_token("class");
      if (!load_class.ok()) return load_class.status();
      const Result<LoadClass> parsed_class = parse_load_class(load_class.value());
      if (!parsed_class.ok()) {
        return Status::error(StatusCode::Corruption, "a load class token is not defined");
      }
      load.load_class = parsed_class.value();
      const Result<bool> is_protected = reader.expect_boolean("protected");
      if (!is_protected.ok()) return is_protected.status();
      load.protected_load = is_protected.value();
      const Status record = reader.expect_type_and_end("load");
      if (!record.ok()) return record;
      inputs.topology.loads.push_back(std::move(load));
      continue;
    }

    if (type == "link") {
      if (inputs.topology.links.size() >= limits.max_links) {
        return Status::error(StatusCode::LimitExceeded, "the payload declares too many paths");
      }
      FeedLink link;
      const Result<std::string> feed = reader.expect_text("feed");
      if (!feed.ok()) return feed.status();
      const Result<FeedId> parsed_feed = FeedId::Parse(feed.value());
      if (!parsed_feed.ok()) {
        return Status::error(StatusCode::Corruption, "a path feed identity is not well-formed");
      }
      link.feed = parsed_feed.value();
      const Result<std::string> load = reader.expect_text("load");
      if (!load.ok()) return load.status();
      const Result<LoadId> parsed_load = LoadId::Parse(load.value());
      if (!parsed_load.ok()) {
        return Status::error(StatusCode::Corruption, "a path load identity is not well-formed");
      }
      link.load = parsed_load.value();
      const Result<std::string> role = reader.expect_token("role");
      if (!role.ok()) return role.status();
      const Result<RedundancyRole> parsed_role = parse_redundancy_role(role.value());
      if (!parsed_role.ok()) {
        return Status::error(StatusCode::Corruption, "a path redundancy role token is not defined");
      }
      link.role = parsed_role.value();
      const Result<std::string> domain = reader.expect_text("domain");
      if (!domain.ok()) return domain.status();
      if (!domain.value().empty()) {
        const Result<FailureDomainId> parsed_domain = FailureDomainId::Parse(domain.value());
        if (!parsed_domain.ok()) {
          return Status::error(StatusCode::Corruption, "a path failure domain identity is not well-formed");
        }
        link.failure_domain = parsed_domain.value();
      }
      const Result<std::uint64_t> observations = reader.expect_num("obs_n");
      if (!observations.ok()) return observations.status();
      const Status record = reader.expect_type_and_end("link");
      if (!record.ok()) return record;
      if (observations.value() > kMaxObservationsPerSubject) {
        return Status::error(StatusCode::Corruption, "a path declares too many observations");
      }
      for (std::uint64_t index = 0; index < observations.value(); ++index) {
        const Status next = reader.next();
        if (!next.ok()) return next;
        const Result<std::string> subject_load = expect_matching_text(reader, "load", link.load.value());
        if (!subject_load.ok()) return subject_load.status();
        const Result<std::string> subject_feed = expect_matching_text(reader, "feed", link.feed.value());
        if (!subject_feed.ok()) return subject_feed.status();
        const Result<RawObservation> raw = read_observation_tail(reader);
        if (!raw.ok()) return raw.status();
        const Status end = reader.expect_type_and_end("obs_link");
        if (!end.ok()) return end;
        const Result<Observation<bool>> observation =
            build_observation<bool>(raw.value(), [](const std::string& token) -> Result<bool> {
              if (token == "present") return true;
              if (token == "absent") return false;
              return Status::error(StatusCode::Corruption, "a path observation value token is not defined");
            });
        if (!observation.ok()) return observation.status();
        link.observed.push_back(observation.value());
      }
      inputs.topology.links.push_back(std::move(link));
      continue;
    }

    if (type == "maint") {
      if (inputs.control.maintenance.size() >= limits.max_maintenance_records) {
        return Status::error(StatusCode::LimitExceeded, "the payload declares too many maintenance records");
      }
      MaintenanceRecord record_value;
      const Result<std::string> feed = reader.expect_text("feed");
      if (!feed.ok()) return feed.status();
      const Result<FeedId> parsed_feed = FeedId::Parse(feed.value());
      if (!parsed_feed.ok()) {
        return Status::error(StatusCode::Corruption, "a maintenance feed identity is not well-formed");
      }
      record_value.feed = parsed_feed.value();
      const Result<std::string> window = reader.expect_text("window");
      if (!window.ok()) return window.status();
      if (!window.value().empty()) {
        const Result<MaintenanceWindowId> parsed_window = MaintenanceWindowId::Parse(window.value());
        if (!parsed_window.ok()) {
          return Status::error(StatusCode::Corruption, "a maintenance window identity is not well-formed");
        }
        record_value.window = parsed_window.value();
      }
      const Result<std::uint64_t> observations = reader.expect_num("obs_n");
      if (!observations.ok()) return observations.status();
      const Status record = reader.expect_type_and_end("maint");
      if (!record.ok()) return record;
      if (observations.value() > kMaxObservationsPerSubject) {
        return Status::error(StatusCode::Corruption, "a maintenance record declares too many observations");
      }
      for (std::uint64_t index = 0; index < observations.value(); ++index) {
        const Status next = reader.next();
        if (!next.ok()) return next;
        const Result<std::string> subject_feed = expect_matching_text(reader, "feed", record_value.feed.value());
        if (!subject_feed.ok()) return subject_feed.status();
        const Result<std::string> subject_window =
            expect_matching_text(reader, "window", record_value.window.value());
        if (!subject_window.ok()) return subject_window.status();
        const Result<RawObservation> raw = read_observation_tail(reader);
        if (!raw.ok()) return raw.status();
        const Status end = reader.expect_type_and_end("obs_maint");
        if (!end.ok()) return end;
        const Result<Observation<MaintenanceExposure>> observation =
            build_observation<MaintenanceExposure>(raw.value(), [](const std::string& token) {
              return parse_maintenance_exposure(token);
            });
        if (!observation.ok()) return observation.status();
        record_value.exposure.push_back(observation.value());
      }
      inputs.control.maintenance.push_back(std::move(record_value));
      continue;
    }

    if (type == "obs_state") {
      const Result<RawObservation> raw = read_observation_tail(reader);
      if (!raw.ok()) return raw.status();
      const Status end = reader.expect_type_and_end("obs_state");
      if (!end.ok()) return end;
      const Result<Observation<OperatingCondition>> observation =
          build_observation<OperatingCondition>(raw.value(), [](const std::string& token) {
            return parse_operating_condition(token);
          });
      if (!observation.ok()) return observation.status();
      inputs.control.condition.push_back(observation.value());
      continue;
    }

    if (type == "rule") {
      if (inputs.policy.rules.size() >= limits.max_rules) {
        return Status::error(StatusCode::LimitExceeded, "the payload declares too many rules");
      }
      EligibilityRule rule;
      const Result<std::string> id = reader.expect_text("id");
      if (!id.ok()) return id.status();
      const Result<RuleId> parsed_id = RuleId::Parse(id.value());
      if (!parsed_id.ok()) return Status::error(StatusCode::Corruption, "a rule identity is not well-formed");
      rule.id = parsed_id.value();
      const Result<std::string> precedence = reader.expect_token("prec");
      if (!precedence.ok()) return precedence.status();
      const Result<PrecedenceClass> parsed_precedence = parse_precedence_class(precedence.value());
      if (!parsed_precedence.ok()) return Status::error(StatusCode::Corruption, "a precedence class token is not defined");
      rule.precedence = parsed_precedence.value();
      const Result<std::string> rank = reader.expect_token("rank");
      if (!rank.ok()) return rank.status();
      const Result<AuthorityRank> parsed_rank = parse_authority_rank(rank.value());
      if (!parsed_rank.ok()) return Status::error(StatusCode::Corruption, "an authority rank token is not defined");
      rule.rank = parsed_rank.value();
      const Result<std::string> effect = reader.expect_token("effect");
      if (!effect.ok()) return effect.status();
      const Result<RuleEffect> parsed_effect = parse_rule_effect(effect.value());
      if (!parsed_effect.ok()) return Status::error(StatusCode::Corruption, "a rule effect token is not defined");
      rule.effect = parsed_effect.value();
      const Result<std::string> path = reader.expect_text("path");
      if (!path.ok()) return path.status();
      if (!path.value().empty()) {
        const Result<AuthorityPathId> parsed_path = AuthorityPathId::Parse(path.value());
        if (!parsed_path.ok()) return Status::error(StatusCode::Corruption, "an authority path identity is not well-formed");
        rule.authority_path = parsed_path.value();
      }
      const Result<std::string> reason = reader.expect_token("reason");
      if (!reason.ok()) return reason.status();
      const Result<ReasonCode> parsed_reason = parse_reason_code(reason.value());
      if (!parsed_reason.ok()) return Status::error(StatusCode::Corruption, "a reason code token is not defined");
      rule.reason = parsed_reason.value();
      const Result<bool> fresh = reader.expect_boolean("fresh");
      if (!fresh.ok()) return fresh.status();
      rule.requires_fresh_evidence = fresh.value();
      const Result<bool> overridable = reader.expect_boolean("overridable");
      if (!overridable.ok()) return overridable.status();
      rule.emergency_overridable = overridable.value();
      const Result<std::string> note = reader.expect_text("note");
      if (!note.ok()) return note.status();
      rule.note = note.value();
      const Result<std::string> scope_feed = reader.expect_text("feed");
      if (!scope_feed.ok()) return scope_feed.status();
      if (!scope_feed.value().empty()) {
        const Result<FeedId> parsed = FeedId::Parse(scope_feed.value());
        if (!parsed.ok()) return Status::error(StatusCode::Corruption, "a rule scope feed identity is not well-formed");
        rule.scope.feed = parsed.value();
      }
      const Result<std::string> scope_load = reader.expect_text("load");
      if (!scope_load.ok()) return scope_load.status();
      if (!scope_load.value().empty()) {
        const Result<LoadId> parsed = LoadId::Parse(scope_load.value());
        if (!parsed.ok()) return Status::error(StatusCode::Corruption, "a rule scope load identity is not well-formed");
        rule.scope.load = parsed.value();
      }
      const Result<std::string> scope_source = reader.expect_token("source");
      if (!scope_source.ok()) return scope_source.status();
      if (scope_source.value() != kUnsetToken) {
        const Result<SourceClass> parsed = parse_source_class(scope_source.value());
        if (!parsed.ok()) return Status::error(StatusCode::Corruption, "a rule scope source class token is not defined");
        rule.scope.source_class = parsed.value();
      }
      const Result<std::string> scope_class = reader.expect_token("class");
      if (!scope_class.ok()) return scope_class.status();
      if (scope_class.value() != kUnsetToken) {
        const Result<LoadClass> parsed = parse_load_class(scope_class.value());
        if (!parsed.ok()) return Status::error(StatusCode::Corruption, "a rule scope load class token is not defined");
        rule.scope.load_class = parsed.value();
      }
      const Result<std::string> scope_role = reader.expect_token("role");
      if (!scope_role.ok()) return scope_role.status();
      if (scope_role.value() != kUnsetToken) {
        const Result<RedundancyRole> parsed = parse_redundancy_role(scope_role.value());
        if (!parsed.ok()) return Status::error(StatusCode::Corruption, "a rule scope role token is not defined");
        rule.scope.role = parsed.value();
      }
      const Result<std::uint64_t> condition_count = reader.expect_num("cond_n");
      if (!condition_count.ok()) return condition_count.status();
      const Result<std::uint64_t> exposure_count = reader.expect_num("expo_n");
      if (!exposure_count.ok()) return exposure_count.status();
      const Result<std::uint64_t> domain_count = reader.expect_num("dom_n");
      if (!domain_count.ok()) return domain_count.status();
      const Status record = reader.expect_type_and_end("rule");
      if (!record.ok()) return record;
      if (condition_count.value() > limits.max_conditions_per_rule ||
          domain_count.value() > limits.max_scope_failure_domains || exposure_count.value() > 4u) {
        return Status::error(StatusCode::LimitExceeded, "a rule declares too many scope values");
      }
      for (std::uint64_t index = 0; index < condition_count.value(); ++index) {
        const Status next = reader.next();
        if (!next.ok()) return next;
        const Result<std::string> subject = expect_matching_text(reader, "id", rule.id.value());
        if (!subject.ok()) return subject.status();
        const Result<std::string> value = reader.expect_token("value");
        if (!value.ok()) return value.status();
        const Result<OperatingCondition> parsed = parse_operating_condition(value.value());
        if (!parsed.ok()) return Status::error(StatusCode::Corruption, "a rule condition token is not defined");
        const Status end = reader.expect_type_and_end("rule_cond");
        if (!end.ok()) return end;
        rule.conditions.push_back(parsed.value());
      }
      for (std::uint64_t index = 0; index < exposure_count.value(); ++index) {
        const Status next = reader.next();
        if (!next.ok()) return next;
        const Result<std::string> subject = expect_matching_text(reader, "id", rule.id.value());
        if (!subject.ok()) return subject.status();
        const Result<std::string> value = reader.expect_token("value");
        if (!value.ok()) return value.status();
        const Result<MaintenanceExposure> parsed = parse_maintenance_exposure(value.value());
        if (!parsed.ok()) return Status::error(StatusCode::Corruption, "a rule exposure token is not defined");
        const Status end = reader.expect_type_and_end("rule_expo");
        if (!end.ok()) return end;
        rule.maintenance_exposures.push_back(parsed.value());
      }
      for (std::uint64_t index = 0; index < domain_count.value(); ++index) {
        const Status next = reader.next();
        if (!next.ok()) return next;
        const Result<std::string> subject = expect_matching_text(reader, "id", rule.id.value());
        if (!subject.ok()) return subject.status();
        const Result<std::string> value = reader.expect_text("value");
        if (!value.ok()) return value.status();
        const Result<FailureDomainId> parsed = FailureDomainId::Parse(value.value());
        if (!parsed.ok()) return Status::error(StatusCode::Corruption, "a rule failure domain identity is not well-formed");
        const Status end = reader.expect_type_and_end("rule_dom");
        if (!end.ok()) return end;
        rule.scope.failure_domains.push_back(parsed.value());
      }
      inputs.policy.rules.push_back(std::move(rule));
      continue;
    }

    if (type == "obligation") {
      if (inputs.policy.obligations.size() >= limits.max_obligations) {
        return Status::error(StatusCode::LimitExceeded, "the payload declares too many obligations");
      }
      ProtectedObligation obligation;
      const Result<std::string> id = reader.expect_text("id");
      if (!id.ok()) return id.status();
      const Result<ObligationId> parsed_id = ObligationId::Parse(id.value());
      if (!parsed_id.ok()) return Status::error(StatusCode::Corruption, "an obligation identity is not well-formed");
      obligation.id = parsed_id.value();
      const Result<std::string> load_class = reader.expect_token("class");
      if (!load_class.ok()) return load_class.status();
      if (load_class.value() != kUnsetToken) {
        const Result<LoadClass> parsed = parse_load_class(load_class.value());
        if (!parsed.ok()) return Status::error(StatusCode::Corruption, "an obligation load class token is not defined");
        obligation.load_class = parsed.value();
      }
      const Result<bool> protected_loads = reader.expect_boolean("protected_loads");
      if (!protected_loads.ok()) return protected_loads.status();
      obligation.applies_to_protected_loads = protected_loads.value();
      const Result<bool> capability = reader.expect_boolean("capability");
      if (!capability.ok()) return capability.status();
      obligation.requires_feed_protected_capability = capability.value();
      const Result<std::uint64_t> domains = reader.expect_num("domains");
      if (!domains.ok()) return domains.status();
      obligation.min_distinct_failure_domains = static_cast<std::uint32_t>(domains.value());
      const Result<bool> overridable = reader.expect_boolean("overridable");
      if (!overridable.ok()) return overridable.status();
      obligation.emergency_overridable = overridable.value();
      const Result<std::string> reason = reader.expect_token("reason");
      if (!reason.ok()) return reason.status();
      const Result<ReasonCode> parsed_reason = parse_reason_code(reason.value());
      if (!parsed_reason.ok()) return Status::error(StatusCode::Corruption, "an obligation reason code token is not defined");
      obligation.reason = parsed_reason.value();
      const Result<std::string> note = reader.expect_text("note");
      if (!note.ok()) return note.status();
      obligation.note = note.value();
      const Result<std::uint64_t> load_count = reader.expect_num("loads_n");
      if (!load_count.ok()) return load_count.status();
      const Result<std::uint64_t> role_count = reader.expect_num("roles_n");
      if (!role_count.ok()) return role_count.status();
      const Result<std::uint64_t> source_count = reader.expect_num("sources_n");
      if (!source_count.ok()) return source_count.status();
      const Status record = reader.expect_type_and_end("obligation");
      if (!record.ok()) return record;
      if (load_count.value() > limits.max_loads || role_count.value() > 4u || source_count.value() > 8u) {
        return Status::error(StatusCode::LimitExceeded, "an obligation declares too many values");
      }
      for (std::uint64_t index = 0; index < load_count.value(); ++index) {
        const Status next = reader.next();
        if (!next.ok()) return next;
        const Result<std::string> subject = expect_matching_text(reader, "id", obligation.id.value());
        if (!subject.ok()) return subject.status();
        const Result<std::string> value = reader.expect_text("value");
        if (!value.ok()) return value.status();
        const Result<LoadId> parsed = LoadId::Parse(value.value());
        if (!parsed.ok()) return Status::error(StatusCode::Corruption, "an obligation load identity is not well-formed");
        const Status end = reader.expect_type_and_end("obligation_load");
        if (!end.ok()) return end;
        obligation.loads.push_back(parsed.value());
      }
      for (std::uint64_t index = 0; index < role_count.value(); ++index) {
        const Status next = reader.next();
        if (!next.ok()) return next;
        const Result<std::string> subject = expect_matching_text(reader, "id", obligation.id.value());
        if (!subject.ok()) return subject.status();
        const Result<std::string> value = reader.expect_token("value");
        if (!value.ok()) return value.status();
        const Result<RedundancyRole> parsed = parse_redundancy_role(value.value());
        if (!parsed.ok()) return Status::error(StatusCode::Corruption, "an obligation role token is not defined");
        const Status end = reader.expect_type_and_end("obligation_role");
        if (!end.ok()) return end;
        obligation.permitted_roles.push_back(parsed.value());
      }
      for (std::uint64_t index = 0; index < source_count.value(); ++index) {
        const Status next = reader.next();
        if (!next.ok()) return next;
        const Result<std::string> subject = expect_matching_text(reader, "id", obligation.id.value());
        if (!subject.ok()) return subject.status();
        const Result<std::string> value = reader.expect_token("value");
        if (!value.ok()) return value.status();
        const Result<SourceClass> parsed = parse_source_class(value.value());
        if (!parsed.ok()) return Status::error(StatusCode::Corruption, "an obligation source class token is not defined");
        const Status end = reader.expect_type_and_end("obligation_source");
        if (!end.ok()) return end;
        obligation.permitted_source_classes.push_back(parsed.value());
      }
      inputs.policy.obligations.push_back(std::move(obligation));
      continue;
    }

    if (type == "option") {
      if (saw_option) {
        return Status::error(StatusCode::Corruption, "an input section has more than one option record");
      }
      const Result<bool> ranking = reader.expect_boolean("ranking");
      if (!ranking.ok()) return ranking.status();
      const Result<bool> emergency = reader.expect_boolean("emergency");
      if (!emergency.ok()) return emergency.status();
      const Status record = reader.expect_type_and_end("option");
      if (!record.ok()) return record;
      inputs.policy.options.ranking.enabled = ranking.value();
      inputs.policy.options.emergency_override_enabled = emergency.value();
      saw_option = true;
      continue;
    }

    if (type == "rank_role") {
      const Result<std::uint64_t> ordinal = reader.expect_num("ordinal");
      if (!ordinal.ok()) return ordinal.status();
      const Result<std::string> value = reader.expect_token("value");
      if (!value.ok()) return value.status();
      const Status record = reader.expect_type_and_end("rank_role");
      if (!record.ok()) return record;
      if (ordinal.value() != expected_rank_ordinal) {
        return Status::error(StatusCode::Corruption, "ranking records are not in ordinal order");
      }
      if (expected_rank_ordinal >= 4u) {
        return Status::error(StatusCode::LimitExceeded, "a ranking declares too many roles");
      }
      const Result<RedundancyRole> parsed = parse_redundancy_role(value.value());
      if (!parsed.ok()) return Status::error(StatusCode::Corruption, "a ranking role token is not defined");
      inputs.policy.options.ranking.role_order.push_back(parsed.value());
      ++expected_rank_ordinal;
      continue;
    }

    return Status::error(StatusCode::Corruption, "an unexpected record appears in an input section");
  }
}

}  // namespace feed_authority::detail
