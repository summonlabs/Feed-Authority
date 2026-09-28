#include "feed_authority/model.hpp"

#include <algorithm>
#include <ostream>
#include <string>
#include <unordered_set>
#include <vector>

namespace feed_authority {

const char* to_string(SourceClass value) noexcept {
  switch (value) {
    case SourceClass::Unknown: return "unknown";
    case SourceClass::Utility: return "utility";
    case SourceClass::Generator: return "generator";
    case SourceClass::Ups: return "ups";
    case SourceClass::Battery: return "battery";
    case SourceClass::Pdu: return "pdu";
    case SourceClass::BusTie: return "bus_tie";
    case SourceClass::Renewable: return "renewable";
  }
  return "unknown";
}

const char* to_string(LoadClass value) noexcept {
  switch (value) {
    case LoadClass::Unknown: return "unknown";
    case LoadClass::LifeSafety: return "life_safety";
    case LoadClass::Critical: return "critical";
    case LoadClass::Essential: return "essential";
    case LoadClass::NonEssential: return "non_essential";
    case LoadClass::Miscellaneous: return "miscellaneous";
  }
  return "unknown";
}

const char* to_string(RedundancyRole value) noexcept {
  switch (value) {
    case RedundancyRole::Unknown: return "unknown";
    case RedundancyRole::Primary: return "primary";
    case RedundancyRole::Secondary: return "secondary";
    case RedundancyRole::Standby: return "standby";
    case RedundancyRole::Spare: return "spare";
  }
  return "unknown";
}

const char* to_string(OperatingCondition value) noexcept {
  switch (value) {
    case OperatingCondition::Unknown: return "unknown";
    case OperatingCondition::Normal: return "normal";
    case OperatingCondition::Maintenance: return "maintenance";
    case OperatingCondition::Degraded: return "degraded";
    case OperatingCondition::Failover: return "failover";
    case OperatingCondition::Emergency: return "emergency";
    case OperatingCondition::Isolated: return "isolated";
  }
  return "unknown";
}

const char* to_string(MaintenanceExposure value) noexcept {
  switch (value) {
    case MaintenanceExposure::Unknown: return "unknown";
    case MaintenanceExposure::None: return "none";
    case MaintenanceExposure::Restricted: return "restricted";
    case MaintenanceExposure::Withdrawn: return "withdrawn";
  }
  return "unknown";
}

const char* to_string(FeedCondition value) noexcept {
  switch (value) {
    case FeedCondition::Unknown: return "unknown";
    case FeedCondition::Energized: return "energized";
    case FeedCondition::DeEnergized: return "de_energized";
    case FeedCondition::Faulted: return "faulted";
    case FeedCondition::Isolated: return "isolated";
  }
  return "unknown";
}

Result<SourceClass> parse_source_class(std::string_view text) {
  if (text == "unknown") return SourceClass::Unknown;
  if (text == "utility") return SourceClass::Utility;
  if (text == "generator") return SourceClass::Generator;
  if (text == "ups") return SourceClass::Ups;
  if (text == "battery") return SourceClass::Battery;
  if (text == "pdu") return SourceClass::Pdu;
  if (text == "bus_tie") return SourceClass::BusTie;
  if (text == "renewable") return SourceClass::Renewable;
  return Status::error(StatusCode::InvalidArgument, "unrecognized source class token");
}

Result<LoadClass> parse_load_class(std::string_view text) {
  if (text == "unknown") return LoadClass::Unknown;
  if (text == "life_safety") return LoadClass::LifeSafety;
  if (text == "critical") return LoadClass::Critical;
  if (text == "essential") return LoadClass::Essential;
  if (text == "non_essential") return LoadClass::NonEssential;
  if (text == "miscellaneous") return LoadClass::Miscellaneous;
  return Status::error(StatusCode::InvalidArgument, "unrecognized load class token");
}

Result<RedundancyRole> parse_redundancy_role(std::string_view text) {
  if (text == "unknown") return RedundancyRole::Unknown;
  if (text == "primary") return RedundancyRole::Primary;
  if (text == "secondary") return RedundancyRole::Secondary;
  if (text == "standby") return RedundancyRole::Standby;
  if (text == "spare") return RedundancyRole::Spare;
  return Status::error(StatusCode::InvalidArgument, "unrecognized redundancy role token");
}

Result<OperatingCondition> parse_operating_condition(std::string_view text) {
  if (text == "unknown") return OperatingCondition::Unknown;
  if (text == "normal") return OperatingCondition::Normal;
  if (text == "maintenance") return OperatingCondition::Maintenance;
  if (text == "degraded") return OperatingCondition::Degraded;
  if (text == "failover") return OperatingCondition::Failover;
  if (text == "emergency") return OperatingCondition::Emergency;
  if (text == "isolated") return OperatingCondition::Isolated;
  return Status::error(StatusCode::InvalidArgument, "unrecognized operating condition token");
}

Result<MaintenanceExposure> parse_maintenance_exposure(std::string_view text) {
  if (text == "unknown") return MaintenanceExposure::Unknown;
  if (text == "none") return MaintenanceExposure::None;
  if (text == "restricted") return MaintenanceExposure::Restricted;
  if (text == "withdrawn") return MaintenanceExposure::Withdrawn;
  return Status::error(StatusCode::InvalidArgument, "unrecognized maintenance exposure token");
}

Result<FeedCondition> parse_feed_condition(std::string_view text) {
  if (text == "unknown") return FeedCondition::Unknown;
  if (text == "energized") return FeedCondition::Energized;
  if (text == "de_energized") return FeedCondition::DeEnergized;
  if (text == "faulted") return FeedCondition::Faulted;
  if (text == "isolated") return FeedCondition::Isolated;
  return Status::error(StatusCode::InvalidArgument, "unrecognized feed condition token");
}

std::ostream& operator<<(std::ostream& stream, SourceClass value) { return stream << to_string(value); }
std::ostream& operator<<(std::ostream& stream, LoadClass value) { return stream << to_string(value); }
std::ostream& operator<<(std::ostream& stream, RedundancyRole value) { return stream << to_string(value); }
std::ostream& operator<<(std::ostream& stream, OperatingCondition value) { return stream << to_string(value); }
std::ostream& operator<<(std::ostream& stream, MaintenanceExposure value) { return stream << to_string(value); }
std::ostream& operator<<(std::ostream& stream, FeedCondition value) { return stream << to_string(value); }

bool condition_may_serve(FeedCondition condition) noexcept {
  return condition == FeedCondition::Energized;
}

const FeedDescriptor* TopologyView::find_feed(const FeedId& id) const noexcept {
  for (const FeedDescriptor& feed : feeds) {
    if (feed.id == id) {
      return &feed;
    }
  }
  return nullptr;
}

const LoadDescriptor* TopologyView::find_load(const LoadId& id) const noexcept {
  for (const LoadDescriptor& load : loads) {
    if (load.id == id) {
      return &load;
    }
  }
  return nullptr;
}

std::vector<const FeedLink*> TopologyView::paths_for(const LoadId& load) const {
  std::vector<const FeedLink*> paths;
  for (const FeedLink& link : links) {
    if (link.load == load) {
      paths.push_back(&link);
    }
  }
  std::sort(paths.begin(), paths.end(),
            [](const FeedLink* left, const FeedLink* right) { return left->feed < right->feed; });
  return paths;
}

Status TopologyView::validate(const Limits& limits) const {
  const Status limits_status = limits.validate();
  if (!limits_status.ok()) {
    return limits_status;
  }
  if (feeds.size() > limits.max_feeds) {
    return Status::error(StatusCode::LimitExceeded, "the topology declares too many feeds");
  }
  if (loads.size() > limits.max_loads) {
    return Status::error(StatusCode::LimitExceeded, "the topology declares too many loads");
  }
  if (links.size() > limits.max_links) {
    return Status::error(StatusCode::LimitExceeded, "the topology declares too many paths");
  }

  std::unordered_set<std::string> feed_ids;
  feed_ids.reserve(feeds.size() * 2u);
  for (const FeedDescriptor& feed : feeds) {
    if (!feed.id.valid()) {
      return Status::error(StatusCode::InvalidArgument, "a feed has no identity");
    }
    if (feed.condition.size() > kMaxObservationsPerSubject) {
      return Status::error(StatusCode::LimitExceeded, "a feed carries too many observations");
    }
    if (!feed_ids.insert(feed.id.value()).second) {
      return Status::error(StatusCode::DuplicateIdentity, "the topology declares a feed twice");
    }
  }

  std::unordered_set<std::string> load_ids;
  load_ids.reserve(loads.size() * 2u);
  for (const LoadDescriptor& load : loads) {
    if (!load.id.valid()) {
      return Status::error(StatusCode::InvalidArgument, "a load has no identity");
    }
    if (!load_ids.insert(load.id.value()).second) {
      return Status::error(StatusCode::DuplicateIdentity, "the topology declares a load twice");
    }
  }

  std::unordered_set<std::string> link_keys;
  link_keys.reserve(links.size() * 2u);
  for (const FeedLink& link : links) {
    if (!link.feed.valid() || !link.load.valid()) {
      return Status::error(StatusCode::InvalidArgument, "a path has an unset endpoint");
    }
    if (link.observed.size() > kMaxObservationsPerSubject) {
      return Status::error(StatusCode::LimitExceeded, "a path carries too many observations");
    }
    if (feed_ids.find(link.feed.value()) == feed_ids.end()) {
      return Status::error(StatusCode::NotFound, "a path references a feed the topology does not declare");
    }
    if (load_ids.find(link.load.value()) == load_ids.end()) {
      return Status::error(StatusCode::NotFound, "a path references a load the topology does not declare");
    }
    // '>' cannot appear in an identity, so this separator is unambiguous.
    std::string key = link.load.value();
    key.push_back('>');
    key += link.feed.value();
    if (!link_keys.insert(key).second) {
      return Status::error(StatusCode::DuplicateIdentity, "the topology declares a path twice");
    }
  }
  return Status::success();
}

void TopologyView::canonicalize(TopologyView& view) {
  std::sort(view.feeds.begin(), view.feeds.end(),
            [](const FeedDescriptor& left, const FeedDescriptor& right) { return left.id < right.id; });
  std::sort(view.loads.begin(), view.loads.end(),
            [](const LoadDescriptor& left, const LoadDescriptor& right) { return left.id < right.id; });
  std::sort(view.links.begin(), view.links.end());
  for (FeedDescriptor& feed : view.feeds) {
    std::sort(feed.condition.begin(), feed.condition.end(),
              [](const Observation<FeedCondition>& left, const Observation<FeedCondition>& right) {
                return left.source() < right.source();
              });
  }
  for (FeedLink& link : view.links) {
    std::sort(link.observed.begin(), link.observed.end(),
              [](const Observation<bool>& left, const Observation<bool>& right) {
                return left.source() < right.source();
              });
  }
}

Status ControlState::validate(const Limits& limits) const {
  const Status limits_status = limits.validate();
  if (!limits_status.ok()) {
    return limits_status;
  }
  if (condition.size() > kMaxObservationsPerSubject) {
    return Status::error(StatusCode::LimitExceeded, "the control state carries too many observations");
  }
  if (maintenance.size() > limits.max_maintenance_records) {
    return Status::error(StatusCode::LimitExceeded, "the control state carries too many maintenance records");
  }
  std::unordered_set<std::string> seen;
  seen.reserve(maintenance.size() * 2u);
  for (const MaintenanceRecord& record : maintenance) {
    if (!record.feed.valid()) {
      return Status::error(StatusCode::InvalidArgument, "a maintenance record has no feed");
    }
    if (record.exposure.size() > kMaxObservationsPerSubject) {
      return Status::error(StatusCode::LimitExceeded, "a maintenance record carries too many observations");
    }
    if (!seen.insert(record.feed.value()).second) {
      return Status::error(StatusCode::DuplicateIdentity,
                           "the control state declares maintenance for a feed twice");
    }
  }
  return Status::success();
}

void ControlState::canonicalize(ControlState& state) {
  std::sort(state.maintenance.begin(), state.maintenance.end(),
            [](const MaintenanceRecord& left, const MaintenanceRecord& right) {
              return left.feed < right.feed;
            });
  for (MaintenanceRecord& record : state.maintenance) {
    std::sort(record.exposure.begin(), record.exposure.end(),
              [](const Observation<MaintenanceExposure>& left,
                 const Observation<MaintenanceExposure>& right) {
                return left.source() < right.source();
              });
  }
  std::sort(state.condition.begin(), state.condition.end(),
            [](const Observation<OperatingCondition>& left,
               const Observation<OperatingCondition>& right) {
              return left.source() < right.source();
            });
}

const MaintenanceRecord* ControlState::maintenance_for(const FeedId& feed) const noexcept {
  for (const MaintenanceRecord& record : maintenance) {
    if (record.feed == feed) {
      return &record;
    }
  }
  return nullptr;
}

}  // namespace feed_authority
