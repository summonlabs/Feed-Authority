#pragma once

// The externally supplied electrical model as Feed Authority sees it.
//
// Feed Authority does not own the topology. It receives a revision-stamped view of
// feeds, loads, paths, failure domains, maintenance exposure and operating
// condition, and answers eligibility questions about it. Nothing in this header
// describes switching, actuation, capacity or energy: the only facts modelled are
// the ones an eligibility answer depends on.

#include <cstdint>
#include <iosfwd>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "feed_authority/evidence.hpp"
#include "feed_authority/generations.hpp"
#include "feed_authority/ids.hpp"
#include "feed_authority/limits.hpp"
#include "feed_authority/status.hpp"

namespace feed_authority {

/// What kind of source a feed is. This is a classification supplied by the
/// topology source, not a measurement.
enum class SourceClass : std::int32_t {
  Unknown = 0,
  Utility = 1,
  Generator = 2,
  Ups = 3,
  Battery = 4,
  Pdu = 5,
  BusTie = 6,
  Renewable = 7,
};

/// What kind of load (service) is served, supplied by the topology source.
enum class LoadClass : std::int32_t {
  Unknown = 0,
  LifeSafety = 1,
  Critical = 2,
  Essential = 3,
  NonEssential = 4,
  Miscellaneous = 5,
};

/// The redundancy role a feed plays for a load or in the facility.
enum class RedundancyRole : std::int32_t {
  Unknown = 0,
  Primary = 1,
  Secondary = 2,
  Standby = 3,
  Spare = 4,
};

/// The declared operating condition of the facility or the affected area.
enum class OperatingCondition : std::int32_t {
  Unknown = 0,
  Normal = 1,
  Maintenance = 2,
  Degraded = 3,
  Failover = 4,
  Emergency = 5,
  Isolated = 6,
};

/// How exposed a feed is to maintenance.
enum class MaintenanceExposure : std::int32_t {
  Unknown = 0,
  /// Not exposed.
  None = 1,
  /// Exposed with reduced capability; ordinary serving may still be permitted by
  /// policy, and a policy rule decides whether it is.
  Restricted = 2,
  /// Withdrawn from service for the window.
  Withdrawn = 3,
};

/// The observed electrical condition of a feed.
enum class FeedCondition : std::int32_t {
  Unknown = 0,
  Energized = 1,
  DeEnergized = 2,
  Faulted = 3,
  Isolated = 4,
};

const char* to_string(SourceClass value) noexcept;
const char* to_string(LoadClass value) noexcept;
const char* to_string(RedundancyRole value) noexcept;
const char* to_string(OperatingCondition value) noexcept;
const char* to_string(MaintenanceExposure value) noexcept;
const char* to_string(FeedCondition value) noexcept;

Result<SourceClass> parse_source_class(std::string_view text);
Result<LoadClass> parse_load_class(std::string_view text);
Result<RedundancyRole> parse_redundancy_role(std::string_view text);
Result<OperatingCondition> parse_operating_condition(std::string_view text);
Result<MaintenanceExposure> parse_maintenance_exposure(std::string_view text);
Result<FeedCondition> parse_feed_condition(std::string_view text);

std::ostream& operator<<(std::ostream& stream, SourceClass value);
std::ostream& operator<<(std::ostream& stream, LoadClass value);
std::ostream& operator<<(std::ostream& stream, RedundancyRole value);
std::ostream& operator<<(std::ostream& stream, OperatingCondition value);
std::ostream& operator<<(std::ostream& stream, MaintenanceExposure value);
std::ostream& operator<<(std::ostream& stream, FeedCondition value);

/// True when the condition leaves the feed electrically able to serve at all.
/// `Unknown` is not able: an unobserved feed is not an energized feed.
bool condition_may_serve(FeedCondition condition) noexcept;

/// One feed in the supplied topology.
struct FeedDescriptor {
  FeedId id;
  SourceClass source_class = SourceClass::Unknown;
  RedundancyRole role = RedundancyRole::Unknown;
  /// The failure domain the feed belongs to. Unset means the topology source did
  /// not name one, which makes diversity obligations unprovable rather than met.
  FailureDomainId failure_domain;
  /// Whether the topology source allows this feed to serve protected loads at all.
  /// Policy may narrow this further; it never widens it.
  bool may_serve_protected_loads = false;
  /// Independent observations of the feed's electrical condition.
  std::vector<Observation<FeedCondition>> condition;

  friend bool operator==(const FeedDescriptor& left, const FeedDescriptor& right) noexcept {
    return left.id == right.id && left.source_class == right.source_class && left.role == right.role &&
           left.failure_domain == right.failure_domain &&
           left.may_serve_protected_loads == right.may_serve_protected_loads &&
           left.condition == right.condition;
  }
};

/// One load (service) in the supplied topology.
struct LoadDescriptor {
  LoadId id;
  LoadClass load_class = LoadClass::Unknown;
  /// Declared by the topology source as carrying a protected obligation. Policy
  /// states what the obligation requires; this flag states that one exists.
  bool protected_load = false;

  friend bool operator==(const LoadDescriptor& left, const LoadDescriptor& right) noexcept {
    return left.id == right.id && left.load_class == right.load_class &&
           left.protected_load == right.protected_load;
  }
};

/// One path from a feed to a load, as declared by the topology source. The path is
/// a structural fact; `observed` is the evidence that the source still sees it.
struct FeedLink {
  FeedId feed;
  LoadId load;
  RedundancyRole role = RedundancyRole::Unknown;
  FailureDomainId failure_domain;
  /// Independent observations of "this path exists in this generation". A fresh
  /// observation with value `false` is an explicit absence, not an unknown.
  std::vector<Observation<bool>> observed;

  friend bool operator==(const FeedLink& left, const FeedLink& right) noexcept {
    return left.feed == right.feed && left.load == right.load && left.role == right.role &&
           left.failure_domain == right.failure_domain && left.observed == right.observed;
  }
  friend bool operator<(const FeedLink& left, const FeedLink& right) noexcept {
    if (left.load != right.load) {
      return left.load < right.load;
    }
    return left.feed < right.feed;
  }
};

/// One maintenance exposure record for a feed.
struct MaintenanceRecord {
  FeedId feed;
  MaintenanceWindowId window;
  std::vector<Observation<MaintenanceExposure>> exposure;

  friend bool operator==(const MaintenanceRecord& left, const MaintenanceRecord& right) noexcept {
    return left.feed == right.feed && left.window == right.window && left.exposure == right.exposure;
  }
};

/// The externally supplied topology view. The order of the vectors is not part of
/// the model: every consumer sorts by identity, and `canonicalize` establishes the
/// canonical order once at adoption.
struct TopologyView {
  TopologyRevision revision{};
  std::vector<FeedDescriptor> feeds;
  std::vector<LoadDescriptor> loads;
  std::vector<FeedLink> links;

  const FeedDescriptor* find_feed(const FeedId& id) const noexcept;
  const LoadDescriptor* find_load(const LoadId& id) const noexcept;
  /// Every path whose load is `load`, in canonical (feed identity) order.
  std::vector<const FeedLink*> paths_for(const LoadId& load) const;

  /// Validates bounds, identity form, duplicate identities and cross references.
  /// Returns the first failure in a fixed documented order.
  Status validate(const Limits& limits) const;

  /// Sorts feeds, loads and links by identity and each observation list by source
  /// identity, so that two logically equal views are byte-identical when encoded.
  static void canonicalize(TopologyView& view);

  friend bool operator==(const TopologyView& left, const TopologyView& right) noexcept {
    return left.revision == right.revision && left.feeds == right.feeds && left.loads == right.loads &&
           left.links == right.links;
  }
};

/// Externally supplied control state: the declared operating condition and the
/// maintenance exposures. Feed Authority reads this and never writes it.
struct ControlState {
  ControlRevision revision{};
  std::vector<Observation<OperatingCondition>> condition;
  std::vector<MaintenanceRecord> maintenance;

  Status validate(const Limits& limits) const;
  static void canonicalize(ControlState& state);
  /// The maintenance record for `feed`, or nullptr when none was supplied.
  const MaintenanceRecord* maintenance_for(const FeedId& feed) const noexcept;

  friend bool operator==(const ControlState& left, const ControlState& right) noexcept {
    return left.revision == right.revision && left.condition == right.condition &&
           left.maintenance == right.maintenance;
  }
};

}  // namespace feed_authority
