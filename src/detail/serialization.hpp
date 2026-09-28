#pragma once

// Canonical record encoding and decoding. The grammar is documented in
// docs/artifact-format.md.

#include <string>
#include <string_view>

#include "detail/canonical.hpp"
#include "feed_authority/inputs.hpp"
#include "feed_authority/limits.hpp"
#include "feed_authority/status.hpp"

namespace feed_authority::detail {

/// Appends the canonical records of a topology view, sorted by identity.
void encode_topology_records(std::string& out, const TopologyView& topology, const Limits& limits);

/// Appends the canonical records of a control state, sorted by feed identity.
void encode_control_records(std::string& out, const ControlState& control, const Limits& limits);

/// Appends the canonical records of a policy set, sorted by identity.
void encode_policy_records(std::string& out, const PolicySet& policy, const Limits& limits);

/// Appends the canonical records of a whole input generation: a `generation`
/// record carrying the four revisions followed by topology, control and policy
/// records.
void encode_input_records(std::string& out, const AuthorityInputs& inputs, const Limits& limits);

/// Decodes input records until the record type `boundary`, which is consumed.
/// Unknown record types, missing records and cross-reference failures are refused.
Status decode_input_records(RecordReader& reader, const Limits& limits, std::string_view boundary,
                            AuthorityInputs& inputs);

}  // namespace feed_authority::detail
