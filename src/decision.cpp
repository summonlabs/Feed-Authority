#include "feed_authority/decision.hpp"

#include <algorithm>
#include <ostream>
#include <string>

#include "detail/canonical.hpp"

namespace feed_authority {

const char* to_string(DecisionOutcome outcome) noexcept {
  switch (outcome) {
    case DecisionOutcome::Allow: return "allow";
    case DecisionOutcome::Deny: return "deny";
    case DecisionOutcome::Indeterminate: return "indeterminate";
  }
  return "indeterminate";
}

Result<DecisionOutcome> parse_decision_outcome(std::string_view text) {
  if (text == "allow") return DecisionOutcome::Allow;
  if (text == "deny") return DecisionOutcome::Deny;
  if (text == "indeterminate") return DecisionOutcome::Indeterminate;
  return Status::error(StatusCode::InvalidArgument, "unrecognized decision outcome token");
}

std::ostream& operator<<(std::ostream& stream, DecisionOutcome outcome) {
  return stream << to_string(outcome);
}

std::size_t DecisionSet::count(DecisionOutcome outcome) const noexcept {
  std::size_t total = 0;
  for (const CandidateDecision& candidate : candidates) {
    if (candidate.outcome == outcome) {
      ++total;
    }
  }
  return total;
}

Digest EvaluationRequest::fingerprint() const {
  std::string payload;
  {
    detail::RecordWriter writer(payload, "request");
    writer.text("load", load.value());
    writer.num("now", static_cast<std::uint64_t>(now.unix_nanos()));
    writer.text("path", required_authority_path ? required_authority_path->value() : std::string());
    writer.num("candidates", candidate_feeds.size());
    writer.end();
  }
  std::vector<FeedId> ordered = candidate_feeds;
  std::sort(ordered.begin(), ordered.end());
  for (const FeedId& feed : ordered) {
    detail::RecordWriter writer(payload, "candidate");
    writer.text("feed", feed.value());
    writer.end();
  }
  return Digest::Of(payload);
}

}  // namespace feed_authority
