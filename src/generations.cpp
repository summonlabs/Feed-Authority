#include "feed_authority/generations.hpp"

#include <cstddef>
#include <ostream>
#include <string>

namespace feed_authority {

template <class Tag>
std::string Counter<Tag>::str() const {
  if (value_ == 0) {
    return "0";
  }
  char buffer[20];
  std::size_t index = sizeof(buffer);
  std::uint64_t remaining = value_;
  while (remaining != 0) {
    buffer[--index] = static_cast<char>('0' + (remaining % 10));
    remaining /= 10;
  }
  return std::string(buffer + index, sizeof(buffer) - index);
}

template <class Tag>
Result<Counter<Tag>> Counter<Tag>::Parse(std::string_view text) {
  if (text.empty() || text.size() > 20) {
    return Status::error(StatusCode::InvalidArgument, "counter text is empty or longer than 20 digits");
  }
  if (text.size() > 1 && text.front() == '0') {
    return Status::error(StatusCode::InvalidArgument, "counter text has a leading zero");
  }
  std::uint64_t value = 0;
  for (const char character : text) {
    if (character < '0' || character > '9') {
      return Status::error(StatusCode::InvalidArgument, "counter text is not decimal digits");
    }
    const std::uint64_t digit = static_cast<std::uint64_t>(character - '0');
    if (value > (0xFFFFFFFFFFFFFFFFull - digit) / 10ull) {
      return Status::error(StatusCode::LimitExceeded, "counter text overflows 64 bits");
    }
    value = value * 10ull + digit;
  }
  return Counter(value);
}

std::ostream& operator<<(std::ostream& stream, Incarnation incarnation) {
  return stream << incarnation.str();
}

std::string AuthorityBinding::to_string() const {
  std::string text;
  text.reserve(96);
  text += "epoch=";
  text += epoch.str();
  text += " topology=";
  text += topology.str();
  text += " policy=";
  text += policy.str();
  text += " control=";
  text += control.str();
  text += " evidence=";
  text += evidence.str();
  text += " decision=";
  text += decision.str();
  return text;
}

template class Counter<TopologyRevisionTag>;
template class Counter<PolicyRevisionTag>;
template class Counter<ControlRevisionTag>;
template class Counter<EvidenceRevisionTag>;
template class Counter<StoreSequenceTag>;
template class Counter<DecisionGenerationTag>;
template class Counter<GrantSequenceTag>;
template class Counter<EventSequenceTag>;
template class Counter<AuthorityEpochTag>;
template class Counter<GrantIdTag>;
template class Counter<EmergencyAuthorizationIdTag>;

}  // namespace feed_authority
