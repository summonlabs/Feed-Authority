#include "feed_authority/diff.hpp"

#include <string>

namespace feed_authority {

std::string PolicyDiff::to_string() const {
  std::string text;
  text += "policy ";
  text += from.str();
  text += " -> ";
  text += to.str();
  text += identical ? " (identical)\n" : "\n";
  for (const RuleDelta& delta : rules) {
    text += "  rule ";
    text += delta.change;
    text += " ";
    text += delta.id.value();
    if (!delta.before.empty()) {
      text += "\n    before: ";
      text += delta.before;
    }
    if (!delta.after.empty()) {
      text += "\n    after:  ";
      text += delta.after;
    }
    text += "\n";
  }
  for (const ObligationDelta& delta : obligations) {
    text += "  obligation ";
    text += delta.change;
    text += " ";
    text += delta.id.value();
    text += "\n";
  }
  for (const std::string& change : option_changes) {
    text += "  option ";
    text += change;
    text += "\n";
  }
  if (identical) {
    text += "  no differences\n";
  }
  return text;
}

std::string InputsDiff::to_string() const {
  std::string text;
  text += "topology ";
  text += from_topology.str();
  text += " -> ";
  text += to_topology.str();
  text += "\npolicy ";
  text += from_policy.str();
  text += " -> ";
  text += to_policy.str();
  text += "\ncontrol ";
  text += from_control.str();
  text += " -> ";
  text += to_control.str();
  text += "\nevidence ";
  text += from_evidence.str();
  text += " -> ";
  text += to_evidence.str();
  text += identical ? "\nidentical=true\n" : "\nidentical=false\n";
  for (const std::string& change : changes) {
    text += "  ";
    text += change;
    text += "\n";
  }
  return text;
}

}  // namespace feed_authority
