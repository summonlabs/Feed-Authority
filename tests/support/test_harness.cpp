#include "test_harness.hpp"

#include <iostream>
#include <string>
#include <utility>
#include <vector>

namespace feed_authority {

std::ostream& operator<<(std::ostream& stream, StatusCode value) { return stream << to_string(value); }
std::ostream& operator<<(std::ostream& stream, AttemptKind value) { return stream << to_string(value); }
std::ostream& operator<<(std::ostream& stream, FaultPoint value) { return stream << to_string(value); }
std::ostream& operator<<(std::ostream& stream, const Status& value) { return stream << value.to_string(); }

}  // namespace feed_authority

namespace fa_test {
namespace {

std::string g_current_suite;
std::string g_current_name;
std::vector<std::string> g_failures;
std::size_t g_checks = 0;
std::size_t g_failed_checks = 0;

}  // namespace

std::vector<TestCase>& registry() {
  static std::vector<TestCase> tests;
  return tests;
}

Registrar::Registrar(const char* suite, const char* name, Body body) {
  registry().push_back(TestCase{suite, name, std::move(body)});
}

void count_check() noexcept { ++g_checks; }

void report_failure(const char* file, int line, const std::string& expression,
                    const std::string& detail) {
  ++g_failed_checks;
  std::string message = std::string(file) + ":" + std::to_string(line) + ": " + g_current_suite +
                        "." + g_current_name + ": " + expression;
  if (!detail.empty()) {
    message += " [" + detail + "]";
  }
  g_failures.push_back(std::move(message));
}

std::string display(const std::string& value) { return value; }
std::string display(const char* value) { return std::string(value == nullptr ? "<null>" : value); }
std::string display(bool value) { return value ? "true" : "false"; }
std::string display(std::nullptr_t) { return "<null>"; }

int run_all(int argc, char** argv) {
  std::string filter;
  for (int index = 1; index < argc; ++index) {
    const std::string argument = argv[index];
    if (argument.rfind("--filter=", 0) == 0) {
      filter = argument.substr(9);
    }
  }
  std::size_t passed = 0;
  std::size_t failed = 0;
  std::size_t skipped = 0;
  for (const TestCase& test : registry()) {
    const std::string full = test.suite + "." + test.name;
    if (!filter.empty() && full.find(filter) == std::string::npos) {
      ++skipped;
      continue;
    }
    g_current_suite = test.suite;
    g_current_name = test.name;
    const std::size_t failures_before = g_failures.size();
    test.body();
    if (g_failures.size() == failures_before) {
      ++passed;
    } else {
      ++failed;
    }
  }
  std::cout << "checks=" << g_checks << " failed_checks=" << g_failed_checks << " passed=" << passed
            << " failed=" << failed << " skipped=" << skipped << "\n";
  for (const std::string& failure : g_failures) {
    std::cout << "FAIL " << failure << "\n";
  }
  return failed == 0 ? 0 : 1;
}

}  // namespace fa_test

int main(int argc, char** argv) { return ::fa_test::run_all(argc, argv); }
