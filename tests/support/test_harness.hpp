#pragma once

// Minimal deterministic test harness. No third-party dependency, no timeouts, no
// watchdog logic: a check either passes, fails, or the program does not finish, and
// an unfinished program is a defect to diagnose.

#include <cstdint>
#include <functional>
#include <ostream>
#include <sstream>
#include <string>
#include <typeinfo>
#include <vector>

#include "feed_authority/authority.hpp"
#include "feed_authority/decision.hpp"
#include "feed_authority/emergency.hpp"
#include "feed_authority/event.hpp"
#include "feed_authority/grant.hpp"
#include "feed_authority/idempotency.hpp"
#include "feed_authority/inputs.hpp"
#include "feed_authority/model.hpp"
#include "feed_authority/policy.hpp"
#include "feed_authority/reason.hpp"
#include "feed_authority/status.hpp"
#include "feed_authority/store.hpp"
#include "feed_authority/time.hpp"

namespace feed_authority {

// Display helpers for the few types the library does not already stream. Every other
// public type has a stream operator in the library itself, and these must not be
// duplicated: a second definition would be a link error rather than a test failure.
std::ostream& operator<<(std::ostream& stream, StatusCode value);
std::ostream& operator<<(std::ostream& stream, AttemptKind value);
std::ostream& operator<<(std::ostream& stream, FaultPoint value);
std::ostream& operator<<(std::ostream& stream, const Status& value);

/// A small deterministic generator for property and randomized tests. The seed is
/// always explicit, so a failure reproduces exactly.
class Rng {
 public:
  explicit Rng(std::uint64_t seed) noexcept : state_(seed == 0 ? 0x9E3779B97F4A7C15ull : seed) {}
  std::uint64_t next() noexcept {
    state_ ^= state_ << 13;
    state_ ^= state_ >> 7;
    state_ ^= state_ << 17;
    return state_;
  }
  std::uint64_t below(std::uint64_t bound) noexcept { return bound == 0 ? 0 : next() % bound; }
  bool coin() noexcept { return (next() & 1u) != 0u; }
  std::uint64_t state() const noexcept { return state_; }

 private:
  std::uint64_t state_;
};

}  // namespace feed_authority

namespace fa_test {

using Body = std::function<void()>;

struct TestCase {
  std::string suite;
  std::string name;
  Body body;
};

std::vector<TestCase>& registry();

class Registrar {
 public:
  Registrar(const char* suite, const char* name, Body body);
};

/// Counts one executed check.
void count_check() noexcept;

/// Records a failure for the currently running test.
void report_failure(const char* file, int line, const std::string& expression,
                    const std::string& detail);

/// Renders a value for a failure message. Types without a stream operator are named
/// by their RTTI name rather than silently omitted.
template <typename T>
std::string display(const T& value) {
  if constexpr (requires(std::ostream& stream, const T& item) { stream << item; }) {
    std::ostringstream stream;
    stream << value;
    return stream.str();
  } else {
    return std::string("<value of type ") + typeid(T).name() + ">";
  }
}

std::string display(const std::string& value);
std::string display(const char* value);
std::string display(bool value);
std::string display(std::nullptr_t value);

/// Extracts the status of either a Status or a Result<T>.
inline ::feed_authority::Status status_of(const ::feed_authority::Status& value) { return value; }

template <typename T>
::feed_authority::Status status_of(const ::feed_authority::Result<T>& value) {
  return value.status();
}

int run_all(int argc, char** argv);

}  // namespace fa_test

#define FA_TEST(suite, name)                                                     \
  static void fa_test_body_##suite##_##name();                                   \
  static const ::fa_test::Registrar fa_test_registrar_##suite##_##name(          \
      #suite, #name, fa_test_body_##suite##_##name);                             \
  static void fa_test_body_##suite##_##name()

#define FA_CHECK(expression)                                                     \
  do {                                                                           \
    ::fa_test::count_check();                                                    \
    if (!(expression)) {                                                         \
      ::fa_test::report_failure(__FILE__, __LINE__, #expression, "");            \
    }                                                                            \
  } while (false)

#define FA_CHECK_MSG(expression, detail)                                         \
  do {                                                                           \
    ::fa_test::count_check();                                                    \
    if (!(expression)) {                                                         \
      ::fa_test::report_failure(__FILE__, __LINE__, #expression, (detail));      \
    }                                                                            \
  } while (false)

#define FA_CHECK_EQ(left, right)                                                 \
  do {                                                                           \
    ::fa_test::count_check();                                                    \
    const auto& fa_left = (left);                                                \
    const auto& fa_right = (right);                                              \
    if (!(fa_left == fa_right)) {                                                \
      ::fa_test::report_failure(__FILE__, __LINE__, #left " == " #right,         \
                                "left=" + ::fa_test::display(fa_left) +          \
                                    " right=" + ::fa_test::display(fa_right));   \
    }                                                                            \
  } while (false)

#define FA_CHECK_NE(left, right)                                                 \
  do {                                                                           \
    ::fa_test::count_check();                                                    \
    const auto& fa_left = (left);                                                \
    const auto& fa_right = (right);                                              \
    if (fa_left == fa_right) {                                                   \
      ::fa_test::report_failure(__FILE__, __LINE__, #left " != " #right,         \
                                "both=" + ::fa_test::display(fa_left));          \
    }                                                                            \
  } while (false)

/// Requires an expression to hold and abandons the test body when it does not.
#define FA_REQUIRE(expression)                                                   \
  do {                                                                           \
    ::fa_test::count_check();                                                    \
    if (!(expression)) {                                                         \
      ::fa_test::report_failure(__FILE__, __LINE__, #expression, "required");    \
      return;                                                                    \
    }                                                                            \
  } while (false)

/// Requires a Status or Result to be Ok and abandons the body otherwise.
#define FA_REQUIRE_OK(expression)                                                \
  do {                                                                           \
    ::fa_test::count_check();                                                    \
    const ::feed_authority::Status fa_status = ::fa_test::status_of(expression); \
    if (!fa_status.ok()) {                                                       \
      ::fa_test::report_failure(__FILE__, __LINE__, #expression,                 \
                                "status=" + fa_status.to_string());              \
      return;                                                                    \
    }                                                                            \
  } while (false)

/// Requires an expression to fail with a specific status code.
#define FA_REQUIRE_ERR(expression, expected_code)                                \
  do {                                                                           \
    ::fa_test::count_check();                                                    \
    const ::feed_authority::Status fa_status = ::fa_test::status_of(expression); \
    if (fa_status.ok()) {                                                        \
      ::fa_test::report_failure(__FILE__, __LINE__, #expression,                 \
                                "expected an error but the call succeeded");     \
      return;                                                                    \
    }                                                                            \
    if (fa_status.code() != (expected_code)) {                                   \
      ::fa_test::report_failure(__FILE__, __LINE__, #expression,                 \
                                "status=" + fa_status.to_string());              \
      return;                                                                    \
    }                                                                            \
  } while (false)
