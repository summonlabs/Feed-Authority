# Test suite.
#
# No test is given a timeout. CTest timeouts, timeout wrappers and watchdog
# processes are prohibited in this repository: a test that does not finish is a
# defect to diagnose, not to bound.

# The probe is a real program that the multiprocess, fencing and crash tests start
# as an independent operating-system process.
add_executable(fa_probe support/fa_probe.cpp)
target_link_libraries(fa_probe PRIVATE feed_authority)
target_include_directories(fa_probe PRIVATE "${CMAKE_SOURCE_DIR}/src")
feed_authority_apply_strict_options(fa_probe)

add_library(fa_test_support STATIC
  support/test_harness.cpp
  support/proc.cpp
  support/fixtures.cpp)
target_include_directories(fa_test_support PUBLIC
  "${CMAKE_CURRENT_SOURCE_DIR}"
  "${CMAKE_CURRENT_SOURCE_DIR}/support"
  PRIVATE "${CMAKE_SOURCE_DIR}/src")
target_link_libraries(fa_test_support PUBLIC feed_authority)
target_compile_definitions(fa_test_support PUBLIC
  "FA_PROBE_EXECUTABLE=\"$<TARGET_FILE:fa_probe>\"")
add_dependencies(fa_test_support fa_probe)
feed_authority_apply_strict_options(fa_test_support)

if(TARGET feed_authority_cli)
  target_compile_definitions(fa_test_support PUBLIC
    "FA_CLI_EXECUTABLE=\"$<TARGET_FILE:feed_authority_cli>\"")
  add_dependencies(fa_test_support feed_authority_cli)
endif()

function(feed_authority_add_test name)
  add_executable(${name} ${ARGN})
  target_link_libraries(${name} PRIVATE fa_test_support)
  # Adversarial store artifacts are built with the same encoder the library uses, so
  # the tests need the internal headers.
  target_include_directories(${name} PRIVATE "${CMAKE_SOURCE_DIR}/src")
  feed_authority_apply_strict_options(${name})
  add_test(NAME ${name} COMMAND ${name})
  set_tests_properties(${name} PROPERTIES
    WORKING_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}")
endfunction()

feed_authority_add_test(fa_test_ids_limits test_ids_limits.cpp)
feed_authority_add_test(fa_test_evidence test_evidence.cpp)
feed_authority_add_test(fa_test_policy test_policy.cpp)
feed_authority_add_test(fa_test_evaluation test_evaluation.cpp)
feed_authority_add_test(fa_test_grants test_grants.cpp)
feed_authority_add_test(fa_test_emergency test_emergency.cpp)
feed_authority_add_test(fa_test_idempotency test_idempotency.cpp)
feed_authority_add_test(fa_test_persistence test_persistence.cpp)
feed_authority_add_test(fa_test_adversarial test_adversarial.cpp)
feed_authority_add_test(fa_test_scenario test_scenario.cpp)
feed_authority_add_test(fa_test_diff_history test_diff_history.cpp)
feed_authority_add_test(fa_test_process_authority test_process_authority.cpp)
feed_authority_add_test(fa_test_crash_recovery test_crash_recovery.cpp)
feed_authority_add_test(fa_test_property test_property.cpp)

if(TARGET feed_authority_cli)
  feed_authority_add_test(fa_test_cli test_cli.cpp)
endif()

if(FEED_AUTHORITY_DOWNSTREAM_PREFIX)
  add_test(NAME fa_test_downstream_install
    COMMAND "${CMAKE_COMMAND}"
      -DFA_SOURCE_DIR=${CMAKE_SOURCE_DIR}
      -DFA_BINARY_DIR=${CMAKE_CURRENT_BINARY_DIR}/downstream
      -DFA_PREFIX=${FEED_AUTHORITY_DOWNSTREAM_PREFIX}
      -DFA_GENERATOR=${CMAKE_GENERATOR}
      -DFA_CONFIG=$<CONFIG>
      -P "${CMAKE_SOURCE_DIR}/cmake/RunDownstreamCheck.cmake")
  set_tests_properties(fa_test_downstream_install PROPERTIES
    WORKING_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}")
endif()
