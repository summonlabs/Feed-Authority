# Runnable examples of the core lifecycle and the failure and stale-authority paths.
#
# They are also registered as tests: an example that stops working is a defect, not
# a stale document.

set(FEED_AUTHORITY_EXAMPLES
  fa_example_primary_secondary
  fa_example_maintenance_restriction
  fa_example_degraded_failover
  fa_example_emergency_authority
  fa_example_contradictory_evidence
  fa_example_stale_grant_refusal)

add_library(fa_example_support STATIC support.cpp)
target_link_libraries(fa_example_support PUBLIC feed_authority)
target_include_directories(fa_example_support PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}")
feed_authority_apply_strict_options(fa_example_support)

add_executable(fa_example_primary_secondary primary_secondary.cpp)
add_executable(fa_example_maintenance_restriction maintenance_restriction.cpp)
add_executable(fa_example_degraded_failover degraded_failover.cpp)
add_executable(fa_example_emergency_authority emergency_authority.cpp)
add_executable(fa_example_contradictory_evidence contradictory_evidence.cpp)
add_executable(fa_example_stale_grant_refusal stale_grant_refusal.cpp)

foreach(example IN LISTS FEED_AUTHORITY_EXAMPLES)
  target_link_libraries(${example} PRIVATE fa_example_support)
  feed_authority_apply_strict_options(${example})
  add_test(NAME ${example} COMMAND ${example})
  set_tests_properties(${example} PROPERTIES
    WORKING_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}")
endforeach()
