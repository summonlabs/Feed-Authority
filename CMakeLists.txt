cmake_minimum_required(VERSION 3.21)

project(FeedAuthority
  VERSION 1.0.0
  DESCRIPTION "Electrical feed serving authority for the Data Center Control Plane"
  HOMEPAGE_URL "https://github.com/summonlabs/Feed-Authority"
  LANGUAGES CXX)

include(GNUInstallDirs)
include(CMakePackageConfigHelpers)

if(CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
  set(FEED_AUTHORITY_IS_TOP_LEVEL ON)
else()
  set(FEED_AUTHORITY_IS_TOP_LEVEL OFF)
endif()

if(NOT CMAKE_CXX_STANDARD)
  set(CMAKE_CXX_STANDARD 20)
endif()
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(FEED_AUTHORITY_IS_TOP_LEVEL)
  option(FEED_AUTHORITY_BUILD_TESTS "Build the Feed Authority test suite" ON)
  option(FEED_AUTHORITY_BUILD_EXAMPLES "Build the Feed Authority examples" ON)
  option(FEED_AUTHORITY_BUILD_BENCHMARKS "Build the Feed Authority benchmarks" ON)
  option(FEED_AUTHORITY_BUILD_TOOLS "Build the Feed Authority command line tool" ON)
else()
  option(FEED_AUTHORITY_BUILD_TESTS "Build the Feed Authority test suite" OFF)
  option(FEED_AUTHORITY_BUILD_EXAMPLES "Build the Feed Authority examples" OFF)
  option(FEED_AUTHORITY_BUILD_BENCHMARKS "Build the Feed Authority benchmarks" OFF)
  option(FEED_AUTHORITY_BUILD_TOOLS "Build the Feed Authority command line tool" OFF)
endif()

option(FEED_AUTHORITY_WARNINGS_AS_ERRORS "Treat first-party compiler warnings as errors" ON)
option(FEED_AUTHORITY_ENABLE_MSVC_ANALYZE "Run the MSVC static analyzer over first-party targets" OFF)

set(FEED_AUTHORITY_DOWNSTREAM_PREFIX "" CACHE PATH
  "Install prefix of a previous Feed Authority installation; enables the downstream consumer test")

# ---------------------------------------------------------------------------
# First-party compile options
# ---------------------------------------------------------------------------
function(feed_authority_apply_strict_options target)
  if(MSVC)
    target_compile_options(${target} PRIVATE /W4 /permissive- /utf-8 /Zc:__cplusplus /EHsc)
    if(FEED_AUTHORITY_WARNINGS_AS_ERRORS)
      target_compile_options(${target} PRIVATE /WX)
    endif()
    if(FEED_AUTHORITY_ENABLE_MSVC_ANALYZE)
      target_compile_options(${target} PRIVATE /analyze /analyze:external-)
    endif()
  else()
    target_compile_options(${target} PRIVATE
      -Wall
      -Wextra
      -Wpedantic
      -Wshadow
      -Wconversion
      -Wsign-conversion
      -Wnon-virtual-dtor
      -Wcast-qual
      -Wdouble-promotion)
    if(FEED_AUTHORITY_WARNINGS_AS_ERRORS)
      target_compile_options(${target} PRIVATE -Werror)
    endif()
  endif()
endfunction()

# ---------------------------------------------------------------------------
# Generated version header
# ---------------------------------------------------------------------------
set(FEED_AUTHORITY_GENERATED_INCLUDE_DIR "${CMAKE_CURRENT_BINARY_DIR}/generated")
configure_file(
  "${CMAKE_CURRENT_SOURCE_DIR}/include/feed_authority/version.hpp.in"
  "${FEED_AUTHORITY_GENERATED_INCLUDE_DIR}/feed_authority/version.hpp"
  @ONLY)

# ---------------------------------------------------------------------------
# Library
# ---------------------------------------------------------------------------
add_library(feed_authority
  src/status.cpp
  src/store.cpp
  src/ids.cpp
  src/generations.cpp
  src/time.cpp
  src/evidence.cpp
  src/model.cpp
  src/policy.cpp
  src/reason.cpp
  src/obligation.cpp
  src/inputs.cpp
  src/decision.cpp
  src/detail/evaluation.cpp
  src/grant.cpp
  src/emergency.cpp
  src/event.cpp
  src/idempotency.cpp
  src/diff.cpp
  src/render.cpp
  src/scenario.cpp
  src/authority.cpp
  src/detail/checked.cpp
  src/detail/digest.cpp
  src/detail/canonical.cpp
  src/detail/codec.cpp
  src/detail/serialization.cpp
  src/detail/store_format.cpp
  src/detail/store_path.cpp
  src/detail/file_lock.cpp
  src/detail/platform_io.cpp)
add_library(FeedAuthority::feed_authority ALIAS feed_authority)

target_include_directories(feed_authority
  PUBLIC
    "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>"
    "$<BUILD_INTERFACE:${FEED_AUTHORITY_GENERATED_INCLUDE_DIR}>"
    "$<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>"
  PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/src")

target_compile_features(feed_authority PUBLIC cxx_std_20)
feed_authority_apply_strict_options(feed_authority)

set_target_properties(feed_authority PROPERTIES
  OUTPUT_NAME "feed_authority"
  VERSION "${PROJECT_VERSION}"
  SOVERSION "${PROJECT_VERSION_MAJOR}"
  CXX_STANDARD 20
  CXX_STANDARD_REQUIRED ON)

if(BUILD_SHARED_LIBS AND WIN32)
  set_target_properties(feed_authority PROPERTIES WINDOWS_EXPORT_ALL_SYMBOLS ON)
endif()

# ---------------------------------------------------------------------------
# CLI tool
# ---------------------------------------------------------------------------
if(FEED_AUTHORITY_BUILD_TOOLS)
  add_executable(feed_authority_cli tools/fa_cli.cpp tools/cli_json.cpp)
  set_target_properties(feed_authority_cli PROPERTIES OUTPUT_NAME "feed-authority")
  target_link_libraries(feed_authority_cli PRIVATE feed_authority)
  target_include_directories(feed_authority_cli PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/tools")
  feed_authority_apply_strict_options(feed_authority_cli)
endif()

# ---------------------------------------------------------------------------
# Install / export
# ---------------------------------------------------------------------------
install(TARGETS feed_authority
  EXPORT FeedAuthorityTargets
  RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}"
  LIBRARY DESTINATION "${CMAKE_INSTALL_LIBDIR}"
  ARCHIVE DESTINATION "${CMAKE_INSTALL_LIBDIR}"
  INCLUDES DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}")

if(FEED_AUTHORITY_BUILD_TOOLS)
  install(TARGETS feed_authority_cli
    RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}")
endif()

install(DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/include/feed_authority"
  DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}"
  FILES_MATCHING PATTERN "*.hpp")
install(FILES "${FEED_AUTHORITY_GENERATED_INCLUDE_DIR}/feed_authority/version.hpp"
  DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/feed_authority")

set(FEED_AUTHORITY_INSTALL_CMAKEDIR "${CMAKE_INSTALL_LIBDIR}/cmake/FeedAuthority")

install(EXPORT FeedAuthorityTargets
  NAMESPACE FeedAuthority::
  FILE FeedAuthorityTargets.cmake
  DESTINATION "${FEED_AUTHORITY_INSTALL_CMAKEDIR}")

configure_package_config_file(
  "${CMAKE_CURRENT_SOURCE_DIR}/cmake/FeedAuthorityConfig.cmake.in"
  "${CMAKE_CURRENT_BINARY_DIR}/FeedAuthorityConfig.cmake"
  INSTALL_DESTINATION "${FEED_AUTHORITY_INSTALL_CMAKEDIR}")

write_basic_package_version_file(
  "${CMAKE_CURRENT_BINARY_DIR}/FeedAuthorityConfigVersion.cmake"
  VERSION "${PROJECT_VERSION}"
  COMPATIBILITY SameMajorVersion)

install(FILES
  "${CMAKE_CURRENT_BINARY_DIR}/FeedAuthorityConfig.cmake"
  "${CMAKE_CURRENT_BINARY_DIR}/FeedAuthorityConfigVersion.cmake"
  DESTINATION "${FEED_AUTHORITY_INSTALL_CMAKEDIR}")

install(FILES "${CMAKE_CURRENT_SOURCE_DIR}/LICENSE" "${CMAKE_CURRENT_SOURCE_DIR}/NOTICE"
  DESTINATION "${CMAKE_INSTALL_DATADIR}/FeedAuthority")

# ---------------------------------------------------------------------------
# Subprojects
# ---------------------------------------------------------------------------
if(FEED_AUTHORITY_IS_TOP_LEVEL AND (FEED_AUTHORITY_BUILD_TESTS OR FEED_AUTHORITY_BUILD_EXAMPLES))
  enable_testing()
endif()

if(FEED_AUTHORITY_BUILD_EXAMPLES)
  add_subdirectory(examples)
endif()

if(FEED_AUTHORITY_BUILD_BENCHMARKS)
  add_subdirectory(bench)
endif()

if(FEED_AUTHORITY_BUILD_TESTS)
  add_subdirectory(tests)
endif()
