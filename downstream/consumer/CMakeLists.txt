cmake_minimum_required(VERSION 3.21)

# Independent out-of-tree consumer of the installed Feed Authority package.
#
# This project is not part of the Feed Authority build tree: it is configured
# separately with CMAKE_PREFIX_PATH pointing at an install prefix, and it uses only
# the installed public headers and the exported FeedAuthority::feed_authority target.

project(FeedAuthorityConsumer
  VERSION 1.0.0
  DESCRIPTION "Out-of-tree consumer of the installed Feed Authority package"
  LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_package(FeedAuthority 1.0 REQUIRED)

add_executable(consumer main.cpp)
target_link_libraries(consumer PRIVATE FeedAuthority::feed_authority)

if(MSVC)
  target_compile_options(consumer PRIVATE /W4 /permissive- /utf-8 /WX)
else()
  target_compile_options(consumer PRIVATE -Wall -Wextra -Wpedantic -Werror)
endif()

# Runs the consumer through a real lifecycle: create a durable store, adopt a
# facility, evaluate, issue a grant, close, reopen, revalidate, verify, audit.
add_custom_target(run_consumer
  COMMAND consumer "${CMAKE_CURRENT_BINARY_DIR}/consumer-store"
  DEPENDS consumer
  COMMENT "Running the installed-package consumer lifecycle"
  VERBATIM)
