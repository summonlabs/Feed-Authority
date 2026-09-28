#pragma once

// Independent-process helpers for the multiprocess and crash-recovery tests.
//
// These spawn real operating-system processes. Nothing here simulates process death
// with a thread, and nothing here establishes a fact by waiting: the readiness loops
// below can only fail, never turn a missing fact into a pass.

#include <cstdint>
#include <filesystem>
#include <map>
#include <string>
#include <vector>

namespace fa_test {

/// Absolute path of the probe executable, injected by the build.
std::string probe_path();

/// Absolute path of the installed-style command line tool, injected by the build.
std::string cli_path();

/// Starts a process that runs to completion with its output redirected to files,
/// and returns its exit code. Redirecting to files rather than pipes keeps the
/// result independent of the environment's pipe policy.
bool run_captured(const std::string& executable, const std::vector<std::string>& arguments,
                  const std::filesystem::path& output_file, int& exit_code, std::string& error);

/// Starts a process and returns immediately with its process id.
bool spawn_nowait(const std::string& executable, const std::vector<std::string>& arguments,
                  const std::filesystem::path& output_file, std::uint64_t& pid, std::string& error);

/// Waits for a process to finish and returns its exit code.
bool spawn_wait(const std::string& executable, const std::vector<std::string>& arguments,
                const std::filesystem::path& output_file, int& exit_code, std::string& error);

/// Terminates a process non-interactively at the operating-system level.
bool terminate_process(std::uint64_t pid, std::string& error);

/// True while the process is still running.
bool process_is_running(std::uint64_t pid);

/// Polls for a file to appear and be non-empty. The attempt count is bounded and
/// the function never reports success for a file that is not there.
bool wait_for_file(const std::filesystem::path& path, int attempts, std::string& error);

std::vector<std::string> read_lines(const std::filesystem::path& path);
std::map<std::string, std::string> read_key_values(const std::filesystem::path& path);
std::uint64_t read_pid(const std::filesystem::path& path);

/// A unique scratch directory under the test binary directory, removed by
/// `remove_tree`.
std::filesystem::path scratch_directory(const std::string& name);

void remove_tree(const std::filesystem::path& path);

/// Writes a file, creating parents.
bool write_file(const std::filesystem::path& path, const std::string& content);

}  // namespace fa_test
