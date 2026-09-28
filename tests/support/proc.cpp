#include "proc.hpp"

#include <chrono>
#include <cstdio>
#include <fstream>
#include <sstream>
#include <thread>
#include <utility>

#if defined(_WIN32)
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#else
#include <csignal>
#include <spawn.h>
#include <sys/wait.h>
#include <unistd.h>
extern char** environ;
#endif

namespace fa_test {
namespace {

std::string quote_argument(const std::string& argument) {
  std::string out = "\"";
  for (const char character : argument) {
    if (character == '"') {
      out += "\\\"";
    } else {
      out.push_back(character);
    }
  }
  out += "\"";
  return out;
}

}  // namespace

std::string probe_path() { return FA_PROBE_EXECUTABLE; }

std::string cli_path() {
#ifdef FA_CLI_EXECUTABLE
  return FA_CLI_EXECUTABLE;
#else
  return std::string();
#endif
}

bool write_file(const std::filesystem::path& path, const std::string& content) {
  std::error_code error;
  if (path.has_parent_path()) {
    std::filesystem::create_directories(path.parent_path(), error);
  }
  std::ofstream stream(path, std::ios::binary | std::ios::trunc);
  if (!stream) {
    return false;
  }
  stream.write(content.data(), static_cast<std::streamsize>(content.size()));
  return stream.good();
}

#if defined(_WIN32)

bool launch(const std::string& executable, const std::vector<std::string>& arguments,
            const std::filesystem::path& output_file, bool wait, int& exit_code,
            std::uint64_t& pid, std::string& error) {
  std::string command = quote_argument(executable);
  for (const std::string& argument : arguments) {
    command += " ";
    command += quote_argument(argument);
  }

  SECURITY_ATTRIBUTES attributes{};
  attributes.nLength = sizeof(attributes);
  attributes.bInheritHandle = TRUE;
  HANDLE output = CreateFileW(output_file.native().c_str(), GENERIC_WRITE,
                              FILE_SHARE_READ | FILE_SHARE_WRITE, &attributes, CREATE_ALWAYS,
                              FILE_ATTRIBUTE_NORMAL, nullptr);
  if (output == INVALID_HANDLE_VALUE) {
    error = "the output file could not be created";
    return false;
  }

  STARTUPINFOW startup{};
  startup.cb = sizeof(startup);
  startup.dwFlags = STARTF_USESTDHANDLES;
  startup.hStdOutput = output;
  startup.hStdError = output;
  startup.hStdInput = nullptr;

  PROCESS_INFORMATION information{};
  std::wstring wide_command(command.begin(), command.end());
  std::vector<wchar_t> buffer(wide_command.begin(), wide_command.end());
  buffer.push_back(L'\0');
  const BOOL created = CreateProcessW(nullptr, buffer.data(), nullptr, nullptr, TRUE, 0, nullptr,
                                      nullptr, &startup, &information);
  CloseHandle(output);
  if (created == 0) {
    error = "the process could not be created";
    return false;
  }
  pid = information.dwProcessId;
  if (wait) {
    WaitForSingleObject(information.hProcess, INFINITE);
    DWORD code = 0;
    GetExitCodeProcess(information.hProcess, &code);
    exit_code = static_cast<int>(code);
  }
  CloseHandle(information.hThread);
  CloseHandle(information.hProcess);
  return true;
}

bool terminate_process(std::uint64_t pid, std::string& error) {
  HANDLE process = OpenProcess(PROCESS_TERMINATE | SYNCHRONIZE, FALSE, static_cast<DWORD>(pid));
  if (process == nullptr) {
    error = "the process could not be opened for termination";
    return false;
  }
  const BOOL terminated = TerminateProcess(process, 3);
  if (terminated != 0) {
    WaitForSingleObject(process, INFINITE);
  }
  CloseHandle(process);
  if (terminated == 0) {
    error = "the process could not be terminated";
    return false;
  }
  return true;
}

bool process_is_running(std::uint64_t pid) {
  HANDLE process = OpenProcess(SYNCHRONIZE, FALSE, static_cast<DWORD>(pid));
  if (process == nullptr) {
    return false;
  }
  const DWORD state = WaitForSingleObject(process, 0);
  CloseHandle(process);
  return state == WAIT_TIMEOUT;
}

#else

bool launch(const std::string& executable, const std::vector<std::string>& arguments,
            const std::filesystem::path& output_file, bool wait, int& exit_code,
            std::uint64_t& pid, std::string& error) {
  std::vector<std::string> storage;
  storage.push_back(executable);
  for (const std::string& argument : arguments) {
    storage.push_back(argument);
  }
  std::vector<char*> argv;
  argv.reserve(storage.size() + 1);
  for (std::string& item : storage) {
    argv.push_back(item.data());
  }
  argv.push_back(nullptr);

  const int descriptor = ::open(output_file.native().c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0644);
  if (descriptor < 0) {
    error = "the output file could not be created";
    return false;
  }
  posix_spawn_file_actions_t actions;
  posix_spawn_file_actions_init(&actions);
  posix_spawn_file_actions_adddup2(&actions, descriptor, STDOUT_FILENO);
  posix_spawn_file_actions_adddup2(&actions, descriptor, STDERR_FILENO);
  pid_t child = 0;
  const int spawned = posix_spawn(&child, executable.c_str(), &actions, nullptr, argv.data(), environ);
  posix_spawn_file_actions_destroy(&actions);
  ::close(descriptor);
  if (spawned != 0) {
    error = "the process could not be created";
    return false;
  }
  pid = static_cast<std::uint64_t>(child);
  if (wait) {
    int status = 0;
    if (::waitpid(child, &status, 0) < 0) {
      error = "the process could not be waited for";
      return false;
    }
    exit_code = WIFEXITED(status) ? WEXITSTATUS(status) : 128 + WTERMSIG(status);
  }
  return true;
}

bool terminate_process(std::uint64_t pid, std::string& error) {
  if (::kill(static_cast<pid_t>(pid), SIGKILL) != 0) {
    error = "the process could not be terminated";
    return false;
  }
  int status = 0;
  ::waitpid(static_cast<pid_t>(pid), &status, 0);
  return true;
}

bool process_is_running(std::uint64_t pid) {
  return ::kill(static_cast<pid_t>(pid), 0) == 0;
}

#endif

bool run_captured(const std::string& executable, const std::vector<std::string>& arguments,
                  const std::filesystem::path& output_file, int& exit_code, std::string& error) {
  std::uint64_t pid = 0;
  return launch(executable, arguments, output_file, true, exit_code, pid, error);
}

bool spawn_nowait(const std::string& executable, const std::vector<std::string>& arguments,
                  const std::filesystem::path& output_file, std::uint64_t& pid, std::string& error) {
  int exit_code = 0;
  return launch(executable, arguments, output_file, false, exit_code, pid, error);
}

bool spawn_wait(const std::string& executable, const std::vector<std::string>& arguments,
                const std::filesystem::path& output_file, int& exit_code, std::string& error) {
  std::uint64_t pid = 0;
  return launch(executable, arguments, output_file, true, exit_code, pid, error);
}

bool wait_for_file(const std::filesystem::path& path, int attempts, std::string& error) {
  for (int attempt = 0; attempt < attempts; ++attempt) {
    std::error_code code;
    if (std::filesystem::exists(path, code) && !code) {
      const auto size = std::filesystem::file_size(path, code);
      if (!code && size > 0) {
        return true;
      }
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(5));
  }
  error = "the file did not appear";
  return false;
}

std::vector<std::string> read_lines(const std::filesystem::path& path) {
  std::vector<std::string> lines;
  std::ifstream stream(path, std::ios::binary);
  std::string line;
  while (std::getline(stream, line)) {
    if (!line.empty() && line.back() == '\r') {
      line.pop_back();
    }
    lines.push_back(line);
  }
  return lines;
}

std::map<std::string, std::string> read_key_values(const std::filesystem::path& path) {
  std::map<std::string, std::string> values;
  for (const std::string& line : read_lines(path)) {
    const std::size_t equals = line.find('=');
    if (equals == std::string::npos) {
      continue;
    }
    values.emplace(line.substr(0, equals), line.substr(equals + 1));
  }
  return values;
}

std::uint64_t read_pid(const std::filesystem::path& path) {
  const std::map<std::string, std::string> values = read_key_values(path);
  const auto found = values.find("pid");
  if (found == values.end()) {
    return 0;
  }
  try {
    return std::stoull(found->second);
  } catch (...) {
    return 0;
  }
}

std::filesystem::path scratch_directory(const std::string& name) {
  const std::filesystem::path base = std::filesystem::current_path() / "fa-test-scratch";
  const std::filesystem::path path = base / name;
  std::error_code error;
  std::filesystem::remove_all(path, error);
  std::filesystem::create_directories(path, error);
  return path;
}

void remove_tree(const std::filesystem::path& path) {
  std::error_code error;
  std::filesystem::remove_all(path, error);
}

}  // namespace fa_test
