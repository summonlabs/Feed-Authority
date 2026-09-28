# Configures, builds and runs the out-of-tree downstream consumer against an
# installed Feed Authority package. Invoked by CTest when
# FEED_AUTHORITY_DOWNSTREAM_PREFIX is set, and by the release verification steps.
#
# A nested CMake project needs a usable C++ toolchain in this process's environment.
# On Windows with MSVC that environment comes from vcvars64.bat, so this script
# locates it through vswhere (never through a hard-coded path) and runs the nested
# commands through a generated batch file. When no toolchain can be reached the check
# fails with the exact reason rather than reporting a pass it did not earn.

foreach(required FA_SOURCE_DIR FA_BINARY_DIR FA_PREFIX)
  if(NOT DEFINED ${required})
    message(FATAL_ERROR "RunDownstreamCheck.cmake requires -D${required}=...")
  endif()
endforeach()

if(NOT EXISTS "${FA_PREFIX}")
  message(FATAL_ERROR "the install prefix '${FA_PREFIX}' does not exist")
endif()

set(fa_vcvars "")
if(WIN32 AND DEFINED FA_VCVARS AND NOT FA_VCVARS STREQUAL "")
  set(fa_vcvars "${FA_VCVARS}")
elseif(WIN32)
  set(fa_program_files_x86 "$ENV{ProgramFiles\(x86\)}")
  set(fa_vswhere "${fa_program_files_x86}/Microsoft Visual Studio/Installer/vswhere.exe")
  if(EXISTS "${fa_vswhere}")
    execute_process(COMMAND "${fa_vswhere}" -latest -products * -requires
                            Microsoft.VisualStudio.Component.VC.Tools.x86.x64
                            -property installationPath
                    OUTPUT_VARIABLE fa_vs_path
                    OUTPUT_STRIP_TRAILING_WHITESPACE
                    ERROR_QUIET)
    if(NOT fa_vs_path STREQUAL "")
      set(fa_vcvars "${fa_vs_path}/VC/Auxiliary/Build/vcvars64.bat")
    endif()
  endif()
endif()

set(fa_run_serial 0)
function(fa_run description)
  math(EXPR fa_run_serial "${fa_run_serial} + 1")
  if(WIN32 AND NOT fa_vcvars STREQUAL "" AND EXISTS "${fa_vcvars}")
    set(fa_batch "${FA_BINARY_DIR}/fa-run-${fa_run_serial}.bat")
    set(fa_script "@echo off\r\ncall \"${fa_vcvars}\" >nul 2>&1\r\n")
    foreach(argument IN LISTS ARGN)
      set(fa_script "${fa_script}\"${argument}\" ")
    endforeach()
    set(fa_script "${fa_script}\r\nexit /b %ERRORLEVEL%\r\n")
    file(WRITE "${fa_batch}" "${fa_script}")
    execute_process(COMMAND cmd /c "${fa_batch}"
      RESULT_VARIABLE fa_result
      OUTPUT_VARIABLE fa_output
      ERROR_VARIABLE fa_output)
  else()
    execute_process(COMMAND ${ARGN}
      RESULT_VARIABLE fa_result
      OUTPUT_VARIABLE fa_output
      ERROR_VARIABLE fa_output)
  endif()

  if(NOT fa_result EQUAL 0)
    if(fa_output MATCHES "No CMAKE_CXX_COMPILER could be found" OR
       fa_output MATCHES "CMAKE_CXX_COMPILER not set")
      message(FATAL_ERROR
              "${description} could not run because no C++ compiler is reachable from this "
              "environment. Run the check from a developer environment (for MSVC, after "
              "vcvars64.bat) to execute the installed-package check for real.\n${fa_output}")
    endif()
    if(fa_output MATCHES "Could not find a package configuration file provided by \"FeedAuthority\"")
      message(FATAL_ERROR
              "${description} failed because no Feed Authority package was found under "
              "'${FA_PREFIX}'. Install the project into that prefix first, for example "
              "'cmake --install <build-dir> --prefix ${FA_PREFIX}'.\n${fa_output}")
    endif()
    message(FATAL_ERROR "${description} failed with exit ${fa_result}:\n${fa_output}")
  endif()
  set(fa_last_output "${fa_output}" PARENT_SCOPE)
endfunction()

file(REMOVE_RECURSE "${FA_BINARY_DIR}")
file(MAKE_DIRECTORY "${FA_BINARY_DIR}")

set(fa_configure "${CMAKE_COMMAND}"
  -S "${FA_SOURCE_DIR}/downstream/consumer"
  -B "${FA_BINARY_DIR}"
  "-DCMAKE_PREFIX_PATH=${FA_PREFIX}")
if(DEFINED FA_GENERATOR AND NOT FA_GENERATOR STREQUAL "")
  list(APPEND fa_configure -G "${FA_GENERATOR}")
endif()
if(DEFINED FA_CONFIG AND NOT FA_CONFIG STREQUAL "")
  list(APPEND fa_configure "-DCMAKE_BUILD_TYPE=${FA_CONFIG}")
endif()

# --config selects the configuration for multi-configuration generators (the Visual
# Studio generators) and is ignored by single-configuration ones, whose build type was
# set at configure time. The installed library was built in ${FA_CONFIG}, so the
# consumer must be built the same way or the C++ runtime library will not match.
set(fa_config_argument "")
if(DEFINED FA_CONFIG AND NOT FA_CONFIG STREQUAL "")
  set(fa_config_argument --config "${FA_CONFIG}")
endif()

fa_run("downstream configure" ${fa_configure})
fa_run("downstream build" "${CMAKE_COMMAND}" --build "${FA_BINARY_DIR}" ${fa_config_argument})
fa_run("downstream run" "${CMAKE_COMMAND}" --build "${FA_BINARY_DIR}" ${fa_config_argument}
       --target run_consumer)

message(STATUS "downstream consumer output:\n${fa_last_output}")
