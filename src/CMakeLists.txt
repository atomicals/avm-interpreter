# Copyright (c) 2017 The Bitcoin developers

project(avmcore)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Default visibility is hidden on all targets.
set(CMAKE_C_VISIBILITY_PRESET hidden)
set(CMAKE_CXX_VISIBILITY_PRESET hidden)

option(BUILD_AVM_CLI "Build avm-cli" ON)
option(BUILD_LIBATOMICALSCONSENSUS "Build the atomicalsconsenus shared library" ON)
option(ENABLE_HARDENING "Harden the executables" ON)
option(ENABLE_REDUCE_EXPORTS "Reduce the amount of exported symbols" OFF)
option(ENABLE_STATIC_LIBGCC "Statically link libgcc" OFF)
option(ENABLE_STATIC_LIBSTDCXX "Statically link libstdc++" OFF)
option(ENABLE_GLIBC_BACK_COMPAT "Enable Glibc compatibility features" OFF)
option(ENABLE_WERROR "Promote some compiler warnings to errors" OFF)
option(ENABLE_CLANG_TIDY "Enable clang-tidy checks for AVM" OFF)
option(ENABLE_PROFILING "Select the profiling tool to use" OFF)

# If ccache is available, then use it.
find_program(CCACHE ccache)
if(CCACHE)
  message(STATUS "Using ccache: ${CCACHE}")
  set(CMAKE_C_COMPILER_LAUNCHER ${CCACHE})
  set(CMAKE_CXX_COMPILER_LAUNCHER ${CCACHE})
endif(CCACHE)

# Disable what we do not need for the native build.
include(NativeExecutable)
native_add_cmake_flags(
  "-DENABLE_QRCODE=OFF"
  "-DENABLE_UPNP=OFF"
  # Forward the current setting for clang-tidy
  "-DENABLE_CLANG_TIDY=${ENABLE_CLANG_TIDY}"
)

if(ENABLE_CLANG_TIDY)
  include(ClangTidy)
endif()

if(ENABLE_SANITIZERS)
  include(Sanitizers)
  enable_sanitizers(${ENABLE_SANITIZERS})
endif()

include(AddCompilerFlags)

# Prefer -g3, defaults to -g if unavailable
foreach(LANGUAGE C CXX)
  set(COMPILER_DEBUG_LEVEL -g)
  check_compiler_flags(G3_IS_SUPPORTED ${LANGUAGE} -g3)
  if(${G3_IS_SUPPORTED})
    set(COMPILER_DEBUG_LEVEL -g3)
  endif()
  add_compile_options_to_configuration_for_language(Debug ${LANGUAGE} ${COMPILER_DEBUG_LEVEL})
endforeach()

# Define the debugging symbols DEBUG and DEBUG_LOCKORDER when the Debug build
# type is selected.
add_compile_definitions_to_configuration(Debug DEBUG DEBUG_LOCKORDER)

# Add -ftrapv when building in Debug
add_compile_options_to_configuration(Debug -ftrapv)

# All versions of gcc that we commonly use for building are subject to bug
# https://gcc.gnu.org/bugzilla/show_bug.cgi?id=90348. To work around that, set
# -fstack-reuse=none for all gcc builds. (Only gcc understands this flag)
if(NOT ENABLE_CLANG_TIDY)
  add_compiler_flags(-fstack-reuse=none)
endif()

# Windows specific flags
if(${CMAKE_SYSTEM_NAME} MATCHES "Windows")
  # Ensure that WINDRES_PREPROC is enabled when using windres.
  list(APPEND CMAKE_RC_FLAGS "-DWINDRES_PREPROC")

  # Build all static so there is no dll file to distribute.
  add_linker_flags(-static)

  # _WIN32_WINNT_WIN7
  add_compile_definitions(_WIN32_WINNT=0x0601)
endif()

if(${CMAKE_SYSTEM_NAME} MATCHES "Darwin")
  add_compile_definitions(MAC_OSX OBJC_OLD_DISPATCH_PROTOTYPES=0)
  add_linker_flags(-Wl,-dead_strip_dylibs)
endif()

if(ENABLE_REDUCE_EXPORTS)
  # Default visibility is set by CMAKE_<LANG>_VISIBILITY_PRESET, but this
  # doesn't tell if the visibility set is effective.
  # Check if the flag -fvisibility=hidden is supported, as using the hidden
  # visibility is a requirement to reduce exports.
  check_compiler_flags(HAS_CXX_FVISIBILITY CXX -fvisibility=hidden)
  if(NOT HAS_CXX_FVISIBILITY)
    message(FATAL_ERROR "Cannot set default symbol visibility. Use -DENABLE_REDUCE_EXPORTS=OFF.")
  endif()

  # Also hide symbols from static libraries
  add_linker_flags(-Wl,--exclude-libs,ALL)
endif()

# Enable statically linking libgcc
if(ENABLE_STATIC_LIBGCC)
  add_linker_flags(-static-libgcc)
endif()

# Enable statically linking libstdc++
if(ENABLE_STATIC_LIBSTDCXX)
  add_linker_flags(-static-libstdc++)
endif()

set(CMAKE_POSITION_INDEPENDENT_CODE ON)

if(ENABLE_HARDENING)
  # Enable stack protection
  add_cxx_compiler_flags(-fstack-protector-all -Wstack-protector)

  # Enable some buffer overflow checking, except in -O0 builds which
  # do not support them
  add_compiler_flags(-U_FORTIFY_SOURCE)
  add_compile_options($<$<NOT:$<CONFIG:Debug>>:-D_FORTIFY_SOURCE=2>)

  # Enable ASLR (these flags are primarily targeting MinGw)
  add_linker_flags(-Wl,--dynamicbase -Wl,--nxcompat -Wl,--high-entropy-va)

  # Make the relocated sections read-only
  add_linker_flags(-Wl,-z,relro -Wl,-z,now)

  # CMake provides the POSITION_INDEPENDENT_CODE property to set PIC/PIE.
  # Unfortunately setting the -pie linker flag this way require CMake >= 3.14,
  # which is not widely distributed at the time of writing.
  # FIXME: remove the fallback case when cmake >= 3.14 get enforced.
  if(POLICY CMP0083)
    cmake_policy(SET CMP0083 NEW)
    include(CheckPIESupported)
    check_pie_supported()
  elseif(NOT ${CMAKE_SYSTEM_NAME} MATCHES "Windows")
    check_linker_flag(PIE_IS_SUPPORTED -pie)
    if(${PIE_IS_SUPPORTED})
      add_link_options($<$<STREQUAL:$<TARGET_PROPERTY:TYPE>,EXECUTABLE>:-pie>)
    endif()
  endif()

  if(${CMAKE_SYSTEM_NAME} MATCHES "Windows")
    # MinGw provides its own libssp for stack smashing protection
    link_libraries(ssp)
  endif()
endif()

if(ENABLE_PROFILING MATCHES "gprof")
  message(STATUS "Enable profiling with gprof")

  # -pg is incompatible with -pie. Since hardening and profiling together
  # doesn't make sense, we simply make them mutually exclusive here.
  # Additionally, hardened toolchains may force -pie by default, in which
  # case it needs to be turned off with -no-pie.
  if(ENABLE_HARDENING)
    message(FATAL_ERROR "Profiling with gprof requires disabling hardening with -DENABLE_HARDENING=OFF.")
  endif()
  add_linker_flags(-no-pie)

  add_compiler_flags(-pg)
  add_linker_flags(-pg)
endif()

if(CMAKE_SYSTEM_PROCESSOR STREQUAL "arm" AND CMAKE_CXX_COMPILER_ID STREQUAL "GNU" AND CMAKE_CXX_COMPILER_VERSION VERSION_GREATER_EQUAL 7)
	# GCC >= 7 for ARM gives a warning about parameter passing format being changed.
	# See https://gcc.gnu.org/bugzilla/show_bug.cgi?id=77728
	# See https://gcc.gnu.org/gcc-7/changes.html
	add_compiler_flags(-Wno-psabi)
endif()

# Create a target for OpenSSL
include(BrewHelper)
find_brew_prefix(OPENSSL_ROOT_DIR openssl)
find_package(OpenSSL REQUIRED)

# libtool style configure
add_subdirectory(config)

# Enable LFS (Large File Support) on targets that don't have it natively.
# This should be defined before the libraries are included as leveldb need the
# definition to be set.
if(NOT HAVE_LARGE_FILE_SUPPORT)
  add_compile_definitions(_FILE_OFFSET_BITS=64)
  add_linker_flags(-Wl,--large-address-aware)
endif()

if(ENABLE_GLIBC_BACK_COMPAT)
  # Wrap some glibc functions with ours
  add_linker_flags(-Wl,--wrap=__divmoddi4)
  add_linker_flags(-Wl,--wrap=log2f)

  if(NOT HAVE_LARGE_FILE_SUPPORT)
    add_linker_flags(-Wl,--wrap=fcntl -Wl,--wrap=fcntl64)
  endif()
endif()

if(USE_JEMALLOC_EXPERIMENTAL)
  find_package(Jemalloc REQUIRED)
  link_libraries(Jemalloc::jemalloc)
endif()


# Make sure that all the global compiler and linker flags are set BEFORE
# including the libraries so they apply as needed.

# libraries
add_subdirectory(crypto)
add_subdirectory(secp256k1)
add_subdirectory(univalue)

# Enable warnings (after libraries, so we don't generate warnings for those)
add_c_compiler_flags(-Wnested-externs -Wstrict-prototypes)
add_compiler_flags(
  -Wall
  -Warray-bounds
  -Wcast-align
  -Wdisabled-optimization
  -Wextra
  -Wformat
  -Winit-self
  -Winvalid-pch
  -Wlogical-op
  -Wmaybe-uninitialized
  -Wmissing-braces
  -Wmissing-include-dirs
  -Wnormalized
  -Woverloaded-virtual
  -Wpacked
  -Wpointer-arith
  -Wrange-loop-analysis
  -Wredundant-decls
  -Wredundant-move
  -Wshadow
  -Wthread-safety-analysis
  -Wuninitialized
  -Wunsafe-loop-optimizations
  -Wvector-operation-performance
  -Wvla
)
# The -Wformat-security option is dependent on -Wformat on GCC. Check for it
# together with -Wformat to avoid a warning.
add_compiler_flag_group(-Wformat -Wformat-security)

option(EXTRA_WARNINGS "Enable extra warnings" OFF)
if(EXTRA_WARNINGS)
  add_compiler_flags(
    -Wconversion
    -Wdouble-promotion
    -Wlong-long
    -Wmissing-declarations
    -Wnon-virtual-dtor
    -Wsuggest-attribute=const
    -Wsuggest-attribute=noreturn
    -Wsuggest-attribute=pure
    -Wsuggest-final-methods
    -Wsuggest-final-types
    -Wsuggest-override
    -Wunused
    -Wuseless-cast
  )
else()
  add_compiler_flags(-Wno-unused-parameter)
endif()

if(ENABLE_WERROR)
  add_compiler_flags(
    -Werror=vla
    -Werror=thread-safety-analysis
  )
endif()


# Find the git root, and returns the full path to the .git/logs/HEAD file if
# it exists.
function(find_git_head_logs_file RESULT)
  find_package(Git)
  if(GIT_FOUND)
    execute_process(
      COMMAND "${GIT_EXECUTABLE}" "rev-parse" "--show-toplevel"
      WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
      OUTPUT_VARIABLE GIT_ROOT
      RESULT_VARIABLE GIT_RESULT
      OUTPUT_STRIP_TRAILING_WHITESPACE
      ERROR_QUIET
    )

    if(GIT_RESULT EQUAL 0)
      set(GIT_LOGS_DIR "${GIT_ROOT}/.git/logs")
      set(GIT_HEAD_LOGS_FILE "${GIT_LOGS_DIR}/HEAD")
      # If the .git/logs/HEAD does not exist, create it
      if(NOT EXISTS "${GIT_HEAD_LOGS_FILE}")
        file(MAKE_DIRECTORY "${GIT_LOGS_DIR}")
        file(TOUCH "${GIT_HEAD_LOGS_FILE}")
      endif()
      set(${RESULT} "${GIT_HEAD_LOGS_FILE}" PARENT_SCOPE)
    endif()
  endif()
endfunction()

find_git_head_logs_file(GIT_HEAD_LOGS_FILE)

set(OBJ_DIR "${CMAKE_CURRENT_BINARY_DIR}/obj")
file(MAKE_DIRECTORY "${OBJ_DIR}")
set(BUILD_HEADER "${OBJ_DIR}/build.h")
set(BUILD_HEADER_TMP "${BUILD_HEADER}.tmp")

add_custom_command(
  DEPENDS
    "${GIT_HEAD_LOGS_FILE}"
    "${CMAKE_SOURCE_DIR}/share/genbuild.sh"
  OUTPUT
    "${BUILD_HEADER}"
  COMMAND
    "${CMAKE_SOURCE_DIR}/share/genbuild.sh"
    "${BUILD_HEADER_TMP}"
    "${CMAKE_SOURCE_DIR}"
  COMMAND
    ${CMAKE_COMMAND} -E copy_if_different "${BUILD_HEADER_TMP}" "${BUILD_HEADER}"
  COMMAND
    ${CMAKE_COMMAND} -E remove "${BUILD_HEADER_TMP}"
)

# Because the source code is disorganised, we
# end up with a bunch of libraries without any apparent
# cohesive structure. This is inherited from Bitcoin Core
# and reflecting this.
# TODO: Improve the structure once cmake is rocking.

# Various completely unrelated features shared by all executables.
add_library(util
  clientversion.cpp
  compat/glibc_sanity.cpp
  compat/glibcxx_sanity.cpp
  compat/strnlen.cpp
  fs.cpp
  logging.cpp
  random.cpp
  support/cleanse.cpp
  support/lockedpool.cpp
  sync.cpp
  threadinterrupt.cpp
  uint256.cpp
  util/asmap.cpp
  util/moneystr.cpp
  util/saltedhashers.cpp
  util/system.cpp
  util/strencodings.cpp
  util/string.cpp
  util/threadnames.cpp
  util/time.cpp

  # obj/build.h
  "${BUILD_HEADER}"
)

target_compile_definitions(util PUBLIC HAVE_CONFIG_H HAVE_BUILD_INFO)
target_include_directories(util
  PUBLIC
    .
    # To access the config/ and obj/ directories
    ${CMAKE_CURRENT_BINARY_DIR}
)

if(ENABLE_GLIBC_BACK_COMPAT)
  target_sources(util PRIVATE compat/glibc_compat.cpp)
endif()

# Target specific configs
if(${CMAKE_SYSTEM_NAME} MATCHES "Windows")
  set(Boost_USE_STATIC_LIBS ON)
  set(Boost_USE_STATIC_RUNTIME ON)
  set(Boost_THREADAPI win32)

  find_package(SHLWAPI REQUIRED)
  # We cannot use the imported target here, because cmake will introduce an
  # -isystem compilation directive and cause the build to fail with MinGw.
  # This comes from a couple cmake bugs:
  #  - https://gitlab.kitware.com/cmake/cmake/issues/16291
  #  - https://gitlab.kitware.com/cmake/cmake/issues/19095
  # These issues are solved from cmake 3.14.1. Once this version is enforced,
  # the following can be used:
  # target_link_libraries(util SHLWAPI::shlwapi)
  target_link_libraries(util ${SHLWAPI_LIBRARIES})
  target_include_directories(util PUBLIC ${SHLWAPI_INCLUDE_DIRS})

  find_library(WS2_32_LIBRARY NAMES ws2_32)
  target_link_libraries(util ${WS2_32_LIBRARY})

  target_compile_definitions(util PUBLIC BOOST_THREAD_USE_LIB)
endif()

# Boost packages
set(BOOST_PACKAGES_REQUIRED chrono filesystem thread)

function(prepend var prefix)
  set(listVar "")
  foreach(f ${ARGN})
    list(APPEND listVar "${prefix}${f}")
  endforeach(f)
  set(${var} "${listVar}" PARENT_SCOPE)
endfunction(prepend)

prepend(BOOST_LIBRARIES "Boost::" ${BOOST_PACKAGES_REQUIRED})

find_package(Boost 1.58 REQUIRED ${BOOST_PACKAGES_REQUIRED})
target_link_libraries(util univalue crypto ${BOOST_LIBRARIES})

# Make sure boost uses std::atomic (it doesn't before 1.63)
target_compile_definitions(util PUBLIC BOOST_SP_USE_STD_ATOMIC BOOST_AC_USE_STD_ATOMIC)

# More completely unrelated features shared by all executables.
# Because nothing says this is different from util than "common"
add_library(common
  amount.cpp
  base58.cpp
  big_int.h
  config.cpp
  consensus/merkle.cpp
  coins.cpp
  compressor.cpp
  feerate.cpp
  core_read.cpp
  core_write.cpp
  hash.cpp
  key.cpp
  primitives/block.cpp
  script/serialize_number.h
  script/script_num.h
  
)

target_link_libraries(common util secp256k1)

# script library
add_library(script
  script/script_utils.cpp
  script/bitfield.cpp
  script/interpreter.cpp
  script/script.cpp
  script/script_error.cpp
  script/script_execution_context.cpp
  script/sigencoding.cpp
  script/sign.cpp
  script/standard.cpp
  script/script_num.cpp
  big_int.cpp
  merkleblock.cpp
  bloom.cpp
)

target_link_libraries(script common)

# libatomicalsconsensus
add_library(atomicalsconsensus
  script/script_utils.cpp
  arith_uint256.cpp
  big_int.cpp
  hash.cpp
  primitives/transaction.h
  primitives/transaction.cpp
  merkleblock.cpp
  primitives/block.cpp
  pubkey.cpp
  uint256.cpp
  util/strencodings.cpp
)

target_link_libraries(atomicalsconsensus script)

include(InstallationHelper)
if(BUILD_LIBATOMICALSCONSENSUS)
  target_compile_definitions(atomicalsconsensus
    PUBLIC
      BUILD_AVM_INTERNAL
      HAVE_CONSENSUS_LIB
  )

  install_shared_library(atomicalsconsensus
    script/atomicalsconsensus.cpp
    PUBLIC_HEADER script/atomicalsconsensus.h
  )
endif()
 
# This require libevent
set(EVENT_MIN_VERSION 2.0.22)
find_package(Event ${EVENT_MIN_VERSION} REQUIRED COMPONENTS event)
 
include(BinaryTest)
    
#  avm-cli
if(BUILD_AVM_CLI)
  add_executable(avm-cli avm-cli.cpp)
  if(${CMAKE_SYSTEM_NAME} MATCHES "Windows")
    target_sources(avm-cli PRIVATE avm-cli-res.rc)
  endif()

  target_link_libraries(avm-cli common Event::event)

  add_to_symbols_check(avm-cli)
  add_to_security_check(avm-cli)

  install_target(avm-cli)
endif()
 