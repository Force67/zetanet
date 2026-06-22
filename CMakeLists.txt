# Copyright (C) 2026 Vincent Hengel.
# For licensing information see LICENSE at the root of this distribution.
#
# CMake build for Zetanet. Supports both the STL-compat configuration (the
# dependency-light path also used by CI, ZNET_USE_STL=ON) and the equilibrium
# configuration (ZNET_USE_STL=OFF), which consumes the vendored equilibrium
# submodule through its own CMake build.

cmake_minimum_required(VERSION 3.16)
project(Zetanet CXX C)

option(ZNET_USE_STL "Build with the STL compatibility layer instead of equilibrium" ON)
option(ZNET_BUILD_SAMPLES "Build the sample and integration-test executables" ON)
set(ZNET_CRYPTO_BACKEND "openssl" CACHE STRING "Crypto backend: openssl or mbedtls")
set_property(CACHE ZNET_CRYPTO_BACKEND PROPERTY STRINGS openssl mbedtls)

if(NOT ZNET_USE_STL AND
   NOT EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/vendor/equilibrium/CMakeLists.txt")
  message(FATAL_ERROR
    "ZNET_USE_STL=OFF requires the vendor/equilibrium submodule "
    "(git submodule update --init vendor/equilibrium vendor/fmtlib)")
endif()

if(NOT ZNET_CRYPTO_BACKEND STREQUAL "openssl" AND
   NOT ZNET_CRYPTO_BACKEND STREQUAL "mbedtls")
  message(FATAL_ERROR "ZNET_CRYPTO_BACKEND must be 'openssl' or 'mbedtls'")
endif()

# The equilibrium base headers require C++23 (premake passes -std=c++2b).
if(ZNET_USE_STL)
  set(CMAKE_CXX_STANDARD 20)
else()
  set(CMAKE_CXX_STANDARD 23)
endif()
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_C_STANDARD 11)
if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  set(CMAKE_BUILD_TYPE Debug CACHE STRING "" FORCE)
endif()

set(ZNET_ROOT "${CMAKE_CURRENT_SOURCE_DIR}")
set(ZNET_LZ4_DIR "${ZNET_ROOT}/vendor/lz4/lib")

# --- lz4 (also provides xxhash used by the serdes checksums) ---
file(GLOB ZNET_LZ4_SOURCES "${ZNET_LZ4_DIR}/*.c")
add_library(znet_lz4 STATIC ${ZNET_LZ4_SOURCES})
target_include_directories(znet_lz4 PUBLIC "${ZNET_LZ4_DIR}")

# --- equilibrium base (ZNET_USE_STL=OFF only) ---
if(NOT ZNET_USE_STL)
  # znet passes std::memory_order_* to base::Atomic; build base in its
  # documented std::atomic mode so the types line up.
  set(EQ_USE_STD_ATOMIC ON CACHE BOOL "" FORCE)
  set(EQ_BUILD_TESTS OFF CACHE BOOL "" FORCE)
  if(WIN32)
    # base's windows file utilities format with fmtlib, which zetanet vendors.
    set(EQ_FMTLIB_DIR "${ZNET_ROOT}/vendor/fmtlib" CACHE PATH "" FORCE)
  endif()
  add_subdirectory("${ZNET_ROOT}/vendor/equilibrium" equilibrium EXCLUDE_FROM_ALL)
endif()

# --- zetanet library ---
file(GLOB ZNET_SOURCES "${ZNET_ROOT}/znet/*.cc")
if(WIN32)
  list(FILTER ZNET_SOURCES EXCLUDE REGEX "z_socket_posix\\.cc$")
else()
  list(FILTER ZNET_SOURCES EXCLUDE REGEX "z_socket_win\\.cc$")
endif()

add_library(zetanet STATIC ${ZNET_SOURCES})
target_include_directories(zetanet PUBLIC "${ZNET_ROOT}" "${ZNET_LZ4_DIR}")
target_compile_definitions(zetanet PUBLIC
  COMPILE_DLL
  "PROJECT_NAME=\"Zetanet\"")
target_link_libraries(zetanet PUBLIC znet_lz4)
if(ZNET_USE_STL)
  target_compile_definitions(zetanet PUBLIC ZNET_USE_STL)
else()
  target_link_libraries(zetanet PUBLIC equilibrium::base)
endif()

if(WIN32)
  target_compile_definitions(zetanet PUBLIC OS_WIN NOMINMAX)
  if(MSVC)
    target_compile_options(zetanet PUBLIC "/utf-8")
  endif()
  target_link_libraries(zetanet PUBLIC ws2_32)
elseif(APPLE)
  target_compile_definitions(zetanet PUBLIC OS_MAC)
  find_package(Threads REQUIRED)
  target_link_libraries(zetanet PUBLIC Threads::Threads)
elseif(UNIX)
  target_compile_definitions(zetanet PUBLIC OS_LINUX)
  find_package(Threads REQUIRED)
  target_link_libraries(zetanet PUBLIC Threads::Threads)
endif()

# --- crypto backend ---
if(ZNET_CRYPTO_BACKEND STREQUAL "openssl")
  find_package(OpenSSL REQUIRED)
  target_compile_definitions(zetanet PUBLIC ZNET_CRYPTO_BACKEND_OPENSSL)
  target_link_libraries(zetanet PUBLIC OpenSSL::Crypto OpenSSL::SSL)
  if(WIN32)
    target_link_libraries(zetanet PUBLIC Crypt32)
  endif()
else()
  target_compile_definitions(zetanet PUBLIC ZNET_CRYPTO_BACKEND_MBEDTLS)
  find_library(MBEDTLS_LIB mbedtls)
  find_library(MBEDX509_LIB mbedx509)
  find_library(MBEDCRYPTO_LIB mbedcrypto)
  if(NOT MBEDTLS_LIB OR NOT MBEDX509_LIB OR NOT MBEDCRYPTO_LIB)
    message(FATAL_ERROR "mbedTLS libraries not found (mbedtls/mbedx509/mbedcrypto)")
  endif()
  target_link_libraries(zetanet PUBLIC ${MBEDTLS_LIB} ${MBEDX509_LIB} ${MBEDCRYPTO_LIB})
  if(WIN32)
    target_link_libraries(zetanet PUBLIC Crypt32)
  endif()
endif()

# --- samples and integration tests ---
if(ZNET_BUILD_SAMPLES)
  set(ZNET_SAMPLES
    simple_client
    simple_server
    p2p_demo
    file_transfer_demo
    handshake_integration
    mp_integration)
  foreach(sample ${ZNET_SAMPLES})
    set(sample_main "${ZNET_ROOT}/samples/${sample}/main.cc")
    if(EXISTS "${sample_main}")
      add_executable(${sample} "${sample_main}")
      target_link_libraries(${sample} PRIVATE zetanet)
    else()
      message(STATUS "Skipping missing sample: ${sample}")
    endif()
  endforeach()

  enable_testing()
  if(TARGET handshake_integration)
    add_test(NAME handshake_integration COMMAND handshake_integration)
  endif()
  if(TARGET mp_integration)
    add_test(NAME mp_integration COMMAND mp_integration)
  endif()
endif()
