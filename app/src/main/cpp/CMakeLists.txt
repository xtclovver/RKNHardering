cmake_minimum_required(VERSION 3.22.1)

project(native_curl_probe LANGUAGES C CXX)

include(FetchContent)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

set(BUILD_SHARED_LIBS OFF CACHE BOOL "" FORCE)
set(BUILD_STATIC_LIBS ON CACHE BOOL "" FORCE)
set(FETCHCONTENT_UPDATES_DISCONNECTED ON CACHE BOOL "" FORCE)

FetchContent_Declare(
    mbedtls
    URL ${CMAKE_CURRENT_SOURCE_DIR}/third_party/mbedtls-3.6.3.zip
    URL_HASH SHA256=2597afb8b0f3f552e27bb2bfa172350983aaee87c98ca35849fafc38d5c770ba
)

set(ENABLE_PROGRAMS OFF CACHE BOOL "" FORCE)
set(ENABLE_TESTING OFF CACHE BOOL "" FORCE)
set(MBEDTLS_FATAL_WARNINGS OFF CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(mbedtls)

# curl's FindMbedTLS.cmake expects find_package-style variables, but we vendor
# mbedTLS via FetchContent in the same build. Point curl at the in-tree targets.
set(MBEDTLS_USE_STATIC_LIBS ON CACHE BOOL "" FORCE)
set(MBEDTLS_INCLUDE_DIR "${mbedtls_SOURCE_DIR}/include" CACHE PATH "" FORCE)
set(MBEDTLS_LIBRARY "mbedtls" CACHE STRING "" FORCE)
set(MBEDX509_LIBRARY "mbedx509" CACHE STRING "" FORCE)
set(MBEDCRYPTO_LIBRARY "mbedcrypto" CACHE STRING "" FORCE)

FetchContent_Declare(
    curl
    URL ${CMAKE_CURRENT_SOURCE_DIR}/third_party/curl-8.19.0.zip
    URL_HASH SHA256=c2842525900529f866ac50ccb6dc175ed317fa1025b439dcf84d089100effdb9
)

set(BUILD_CURL_EXE OFF CACHE BOOL "" FORCE)
set(CURL_DISABLE_INSTALL ON CACHE BOOL "" FORCE)
set(CURL_ENABLE_SSL ON CACHE BOOL "" FORCE)
set(CURL_USE_MBEDTLS ON CACHE BOOL "" FORCE)
set(CURL_USE_OPENSSL OFF CACHE BOOL "" FORCE)
set(CURL_USE_LIBPSL OFF CACHE BOOL "" FORCE)
set(ENABLE_ARES OFF CACHE BOOL "" FORCE)
set(USE_NGHTTP2 OFF CACHE BOOL "" FORCE)
set(HTTP_ONLY ON CACHE BOOL "" FORCE)
set(CURL_DISABLE_PROXY ON CACHE BOOL "" FORCE)
set(BUILD_TESTING OFF CACHE BOOL "" FORCE)
set(CURL_BUILD_TESTS OFF CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(curl)

add_library(
    native_curl_probe
    SHARED
    native_curl_probe.cpp
)

target_include_directories(
    native_curl_probe
    PRIVATE
    ${curl_SOURCE_DIR}/include
    ${mbedtls_SOURCE_DIR}/include
)

target_compile_definitions(native_curl_probe PRIVATE CURL_STATICLIB)

target_link_libraries(
    native_curl_probe
    PRIVATE
    libcurl
    mbedcrypto
    mbedtls
    mbedx509
    log
)

add_library(
    native_signs_probe
    SHARED
    native_signs_probe.cpp
)

target_compile_options(
    native_signs_probe
    PRIVATE
    -fvisibility=hidden
    -fno-exceptions
    -fno-rtti
    -ffunction-sections
    -fdata-sections
    -Wall
    -Wextra
)

target_link_options(
    native_signs_probe
    PRIVATE
    -Wl,--gc-sections
)

target_link_libraries(
    native_signs_probe
    PRIVATE
    log
    dl
)
