cmake_minimum_required(VERSION 3.20)
project(qbuem-auth VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

include(FetchContent)

# ── qbuem-stack ───────────────────────────────────────────────────────────────
set(QBUEM_BUILD_TESTS    OFF CACHE BOOL "" FORCE)
set(QBUEM_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
set(QBUEM_BUILD_BENCH    OFF CACHE BOOL "" FORCE)
set(QBUEM_INSTALL        OFF CACHE BOOL "" FORCE)

FetchContent_Declare(
    qbuem_stack
    GIT_REPOSITORY https://github.com/qbuem/qbuem-stack.git
    GIT_TAG        main
)
FetchContent_MakeAvailable(qbuem_stack)

# ── OpenSSL (OAuth HTTPS + TLS) ───────────────────────────────────────────────
find_package(OpenSSL REQUIRED)

# ── qbuem-auth (header-only) ──────────────────────────────────────────────────
# jwt.hpp        — HS256 JWT (qbuem::crypto only, no OpenSSL)
# https_client.hpp — HTTPS 클라이언트 (OpenSSL BIO)
# oauth.hpp      — Google / GitHub / Discord / Microsoft / Facebook / Naver / Kakao OAuth2
add_library(qbuem_auth INTERFACE)
target_include_directories(qbuem_auth INTERFACE ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_link_libraries(qbuem_auth INTERFACE
    qbuem-stack::crypto
    qbuem-stack::http
    OpenSSL::SSL
    OpenSSL::Crypto
)
add_library(qbuem-auth::auth ALIAS qbuem_auth)
