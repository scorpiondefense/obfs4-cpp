cmake_minimum_required(VERSION 3.21)
project(obfs4-cpp VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Find OpenSSL
find_package(OpenSSL 3.0 REQUIRED)

# Options
option(OBFS4_ENABLE_MEEK "Enable meek_lite transport (requires cpp-httplib)" OFF)
option(BUILD_OBFS4PROXY "Build the obfs4proxy binary" OFF)

# Library sources
set(OBFS4_SOURCES
    # Crypto primitives
    src/crypto/field25519.cpp
    src/crypto/hash.cpp
    src/crypto/secretbox.cpp
    src/crypto/elligator2.cpp
    src/crypto/aes_ctr.cpp

    # Common utilities
    src/common/csrand.cpp
    src/common/drbg.cpp
    src/common/ntor.cpp
    src/common/replay_filter.cpp
    src/common/prob_dist.cpp
    src/common/uniform_dh.cpp
    src/common/log.cpp

    # Transport core (obfs4)
    src/transport/framing.cpp
    src/transport/packet.cpp
    src/transport/handshake.cpp
    src/transport/conn.cpp
    src/transport/state.cpp

    # Transport base
    src/transports/base.cpp

    # obfs2 protocol
    src/transports/obfs2/obfs2.cpp

    # obfs3 protocol
    src/transports/obfs3/obfs3.cpp

    # obfs4 transport wrapper
    src/transports/obfs4/obfs4.cpp

    # ScrambleSuit protocol (client-only)
    src/transports/scramblesuit/scramblesuit.cpp
    src/transports/scramblesuit/ticket_store.cpp

    # Transport registry
    src/transports/registry.cpp

    # SOCKS5 protocol
    src/proxy/socks5.cpp
)

# Conditionally add meek_lite sources
if(OBFS4_ENABLE_MEEK)
    list(APPEND OBFS4_SOURCES src/transports/meek_lite/meek_lite.cpp)
endif()

add_library(obfs4 STATIC ${OBFS4_SOURCES})

target_include_directories(obfs4 PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
)

target_link_libraries(obfs4 PUBLIC OpenSSL::Crypto)

# meek_lite requires OpenSSL::SSL and cpp-httplib
if(OBFS4_ENABLE_MEEK)
    target_link_libraries(obfs4 PUBLIC OpenSSL::SSL)
    target_compile_definitions(obfs4 PUBLIC OBFS4_ENABLE_MEEK)

    include(FetchContent)
    FetchContent_Declare(
        httplib
        GIT_REPOSITORY https://github.com/yhirose/cpp-httplib.git
        GIT_TAG v0.15.3
    )
    FetchContent_MakeAvailable(httplib)
    target_link_libraries(obfs4 PRIVATE httplib::httplib)
    target_compile_definitions(obfs4 PRIVATE CPPHTTPLIB_OPENSSL_SUPPORT)
endif()

target_compile_options(obfs4 PRIVATE
    -Wall -Wextra -Wpedantic -Werror
)

# obfs4proxy binary
if(BUILD_OBFS4PROXY)
    set(PROXY_SOURCES
        proxy/main.cpp
        proxy/pt_protocol.cpp
        proxy/pt_env.cpp
        proxy/socks5_server.cpp
        proxy/proxy_dialer.cpp
        proxy/client_handler.cpp
        proxy/server_handler.cpp
        proxy/copy_loop.cpp
        proxy/term_monitor.cpp
    )

    add_executable(obfs4proxy ${PROXY_SOURCES})
    target_include_directories(obfs4proxy PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${CMAKE_CURRENT_SOURCE_DIR}/proxy
    )
    target_link_libraries(obfs4proxy PRIVATE obfs4)
    target_compile_options(obfs4proxy PRIVATE
        -Wall -Wextra -Wpedantic -Werror
    )
endif()

# Tests
option(BUILD_TESTING "Build tests" ON)
if(BUILD_TESTING)
    include(FetchContent)
    FetchContent_Declare(
        Catch2
        GIT_REPOSITORY https://github.com/catchorg/Catch2.git
        GIT_TAG v3.5.2
    )
    FetchContent_MakeAvailable(Catch2)

    set(TEST_SOURCES
        tests/test_main.cpp
        tests/test_field25519.cpp
        tests/test_elligator2.cpp
        tests/test_secretbox.cpp
        tests/test_ntor.cpp
        tests/test_drbg.cpp
        tests/test_framing.cpp
        tests/test_handshake.cpp
        tests/test_obfs4.cpp
        tests/test_aes_ctr.cpp
        tests/test_uniform_dh.cpp
        tests/test_log.cpp
        tests/test_obfs2.cpp
        tests/test_obfs3.cpp
        tests/test_scramblesuit.cpp
        tests/test_socks5.cpp
        tests/test_registry.cpp
        tests/test_pt_env.cpp
    )

    add_executable(obfs4_tests ${TEST_SOURCES})
    target_link_libraries(obfs4_tests PRIVATE obfs4 Catch2::Catch2WithMain)

    include(CTest)
    include(Catch)
    catch_discover_tests(obfs4_tests)
endif()
