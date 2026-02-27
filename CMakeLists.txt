cmake_minimum_required(VERSION 3.21)
project(obfs4-cpp VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Find OpenSSL
find_package(OpenSSL 3.0 REQUIRED)

# Library sources
set(OBFS4_SOURCES
    src/crypto/field25519.cpp
    src/crypto/hash.cpp
    src/crypto/secretbox.cpp
    src/crypto/elligator2.cpp
    src/common/csrand.cpp
    src/common/drbg.cpp
    src/common/ntor.cpp
    src/common/replay_filter.cpp
    src/common/prob_dist.cpp
    src/transport/framing.cpp
    src/transport/packet.cpp
    src/transport/handshake.cpp
    src/transport/conn.cpp
    src/transport/state.cpp
)

add_library(obfs4 STATIC ${OBFS4_SOURCES})

target_include_directories(obfs4 PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
)

target_link_libraries(obfs4 PUBLIC OpenSSL::Crypto)

target_compile_options(obfs4 PRIVATE
    -Wall -Wextra -Wpedantic -Werror
)

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
    )

    add_executable(obfs4_tests ${TEST_SOURCES})
    target_link_libraries(obfs4_tests PRIVATE obfs4 Catch2::Catch2WithMain)

    include(CTest)
    include(Catch)
    catch_discover_tests(obfs4_tests)
endif()
