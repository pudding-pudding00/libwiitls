cmake_minimum_required(VERSION 3.20)
project(libwiitls VERSION 0.1.0 LANGUAGES C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS ON) # libogc headers need GNU extensions

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()

# ---------------------------------------------------------------------------
# Platform selection
if(NINTENDO_WII)
    set(WTLS_PLATFORM_DEFAULT ogc)
    set(WTLS_BUILD_TESTS_DEFAULT OFF)
else()
    set(WTLS_PLATFORM_DEFAULT host)
    set(WTLS_BUILD_TESTS_DEFAULT ON)
endif()
set(WTLS_PLATFORM ${WTLS_PLATFORM_DEFAULT} CACHE STRING "Platform layer: ogc or host")
set_property(CACHE WTLS_PLATFORM PROPERTY STRINGS ogc host)
option(WTLS_BUILD_TESTS "Build libwiitls tests" ${WTLS_BUILD_TESTS_DEFAULT})

# ---------------------------------------------------------------------------
# Mbed TLS 4.1.1 LTS (release tarball contains all generated files: no Python needed)
include(FetchContent)
set(ENABLE_PROGRAMS OFF CACHE BOOL "" FORCE)
set(ENABLE_TESTING OFF CACHE BOOL "" FORCE)
set(GEN_FILES OFF CACHE BOOL "" FORCE)
set(MBEDTLS_FATAL_WARNINGS OFF CACHE BOOL "" FORCE)
set(USE_SHARED_MBEDTLS_LIBRARY OFF CACHE BOOL "" FORCE)
set(USE_STATIC_MBEDTLS_LIBRARY ON CACHE BOOL "" FORCE)
set(MBEDTLS_CONFIG_FILE "${CMAKE_CURRENT_SOURCE_DIR}/config/wtls_mbedtls_config.h" CACHE FILEPATH "" FORCE)
set(TF_PSA_CRYPTO_CONFIG_FILE "${CMAKE_CURRENT_SOURCE_DIR}/config/wtls_crypto_config.h" CACHE FILEPATH "" FORCE)
FetchContent_Declare(mbedtls
    URL https://github.com/Mbed-TLS/mbedtls/releases/download/mbedtls-4.1.1/mbedtls-4.1.1.tar.bz2
    URL_HASH SHA256=3359a349e23db3d5536fcee032ae7b2ecbfc08972fab643089b5cbf2a375c98c
    DOWNLOAD_EXTRACT_TIMESTAMP TRUE
)
FetchContent_MakeAvailable(mbedtls)
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    foreach(t mbedtls mbedx509 tfpsacrypto)
        target_compile_definitions(${t} PUBLIC WTLS_DEBUG)
    endforeach()
endif()

# ---------------------------------------------------------------------------
# libwiitls
add_library(wiitls STATIC
    src/wtls_core.c
    src/wtls_entropy.c
    src/wtls_jitter.c
    src/plat/plat_common.c
    src/plat/plat_${WTLS_PLATFORM}.c
)
set_target_properties(wiitls PROPERTIES OUTPUT_NAME wiitls PREFIX lib)
target_include_directories(wiitls
    PUBLIC  ${CMAKE_CURRENT_SOURCE_DIR}/include
    PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_link_libraries(wiitls PUBLIC mbedtls mbedx509 tfpsacrypto)
# tfpsacrypto calls back into libwiitls (mbedtls_platform_get_entropy): close the
# static-link cycle so linkers that do not rescan archives still resolve it.
target_link_libraries(tfpsacrypto INTERFACE wiitls)
target_compile_options(wiitls PRIVATE -Wall -Wextra)
if(WTLS_PLATFORM STREQUAL "host")
    target_compile_definitions(wiitls PRIVATE WTLS_PLATFORM_HOST)
    if(WIN32)
        target_link_libraries(wiitls PUBLIC ws2_32 bcrypt)
    endif()
else()
    target_compile_definitions(wiitls PRIVATE WTLS_PLATFORM_OGC)
endif()

# ---------------------------------------------------------------------------
# Tests
if(WTLS_BUILD_TESTS AND WTLS_PLATFORM STREQUAL "host")
    enable_testing()
    function(wtls_host_test name)
        add_executable(${name} tests/host/${name}.c ${ARGN})
        target_include_directories(${name} PRIVATE tests/common src)
        target_link_libraries(${name} PRIVATE wiitls)
        add_test(NAME ${name} COMMAND ${name})
        set_tests_properties(${name} PROPERTIES PASS_REGULAR_EXPRESSION "WTLS-TEST DONE pass=[0-9]+ fail=0")
    endfunction()
    find_package(Python3 REQUIRED COMPONENTS Interpreter)
    # Test that needs tests/host/tls_test_server.py; the fixed ports force serial runs.
    function(wtls_host_server_test name)
        add_executable(${name} tests/host/${name}.c ${ARGN})
        target_include_directories(${name} PRIVATE tests/common src)
        target_link_libraries(${name} PRIVATE wiitls)
        add_test(NAME ${name}
                 COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/tests/host/run_with_server.py
                         $<TARGET_FILE:${name}>)
        set_tests_properties(${name} PROPERTIES
            PASS_REGULAR_EXPRESSION "WTLS-TEST DONE pass=[0-9]+ fail=0"
            RESOURCE_LOCK tls_test_server)
    endfunction()

    wtls_host_test(test_smoke)
    wtls_host_test(test_jitter)
    wtls_host_server_test(test_plat tests/common/plat_tests.c)
endif()

if(WTLS_PLATFORM STREQUAL "ogc")
    option(WTLS_BUILD_HWTEST "Build the Wii hardware test runner" ON)
    if(WTLS_BUILD_HWTEST)
        add_subdirectory(tests/hw)
    endif()
endif()
