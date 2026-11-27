# Wii hardware test runner: wtls_hwtest.dol
add_executable(wtls_hwtest
    main.c
    spike_ios.c
    entropy_suite.c
    time_suite.c
    ${PROJECT_SOURCE_DIR}/tests/common/plat_tests.c
    ${PROJECT_SOURCE_DIR}/tests/common/crypto_tests.c
    ${PROJECT_SOURCE_DIR}/tests/common/tls_tests.c
    ${PROJECT_SOURCE_DIR}/tests/common/log_tests.c
    ${PROJECT_SOURCE_DIR}/tests/common/alloc_tests.c
    ${PROJECT_SOURCE_DIR}/tests/common/sig_tests.c
    ${PROJECT_SOURCE_DIR}/tests/common/http_tests.c
    ${PROJECT_SOURCE_DIR}/tests/common/soak_tests.c
    realworld_tests.c
)
target_include_directories(wtls_hwtest PRIVATE ${CMAKE_CURRENT_SOURCE_DIR} ${PROJECT_SOURCE_DIR}/tests/common ${PROJECT_SOURCE_DIR}/src)
# The suites call internal wiitls code (src/), compiled for the ogc platform.
target_compile_definitions(wtls_hwtest PRIVATE WTLS_PLATFORM_OGC WTLS_KEYLOG=$<BOOL:${WTLS_KEYLOG}>)
if(WTLS_GZIP)
    target_compile_definitions(wtls_hwtest PRIVATE WTLS_GZIP=1) # gzip cases in http_tests.c
endif()
target_compile_definitions(wtls_hwtest PRIVATE WTLS_HTTP2=$<BOOL:${WTLS_HTTP2}>)
target_link_libraries(wtls_hwtest PRIVATE wiitls m)
target_compile_options(wtls_hwtest PRIVATE -Wall -Wextra)
ogc_create_dol(wtls_hwtest)
