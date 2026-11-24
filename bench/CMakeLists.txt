# Wii benchmark runner: wtls_bench.dol (the host run is test_bench in the root CMakeLists).
add_executable(wtls_bench main.c bench_core.c psa_prof.c)
target_include_directories(wtls_bench PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}
    ${PROJECT_SOURCE_DIR}/tests/common ${PROJECT_SOURCE_DIR}/tests/hw ${PROJECT_SOURCE_DIR}/src)
target_compile_definitions(wtls_bench PRIVATE WTLS_PLATFORM_OGC)
target_link_libraries(wtls_bench PRIVATE wiitls m)
wtls_bench_wrap(wtls_bench)
target_compile_options(wtls_bench PRIVATE -Wall -Wextra)
ogc_create_dol(wtls_bench)
