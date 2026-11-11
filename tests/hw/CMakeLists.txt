# Wii hardware test runner: wtls_hwtest.dol
add_executable(wtls_hwtest
    main.c
    spike_ios.c
)
target_include_directories(wtls_hwtest PRIVATE ${CMAKE_CURRENT_SOURCE_DIR} ${PROJECT_SOURCE_DIR}/tests/common ${PROJECT_SOURCE_DIR}/src)
target_link_libraries(wtls_hwtest PRIVATE wiitls m)
target_compile_options(wtls_hwtest PRIVATE -Wall -Wextra)
ogc_create_dol(wtls_hwtest)
