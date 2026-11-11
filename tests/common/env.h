/* Test environment shared by host and Wii runners. */
#ifndef WTLS_TEST_ENV_H
#define WTLS_TEST_ENV_H

#include <stdbool.h>
#include <stdint.h>

typedef struct {
    const char *server_host; /* host running tests/host/tls_test_server.py */
    bool is_hw;              /* running on real Wii hardware */
    int64_t pc_time;         /* Unix time of the PC when the run started (0 = unknown) */
} wtls_test_env;

extern wtls_test_env g_env;

#endif
