/* Host entry for tests/common/ws_tests.c (run via run_with_server.py). */
#include "check.h"
#include "env.h"

WTLS_CHECK_DEFINE_COUNTERS;
wtls_test_env g_env = {"localhost", false, 0};

void wtls_suite_ws(void);

int main(void) {
    wtls_suite_ws();
    return CHECK_DONE();
}
