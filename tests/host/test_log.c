/* Host entry for tests/common/log_tests.c (run via run_with_server.py). */
#include "check.h"
#include "env.h"

WTLS_CHECK_DEFINE_COUNTERS;
wtls_test_env g_env = {"localhost", false, 0};

void wtls_suite_log(void);

int main(void) {
    wtls_suite_log();
    return CHECK_DONE();
}
