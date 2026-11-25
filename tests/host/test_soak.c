/* Host entry for tests/common/soak_tests.c (run via run_with_server.py). */
#include "check.h"
#include "env.h"

WTLS_CHECK_DEFINE_COUNTERS;
wtls_test_env g_env = {"localhost", false, 0, 0};

void wtls_suite_soak(void);

int main(void) {
    wtls_suite_soak();
    return CHECK_DONE();
}
