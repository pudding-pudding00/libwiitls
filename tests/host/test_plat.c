/* Host entry for tests/common/plat_tests.c (run via run_with_server.py). */
#include "check.h"
#include "env.h"

WTLS_CHECK_DEFINE_COUNTERS;
wtls_test_env g_env = {"127.0.0.1", false, 0};

void wtls_suite_plat(void);

int main(void) {
    wtls_suite_plat();
    return CHECK_DONE();
}
