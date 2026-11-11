/* Host entry for tests/common/tls_tests.c (run via run_with_server.py). */
#include "check.h"
#include "env.h"

WTLS_CHECK_DEFINE_COUNTERS;
/* A DNS name, so the default path resolves and verifies against DNS:localhost. */
wtls_test_env g_env = {"localhost", false, 0};

void wtls_suite_tls(void);

int main(void) {
    wtls_suite_tls();
    return CHECK_DONE();
}
