/* Host entry for tests/common/sig_tests.c. */
#include "check.h"

WTLS_CHECK_DEFINE_COUNTERS;

void wtls_suite_sig(void);

int main(void) {
    wtls_suite_sig();
    return CHECK_DONE();
}
