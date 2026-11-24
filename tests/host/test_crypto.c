/* Host entry for tests/common/crypto_tests.c. */
#include "check.h"

WTLS_CHECK_DEFINE_COUNTERS;

void wtls_suite_crypto(void);

int main(void) {
    wtls_suite_crypto();
    return CHECK_DONE();
}
