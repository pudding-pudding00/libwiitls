#include <stdint.h>
#include <string.h>

#include <psa/crypto.h>
#include <wiitls/wiitls.h>

#include "check.h"

WTLS_CHECK_DEFINE_COUNTERS;

static void test_psa_init_and_sha256(void) {
    CHECK_EQ_INT(psa_crypto_init(), PSA_SUCCESS);
    uint8_t h[32];
    size_t hl;
    CHECK_EQ_INT(psa_hash_compute(PSA_ALG_SHA_256, (const uint8_t *)"abc", 3, h, 32, &hl),
                 PSA_SUCCESS);
    CHECK_MEM(h, "\xba\x78\x16\xbf\x8f\x01\xcf\xea\x41\x41\x40\xde\x5d\xae\x22\x23"
                 "\xb0\x03\x61\xa3\x96\x17\x7a\x9c\xb4\x10\xff\x61\xf2\x00\x15\xad", 32);
}

static void test_strerror_known_and_unknown(void) {
    CHECK(strcmp(wtls_strerror(WTLS_ERR_CERT), "certificate verification failed") == 0);
    CHECK(strcmp(wtls_strerror(12345), "unknown error") == 0);
}

int main(void) {
    RUN(test_psa_init_and_sha256);
    RUN(test_strerror_known_and_unknown);
    return CHECK_DONE();
}
