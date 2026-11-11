/* Suite "entropy": the timebase-jitter source on real hardware (Task 3). */
#include <malloc.h>
#include <stdlib.h>
#include <string.h>

#include <ogc/lwp_watchdog.h>
#include <psa/crypto.h>
#include <wiitls/wiitls.h>

#include "check.h"
#include "plat/plat.h"
#include "suites.h"
#include "wtls_jitter.h"

static uint32_t sample_cb(void *ctx) {
    (void)ctx;
    return wtls_plat_jitter_sample();
}

static void hw_psa_init_with_jitter(void) {
    u64 t0 = gettime();
    CHECK_EQ_INT(psa_crypto_init(), PSA_SUCCESS);
    TLOG("    psa_crypto_init took %u ms\n", (unsigned)ticks_to_millisecs(gettime() - t0));
}

static void hw_random_differs(void) {
    uint8_t a[32], b[32];
    CHECK_EQ_INT(psa_generate_random(a, sizeof a), PSA_SUCCESS);
    CHECK_EQ_INT(psa_generate_random(b, sizeof b), PSA_SUCCESS);
    CHECK(memcmp(a, b, sizeof a) != 0);
}

static void hw_jitter_64k_passes_health_tests(void) {
    size_t len = 64 * 1024;
    uint8_t *buf = malloc(len);
    CHECK(buf != NULL);
    if (!buf) return;
    u64 t0 = gettime();
    CHECK_EQ_INT(wtls_jitter_collect(sample_cb, NULL, buf, len), WTLS_OK);
    TLOG("    64 KiB raw samples in %u ms\n", (unsigned)ticks_to_millisecs(gettime() - t0));
    wtls_plat_jitter_release();
    free(buf);
}

void wtls_suite_entropy(void) {
    RUN(hw_psa_init_with_jitter);
    RUN(hw_random_differs);
    RUN(hw_jitter_64k_passes_health_tests);
}
