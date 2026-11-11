#include <stdint.h>
#include <string.h>

#include <wiitls/wiitls.h>

#include "check.h"
#include "wtls_jitter.h"

WTLS_CHECK_DEFINE_COUNTERS;

static uint32_t src_constant(void *ctx) {
    (void)ctx;
    return 7;
}

/* Deterministic 90 % 0x10 / 10 % 0x11. Runs of 9 equal values: passes RCT, fails APT. */
static uint32_t src_two_value(void *ctx) {
    uint32_t *i = ctx;
    return ((*i)++ % 10 == 9) ? 0x11 : 0x10;
}

static uint32_t src_lcg(void *ctx) {
    uint32_t *x = ctx;
    *x = *x * 1664525u + 1013904223u;
    return *x >> 24;
}

static uint32_t src_counter(void *ctx) {
    uint32_t *i = ctx;
    uint32_t v = 0x100u * (*i + 1) + *i;
    (*i)++;
    return v;
}

static uint8_t buf[4096];

static void test_constant_source_fails_rct(void) {
    CHECK_EQ_INT(wtls_jitter_collect(src_constant, NULL, buf, 1024), WTLS_ERR_ENTROPY);
}

static void test_two_value_source_fails_apt(void) {
    uint32_t i = 0;
    CHECK_EQ_INT(wtls_jitter_collect(src_two_value, &i, buf, 1024), WTLS_ERR_ENTROPY);
}

static void test_lcg_source_passes(void) {
    uint32_t x = 12345;
    memset(buf, 0, sizeof buf);
    CHECK_EQ_INT(wtls_jitter_collect(src_lcg, &x, buf, 1024), WTLS_OK);
    int distinct = 0;
    for (size_t k = 1; k < 1024; k++) distinct |= buf[k] != buf[0];
    CHECK(distinct);
}

static void test_output_is_low_byte(void) {
    uint32_t i = 0;
    wtls_jitter_reset_warmup(false);
    CHECK_EQ_INT(wtls_jitter_collect(src_counter, &i, buf, 256), WTLS_OK);
    uint8_t want[256];
    for (int k = 0; k < 256; k++) want[k] = (uint8_t)k;
    CHECK_MEM(buf, want, 256);
}

static void test_warmup_discards_1024_samples_once(void) {
    uint32_t i = 0;
    wtls_jitter_reset_warmup(true);
    CHECK_EQ_INT(wtls_jitter_collect(src_counter, &i, buf, 4), WTLS_OK);
    CHECK_EQ_INT(i, 1024 + 4);
    CHECK_EQ_INT(wtls_jitter_collect(src_counter, &i, buf, 4), WTLS_OK);
    CHECK_EQ_INT(i, 1024 + 8);
}

/* Conditioned output: full length, not a copy of the raw bytes, fail-closed on bad sources. */
static void test_conditioned_fills_any_length(void) {
    uint32_t x = 99;
    uint8_t out[70];
    memset(out, 0, sizeof out);
    CHECK_EQ_INT(wtls_jitter_conditioned(src_lcg, &x, out, sizeof out), WTLS_OK);
    int nonzero_tail = 0;
    for (size_t k = 64; k < sizeof out; k++) nonzero_tail |= out[k];
    CHECK(nonzero_tail);
    CHECK(memcmp(out, out + 32, 32) != 0);
}

static void test_conditioned_fails_closed(void) {
    uint8_t out[32];
    CHECK_EQ_INT(wtls_jitter_conditioned(src_constant, NULL, out, sizeof out), WTLS_ERR_ENTROPY);
}

int main(void) {
    wtls_jitter_reset_warmup(false);
    RUN(test_constant_source_fails_rct);
    RUN(test_two_value_source_fails_apt);
    RUN(test_lcg_source_passes);
    RUN(test_output_is_low_byte);
    RUN(test_warmup_discards_1024_samples_once);
    RUN(test_conditioned_fills_any_length);
    RUN(test_conditioned_fails_closed);
    return CHECK_DONE();
}
