/* wtls_init_start()/wtls_init_step(): entropy collected in slices before the
 * network is up, the same credit per raw sample as the classic wtls_init().
 * The host routes PSA's entropy through the jitter path with a test sampler,
 * so both paths run the code the Wii runs. */
#include <stdint.h>
#include <string.h>

#include <psa/crypto.h>
#include <wiitls/wiitls.h>

#include "check.h"
#include "plat/plat.h"
#include "wtls_entropy.h"
#include "wtls_jitter.h"

WTLS_CHECK_DEFINE_COUNTERS;

static size_t g_samples;

static uint32_t src_lcg(void *ctx) {
    uint32_t *x = ctx;
    g_samples++;
    *x = *x * 1664525u + 1013904223u;
    return *x >> 24;
}

static uint32_t src_constant(void *ctx) {
    (void)ctx;
    g_samples++;
    return 7;
}

static uint32_t g_lcg = 1;

static void arm(wtls_sample_fn fn) {
    wtls_entropy_set_test_sampler(fn, &g_lcg);
    wtls_jitter_reset_warmup(true);
    wtls_entropy_test_delivered = 0;
    g_samples = 0;
}

static size_t s_classic_delivered;

static void init_classic_unchanged(void) {
    arm(src_lcg);
    CHECK_EQ_INT(wtls_init(), WTLS_OK);
    s_classic_delivered = wtls_entropy_test_delivered;
    CHECK(s_classic_delivered > 0);
    /* Every delivered byte came out of a conditioned block: warm-up plus
     * 2 * 256 / WTLS_JITTER_BITS_PER_SAMPLE raw samples per 32 bytes. */
    size_t blocks = (s_classic_delivered + 31) / 32;
    CHECK(g_samples >= WTLS_JITTER_WARMUP + blocks * (2 * 256 / WTLS_JITTER_BITS_PER_SAMPLE));
    uint8_t a[32], b[32];
    CHECK_EQ_INT(psa_generate_random(a, sizeof a), PSA_SUCCESS);
    CHECK_EQ_INT(psa_generate_random(b, sizeof b), PSA_SUCCESS);
    CHECK(memcmp(a, b, sizeof a) != 0);
    wtls_shutdown();
}

static void init_step_same_entropy_credit(void) {
    arm(src_lcg);
    CHECK_EQ_INT(wtls_init_start(), WTLS_WANT_READ);
    int steps = 0;
    wtls_status st;
    while ((st = wtls_init_step(0)) == WTLS_WANT_READ && ++steps < 100000) {}
    CHECK_EQ_INT(st, WTLS_OK);
    CHECK(steps >= 2); /* budget 0: one slice of samples per call */
    CHECK_EQ_INT(wtls_entropy_test_delivered, s_classic_delivered);
    /* Pooled bytes are conditioned exactly like the inline ones. */
    size_t blocks = (s_classic_delivered + 31) / 32;
    CHECK(g_samples >= WTLS_JITTER_WARMUP + blocks * (2 * 256 / WTLS_JITTER_BITS_PER_SAMPLE));
    CHECK_EQ_INT(wtls_init_step(0), WTLS_OK); /* done: further calls are no-ops */
    CHECK_EQ_INT(wtls_init(), WTLS_OK);
    uint8_t r[16];
    CHECK_EQ_INT(psa_generate_random(r, sizeof r), PSA_SUCCESS);
    wtls_shutdown();
}

/* budget_ms bounds a step: a step must not run a whole block (512 IPC round
 * trips, ~40 ms on the Wii) or the warm-up in one go. */
static void init_step_slices_are_small(void) {
    arm(src_lcg);
    CHECK_EQ_INT(wtls_init_start(), WTLS_WANT_READ);
    CHECK_EQ_INT(wtls_init_step(0), WTLS_WANT_READ); /* first step: inside the warm-up */
    CHECK(g_samples > 0);
    CHECK(g_samples <= WTLS_ENTROPY_SLICE_SAMPLES);
    size_t before = g_samples;
    while (g_samples < WTLS_JITTER_WARMUP + 100) CHECK_EQ_INT(wtls_init_step(0), WTLS_WANT_READ);
    before = g_samples;
    CHECK_EQ_INT(wtls_init_step(0), WTLS_WANT_READ); /* inside a block */
    CHECK(g_samples - before <= WTLS_ENTROPY_SLICE_SAMPLES);
    wtls_status st;
    int steps = 0;
    while ((st = wtls_init_step(0)) == WTLS_WANT_READ && ++steps < 100000) {}
    CHECK_EQ_INT(st, WTLS_OK);
    CHECK_EQ_INT(wtls_entropy_test_delivered, s_classic_delivered);
    wtls_shutdown();
}

static void init_step_before_net_init(void) {
    arm(src_lcg);
    wtls_plat_test_net_down = true;
    CHECK_EQ_INT(wtls_init_start(), WTLS_WANT_READ); /* allowed without network */
    wtls_status st;
    int steps = 0;
    while ((st = wtls_init_step(1000)) == WTLS_WANT_READ && ++steps < 1000) {}
    CHECK_EQ_INT(st, WTLS_ERR_NET); /* entropy is ready, the network is not */
    size_t before = g_samples;
    CHECK_EQ_INT(wtls_init_step(1000), WTLS_ERR_NET); /* retryable, no new samples */
    CHECK_EQ_INT(g_samples, before);
    wtls_plat_test_net_down = false;
    CHECK_EQ_INT(wtls_init_step(0), WTLS_OK);
    CHECK_EQ_INT(g_samples, before); /* PSA was seeded from the pool */
    wtls_shutdown();
}

static void init_step_needs_start(void) {
    arm(src_lcg);
    CHECK_EQ_INT(wtls_init_step(0), WTLS_ERR_STATE);
}

static void init_step_fails_closed(void) {
    arm(src_constant);
    CHECK_EQ_INT(wtls_init_start(), WTLS_WANT_READ);
    wtls_status st;
    int steps = 0;
    while ((st = wtls_init_step(1000)) == WTLS_WANT_READ && ++steps < 1000) {}
    CHECK_EQ_INT(st, WTLS_ERR_ENTROPY);
    CHECK_EQ_INT(wtls_init_step(0), WTLS_ERR_STATE); /* the attempt is over */
    arm(src_lcg);
    CHECK_EQ_INT(wtls_init(), WTLS_OK);
    wtls_shutdown();
}

/* WP6: Dolphin's timing is deterministic (the IPC round trip alternates
 * between two timebase deltas: ~0 bits/sample, docs/dolphin.md) yet passes
 * RCT/APT. In an emulator both init paths therefore fail closed. */
static void entropy_refused_in_emulator(void) {
#if WTLS_DOLPHIN_DEV_ENTROPY
    SKIP("WTLS_DOLPHIN_DEV_ENTROPY lets it run");
    return;
#endif
    arm(src_lcg);
    wtls_plat_test_emulated = true;
    CHECK_EQ_INT(wtls_init(), WTLS_ERR_ENTROPY);
    CHECK_EQ_INT(wtls_init_start(), WTLS_WANT_READ);
    CHECK_EQ_INT(wtls_init_step(1000), WTLS_ERR_ENTROPY);
    CHECK_EQ_INT(wtls_entropy_test_delivered, 0);
    wtls_plat_test_emulated = false;
    CHECK_EQ_INT(wtls_init(), WTLS_OK);
    wtls_shutdown();
}

int main(void) {
    RUN(init_classic_unchanged);
    RUN(init_step_same_entropy_credit);
    RUN(init_step_slices_are_small);
    RUN(init_step_before_net_init);
    RUN(init_step_needs_start);
    RUN(init_step_fails_closed);
    RUN(entropy_refused_in_emulator);
    wtls_entropy_set_test_sampler(NULL, NULL);
    return CHECK_DONE();
}
