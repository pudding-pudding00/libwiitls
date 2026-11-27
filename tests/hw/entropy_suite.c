/* Suite "entropy": the timebase-jitter source on real hardware. */
#include <malloc.h>
#include <stdlib.h>
#include <string.h>

#include <network.h>
#include <ogc/ipc.h>
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
    TLOG("    emulator: %s\n", wtls_plat_is_dolphin() ? "yes (Dolphin)" : "no");
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
    wtls_jitter_stats st = {0};
    u64 t0 = gettime();
    CHECK_EQ_INT(wtls_jitter_collect_ex(sample_cb, NULL, buf, len, &st), WTLS_OK);
    TLOG("    64 KiB raw samples in %u ms (IOS %d, RCT max %u/%u, APT max %u/%u)\n",
         (unsigned)ticks_to_millisecs(gettime() - t0), (int)IOS_GetVersion(),
         st.max_rct, WTLS_RCT_CUTOFF, st.max_apt, WTLS_APT_CUTOFF);
    free(buf);
}

/* WP17: wtls_init_start()/wtls_init_step() against wtls_init(). Warm-up is
 * already done (first test), so both measure the same work. */
static void hw_init_step_timing(void) {
    mbedtls_psa_crypto_free(); /* PSA state of hw_psa_init_with_jitter */
    u64 t0 = gettime();
    CHECK_EQ_INT(wtls_init(), WTLS_OK);
    unsigned classic_us = (unsigned)ticks_to_microsecs(gettime() - t0);
    wtls_shutdown();

    t0 = gettime();
    CHECK_EQ_INT(wtls_init_start(), WTLS_WANT_READ);
    unsigned steps = 0, longest_us = 0, last_us = 0;
    wtls_status st;
    do {
        u64 s0 = gettime();
        st = wtls_init_step(5);
        last_us = (unsigned)ticks_to_microsecs(gettime() - s0);
        if (st == WTLS_WANT_READ && last_us > longest_us) longest_us = last_us;
        steps++;
    } while (st == WTLS_WANT_READ && steps < 10000);
    unsigned total_us = (unsigned)ticks_to_microsecs(gettime() - t0);
    CHECK_EQ_INT(st, WTLS_OK);
    TLOG("    wtls_init %u us; init_step(5): %u steps, %u us total, longest collecting step %u us, "
         "final step (psa_crypto_init from the pool) %u us\n",
         classic_us, steps, total_us, longest_us, last_us);
    uint8_t r[16];
    CHECK_EQ_INT(psa_generate_random(r, sizeof r), PSA_SUCCESS);
    wtls_shutdown();
}

/* Suite "jitterdump": raw low bytes of the library's jitter sampler (b) and,
 * for comparison, of an IPC round trip through the network stack (i),
 * collected first, then streamed as "JD <variant> <hex>" lines (TCP log only)
 * for tools/jitter_assess.py. No health tests: this measures the sources. */
#define DUMP_LINE 200

static inline uint32_t tb_now(void) {
    uint32_t t;
    __asm__ volatile("mftb %0" : "=r"(t));
    return t;
}

static void dump_hex(char variant, const uint8_t *raw, size_t n_total) {
    static const char hex[] = "0123456789abcdef";
    char line[8 + 2 * DUMP_LINE];
    for (size_t off = 0; off < n_total; off += DUMP_LINE) {
        size_t n = n_total - off < DUMP_LINE ? n_total - off : DUMP_LINE;
        char *p = line;
        *p++ = 'J'; *p++ = 'D'; *p++ = ' '; *p++ = variant; *p++ = ' ';
        for (size_t k = 0; k < n; k++) {
            *p++ = hex[raw[off + k] >> 4];
            *p++ = hex[raw[off + k] & 15];
        }
        *p = '\0';
        TLOG("%s\n", line);
    }
}

static void collect(char variant, uint8_t *raw, size_t n) {
    u64 t0 = gettime();
    if (variant == 'b') {
        for (size_t i = 0; i < n; i++) raw[i] = (uint8_t)wtls_plat_jitter_sample();
    } else if (variant == 'i') {
        uint32_t prev = tb_now();
        for (size_t i = 0; i < n; i++) {
            (void)net_gethostip();
            uint32_t now = tb_now();
            raw[i] = (uint8_t)(now - prev);
            prev = now;
        }
    }
    TLOG("JDINFO variant=%c samples=%u collect_us=%u\n", variant, (unsigned)n,
         (unsigned)ticks_to_microsecs(gettime() - t0));
}

static void hw_jitter_dump(void) {
    static const struct { char v; size_t n; } k_plan[] = {
        {'b', 200000}, {'i', 50000}};
    uint8_t *raw = malloc(200000);
    CHECK(raw != NULL);
    if (!raw) return;
    for (size_t k = 0; k < sizeof k_plan / sizeof k_plan[0]; k++) {
        collect(k_plan[k].v, raw, k_plan[k].n);
        dump_hex(k_plan[k].v, raw, k_plan[k].n);
    }
    free(raw);
}

void wtls_suite_jitterdump(void) { RUN(hw_jitter_dump); }

void wtls_suite_entropy(void) {
    RUN(hw_psa_init_with_jitter);
    RUN(hw_random_differs);
    RUN(hw_jitter_64k_passes_health_tests);
    RUN(hw_init_step_timing);
}
