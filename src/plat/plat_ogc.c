#include "plat.h"

#include <malloc.h>
#include <stdlib.h>

#include <ogc/lwp_watchdog.h>
#include <mbedtls/platform_time.h>
#include <wiitls/wiitls.h>

int wtls_plat_os_entropy(uint8_t *out, size_t len) {
    (void)out;
    (void)len;
    return WTLS_ERR_ENTROPY; /* no OS entropy source on the Wii; see wtls_jitter */
}

/* MBEDTLS_PLATFORM_MS_TIME_ALT: monotonic milliseconds from the timebase. */
mbedtls_ms_time_t mbedtls_ms_time(void) {
    return (mbedtls_ms_time_t)ticks_to_millisecs(gettime());
}

/* ---- timebase jitter (variant b of the Task 2 spike) ---- */
#define JIT_WALK_BYTES (256 * 1024)
#define JIT_STRIDE (4096 + 32)

static volatile uint8_t *g_walk;
static size_t g_walk_pos;
static uint32_t g_prev_tb;

static inline uint32_t tb_read(void) {
    uint32_t t;
    __asm__ volatile("mftb %0" : "=r"(t));
    return t;
}

uint32_t wtls_plat_jitter_sample(void) {
    if (!g_walk) {
        g_walk = memalign(32, JIT_WALK_BYTES);
        if (!g_walk) return 0;
        g_walk_pos = 0;
        g_prev_tb = tb_read();
    }
    g_walk[g_walk_pos] ^= (uint8_t)g_prev_tb;
    g_walk_pos = (g_walk_pos + JIT_STRIDE) % JIT_WALK_BYTES;
    uint32_t now = tb_read();
    uint32_t d = now - g_prev_tb;
    g_prev_tb = now;
    return d;
}

void wtls_plat_jitter_release(void) {
    free((void *)g_walk);
    g_walk = NULL;
}
