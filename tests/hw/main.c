/* Wii hardware test runner (wtls_hwtest.dol).
 *
 * Arguments (via wiiload): logip=<a.b.c.d> logport=<n> suite=<name>
 *                          server=<a.b.c.d> pctime=<unix>
 * Every line goes to the console AND to the TCP log at logip:logport.
 * The last line is always "WTLS-HWTEST DONE pass=P fail=F skip=S".
 */
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <gccore.h>
#include <network.h>

#include "check.h"
#include "env.h"
#include "hw_net.h"
#include "suites.h"

WTLS_CHECK_DEFINE_COUNTERS;
wtls_test_env g_env;

static int g_log_fd = -1;

int wtls_hw_printf(const char *fmt, ...) {
    char buf[512];
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(buf, sizeof buf, fmt, ap);
    va_end(ap);
    if (n < 0) return n;
    size_t len = (size_t)n < sizeof buf ? (size_t)n : sizeof buf - 1;
    /* Bulk data lines ("JD ...", jitterdump) go to the TCP log only: scrolling
     * them through the console would take minutes. */
    if (strncmp(buf, "JD ", 3) != 0 || g_log_fd < 0) fputs(buf, stdout);
    if (g_log_fd >= 0) {
        size_t off = 0;
        while (off < len) {
            s32 r = net_send(g_log_fd, buf + off, (s32)(len - off), 0);
            if (r <= 0) break;
            off += (size_t)r;
        }
    }
    return n;
}

static void suite_selftest(void) {
    CHECK(1);
}

static void run_selftest(void) { RUN(suite_selftest); }

static const struct {
    const char *name;
    void (*fn)(void);
} k_suites[] = {
    {"selftest", run_selftest},
#include "suites.inc"
};

static void video_init(void) {
    VIDEO_Init();
    GXRModeObj *rmode = VIDEO_GetPreferredMode(NULL);
    void *xfb = MEM_K0_TO_K1(SYS_AllocateFramebuffer(rmode));
    console_init(xfb, 20, 20, rmode->fbWidth, rmode->xfbHeight,
                 rmode->fbWidth * VI_DISPLAY_PIX_SZ);
    VIDEO_Configure(rmode);
    VIDEO_SetNextFramebuffer(xfb);
    VIDEO_SetBlack(false);
    VIDEO_Flush();
    VIDEO_WaitVSync();
    if (rmode->viTVMode & VI_NON_INTERLACE) VIDEO_WaitVSync();
}

int main(int argc, char **argv) {
    video_init();
    printf("libwiitls hardware test runner\n");

    const char *logip = NULL, *suite = "selftest";
    int logport = 4405;
    for (int i = 0; i < argc; i++) { /* wiiload may put the first argument in argv[0] */
        if (!strncmp(argv[i], "logip=", 6)) logip = argv[i] + 6;
        else if (!strncmp(argv[i], "logport=", 8)) logport = atoi(argv[i] + 8);
        else if (!strncmp(argv[i], "suite=", 6)) suite = argv[i] + 6;
        else if (!strncmp(argv[i], "server=", 7)) g_env.server_host = argv[i] + 7;
        else if (!strncmp(argv[i], "pctime=", 7)) g_env.pc_time = strtoll(argv[i] + 7, NULL, 10);
        else if (!strncmp(argv[i], "iters=", 6)) g_env.soak_iters = (unsigned)strtoul(argv[i] + 6, NULL, 10);
    }
    g_env.is_hw = true;

    s32 r = hw_net_init();
    if (r >= 0 && logip) g_log_fd = hw_log_connect(logip, logport);

    wtls_hw_printf("suite=%s server=%s pctime=%lld log=%s\n", suite,
                   g_env.server_host ? g_env.server_host : "-", (long long)g_env.pc_time,
                   g_log_fd >= 0 ? "tcp" : "console");

    int found = 0;
    if (r >= 0) {
        const char *p = !strcmp(suite, "all") ? "time,plat,crypto,tls,log,alloc,http,soak,realworld" : suite;
        while (*p) {
            const char *comma = strchr(p, ',');
            size_t len = comma ? (size_t)(comma - p) : strlen(p);
            int matched = 0;
            for (size_t i = 0; i < sizeof k_suites / sizeof k_suites[0]; i++) {
                if (strlen(k_suites[i].name) == len && !strncmp(k_suites[i].name, p, len)) {
                    int p0 = wtls_t_pass, f0 = wtls_t_fail, s0 = wtls_t_skip;
                    wtls_hw_printf("=== suite %s ===\n", k_suites[i].name);
                    k_suites[i].fn();
                    wtls_hw_printf("=== suite %s: pass=%d fail=%d skip=%d ===\n",
                                   k_suites[i].name, wtls_t_pass - p0, wtls_t_fail - f0,
                                   wtls_t_skip - s0);
                    matched = 1;
                    found = 1;
                    break;
                }
            }
            if (!matched) {
                wtls_hw_printf("unknown suite: %.*s\n", (int)len, p);
                wtls_t_fail++;
            }
            p = comma ? comma + 1 : p + len;
        }
    }
    if (!found) {
        wtls_hw_printf("unknown suite or no network: %s\n", suite);
        wtls_t_fail++;
    }
    wtls_hw_printf("WTLS-HWTEST DONE pass=%d fail=%d skip=%d\n", wtls_t_pass, wtls_t_fail,
                   wtls_t_skip);
    bool logged = g_log_fd >= 0;
    if (logged) net_close(g_log_fd);
    hw_hold_screen(logged);
    return 0;
}
