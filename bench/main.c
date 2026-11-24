/* Wii benchmark runner (wtls_bench.dol), driven by tools/hwtest.py:
 *
 *   python tools/hwtest.py --wii <ip> --dol build-wii/bench/wtls_bench.dol --suite bench
 *
 * Same arguments and log protocol as the hardware test runner (tests/hw/main.c):
 * logip=<a.b.c.d> logport=<n> suite=bench server=<a.b.c.d> pctime=<unix>.
 * Output: BENCH/GATE lines, last line "WTLS-HWTEST DONE pass=P fail=F skip=S". */
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <gccore.h>
#include <network.h>

#include "bench.h"
#include "check.h"
#include "env.h"
#include "hw_net.h"

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
    fputs(buf, stdout);
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
    printf("libwiitls benchmark\n");

    const char *logip = NULL, *suite = "bench";
    int logport = 4405;
    for (int i = 0; i < argc; i++) { /* wiiload may put the first argument in argv[0] */
        if (!strncmp(argv[i], "logip=", 6)) logip = argv[i] + 6;
        else if (!strncmp(argv[i], "logport=", 8)) logport = atoi(argv[i] + 8);
        else if (!strncmp(argv[i], "suite=", 6)) suite = argv[i] + 6;
        else if (!strncmp(argv[i], "server=", 7)) g_env.server_host = argv[i] + 7;
        else if (!strncmp(argv[i], "pctime=", 7)) g_env.pc_time = strtoll(argv[i] + 7, NULL, 10);
    }
    g_env.is_hw = true;

    s32 r = hw_net_init();
    if (r >= 0 && logip) g_log_fd = hw_log_connect(logip, logport);

    wtls_hw_printf("suite=%s server=%s log=%s\n", suite,
                   g_env.server_host ? g_env.server_host : "-", g_log_fd >= 0 ? "tcp" : "console");
    if (r >= 0 && !strcmp(suite, "bench") && g_env.server_host) {
        wtls_bench_run();
    } else {
        wtls_hw_printf("need network, suite=bench and server=<pc ip>\n");
        wtls_t_fail++;
    }
    wtls_hw_printf("WTLS-HWTEST DONE pass=%d fail=%d skip=%d\n", wtls_t_pass, wtls_t_fail,
                   wtls_t_skip);
    bool logged = g_log_fd >= 0;
    if (logged) net_close(g_log_fd);
    hw_hold_screen(logged);
    return 0;
}
