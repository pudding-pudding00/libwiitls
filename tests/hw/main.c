/* Wii hardware test runner (wtls_hwtest.dol).
 *
 * Arguments (via wiiload): logip=<a.b.c.d> logport=<n> suite=<name>
 *                          server=<a.b.c.d> pctime=<unix>
 * Every line goes to the console AND to the TCP log at logip:logport.
 * The last line is always "WTLS-HWTEST DONE pass=P fail=F".
 */
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <gccore.h>
#include <network.h>

#include "check.h"
#include "env.h"
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

static void suite_selftest(void) {
    CHECK(1);
}

static void run_selftest(void) { RUN(suite_selftest); }

static const struct {
    const char *name;
    void (*fn)(void);
} k_suites[] = {
    {"selftest", run_selftest},
    {"spike", wtls_suite_spike},
    WTLS_HW_SUITES
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

static int log_connect(const char *ip, int port) {
    s32 fd = net_socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
    if (fd < 0) return -1;
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof sa);
    sa.sin_family = AF_INET;
    sa.sin_port = htons((u16)port);
    sa.sin_addr.s_addr = inet_addr(ip);
    if (net_connect(fd, (struct sockaddr *)&sa, sizeof sa) < 0) {
        net_close(fd);
        return -1;
    }
    return fd;
}

int main(int argc, char **argv) {
    video_init();
    printf("libwiitls hardware test runner\n");

    const char *logip = NULL, *suite = "selftest";
    int logport = 4405;
    for (int i = 1; i < argc; i++) {
        if (!strncmp(argv[i], "logip=", 6)) logip = argv[i] + 6;
        else if (!strncmp(argv[i], "logport=", 8)) logport = atoi(argv[i] + 8);
        else if (!strncmp(argv[i], "suite=", 6)) suite = argv[i] + 6;
        else if (!strncmp(argv[i], "server=", 7)) g_env.server_host = argv[i] + 7;
        else if (!strncmp(argv[i], "pctime=", 7)) g_env.pc_time = strtoll(argv[i] + 7, NULL, 10);
    }
    g_env.is_hw = true;

    s32 r = -1;
    for (int tries = 0; tries < 10 && r < 0; tries++) r = net_init();
    if (r < 0) printf("net_init failed: %d\n", (int)r);
    else if (logip) g_log_fd = log_connect(logip, logport);

    wtls_hw_printf("suite=%s server=%s pctime=%lld log=%s\n", suite,
                   g_env.server_host ? g_env.server_host : "-", (long long)g_env.pc_time,
                   g_log_fd >= 0 ? "tcp" : "console");

    int found = 0;
    if (r >= 0) {
        for (size_t i = 0; i < sizeof k_suites / sizeof k_suites[0]; i++) {
            if (!strcmp(k_suites[i].name, suite)) {
                k_suites[i].fn();
                found = 1;
            }
        }
    }
    if (!found) {
        wtls_hw_printf("unknown suite or no network: %s\n", suite);
        wtls_t_fail++;
    }
    wtls_hw_printf("WTLS-HWTEST DONE pass=%d fail=%d\n", wtls_t_pass, wtls_t_fail);
    if (g_log_fd >= 0) net_close(g_log_fd);

    for (int i = 0; i < 60 * 3; i++) VIDEO_WaitVSync(); /* keep the result visible */
    return 0;
}
