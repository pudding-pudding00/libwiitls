/* https_get - minimal libwiitls example for the Wii.
 *
 *   wiiload https_get.dol url=https://example.com/
 *
 * The main thread only draws a spinner; every wtls_* call happens on one
 * dedicated network thread (libwiitls is single-threaded by contract). The
 * thread brings the network up, initialises libwiitls, syncs the clock via SNTP
 * if needed, fetches the URL twice and prints the response and the connection
 * info. The second request shows TLS 1.3 session resumption (resumed=yes). */
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <gccore.h>
#include <network.h>
#include <ogc/lwp.h>
#include <ogc/mutex.h>

#include <wiitls/wiitls.h>

#define NET_STACK_SIZE (64 * 1024)
#define BODY_PREVIEW 1024

static uint8_t s_net_stack[NET_STACK_SIZE] __attribute__((aligned(32)));
static mutex_t s_con;            /* guards the console: two threads print */
static volatile bool s_done;

static char s_host[256];
static uint16_t s_port = 443;
static char s_path[512] = "/";

#define LOCKED_PRINTF(...)            \
    do {                              \
        LWP_MutexLock(s_con);         \
        printf(__VA_ARGS__);          \
        LWP_MutexUnlock(s_con);       \
    } while (0)

/* Splits https://host[:port]/path. Only https is supported. */
static bool parse_url(const char *url) {
    const char *p = url;
    if (strncmp(p, "https://", 8) != 0) return false;
    p += 8;
    size_t hlen = strcspn(p, ":/");
    if (hlen == 0 || hlen >= sizeof s_host) return false;
    memcpy(s_host, p, hlen);
    s_host[hlen] = '\0';
    p += hlen;
    if (*p == ':') {
        char *end;
        long port = strtol(p + 1, &end, 10);
        if (end == p + 1 || port <= 0 || port > 65535) return false;
        s_port = (uint16_t)port;
        p = end;
    }
    if (*p == '\0') p = "/";
    if (*p != '/' || strlen(p) >= sizeof s_path) return false;
    strcpy(s_path, p);
    return true;
}

static int connect_with_clock_fix(wtls_conn **c) {
    static const char *const alpn[] = {"http/1.1", NULL};
    wtls_options opt = {0};
    opt.alpn = alpn;
    int r = wtls_connect(c, s_host, s_port, &opt);
    if (r == WTLS_ERR_CLOCK) {
        /* The Wii RTC is often wrong; certificates cannot be checked without a clock. */
        LOCKED_PRINTF("Clock not plausible, syncing via SNTP...\n");
        int s = wtls_time_sync_sntp(NULL, 3000);
        LOCKED_PRINTF("SNTP: %s\n", wtls_strerror(s));
        if (s == WTLS_OK) r = wtls_connect(c, s_host, s_port, &opt);
    }
    return r;
}

static void fetch(int round) {
    LOCKED_PRINTF("\n--- request %d: https://%s:%u%s ---\n", round, s_host, s_port, s_path);
    wtls_conn *c = NULL;
    int r = connect_with_clock_fix(&c);
    if (r != WTLS_OK) {
        LOCKED_PRINTF("connect failed: %s (verify flags 0x%x)\n", wtls_strerror(r),
                      (unsigned)wtls_last_verify_flags());
        return;
    }

    char req[1024];
    int n = snprintf(req, sizeof req,
                     "GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: libwiitls-https_get\r\n"
                     "Accept: */*\r\nConnection: close\r\n\r\n",
                     s_path, s_host);
    if (n <= 0 || (size_t)n >= sizeof req || wtls_write(c, req, (size_t)n) != n) {
        LOCKED_PRINTF("write failed\n");
        wtls_close(c);
        return;
    }

    /* Print the header block in full and the first BODY_PREVIEW bytes of the
     * body, but keep reading to the end: that also captures the session ticket. */
    static char buf[4096];
    size_t total = 0, body_shown = 0;
    bool in_body = false;
    int match = 0; /* progress through "\r\n\r\n" */
    for (;;) {
        r = wtls_read(c, buf, sizeof buf);
        if (r <= 0) break;
        total += (size_t)r;
        LWP_MutexLock(s_con);
        for (int i = 0; i < r; i++) {
            char ch = buf[i];
            if (!in_body) {
                if (ch != '\r') putchar(ch);
                match = (ch == "\r\n\r\n"[match]) ? match + 1 : (ch == '\r' ? 1 : 0);
                if (match == 4) in_body = true;
            } else if (body_shown < BODY_PREVIEW) {
                if (ch != '\r') putchar(ch);
                body_shown++;
            }
        }
        LWP_MutexUnlock(s_con);
    }
    if (r != WTLS_ERR_CLOSED && r != WTLS_ERR_IO) LOCKED_PRINTF("\nread: %s\n", wtls_strerror(r));

    wtls_conn_info info;
    if (wtls_get_info(c, &info) == WTLS_OK)
        LOCKED_PRINTF("\n[%u bytes] %s %s alpn=%s resumed=%s handshake=%u ms\n", (unsigned)total,
                      info.tls_version, info.ciphersuite, info.alpn ? info.alpn : "-",
                      info.resumed ? "yes" : "no", (unsigned)info.handshake_ms);
    wtls_close(c);
}

static void *net_thread(void *arg) {
    (void)arg;
    s32 r = -1;
    for (int tries = 0; tries < 10 && r < 0; tries++) r = net_init();
    if (r < 0) {
        LOCKED_PRINTF("net_init failed: %d\n", (int)r);
    } else if ((r = wtls_init()) != WTLS_OK) {
        LOCKED_PRINTF("wtls_init failed: %s\n", wtls_strerror(r));
    } else {
        fetch(1);
        fetch(2); /* same host: resumes the TLS 1.3 session */
        wtls_shutdown();
    }
    s_done = true;
    return NULL;
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
    printf("libwiitls https_get example\n");

    const char *url = "https://example.com/";
    for (int i = 1; i < argc; i++)
        if (!strncmp(argv[i], "url=", 4)) url = argv[i] + 4;
    if (!parse_url(url)) {
        printf("bad url: %s (expected https://host[:port]/path)\n", url);
        for (int i = 0; i < 60 * 5; i++) VIDEO_WaitVSync();
        return 1;
    }

    LWP_MutexInit(&s_con, false);
    lwp_t th;
    if (LWP_CreateThread(&th, net_thread, NULL, s_net_stack, NET_STACK_SIZE, 64) < 0) {
        printf("cannot start the network thread\n");
        return 1;
    }

    /* The UI thread stays responsive while the network thread blocks. The
     * spinner sits in the top-right corner; save/restore keeps the cursor of
     * the network thread's output where it was. */
    static const char spin[] = "|/-\\";
    for (unsigned frame = 0; !s_done; frame++) {
        LWP_MutexLock(s_con);
        printf("\x1b[s\x1b[1;70H%c\x1b[u", spin[(frame / 8) % 4]);
        LWP_MutexUnlock(s_con);
        VIDEO_WaitVSync();
    }
    LWP_JoinThread(th, NULL);
    printf("\x1b[s\x1b[1;70H \x1b[u\nDone. Returning to the loader in 20 s.\n");
    for (int i = 0; i < 60 * 20; i++) VIDEO_WaitVSync();
    return 0;
}
