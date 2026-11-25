/* https_get - minimal libwiitls example for the Wii.
 *
 *   wiiload https_get.dol url=https://example.com/
 *
 * The main thread only draws a spinner; every wtls_* call happens on one
 * dedicated network thread (libwiitls is single-threaded by contract). The
 * thread brings the network up, initialises libwiitls, syncs the clock via SNTP
 * if needed, fetches the URL twice with the HTTP client (wtls_http_open) and
 * prints status, headers, the start of the body and the request info. The
 * second request reuses the kept-alive connection (reused=yes). */
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <gccore.h>
#include <network.h>
#include <ogc/lwp.h>
#include <ogc/mutex.h>

#include <mbedtls/x509.h> /* MBEDTLS_X509_BADCERT_* */
#include <wiitls/http.h>
#include <wiitls/wiitls.h>

#define NET_STACK_SIZE (64 * 1024)
#define BODY_PREVIEW 1024

static uint8_t s_net_stack[NET_STACK_SIZE] __attribute__((aligned(32)));
static mutex_t s_con;            /* guards the console: two threads print */
static volatile bool s_done;

static const char *s_url = "https://example.com/";

#define LOCKED_PRINTF(...)            \
    do {                              \
        LWP_MutexLock(s_con);         \
        printf(__VA_ARGS__);          \
        LWP_MutexUnlock(s_con);       \
    } while (0)

static int open_with_clock_fix(wtls_http_response **res, const wtls_http_request *req) {
    int r = wtls_http_open(res, req);
    /* The Wii RTC is often wrong; certificates cannot be checked without a
     * clock. A clock off by only a few years shows up as an expired or
     * not-yet-valid certificate instead of WTLS_ERR_CLOCK. */
    static bool synced;
    bool time_flags = wtls_last_verify_flags() & (MBEDTLS_X509_BADCERT_EXPIRED | MBEDTLS_X509_BADCERT_FUTURE);
    if (!synced && (r == WTLS_ERR_CLOCK || (r == WTLS_ERR_CERT && time_flags))) {
        synced = true;
        LOCKED_PRINTF("Clock looks wrong, syncing via SNTP...\n");
        int s = wtls_time_sync_sntp(NULL, 3000);
        LOCKED_PRINTF("SNTP: %s\n", wtls_strerror(s));
        if (s == WTLS_OK) r = wtls_http_open(res, req);
    }
    return r;
}

static void fetch(int round) {
    LOCKED_PRINTF("\n--- request %d: %s ---\n", round, s_url);
    static const wtls_http_header hdrs[] = {{"User-Agent", "libwiitls-https_get"}};
    wtls_http_request req = {0};
    req.url = s_url;
    req.headers = hdrs;
    req.n_headers = 1;
    wtls_http_response *res = NULL;
    int r = open_with_clock_fix(&res, &req);
    if (r != WTLS_OK) {
        LOCKED_PRINTF("request failed: %s (verify flags 0x%x)\n", wtls_strerror(r),
                      (unsigned)wtls_last_verify_flags());
        return;
    }

    /* A status >= 400 is a response, not an error: print it like any other. */
    LOCKED_PRINTF("HTTP %d\n", wtls_http_status(res));
    const char *name, *value;
    for (size_t i = 0; wtls_http_header_at(res, i, &name, &value); i++) LOCKED_PRINTF("%s: %s\n", name, value);
    LOCKED_PRINTF("\n");

    /* Show the first BODY_PREVIEW bytes but read to the end: only a fully read
     * response lets the connection go back to the keep-alive pool. */
    static char buf[4096];
    size_t total = 0, shown = 0;
    while ((r = wtls_http_read(res, buf, sizeof buf)) > 0) {
        if (shown < BODY_PREVIEW) {
            size_t n = (size_t)r < BODY_PREVIEW - shown ? (size_t)r : BODY_PREVIEW - shown;
            LWP_MutexLock(s_con);
            for (size_t i = 0; i < n; i++)
                if (buf[i] != '\r') putchar(buf[i]);
            LWP_MutexUnlock(s_con);
            shown += n;
        }
        total += (size_t)r;
    }
    if (r < 0) LOCKED_PRINTF("\nread: %s (the body is incomplete)\n", wtls_strerror(r));

    wtls_http_info info;
    if (wtls_http_get_info(res, &info) == WTLS_OK) {
        LOCKED_PRINTF("\n[%u body bytes%s] reused=%s redirects=%u url=%s\n", (unsigned)total,
                      info.gzip ? ", gunzipped" : "", info.reused_connection ? "yes" : "no",
                      (unsigned)info.redirects, info.url);
        if (info.secure)
            LOCKED_PRINTF("%s %s resumed=%s handshake=%u ms\n", info.tls.tls_version, info.tls.ciphersuite,
                          info.tls.resumed ? "yes" : "no", (unsigned)info.tls.handshake_ms);
    }
    wtls_http_close(res);
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
        fetch(2); /* same host: reuses the pooled connection */
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

    for (int i = 0; i < argc; i++) /* wiiload may put the first argument in argv[0] */
        if (!strncmp(argv[i], "url=", 4)) s_url = argv[i] + 4;
    if (strncmp(s_url, "https://", 8) != 0 && strncmp(s_url, "http://", 7) != 0) {
        printf("bad url: %s (expected https://host[:port]/path or http://...)\n", s_url);
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
