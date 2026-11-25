/* upload_mtls_abort - streaming upload, optional mTLS/SPKI pinning, progress
 * reporting, and Wiimote/GameCube cooperative cancellation (abort_cb).
 *
 *   wiiload upload_mtls_abort.dol url=https://httpbin.org/post
 *
 * Press B or HOME (Wiimote) or B/START (GC controller) at any time to cancel
 * cleanly with WTLS_ERR_CANCELLED instead of hanging or killing threads. */
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <gccore.h>
#include <network.h>
#include <ogc/lwp.h>
#include <ogc/mutex.h>
#include <wiiuse/wpad.h>

#include <mbedtls/x509.h>
#include <wiitls/http.h>
#include <wiitls/wiitls.h>

#define NET_STACK_SIZE (64 * 1024)
#define UPLOAD_TOTAL (64u * 1024u)

static uint8_t s_net_stack[NET_STACK_SIZE] __attribute__((aligned(32)));
static mutex_t s_con;
static volatile bool s_done;
static volatile bool s_cancel;

static const char *s_url = "https://httpbin.org/post";
static const char *s_client_cert_pem = NULL;
static const char *s_client_key_pem = NULL;
static uint8_t s_spki_pin[WTLS_SPKI_SHA256_LEN];
static bool s_has_pin;

#define LOCKED_PRINTF(...)      \
    do {                        \
        LWP_MutexLock(s_con);   \
        printf(__VA_ARGS__);    \
        LWP_MutexUnlock(s_con); \
    } while (0)

static bool on_abort(void *ctx) {
    (void)ctx;
    return s_cancel;
}

typedef struct {
    size_t sent;
    size_t total;
} up_ctx;

static int on_upload_chunk(void *ctx, void *buf, size_t cap) {
    up_ctx *u = ctx;
    if (u->sent >= u->total) return 0;
    size_t n = u->total - u->sent;
    if (n > 4096u) n = 4096u;
    if (n > cap) n = cap;
    for (size_t i = 0; i < n; i++) ((uint8_t *)buf)[i] = (uint8_t)('A' + ((u->sent + i) % 26u));
    u->sent += n;
    return (int)n;
}

static void on_progress(void *ctx, size_t done, int64_t total) {
    (void)ctx;
    if (total > 0) {
        unsigned pct = (unsigned)((done * 100u) / (size_t)total);
        LOCKED_PRINTF("\r  rx: %u / %lld bytes (%u%%)", (unsigned)done, (long long)total, pct);
    } else {
        LOCKED_PRINTF("\r  rx: %u bytes", (unsigned)done);
    }
}

static int parse_hex_pin(const char *hex, uint8_t out[WTLS_SPKI_SHA256_LEN]) {
    if (!hex || strlen(hex) != WTLS_SPKI_SHA256_LEN * 2u) return -1;
    for (size_t i = 0; i < WTLS_SPKI_SHA256_LEN; i++) {
        unsigned v = 0;
        if (sscanf(hex + i * 2u, "%2x", &v) != 1) return -1;
        out[i] = (uint8_t)v;
    }
    return 0;
}

static void *net_thread(void *arg) {
    (void)arg;
    s32 r = -1;
    for (int i = 0; i < 20 && r < 0 && !s_cancel; i++) r = net_init();
    if (s_cancel) {
        LOCKED_PRINTF("Cancelled before network bring-up.\n");
        s_done = true;
        return NULL;
    }
    if (r < 0) {
        LOCKED_PRINTF("net_init failed: %d\n", (int)r);
        s_done = true;
        return NULL;
    }
    if ((r = wtls_init()) != WTLS_OK) {
        LOCKED_PRINTF("wtls_init failed: %s\n", wtls_strerror(r));
        s_done = true;
        return NULL;
    }

    wtls_client_cred *cred = NULL;
    if (s_client_cert_pem && s_client_key_pem) {
        r = wtls_client_cred_load(&cred, (const uint8_t *)s_client_cert_pem,
                                  strlen(s_client_cert_pem) + 1u,
                                  (const uint8_t *)s_client_key_pem,
                                  strlen(s_client_key_pem) + 1u);
        if (r != WTLS_OK) LOCKED_PRINTF("client cred load failed: %s\n", wtls_strerror(r));
    }

    wtls_options tls = {0};
    tls.abort_cb = on_abort;
    tls.client_cred = cred;
    if (s_has_pin) {
        memcpy(tls.spki_pins[0], s_spki_pin, WTLS_SPKI_SHA256_LEN);
        tls.n_spki_pins = 1;
    }

    up_ctx up = {.total = UPLOAD_TOTAL};
    wtls_http_request req = {0};
    req.method = "POST";
    req.url = s_url;
    req.body_cb = on_upload_chunk;
    req.body_ctx = &up;
    req.body_len = up.total;
    req.progress_cb = on_progress;
    req.tls = &tls;

    LOCKED_PRINTF("POST %u bytes -> %s\n", (unsigned)up.total, s_url);
    wtls_http_result res;
    r = wtls_http_fetch(&req, 256u * 1024u, &res);
    if (r == WTLS_ERR_CLOCK ||
        (r == WTLS_ERR_CERT &&
         (wtls_last_verify_flags() & (MBEDTLS_X509_BADCERT_EXPIRED | MBEDTLS_X509_BADCERT_FUTURE)))) {
        LOCKED_PRINTF("\nClock off, syncing via SNTP...\n");
        if (wtls_time_sync_sntp(NULL, 3000) == WTLS_OK) {
            up.sent = 0;
            r = wtls_http_fetch(&req, 256u * 1024u, &res);
        }
    }

    if (r == WTLS_OK) {
        LOCKED_PRINTF("\nHTTP %d, received %u bytes\n", res.status, (unsigned)res.body_len);
        wtls_http_result_free(&res);
    } else {
        LOCKED_PRINTF("\nUpload ended: %s (flags 0x%x)\n", wtls_strerror(r),
                      (unsigned)wtls_last_verify_flags());
    }

    wtls_client_cred_free(cred);
    wtls_shutdown();
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
    PAD_Init();
    WPAD_Init();
    printf("libwiitls %s upload_mtls_abort example\n", wtls_version());
    printf("Press B / HOME (Wiimote) or B / START (GC) to cancel\n");

    for (int i = 0; i < argc; i++) {
        if (!strncmp(argv[i], "url=", 4)) s_url = argv[i] + 4;
        else if (!strncmp(argv[i], "spki=", 5)) {
            if (parse_hex_pin(argv[i] + 5, s_spki_pin) == 0) s_has_pin = true;
        } else if (!strncmp(argv[i], "cert=", 5)) s_client_cert_pem = argv[i] + 5;
        else if (!strncmp(argv[i], "key=", 4)) s_client_key_pem = argv[i] + 4;
    }

    LWP_MutexInit(&s_con, false);
    lwp_t th;
    if (LWP_CreateThread(&th, net_thread, NULL, s_net_stack, NET_STACK_SIZE, 64) < 0) {
        printf("cannot start network thread\n");
        return 1;
    }

    while (!s_done) {
        PAD_ScanPads();
        WPAD_ScanPads();
        if ((WPAD_ButtonsDown(0) & (WPAD_BUTTON_B | WPAD_BUTTON_HOME)) ||
            (PAD_ButtonsDown(0) & (PAD_BUTTON_B | PAD_BUTTON_START))) {
            s_cancel = true;
        }
        VIDEO_WaitVSync();
    }
    LWP_JoinThread(th, NULL);
    printf("\nDone. Returning to loader in 10 s.\n");
    for (int i = 0; i < 60 * 10; i++) VIDEO_WaitVSync();
    return 0;
}
