/* Long-running soak / endurance suite: exercises keep-alive reuse, cold
 * and resumed TLS 1.3/1.2 handshakes, mTLS streaming uploads, gzip decoding,
 * redirects, cooperative abort_cb, wtls_net_reset(), and heap stability.
 *
 * Host CTest runs a short cycle count; on the Wii run suite=soak (default 200
 * iterations, or override with iters=<N>, e.g. iters=1500 for an overnight run). */
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef WTLS_PLATFORM_OGC
#include <malloc.h>
#endif

#include <wiitls/http.h>
#include <wiitls/wiitls.h>

#include "check.h"
#include "env.h"
#include "plat/plat.h"
#include "wtls_dns.h"
#include "wtls_scache.h"

#define SOAK_PLAIN_PORT 4430
#define SOAK_TLS12_PORT 4433
#define SOAK_HTTP_PORT 4438
#define SOAK_HTTP2_PORT 4439
#define SOAK_MTLS_HTTP_PORT 4442

static bool soak_recv_exact(int fd, uint8_t *buf, size_t n, uint64_t deadline) {
    size_t off = 0;
    while (off < n) {
        uint64_t now = wtls_plat_now_ms();
        if (now >= deadline) return false;
        int r = wtls_plat_recv(fd, buf + off, n - off);
        if (r > 0) off += (size_t)r;
        else if (r == WTLS_WANT_READ) wtls_plat_poll(fd, true, false, (uint32_t)(deadline - now));
        else return false;
    }
    return true;
}

static uint8_t *soak_plain_fetch(const char *cmd, size_t *len) {
    *len = 0;
    uint32_t ip;
    int fd = -1;
    if (wtls_plat_resolve(g_env.server_host, &ip) != WTLS_OK) return NULL;
    if (wtls_plat_connect(ip, SOAK_PLAIN_PORT, 3000, &fd) != WTLS_OK) return NULL;
    uint8_t *buf = NULL;
    char full[48];
    int n = snprintf(full, sizeof full, "%s\n", cmd);
    uint64_t deadline = wtls_plat_now_ms() + 3000;
    if (n > 0 && n < (int)sizeof full && wtls_plat_send(fd, (const uint8_t *)full, (size_t)n) == n) {
        char line[16] = {0};
        size_t i = 0;
        while (i < sizeof line - 1 && soak_recv_exact(fd, (uint8_t *)&line[i], 1, deadline) &&
               line[i] != '\n')
            i++;
        long want = strtol(line, NULL, 10);
        if (want > 0 && want < 16384 && (buf = malloc((size_t)want))) {
            if (soak_recv_exact(fd, buf, (size_t)want, deadline)) *len = (size_t)want;
            else {
                free(buf);
                buf = NULL;
            }
        }
    }
    wtls_plat_close(fd);
    return buf;
}

static bool soak_trust_ca(void) {
    size_t len = 0;
    uint8_t *der = soak_plain_fetch("CA", &len);
    bool ok = der && wtls_add_trusted_ca(der, len) == WTLS_OK;
    free(der);
    return ok;
}

static wtls_client_cred *soak_load_cred(const char *name) {
    char cmd[48];
    size_t clen = 0, klen = 0;
    snprintf(cmd, sizeof cmd, "CLIENTCERT %s", name);
    uint8_t *cert = soak_plain_fetch(cmd, &clen);
    snprintf(cmd, sizeof cmd, "CLIENTKEY %s", name);
    uint8_t *key0 = soak_plain_fetch(cmd, &klen);
    uint8_t *key = NULL;
    if (key0) {
        key = malloc(klen + 1);
        if (key) {
            memcpy(key, key0, klen);
            key[klen] = 0;
            klen += 1;
        }
        free(key0);
    }
    wtls_client_cred *cred = NULL;
    if (cert && key) {
        if (wtls_client_cred_load(&cred, cert, clen, key, klen) != WTLS_OK) cred = NULL;
    }
    free(cert);
    free(key);
    return cred;
}

typedef struct {
    size_t len, off, chunk;
} soak_up_ctx;

static int soak_up_cb(void *ctx, void *buf, size_t cap) {
    soak_up_ctx *s = ctx;
    if (s->off >= s->len) return 0;
    size_t n = s->len - s->off;
    if (n > s->chunk) n = s->chunk;
    if (n > cap) n = cap;
    for (size_t i = 0; i < n; i++) ((uint8_t *)buf)[i] = (uint8_t)((s->off + i) % 251);
    s->off += n;
    return (int)n;
}

typedef struct {
    int calls;
    int limit;
} soak_abort_ctx;

static bool soak_abort_cb(void *ctx) {
    soak_abort_ctx *a = ctx;
    return ++a->calls >= a->limit;
}

static void soak_url(char *out, size_t cap, uint16_t port, const char *path) {
    snprintf(out, cap, "https://%s:%u%s", g_env.server_host, (unsigned)port, path);
}

static bool soak_pattern_ok(const uint8_t *p, size_t n) {
    for (size_t i = 0; i < n; i++) {
        if (p[i] != (uint8_t)(i % 251)) return false;
    }
    return true;
}

static void soak_step(unsigned iter, wtls_client_cred *cred) {
    char url[512];
    wtls_http_result res;
    switch (iter % 8u) {
    case 0: {
        /* Keep-alive GET */
        soak_url(url, sizeof url, SOAK_HTTP_PORT, (iter & 8u) ? "/len?n=4096" : "/hello");
        wtls_http_request req = {0};
        req.url = url;
        CHECK_EQ_INT(wtls_http_fetch(&req, 0, &res), WTLS_OK);
        CHECK_EQ_INT(res.status, 200);
        wtls_http_result_free(&res);
        break;
    }
    case 1: {
        /* Cold full handshake + chunked transfer */
        soak_url(url, sizeof url, SOAK_HTTP_PORT, "/chunked?n=8192&size=777");
        wtls_options tls = {0};
        tls.no_resumption = true;
        wtls_http_request req = {0};
        req.url = url;
        req.no_keepalive = true;
        req.tls = &tls;
        CHECK_EQ_INT(wtls_http_fetch(&req, 0, &res), WTLS_OK);
        CHECK_EQ_INT(res.status, 200);
        CHECK_EQ_INT((long long)res.body_len, 8192);
        CHECK(res.body && soak_pattern_ok((const uint8_t *)res.body, res.body_len));
        wtls_http_result_free(&res);
        break;
    }
    case 2: {
        /* Resumed TLS 1.3 handshake (no HTTP pool) */
        soak_url(url, sizeof url, SOAK_HTTP_PORT, "/len?n=2048");
        wtls_http_request req = {0};
        req.url = url;
        req.no_keepalive = true;
        CHECK_EQ_INT(wtls_http_fetch(&req, 0, &res), WTLS_OK);
        CHECK_EQ_INT(res.status, 200);
        CHECK_EQ_INT((long long)res.body_len, 2048);
        wtls_http_result_free(&res);
        break;
    }
    case 3: {
        /* Streaming mTLS upload (64 KiB) + echo verification */
        soak_url(url, sizeof url, SOAK_MTLS_HTTP_PORT, "/echo");
        wtls_options tls = {0};
        tls.client_cred = cred;
        soak_up_ctx up = {.len = 65536u, .chunk = 4096u};
        wtls_http_request req = {0};
        req.method = "POST";
        req.url = url;
        req.body_cb = soak_up_cb;
        req.body_ctx = &up;
        req.body_len = up.len;
        req.tls = &tls;
        CHECK_EQ_INT(wtls_http_fetch(&req, 128u * 1024u, &res), WTLS_OK);
        CHECK_EQ_INT(res.status, 200);
        CHECK_EQ_INT((long long)res.body_len, 65536);
        CHECK(res.body && soak_pattern_ok((const uint8_t *)res.body, res.body_len));
        wtls_http_result_free(&res);
        break;
    }
    case 4: {
        /* Gzip compressed response (chunked) when built with zlib */
#if WTLS_GZIP
        soak_url(url, sizeof url, SOAK_HTTP_PORT, "/gzip?n=16384&chunked=1");
#else
        soak_url(url, sizeof url, SOAK_HTTP_PORT, "/len?n=16384");
#endif
        wtls_http_request req = {0};
        req.url = url;
        CHECK_EQ_INT(wtls_http_fetch(&req, 0, &res), WTLS_OK);
        CHECK_EQ_INT(res.status, 200);
        CHECK_EQ_INT((long long)res.body_len, 16384);
        CHECK(res.body && soak_pattern_ok((const uint8_t *)res.body, res.body_len));
        wtls_http_result_free(&res);
        break;
    }
    case 5: {
        /* Cross-port redirect chain */
        char target[128];
        soak_url(target, sizeof target, SOAK_HTTP2_PORT, "/hello");
        char path[256];
        snprintf(path, sizeof path, "/redirect?code=302&to=%s", target);
        soak_url(url, sizeof url, SOAK_HTTP_PORT, path);
        wtls_http_request req = {0};
        req.url = url;
        CHECK_EQ_INT(wtls_http_fetch(&req, 0, &res), WTLS_OK);
        CHECK_EQ_INT(res.status, 200);
        CHECK(res.body && res.body_len == 5 && memcmp(res.body, "hello", 5) == 0);
        wtls_http_result_free(&res);
        break;
    }
    case 6: {
        /* Controlled cancellation during slow response headers */
        soak_url(url, sizeof url, SOAK_HTTP_PORT, "/slowhead");
        soak_abort_ctx ab = {.limit = 4};
        wtls_options tls = {0};
        tls.abort_cb = soak_abort_cb;
        tls.abort_ctx = &ab;
        wtls_http_request req = {0};
        req.url = url;
        req.header_timeout_ms = 5000;
        req.tls = &tls;
        wtls_http_response *r = (wtls_http_response *)1;
        CHECK_EQ_INT(wtls_http_open(&r, &req), WTLS_ERR_CANCELLED);
        CHECK(r == NULL);
        break;
    }
    default: {
        /* Raw TLS 1.2 echo + clean close_notify */
        wtls_conn *c = NULL;
        CHECK_EQ_INT(wtls_connect(&c, g_env.server_host, SOAK_TLS12_PORT, NULL), WTLS_OK);
        if (c) {
            CHECK_EQ_INT(wtls_write(c, "PING\n", 5), 5);
            char buf[16] = {0};
            CHECK_EQ_INT(wtls_read(c, buf, sizeof buf - 1), 5);
            CHECK(strcmp(buf, "PING\n") == 0);
            wtls_close(c);
        }
        break;
    }
    }
}

static size_t soak_heap_used(void) {
#ifdef WTLS_PLATFORM_OGC
    struct mallinfo mi = mallinfo();
    return (size_t)mi.uordblks;
#else
    return 0;
#endif
}

static void test_soak_endurance(void) {
    unsigned total = g_env.soak_iters ? g_env.soak_iters : (g_env.is_hw ? 200u : 24u);
    wtls_client_cred *cred = soak_load_cred("client-ec");
    CHECK(cred != NULL);
    if (!cred) return;

    /* Warm up once (one full 8-step cycle) so steady-state caches settle before baseline. */
    for (unsigned i = 0; i < 8u; i++) soak_step(i, cred);
    wtls_http_pool_flush();
    wtls_scache_clear();
    wtls_dns_clear();
    size_t u_base = soak_heap_used();
    TLOG("  [soak] running %u iterations (baseline uordblks=%u)\n", total, (unsigned)u_base);

    for (unsigned i = 0; i < total; i++) {
        soak_step(i, cred);
        if ((i + 1u) % 32u == 0 || (i + 1u) == total) {
            if ((i + 1u) % 64u == 0) wtls_net_reset();
            TLOG("  [soak] %u/%u uordblks=%u\n", i + 1u, total, (unsigned)soak_heap_used());
        }
    }

    wtls_client_cred_free(cred);
    wtls_net_reset();
    wtls_scache_clear();
    size_t u_end = soak_heap_used();
    TLOG("  [soak] final uordblks=%u (delta %+ld B)\n",
         (unsigned)u_end, (long)u_end - (long)u_base);
#ifdef WTLS_PLATFORM_OGC
    CHECK(u_end <= u_base + 4096u);
#endif
}

void wtls_suite_soak(void) {
    int r = wtls_init();
    CHECK_EQ_INT(r, WTLS_OK);
    if (r != WTLS_OK) return;
    if (!soak_trust_ca()) {
        CHECK(false);
        wtls_shutdown();
        return;
    }
    RUN(test_soak_endurance);
    wtls_shutdown();
}
