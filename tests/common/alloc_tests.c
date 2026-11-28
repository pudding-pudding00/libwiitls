/* Allocator hook tests, run on the host (tests/host/test_alloc.c) and on the
 * Wii (suite "alloc"). Server: tests/host/tls_test_server.py with --certs. */
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <wiitls/http.h>
#include <wiitls/wiitls.h>

#include "check.h"
#include "env.h"
#include "plat/plat.h"

#define PLAIN_PORT 4430
#define P_TLS13_ECDSA 4431
#define P_HTTP 4438
#define MAX_FAIL_ITERS 3000

/* Counting allocator with fault injection: the fail_at-th allocation (1-based,
 * calloc and growing realloc alike) returns NULL. 0 = never fail. */
typedef struct {
    long allocs, frees, calls;
    long fail_at;
    long live; /* blocks currently allocated: must be 0 after shutdown */
    bool failed;
} alloc_state;

static alloc_state s_st;

static void *t_calloc(void *ctx, size_t n, size_t size) {
    alloc_state *s = ctx;
    s->calls++;
    if (s->fail_at && s->calls == s->fail_at) {
        s->failed = true;
        return NULL;
    }
    void *p = calloc(n, size);
    if (p) {
        s->allocs++;
        s->live++;
    }
    return p;
}

static void *t_realloc(void *ctx, void *p, size_t size) {
    alloc_state *s = ctx;
    s->calls++;
    if (s->fail_at && s->calls == s->fail_at) {
        s->failed = true;
        return NULL;
    }
    return realloc(p, size);
}

static void t_free(void *ctx, void *p) {
    alloc_state *s = ctx;
    CHECK(p != NULL); /* NULL is never passed to free_fn */
    s->frees++;
    s->live--;
    free(p);
}

static wtls_allocator counting(bool with_realloc) {
    wtls_allocator a = {t_calloc, with_realloc ? t_realloc : NULL, t_free, &s_st};
    return a;
}

static bool plain_recv_exact(int fd, uint8_t *buf, size_t n, uint64_t deadline) {
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

static bool trust_test_ca(void) {
    uint32_t ip;
    int fd = -1;
    if (wtls_plat_resolve(g_env.server_host, &ip) != WTLS_OK) return false;
    if (wtls_plat_connect(ip, PLAIN_PORT, 3000, &fd) != WTLS_OK) return false;
    bool ok = false;
    uint8_t *der = NULL;
    uint64_t deadline = wtls_plat_now_ms() + 3000;
    if (wtls_plat_send(fd, (const uint8_t *)"CA\n", 3) == 3) {
        char line[16] = {0};
        size_t i = 0;
        while (i < sizeof line - 1 && plain_recv_exact(fd, (uint8_t *)&line[i], 1, deadline) && line[i] != '\n') i++;
        long len = strtol(line, NULL, 10);
        if (len > 0 && len < 8192 && (der = malloc((size_t)len)) &&
            plain_recv_exact(fd, der, (size_t)len, deadline))
            ok = wtls_add_trusted_ca(der, (size_t)len) == WTLS_OK;
    }
    free(der);
    wtls_plat_close(fd);
    return ok;
}

/* Installs the counting allocator, initialises and trusts the test CA. */
static bool start(bool with_realloc) {
    memset(&s_st, 0, sizeof s_st);
    wtls_allocator a = counting(with_realloc);
    CHECK_EQ_INT(wtls_set_allocator(&a), WTLS_OK);
    int r = wtls_init();
    CHECK_EQ_INT(r, WTLS_OK);
    if (r != WTLS_OK) return false;
    bool t = trust_test_ca();
    CHECK(t);
    return t;
}

static void finish(void) {
    wtls_shutdown();
    CHECK_EQ_INT(s_st.live, 0); /* every block came back through free_fn */
    CHECK_EQ_INT(s_st.allocs, s_st.frees);
    CHECK_EQ_INT(wtls_set_allocator(NULL), WTLS_OK);
}

static void test_alloc_custom_used_by_connect(void) {
    if (!start(true)) {
        wtls_shutdown();
        wtls_set_allocator(NULL);
        return;
    }
    long before = s_st.allocs;
    wtls_conn *c = NULL;
    CHECK_EQ_INT(wtls_connect(&c, g_env.server_host, P_TLS13_ECDSA, NULL), WTLS_OK);
    CHECK(s_st.allocs > before);
    wtls_close(c);
    finish();
    CHECK(s_st.allocs > 0);
}

static void test_alloc_without_realloc_fn(void) {
    if (!start(false)) {
        wtls_shutdown();
        wtls_set_allocator(NULL);
        return;
    }
    wtls_http_request req = {0};
    char url[96];
    snprintf(url, sizeof url, "https://%s:%u/hello", g_env.server_host, (unsigned)P_HTTP);
    req.url = url;
    wtls_http_result res;
    CHECK_EQ_INT(wtls_http_fetch(&req, 0, &res), WTLS_OK);
    CHECK_EQ_INT(res.status, 200);
    CHECK(res.body && strcmp(res.body, "hello") == 0);
    wtls_http_result_free(&res);
    finish();
}

static void test_alloc_set_after_init_refused(void) {
    CHECK_EQ_INT(wtls_init(), WTLS_OK);
    wtls_allocator a = counting(true);
    CHECK_EQ_INT(wtls_set_allocator(&a), WTLS_ERR_STATE);
    wtls_shutdown();
    CHECK_EQ_INT(wtls_set_allocator(&a), WTLS_OK); /* fine again after shutdown */
    CHECK_EQ_INT(wtls_set_allocator(NULL), WTLS_OK);
}

static void test_alloc_missing_functions_arg(void) {
    wtls_allocator a = {NULL, NULL, t_free, NULL};
    CHECK_EQ_INT(wtls_set_allocator(&a), WTLS_ERR_ARG);
    a.calloc_fn = t_calloc;
    a.free_fn = NULL;
    CHECK_EQ_INT(wtls_set_allocator(&a), WTLS_ERR_ARG);
}

/* Fails the n-th allocation of one operation for n = 1, 2, ... until the
 * operation succeeds untouched. Every failure must be a clean error, and
 * nothing may leak (checked by finish()). */
static void test_alloc_fail_nth_connect(void) {
    if (!start(true)) {
        wtls_shutdown();
        wtls_set_allocator(NULL);
        return;
    }
    int failures = 0;
    bool completed = false, uninjected = false;
    for (long n = 1; n <= MAX_FAIL_ITERS; n++) {
        s_st.calls = 0;
        s_st.failed = false;
        s_st.fail_at = n;
        wtls_conn *c = (wtls_conn *)1;
        int r = wtls_connect(&c, g_env.server_host, P_TLS13_ECDSA, NULL);
        s_st.fail_at = 0;
        if (r == WTLS_OK) {
            wtls_close(c);
            if (!s_st.failed) {
                completed = true;
                break;
            }
            failures++; /* the library tolerated the failure (optional allocation) */
            continue;
        }
        CHECK(r < 0);
        CHECK(c == NULL);
        if (!s_st.failed && !uninjected) { /* failed although no allocation was refused: state left behind */
            uninjected = true;
            CHECK(s_st.failed);
            TLOG("  connect failed without an injected failure: n=%ld r=%d (%s), allocs=%ld\n", n, r,
                 wtls_strerror(r), (long)s_st.calls);
        }
        failures++;
    }
    CHECK(completed);
    CHECK(failures > 10);
    TLOG("  connect survived %d injected allocation failures\n", failures);
    finish();
}

static void test_alloc_fail_nth_http_fetch(void) {
    if (!start(true)) {
        wtls_shutdown();
        wtls_set_allocator(NULL);
        return;
    }
    char url[96];
    snprintf(url, sizeof url, "https://%s:%u/hello", g_env.server_host, (unsigned)P_HTTP);
    int failures = 0;
    bool completed = false;
    for (long n = 1; n <= MAX_FAIL_ITERS; n++) {
        wtls_http_pool_flush();
        s_st.calls = 0;
        s_st.failed = false;
        s_st.fail_at = n;
        wtls_http_request req = {0};
        req.url = url;
        req.no_keepalive = true;
        wtls_http_result res;
        memset(&res, 0, sizeof res);
        int r = wtls_http_fetch(&req, 0, &res);
        s_st.fail_at = 0;
        if (r == WTLS_OK) {
            CHECK(res.body && strcmp(res.body, "hello") == 0);
            wtls_http_result_free(&res);
            if (!s_st.failed) {
                completed = true;
                break;
            }
            failures++;
            continue;
        }
        CHECK(r < 0);
        CHECK(res.body == NULL);
        failures++;
    }
    CHECK(completed);
    CHECK(failures > 10);
    TLOG("  fetch survived %d injected allocation failures\n", failures);
    finish();
}

#if defined(WTLS_GZIP) && WTLS_GZIP
static void test_alloc_gzip_uses_hook(void) {
    if (!start(true)) {
        wtls_shutdown();
        wtls_set_allocator(NULL);
        return;
    }
    char url[128];
    snprintf(url, sizeof url, "https://%s:%u/gzip?n=4000", g_env.server_host, (unsigned)P_HTTP);
    wtls_http_request req = {0};
    req.url = url;
    wtls_http_result res;
    long before = s_st.allocs;
    CHECK_EQ_INT(wtls_http_fetch(&req, 0, &res), WTLS_OK);
    CHECK_EQ_INT((long)res.body_len, 4000);
    /* zlib's inflate state alone is more than 7 KiB: it must have gone through us */
    CHECK(s_st.allocs - before >= 3);
    wtls_http_result_free(&res);
    finish();
}
#endif

void wtls_suite_alloc(void) {
    RUN(test_alloc_set_after_init_refused);
    RUN(test_alloc_missing_functions_arg);
    RUN(test_alloc_custom_used_by_connect);
    RUN(test_alloc_without_realloc_fn);
    RUN(test_alloc_fail_nth_connect);
    RUN(test_alloc_fail_nth_http_fetch);
#if defined(WTLS_GZIP) && WTLS_GZIP
    RUN(test_alloc_gzip_uses_hook);
#endif
}
