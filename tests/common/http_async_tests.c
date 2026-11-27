/* wtls_http_start / wtls_http_step / wtls_http_wait tests, run on the host (tests/host/test_http_async.c) and on
 * the Wii (suite "httpasync"). Server: tests/host/tls_test_server.py. */
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <wiitls/http.h>

#include "check.h"
#include "env.h"
#include "plat/plat.h"
#include "wtls_dns.h"

#define PLAIN_PORT 4430
#define P_HTTP 4438
#define P_HTTP_PLAIN 4440
#define P_CLOSED 4499

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
        if (len > 0 && len < 8192 && (der = malloc((size_t)len)) && plain_recv_exact(fd, der, (size_t)len, deadline))
            ok = wtls_add_trusted_ca(der, (size_t)len) == WTLS_OK;
    }
    free(der);
    wtls_plat_close(fd);
    return ok;
}

/* ---- helpers -------------------------------------------------------------- */

static const char *url_of(const char *scheme, uint16_t port, const char *path) {
    static char bufs[6][400];
    static unsigned next;
    char *b = bufs[next++ % 6];
    snprintf(b, sizeof bufs[0], "%s://%s:%u%s", scheme, g_env.server_host, (unsigned)port, path);
    return b;
}

static const char *purl(const char *path) { return url_of("http", P_HTTP_PLAIN, path); }
static const char *surl(const char *path) { return url_of("https", P_HTTP, path); }

/* Steps until the head is complete or it failed; at most max_ms. */
static int drive(wtls_http_response *r, int st, uint32_t max_ms) {
    uint64_t end = wtls_plat_now_ms() + max_ms;
    while (st == WTLS_WANT_READ || st == WTLS_WANT_WRITE) {
        if (wtls_plat_now_ms() >= end) return WTLS_ERR_TIMEOUT;
        wtls_http_wait(&r, 1, 50);
        st = wtls_http_step(r);
    }
    return st;
}

/* Reads the whole body with non-blocking reads; returns the final status of the read loop (0 = clean end). */
static int read_body(wtls_http_response *r, uint8_t *buf, size_t cap, size_t *len, uint32_t max_ms) {
    uint64_t end = wtls_plat_now_ms() + max_ms;
    *len = 0;
    for (;;) {
        if (*len == cap) return WTLS_ERR_HTTP_LIMIT;
        int k = wtls_http_read(r, buf + *len, cap - *len);
        if (k > 0) {
            *len += (size_t)k;
        } else if (k == WTLS_WANT_READ || k == WTLS_WANT_WRITE) {
            if (wtls_plat_now_ms() >= end) return WTLS_ERR_TIMEOUT;
            if (!wtls_http_pending(r)) wtls_http_wait(&r, 1, 50);
        } else {
            return k;
        }
    }
}

/* start + drive; the response (or NULL) comes back, the status in *st. */
static wtls_http_response *begin(const wtls_http_request *req, int *st) {
    wtls_http_response *r = NULL;
    *st = wtls_http_start(&r, req);
    if (*st == WTLS_WANT_READ || *st == WTLS_WANT_WRITE) {
        CHECK(r != NULL);
        *st = drive(r, *st, 10000);
    } else if (*st != WTLS_OK) {
        CHECK(r == NULL);
    }
    return r;
}

static bool is_pattern(const uint8_t *p, size_t n) {
    for (size_t i = 0; i < n; i++)
        if (p[i] != (uint8_t)(i % 251)) return false;
    return true;
}

/* ---- tests ------------------------------------------------------------------ */

static void get_hello(const char *u, bool tls) {
    wtls_http_pool_flush();
    wtls_http_request req = {0};
    req.url = u;
    int st;
    wtls_http_response *r = begin(&req, &st);
    CHECK_EQ_INT(st, WTLS_OK);
    if (!r) return;
    CHECK_EQ_INT(wtls_http_status(r), 200);
    wtls_http_info info;
    CHECK_EQ_INT(wtls_http_get_info(r, &info), WTLS_OK);
    CHECK(info.secure == tls && !info.http2);
    uint8_t buf[64];
    size_t n;
    CHECK_EQ_INT(read_body(r, buf, sizeof buf, &n, 5000), 0);
    CHECK(n == 5 && memcmp(buf, "hello", 5) == 0);
    wtls_http_close(r);
}

static void test_async_get_plain(void) { get_hello(purl("/hello"), false); }
static void test_async_get_tls(void) { get_hello(surl("/hello"), true); }

static void test_async_large_body_identical_to_blocking(void) {
    wtls_http_pool_flush();
    wtls_http_request req = {0};
    req.url = surl("/len?n=300000");
    int st;
    wtls_http_response *r = begin(&req, &st);
    CHECK_EQ_INT(st, WTLS_OK);
    if (!r) return;
    uint8_t *buf = malloc(300001);
    size_t n;
    CHECK_EQ_INT(read_body(r, buf, 300001, &n, 20000), 0);
    CHECK_EQ_INT((long)n, 300000);
    CHECK(is_pattern(buf, n));
    free(buf);
    wtls_http_close(r);
}

static void test_async_chunked_and_gzip(void) {
    wtls_http_pool_flush();
    wtls_http_request req = {0};
    req.url = purl("/chunked?n=50000&size=700");
    int st;
    wtls_http_response *r = begin(&req, &st);
    CHECK_EQ_INT(st, WTLS_OK);
    if (r) {
        uint8_t *buf = malloc(50001);
        size_t n;
        CHECK_EQ_INT(read_body(r, buf, 50001, &n, 10000), 0);
        CHECK(n == 50000 && is_pattern(buf, n));
        free(buf);
        wtls_http_close(r);
    }
#if WTLS_GZIP
    req.url = purl("/gzip?n=4000");
    r = begin(&req, &st);
    CHECK_EQ_INT(st, WTLS_OK);
    if (r) {
        wtls_http_info info;
        wtls_http_get_info(r, &info);
        CHECK(info.gzip);
        uint8_t buf[4100];
        size_t n;
        CHECK_EQ_INT(read_body(r, buf, sizeof buf, &n, 5000), 0);
        CHECK(n == 4000 && is_pattern(buf, n));
        wtls_http_close(r);
    }
#endif
}

static void test_async_redirect_followed(void) {
    wtls_http_pool_flush();
    wtls_http_request req = {0};
    req.url = surl("/redirect-chain?n=2");
    int st;
    wtls_http_response *r = begin(&req, &st);
    CHECK_EQ_INT(st, WTLS_OK);
    if (!r) return;
    wtls_http_info info;
    wtls_http_get_info(r, &info);
    CHECK_EQ_INT(info.redirects, 2);
    uint8_t buf[16];
    size_t n;
    CHECK_EQ_INT(read_body(r, buf, sizeof buf, &n, 5000), 0);
    CHECK(n == 4 && memcmp(buf, "done", 4) == 0);
    wtls_http_close(r);
    req.max_redirects = -1; /* not followed on request */
    r = begin(&req, &st);
    CHECK_EQ_INT(st, WTLS_OK);
    if (r) {
        CHECK_EQ_INT(wtls_http_status(r), 302);
        wtls_http_close(r);
    }
}

typedef struct {
    size_t sent, total;
    size_t piece;
} gen;

static int gen_cb(void *ctx, void *buf, size_t len) {
    gen *g = ctx;
    size_t n = g->total - g->sent;
    if (n > len) n = len;
    if (n > g->piece) n = g->piece;
    for (size_t i = 0; i < n; i++) ((uint8_t *)buf)[i] = (uint8_t)((g->sent + i) % 251);
    g->sent += n;
    return (int)n;
}

static void echo_case(const wtls_http_request *tmpl, size_t want_len) {
    wtls_http_request req = *tmpl;
    int st;
    wtls_http_response *r = begin(&req, &st);
    CHECK_EQ_INT(st, WTLS_OK);
    if (!r) return;
    CHECK_EQ_INT(wtls_http_status(r), 200);
    uint8_t *buf = malloc(want_len + 1);
    size_t n;
    CHECK_EQ_INT(read_body(r, buf, want_len + 1, &n, 20000), 0);
    CHECK_EQ_INT((long)n, (long)want_len);
    CHECK(is_pattern(buf, n));
    free(buf);
    wtls_http_close(r);
}

static void test_async_uploads(void) {
    wtls_http_pool_flush();
    static uint8_t big[100000];
    for (size_t i = 0; i < sizeof big; i++) big[i] = (uint8_t)(i % 251);
    wtls_http_request req = {0};
    req.method = "POST";
    req.url = purl("/echo");
    req.body = big;
    req.body_len = 300; /* small: head and body go out together */
    echo_case(&req, 300);
    req.body_len = sizeof big; /* big: head, then the body */
    echo_case(&req, sizeof big);
    req.url = surl("/echo");
    echo_case(&req, sizeof big);
    gen g = {0, 70000, 1000};
    req.body = NULL;
    req.body_len = g.total; /* callback with Content-Length */
    req.body_cb = gen_cb;
    req.body_ctx = &g;
    echo_case(&req, g.total);
    gen g2 = {0, 70000, 3333};
    req.body_len = 0;
    req.body_chunked = true; /* callback, chunked */
    req.body_ctx = &g2;
    echo_case(&req, g2.total);
}

static void test_async_keepalive_reuse(void) {
    wtls_http_pool_flush();
    for (int round = 0; round < 3; round++) {
        wtls_http_request req = {0};
        req.url = purl("/hello");
        int st;
        wtls_http_response *r = begin(&req, &st);
        CHECK_EQ_INT(st, WTLS_OK);
        if (!r) return;
        wtls_http_info info;
        wtls_http_get_info(r, &info);
        CHECK_EQ_INT(info.reused_connection, round > 0);
        uint8_t buf[16];
        size_t n;
        CHECK_EQ_INT(read_body(r, buf, sizeof buf, &n, 5000), 0);
        wtls_http_close(r); /* read to the end: back into the pool */
    }
}

static void test_async_stale_pooled_connection_retried(void) {
    wtls_http_pool_flush();
    wtls_http_request req = {0};
    req.url = purl("/drop-next"); /* the server drops the next request on this connection */
    wtls_http_result res;
    CHECK_EQ_INT(wtls_http_fetch(&req, 64, &res), WTLS_OK);
    wtls_http_result_free(&res);
    req.url = purl("/hello");
    int st;
    wtls_http_response *r = begin(&req, &st);
    CHECK_EQ_INT(st, WTLS_OK);
    if (!r) return;
    wtls_http_info info;
    wtls_http_get_info(r, &info);
    CHECK(!info.reused_connection); /* the pooled one failed, a new one answered */
    wtls_http_close(r);
}

static void test_async_cookie_jar(void) {
    wtls_http_pool_flush();
    wtls_cookie_jar *jar = wtls_cookie_jar_new(0);
    wtls_http_request req = {0};
    req.cookie_jar = jar;
    req.no_keepalive = true;
    req.url = purl("/setcookie?c=sid%3Dasync1");
    int st;
    wtls_http_response *r = begin(&req, &st);
    CHECK_EQ_INT(st, WTLS_OK);
    if (r) wtls_http_close(r);
    CHECK_EQ_INT((int)wtls_cookie_jar_count(jar), 1);
    req.url = purl("/headers");
    r = begin(&req, &st);
    CHECK_EQ_INT(st, WTLS_OK);
    if (r) {
        uint8_t buf[2048];
        size_t n;
        CHECK_EQ_INT(read_body(r, buf, sizeof buf - 1, &n, 5000), 0);
        buf[n] = 0;
        CHECK(strstr((char *)buf, "sid=async1") != NULL);
        wtls_http_close(r);
    }
    wtls_cookie_jar_free(jar);
}

/* ---- many at once ------------------------------------------------------------ */

static void test_async_concurrent_requests_overlap(void) {
    wtls_http_pool_flush();
    enum { N = 4 };
    wtls_http_request req[N];
    wtls_http_response *r[N];
    int st[N];
    uint64_t t0 = wtls_plat_now_ms();
    for (int i = 0; i < N; i++) {
        memset(&req[i], 0, sizeof req[i]);
        req[i].url = i & 1 ? surl("/slowbody?ms=400") : purl("/slowbody?ms=400");
        req[i].no_keepalive = true;
        r[i] = NULL;
        st[i] = wtls_http_start(&r[i], &req[i]);
        CHECK(st[i] == WTLS_OK || st[i] == WTLS_WANT_READ || st[i] == WTLS_WANT_WRITE);
    }
    int done = 0;
    bool got_body[N] = {false};
    uint64_t end = wtls_plat_now_ms() + 15000;
    while (done < N && wtls_plat_now_ms() < end) {
        wtls_http_response *live[N];
        for (int i = 0; i < N; i++) live[i] = (r[i] && !got_body[i]) ? r[i] : NULL;
        wtls_http_wait(live, N, 100);
        for (int i = 0; i < N; i++) {
            if (!r[i] || got_body[i]) continue;
            if (st[i] == WTLS_WANT_READ || st[i] == WTLS_WANT_WRITE) {
                st[i] = wtls_http_step(r[i]);
                CHECK(st[i] >= WTLS_ERR_CERT || st[i] == WTLS_OK || st[i] == WTLS_WANT_READ || st[i] == WTLS_WANT_WRITE);
            }
            if (st[i] == WTLS_OK) {
                char b[8];
                int k = wtls_http_read(r[i], b, sizeof b);
                if (k == 0 || k == 2) {
                    got_body[i] = true;
                    done++;
                } else if (k < 0 && k != WTLS_WANT_READ) {
                    CHECK(false);
                    got_body[i] = true;
                    done++;
                }
            }
        }
    }
    uint64_t dt = wtls_plat_now_ms() - t0;
    CHECK_EQ_INT(done, N);
    CHECK(dt < 1100); /* four 400 ms bodies one after another would take 1600 ms */
    for (int i = 0; i < N; i++) wtls_http_close(r[i]);
}

static void test_async_wait_times_out_without_data(void) {
    wtls_http_pool_flush();
    wtls_http_request req = {0};
    req.url = purl("/slowhead"); /* the status line, then silence */
    req.no_keepalive = true;
    wtls_http_response *r = NULL;
    int st = wtls_http_start(&r, &req);
    CHECK(st == WTLS_WANT_READ);
    if (!r) return;
    st = drive(r, st, 300);
    CHECK_EQ_INT(st, WTLS_ERR_TIMEOUT); /* drive gave up: the response is still pending */
    uint64_t t0 = wtls_plat_now_ms();
    int w = wtls_http_wait(&r, 1, 200);
    CHECK_EQ_INT(w, 0);
    CHECK(wtls_plat_now_ms() - t0 >= 150);
    CHECK(wtls_http_get_fd(r) >= 0);
    wtls_http_close(r);
}

/* ---- cancelling ---------------------------------------------------------------- */

static void test_async_close_while_pending_in_every_phase(void) {
    wtls_http_pool_flush();
    wtls_http_request req = {0};
    req.no_keepalive = false;
    wtls_http_response *r = NULL;
    /* in the head phase */
    req.url = purl("/slowhead");
    CHECK(wtls_http_start(&r, &req) == WTLS_WANT_READ);
    wtls_http_close(r);
    /* during the TLS handshake: a TLS client against the plain control port, which never answers */
    req.url = url_of("https", PLAIN_PORT, "/");
    r = NULL;
    int st = wtls_http_start(&r, &req);
    CHECK(st == WTLS_WANT_READ || st == WTLS_WANT_WRITE);
    wtls_http_close(r);
    /* in the body phase */
    req.url = purl("/slowbody?ms=1500");
    r = NULL;
    st = wtls_http_start(&r, &req);
    if (r) {
        st = drive(r, st, 5000);
        CHECK_EQ_INT(st, WTLS_OK);
        char b[8];
        CHECK_EQ_INT(wtls_http_read(r, b, sizeof b), WTLS_WANT_READ);
        wtls_http_close(r); /* body unread: the connection must not go back into the pool */
    }
    /* the pool holds nothing half-used: the next request gets a fresh connection and a clean answer */
    wtls_http_request again = {0};
    again.url = purl("/hello");
    r = begin(&again, &st);
    CHECK_EQ_INT(st, WTLS_OK);
    if (r) {
        wtls_http_info info;
        wtls_http_get_info(r, &info);
        CHECK(!info.reused_connection);
        uint8_t buf[16];
        size_t n;
        CHECK_EQ_INT(read_body(r, buf, sizeof buf, &n, 5000), 0);
        CHECK(n == 5 && memcmp(buf, "hello", 5) == 0);
        wtls_http_close(r);
    }
}

static uint64_t s_abort_at;
static bool abort_late(void *ctx) {
    (void)ctx;
    return wtls_plat_now_ms() >= s_abort_at;
}

static void test_async_abort_cb(void) {
    wtls_http_pool_flush();
    wtls_options tls = {0};
    tls.abort_cb = abort_late;
    wtls_http_request req = {0};
    req.url = purl("/slowhead");
    req.tls = &tls;
    s_abort_at = wtls_plat_now_ms() + 150;
    wtls_http_response *r = NULL;
    int st = wtls_http_start(&r, &req);
    CHECK(st == WTLS_WANT_READ);
    if (!r) return;
    uint64_t t0 = wtls_plat_now_ms();
    st = drive(r, st, 3000);
    CHECK_EQ_INT(st, WTLS_ERR_CANCELLED);
    CHECK(wtls_plat_now_ms() - t0 < 600);
    CHECK_EQ_INT(wtls_http_step(r), WTLS_ERR_CANCELLED); /* sticky */
    wtls_http_close(r);
}

/* ---- time limits ----------------------------------------------------------------- */

static void test_async_timeouts(void) {
    wtls_http_pool_flush();
    int st;
    wtls_http_request req = {0};
    req.url = purl("/slowhead");
    req.header_timeout_ms = 300;
    uint64_t t0 = wtls_plat_now_ms();
    wtls_http_response *r = begin(&req, &st);
    CHECK_EQ_INT(st, WTLS_ERR_TIMEOUT); /* begin() closes nothing: the response is returned for closing */
    uint64_t dt = wtls_plat_now_ms() - t0;
    CHECK(dt >= 250 && dt < 1500);
    if (r) wtls_http_close(r);

    memset(&req, 0, sizeof req); /* total deadline over a slow body */
    req.url = purl("/slowbody?ms=3000");
    req.total_timeout_ms = 500;
    t0 = wtls_plat_now_ms();
    r = begin(&req, &st);
    CHECK_EQ_INT(st, WTLS_OK);
    if (r) {
        uint8_t buf[8];
        size_t n;
        CHECK_EQ_INT(read_body(r, buf, sizeof buf, &n, 5000), WTLS_ERR_TIMEOUT);
        dt = wtls_plat_now_ms() - t0;
        CHECK(dt >= 450 && dt < 1500);
        wtls_http_close(r);
    }

    wtls_options tls = {0}; /* idle timeout of the body: no byte for io_timeout_ms */
    tls.io_timeout_ms = 300;
    memset(&req, 0, sizeof req);
    req.url = purl("/slowbody?ms=2500");
    req.tls = &tls;
    t0 = wtls_plat_now_ms();
    r = begin(&req, &st);
    CHECK_EQ_INT(st, WTLS_OK);
    if (r) {
        uint8_t buf[8];
        size_t n;
        CHECK_EQ_INT(read_body(r, buf, sizeof buf, &n, 5000), WTLS_ERR_TIMEOUT);
        dt = wtls_plat_now_ms() - t0;
        CHECK(dt >= 250 && dt < 1500);
        wtls_http_close(r);
    }
}

static void test_async_retry_with_backoff_does_not_block(void) {
    wtls_http_pool_flush();
    wtls_http_request req = {0};
    req.url = purl("/flaky?id=async-r1&fails=2");
    req.no_keepalive = true;
    req.max_retries = 2;
    req.retry_backoff_ms = 150;
    wtls_http_response *r = NULL;
    int st = wtls_http_start(&r, &req);
    int idle_steps = 0; /* steps that returned WANT with nothing to poll: the backoff */
    uint64_t end = wtls_plat_now_ms() + 10000;
    uint64_t longest_step = 0;
    while ((st == WTLS_WANT_READ || st == WTLS_WANT_WRITE) && wtls_plat_now_ms() < end) {
        if (wtls_http_get_fd(r) < 0) idle_steps++;
        wtls_http_wait(&r, 1, 50);
        uint64_t s0 = wtls_plat_now_ms();
        st = wtls_http_step(r);
        uint64_t d = wtls_plat_now_ms() - s0;
        if (d > longest_step) longest_step = d;
    }
    CHECK_EQ_INT(st, WTLS_OK);
    CHECK(idle_steps >= 2);
    CHECK(longest_step < 100); /* the waits between attempts happen in wtls_http_wait, not in a step */
    if (r) {
        uint8_t buf[8];
        size_t n;
        CHECK_EQ_INT(read_body(r, buf, sizeof buf, &n, 5000), 0);
        CHECK(n == 2 && memcmp(buf, "ok", 2) == 0);
        wtls_http_close(r);
    }
    /* without retries the first drop is the answer */
    req.url = purl("/flaky?id=async-r2&fails=1");
    req.max_retries = 0;
    r = begin(&req, &st);
    CHECK_EQ_INT(st, WTLS_ERR_IO);
    if (r) wtls_http_close(r);
    /* 503 + Retry-After */
    req.url = purl("/flaky?id=async-r3&fails=1&mode=503&ra=1");
    req.max_retries = 1;
    req.retry_on_503 = true;
    uint64_t t0 = wtls_plat_now_ms();
    r = begin(&req, &st);
    CHECK_EQ_INT(st, WTLS_OK);
    if (r) {
        CHECK_EQ_INT(wtls_http_status(r), 200);
        CHECK(wtls_plat_now_ms() - t0 >= 900);
        wtls_http_close(r);
    }
}

/* ---- DNS without blocking ------------------------------------------------------------ */

static uint32_t s_dns_ip;

static int slow_dns(const char *host, uint32_t *addrs, size_t cap, size_t *count) {
    (void)host;
    (void)cap;
    wtls_plat_sleep_ms(400);
    addrs[0] = s_dns_ip;
    *count = 1;
    return WTLS_OK;
}

static void test_async_start_returns_during_dns(void) {
    if (g_env.is_hw) {
        SKIP("the Wii resolves inside the call (no helper thread yet)");
        return;
    }
    if (wtls_plat_resolve(g_env.server_host, &s_dns_ip) != WTLS_OK) return;
    wtls_http_pool_flush();
    wtls_dns_clear();
    wtls_dns_set_resolver_all(slow_dns);
    wtls_http_request req = {0};
    req.url = purl("/hello");
    wtls_http_response *r = NULL;
    uint64_t t0 = wtls_plat_now_ms();
    int st = wtls_http_start(&r, &req);
    CHECK(wtls_plat_now_ms() - t0 < 150); /* the lookup takes 400 ms */
    CHECK_EQ_INT(st, WTLS_WANT_READ);
    if (r) {
        CHECK_EQ_INT(wtls_http_get_fd(r), -1);
        CHECK_EQ_INT(wtls_http_read(r, &st, 1), WTLS_ERR_STATE); /* no head yet */
        st = drive(r, st, 5000);
        CHECK_EQ_INT(st, WTLS_OK);
        CHECK_EQ_INT(wtls_http_status(r), 200);
        wtls_http_close(r);
    }
    /* closing during the lookup must not leave the job behind */
    wtls_dns_clear();
    r = NULL;
    st = wtls_http_start(&r, &req);
    CHECK_EQ_INT(st, WTLS_WANT_READ);
    wtls_http_close(r);
    wtls_plat_sleep_ms(600);
    wtls_dns_set_resolver_all(NULL);
    wtls_dns_clear();
}

/* ---- arguments ------------------------------------------------------------------------ */

static void test_async_unsupported_and_bad_arguments(void) {
    wtls_http_response *r = (wtls_http_response *)1;
    wtls_http_request req = {0};
    req.url = purl("/hello");
    req.proxy_url = "http://127.0.0.1:4444";
    CHECK_EQ_INT(wtls_http_start(&r, &req), WTLS_ERR_UNSUPPORTED);
    CHECK(r == NULL);
    req.proxy_url = NULL;
    req.allow_upgrade = true;
    CHECK_EQ_INT(wtls_http_start(&r, &req), WTLS_ERR_UNSUPPORTED);
    req.allow_upgrade = false;
    req.expect_100_continue = true;
    CHECK_EQ_INT(wtls_http_start(&r, &req), WTLS_ERR_UNSUPPORTED);
    req.expect_100_continue = false;
    req.url = "ftp://x/";
    CHECK_EQ_INT(wtls_http_start(&r, &req), WTLS_ERR_ARG);
    CHECK_EQ_INT(wtls_http_start(NULL, &req), WTLS_ERR_ARG);
    CHECK_EQ_INT(wtls_http_step(NULL), WTLS_ERR_ARG);
    CHECK_EQ_INT(wtls_http_get_fd(NULL), -1);
    CHECK_EQ_INT(wtls_http_wait(NULL, 1, 1), WTLS_ERR_ARG);
    /* a connection that is refused is an error of start/step, not a hang */
    req.url = url_of("http", P_CLOSED, "/");
    int st;
    r = begin(&req, &st);
    CHECK_EQ_INT(st, WTLS_ERR_CONNECT);
    if (r) wtls_http_close(r);
}

void wtls_suite_http_async(void) {
    int rc = wtls_init();
    CHECK_EQ_INT(rc, WTLS_OK);
    if (rc != WTLS_OK) return;
    bool trusted = trust_test_ca();
    CHECK(trusted);
    if (!trusted) return;
    RUN(test_async_get_plain);
    RUN(test_async_get_tls);
    RUN(test_async_large_body_identical_to_blocking);
    RUN(test_async_chunked_and_gzip);
    RUN(test_async_redirect_followed);
    RUN(test_async_uploads);
    RUN(test_async_keepalive_reuse);
    RUN(test_async_stale_pooled_connection_retried);
    RUN(test_async_cookie_jar);
    RUN(test_async_concurrent_requests_overlap);
    RUN(test_async_wait_times_out_without_data);
    RUN(test_async_close_while_pending_in_every_phase);
    RUN(test_async_abort_cb);
    RUN(test_async_timeouts);
    RUN(test_async_retry_with_backoff_does_not_block);
    RUN(test_async_start_returns_during_dns);
    RUN(test_async_unsupported_and_bad_arguments);
    wtls_shutdown();
}
