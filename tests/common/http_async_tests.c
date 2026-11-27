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

/* wtls_http_start() is still waiting: for the answer, or (over a real network) still for the connect. */
static bool is_pending(int st) { return st == WTLS_WANT_READ || st == WTLS_WANT_WRITE; }

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
    CHECK(is_pending(st));
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
    CHECK(is_pending(wtls_http_start(&r, &req)));
    wtls_http_close(r);
    /* during the TLS handshake: a TLS client against the plain control port, which never answers */
    req.url = url_of("https", PLAIN_PORT, "/");
    r = NULL;
    int st = wtls_http_start(&r, &req);
    CHECK(is_pending(st));
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
    CHECK(is_pending(st));
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


/* ---- HTTP/2 (WTLS_HTTP2): one session, several streams ---------------------------------------------------- */

#if WTLS_HTTP2
#ifndef WTLS_H2_MAX_STREAMS
#define WTLS_H2_MAX_STREAMS 4
#endif
#define P_H2 4445
#define P_MUX 4449  /* concurrent server, 100 streams at once */
#define P_MUX2 4450 /* concurrent server, 2 streams at once */

static const char *h2url(uint16_t port, const char *path) { return url_of("https", port, path); }

typedef struct {
    wtls_http_request req;
    wtls_http_response *r;
    int st;       /* status of the last start/step */
    bool head;
    bool done;    /* the body has ended (or failed: see err) */
    bool stall;   /* leave the body unread */
    int err;
    uint8_t *body;
    size_t len, cap;
    uint64_t t_head, t_done;
} job;

static void job_start(job *j, const char *url, size_t cap) {
    memset(j, 0, sizeof *j);
    j->req.url = url;
    j->cap = cap;
    j->body = malloc(cap ? cap : 1);
    j->st = wtls_http_start(&j->r, &j->req);
    CHECK(j->st == WTLS_OK || j->st == WTLS_WANT_READ || j->st == WTLS_WANT_WRITE);
    if (j->st == WTLS_OK) j->head = true;
    if (j->st != WTLS_OK && j->st != WTLS_WANT_READ && j->st != WTLS_WANT_WRITE) {
        j->err = j->st;
        j->done = true;
    }
}

static void job_free(job *j) {
    wtls_http_close(j->r);
    free(j->body);
    j->r = NULL;
    j->body = NULL;
}

/* One round for one job: step to the head, then read what is there. */
static void job_pump(job *j) {
    if (!j->r || j->done) return;
    if (!j->head) {
        j->st = wtls_http_step(j->r);
        if (j->st == WTLS_OK) {
            j->head = true;
            j->t_head = wtls_plat_now_ms();
        } else if (j->st != WTLS_WANT_READ && j->st != WTLS_WANT_WRITE) {
            j->err = j->st;
            j->done = true;
            return;
        }
    }
    while (j->head && !j->stall && !j->done) {
        if (j->len == j->cap) {
            j->err = WTLS_ERR_HTTP_LIMIT;
            j->done = true;
            return;
        }
        int k = wtls_http_read(j->r, j->body + j->len, j->cap - j->len);
        if (k > 0) {
            j->len += (size_t)k;
        } else if (k == 0) {
            j->done = true;
            j->t_done = wtls_plat_now_ms();
        } else if (k == WTLS_WANT_READ || k == WTLS_WANT_WRITE) {
            return;
        } else {
            j->err = k;
            j->done = true;
            return;
        }
    }
}

/* Runs the jobs until every one is done or stalled on purpose, or max_ms are over. stop(ctx) may end it early. */
static bool jobs_run(job *js, size_t n, uint32_t max_ms, bool (*stop)(void *), void *ctx) {
    uint64_t end = wtls_plat_now_ms() + max_ms;
    while (wtls_plat_now_ms() < end) {
        bool all = true;
        wtls_http_response *live[16];
        for (size_t i = 0; i < n; i++) {
            live[i] = NULL;
            if (js[i].r && !js[i].done && !(js[i].stall && js[i].head)) {
                live[i] = js[i].r;
                all = false;
            }
        }
        if (all || (stop && stop(ctx))) return true;
        wtls_http_wait(live, n, 50);
        for (size_t i = 0; i < n; i++) job_pump(&js[i]);
    }
    return false;
}

static const char *conn_of(const job *j) { return wtls_http_get_header(j->r, "x-conn"); }

static bool is_h2(const job *j) {
    wtls_http_info info;
    return wtls_http_get_info(j->r, &info) == WTLS_OK && info.http2 && info.tls.alpn && strcmp(info.tls.alpn, "h2") == 0;
}

static void test_async_h2_get_and_bodies(void) {
    wtls_http_pool_flush();
    job j;
    job_start(&j, h2url(P_H2, "/hello"), 64);
    CHECK(jobs_run(&j, 1, 10000, NULL, NULL));
    CHECK_EQ_INT(j.err, 0);
    CHECK(j.r && is_h2(&j) && wtls_http_status(j.r) == 200);
    CHECK(j.len == 5 && memcmp(j.body, "hello", 5) == 0);
    job_free(&j);

    job_start(&j, h2url(P_H2, "/len?n=300000"), 300001);
    CHECK(jobs_run(&j, 1, 20000, NULL, NULL));
    CHECK_EQ_INT(j.err, 0);
    CHECK(j.len == 300000 && is_pattern(j.body, j.len));
    job_free(&j);

    job_start(&j, h2url(P_H2, "/hello?no_cl=1"), 64); /* body ended by END_STREAM only */
    CHECK(jobs_run(&j, 1, 10000, NULL, NULL));
    CHECK(j.len == 5 && j.err == 0);
    job_free(&j);

    job_start(&j, h2url(P_H2, "/redirect?to=/hello"), 64); /* a redirect stays on the session machinery */
    CHECK(jobs_run(&j, 1, 10000, NULL, NULL));
    CHECK(j.len == 5 && j.err == 0 && wtls_http_status(j.r) == 200);
    job_free(&j);

    job_start(&j, h2url(P_H2, "/cont"), 64); /* head split over HEADERS + CONTINUATION, dynamic table entry */
    CHECK(jobs_run(&j, 1, 10000, NULL, NULL));
    CHECK(j.len == 4 && memcmp(j.body, "cont", 4) == 0);
    job_free(&j);

    job_start(&j, h2url(P_H2, "/gzip?n=20000"), 20001);
    CHECK(jobs_run(&j, 1, 10000, NULL, NULL));
    CHECK(j.len == 20000 && is_pattern(j.body, j.len));
    job_free(&j);

    job_start(&j, h2url(P_H2, "/status?code=404"), 64);
    CHECK(jobs_run(&j, 1, 10000, NULL, NULL));
    CHECK(wtls_http_status(j.r) == 404 && j.len == 0 && j.err == 0);
    job_free(&j);
}

static void test_async_h2_uploads(void) {
    wtls_http_pool_flush();
    static uint8_t big[150000];
    for (size_t i = 0; i < sizeof big; i++) big[i] = (uint8_t)(i % 251);
    wtls_http_request tmpl = {0};
    tmpl.method = "POST";
    for (int variant = 0; variant < 4; variant++) {
        gen g = {0, 70000, 1000};
        gen g2 = {0, 70000, 3333};
        size_t want = sizeof big;
        tmpl.body = big;
        tmpl.body_len = sizeof big; /* bigger than the 65535 byte windows: waits for WINDOW_UPDATEs */
        tmpl.body_cb = NULL;
        tmpl.body_chunked = false;
        if (variant == 1) {
            tmpl.body_len = 300;
            want = 300;
        } else if (variant == 2) {
            tmpl.body = NULL;
            tmpl.body_len = g.total;
            tmpl.body_cb = gen_cb;
            tmpl.body_ctx = &g;
            want = g.total;
        } else if (variant == 3) {
            tmpl.body = NULL;
            tmpl.body_len = 0;
            tmpl.body_chunked = true;
            tmpl.body_cb = gen_cb;
            tmpl.body_ctx = &g2;
            want = g2.total;
        }
        job j;
        memset(&j, 0, sizeof j);
        j.req = tmpl;
        j.req.url = h2url(P_MUX, "/echo");
        j.cap = want + 1;
        j.body = malloc(j.cap);
        j.st = wtls_http_start(&j.r, &j.req);
        CHECK(j.st == WTLS_OK || j.st == WTLS_WANT_READ || j.st == WTLS_WANT_WRITE);
        CHECK(jobs_run(&j, 1, 20000, NULL, NULL));
        CHECK_EQ_INT(j.err, 0);
        CHECK_EQ_INT((long)j.len, (long)want);
        CHECK(is_pattern(j.body, j.len));
        job_free(&j);
    }
}

static bool all_heads(void *ctx) {
    const job *js = ctx;
    for (int i = 0; i < 4; i++)
        if (!js[i].head) return false;
    return true;
}

static void test_async_h2_streams_share_one_connection(void) {
    wtls_http_pool_flush();
    enum { N = 4 };
    job js[N];
    uint64_t t0 = wtls_plat_now_ms();
    for (int i = 0; i < N; i++) job_start(&js[i], h2url(P_MUX, "/slow?n=30000&delay=300"), 30001);
    CHECK(jobs_run(js, N, 20000, NULL, NULL));
    uint64_t dt = wtls_plat_now_ms() - t0;
    int maxactive = 0;
    for (int i = 0; i < N; i++) {
        CHECK_EQ_INT(js[i].err, 0);
        CHECK(js[i].len == 30000 && is_pattern(js[i].body, js[i].len));
        CHECK(js[i].r && is_h2(&js[i]));
        const char *c0 = conn_of(&js[0]), *ci = conn_of(&js[i]), *ma = wtls_http_get_header(js[i].r, "x-maxactive");
        CHECK(c0 && ci && strcmp(c0, ci) == 0); /* one connection for all of them */
        if (ma && atoi(ma) > maxactive) maxactive = atoi(ma);
    }
    CHECK(maxactive >= (WTLS_H2_MAX_STREAMS < 3 ? WTLS_H2_MAX_STREAMS : 3)); /* they really were open together */
    if (WTLS_H2_MAX_STREAMS >= 2) CHECK(dt < 1100); /* four 300 ms answers one after another would take 1200 ms */
    (void)all_heads;
    for (int i = 0; i < N; i++) job_free(&js[i]);

    /* the session stays for the next request */
    job j;
    job_start(&j, h2url(P_MUX, "/hello"), 16);
    CHECK(jobs_run(&j, 1, 10000, NULL, NULL));
    CHECK(j.len == 5 && j.r && conn_of(&j) && strcmp(conn_of(&j), "0") != 0);
    wtls_http_info info;
    CHECK(j.r && wtls_http_get_info(j.r, &info) == WTLS_OK && info.reused_connection);
    job_free(&j);
}

static void test_async_h2_small_answers_pass_a_stalled_big_one(void) {
    wtls_http_pool_flush();
    job js[3];
    job_start(&js[0], h2url(P_MUX, "/len?n=3000000"), 3000001);
    js[0].stall = true; /* nobody reads it: its window fills up and the server must wait */
    job_start(&js[1], h2url(P_MUX, "/hello"), 16);
    job_start(&js[2], h2url(P_MUX, "/len?n=1000"), 1001);
    CHECK(jobs_run(js, 3, 15000, NULL, NULL));
    CHECK_EQ_INT(js[1].err, 0);
    CHECK_EQ_INT(js[2].err, 0);
    CHECK(js[1].len == 5 && js[2].len == 1000 && is_pattern(js[2].body, 1000));
    CHECK(js[0].head && !js[0].done);
    /* now read the big one; the others' answers did not disturb it */
    js[0].stall = false;
    CHECK(jobs_run(js, 1, 30000, NULL, NULL));
    CHECK_EQ_INT(js[0].err, 0);
    CHECK(js[0].len == 3000000 && is_pattern(js[0].body, js[0].len));
    for (int i = 0; i < 3; i++) job_free(&js[i]);
}

static void test_async_h2_cancel_one_stream(void) {
    wtls_http_pool_flush();
    job js[3];
    job_start(&js[0], h2url(P_MUX, "/trickle?n=200000&chunk=1000&gap=20"), 200001);
    job_start(&js[1], h2url(P_MUX, "/slow?n=20000&delay=200"), 20001);
    job_start(&js[2], h2url(P_MUX, "/len?n=5000"), 5001);
    js[0].stall = false;
    uint64_t end = wtls_plat_now_ms() + 10000;
    while (!js[0].head && wtls_plat_now_ms() < end) {
        wtls_http_response *live[3] = {js[0].r, js[1].r, js[2].r};
        wtls_http_wait(live, 3, 50);
        for (int i = 0; i < 3; i++) job_pump(&js[i]);
    }
    CHECK(js[0].head);
    wtls_http_close(js[0].r); /* gives up on the trickle: RST_STREAM for it, the others go on */
    js[0].r = NULL;
    js[0].done = true;
    CHECK(jobs_run(&js[1], 2, 15000, NULL, NULL));
    CHECK_EQ_INT(js[1].err, 0);
    CHECK_EQ_INT(js[2].err, 0);
    CHECK(js[1].len == 20000 && js[2].len == 5000);
    /* the server saw the reset */
    job st;
    job_start(&st, h2url(P_MUX, "/stats"), 256);
    CHECK(jobs_run(&st, 1, 10000, NULL, NULL));
    st.body[st.len < st.cap ? st.len : st.cap - 1] = 0;
    CHECK(strstr((char *)st.body, "cancelled=") != NULL && strstr((char *)st.body, "cancelled=0") == NULL);
    job_free(&st);
    job_free(&js[1]);
    job_free(&js[2]);
    free(js[0].body);
}

static void test_async_h2_server_limit_of_two_streams(void) {
    wtls_http_pool_flush();
    enum { N = 6 };
    job js[N];
    for (int i = 0; i < N; i++) job_start(&js[i], h2url(P_MUX2, "/slow?n=10000&delay=100"), 10001);
    CHECK(jobs_run(js, N, 30000, NULL, NULL));
    for (int i = 0; i < N; i++) {
        CHECK_EQ_INT(js[i].err, 0); /* the server answers a stream over its limit with GOAWAY: none of that may happen */
        CHECK(js[i].len == 10000);
        const char *ma = js[i].r ? wtls_http_get_header(js[i].r, "x-maxactive") : NULL;
        CHECK(ma && atoi(ma) <= 2);
    }
    for (int i = 0; i < N; i++) job_free(&js[i]);
}

static char *unique_token(char *buf, size_t cap) {
    static unsigned n;
    snprintf(buf, cap, "t%llu_%u", (unsigned long long)wtls_plat_now_ms(), n++);
    return buf;
}

static void test_async_h2_goaway_and_refused_stream_are_retried(void) {
    wtls_http_pool_flush();
    char token[64], path[160];
    job j;
    /* the server drops the stream and closes the session: the request goes to a new connection */
    snprintf(path, sizeof path, "/goaway_once?token=%s", unique_token(token, sizeof token));
    job_start(&j, h2url(P_MUX, path), 32);
    CHECK(jobs_run(&j, 1, 15000, NULL, NULL));
    CHECK_EQ_INT(j.err, 0);
    CHECK(j.len == 5 && memcmp(j.body, "again", 5) == 0);
    job_free(&j);
    /* refused: the same session takes it again */
    snprintf(path, sizeof path, "/refuse_once?token=%s", unique_token(token, sizeof token));
    job_start(&j, h2url(P_MUX, path), 32);
    CHECK(jobs_run(&j, 1, 15000, NULL, NULL));
    CHECK_EQ_INT(j.err, 0);
    CHECK(j.len == 5 && memcmp(j.body, "again", 5) == 0);
    job_free(&j);
    /* a POST is not repeated behind the caller's back */
    snprintf(path, sizeof path, "/goaway_once?token=%s", unique_token(token, sizeof token));
    memset(&j, 0, sizeof j);
    j.req.url = h2url(P_MUX, path);
    j.req.method = "POST";
    j.req.body = "x";
    j.req.body_len = 1;
    j.cap = 32;
    j.body = malloc(32);
    j.st = wtls_http_start(&j.r, &j.req);
    CHECK(jobs_run(&j, 1, 15000, NULL, NULL));
    CHECK(j.err != 0);
    job_free(&j);
}

static void test_async_h2_trailers_keep_the_header_table_in_step(void) {
    wtls_http_pool_flush();
    job js[3];
    job_start(&js[0], h2url(P_MUX, "/trailers?n=3000"), 3001);
    job_start(&js[1], h2url(P_MUX, "/trailers?n=100"), 101);
    job_start(&js[2], h2url(P_MUX, "/hello"), 16);
    CHECK(jobs_run(js, 3, 15000, NULL, NULL));
    for (int i = 0; i < 3; i++) CHECK_EQ_INT(js[i].err, 0);
    CHECK(js[0].len == 3000 && js[1].len == 100 && js[2].len == 5);
    for (int i = 0; i < 3; i++) job_free(&js[i]);
    job j; /* the session still works afterwards */
    job_start(&j, h2url(P_MUX, "/hello"), 16);
    CHECK(jobs_run(&j, 1, 10000, NULL, NULL));
    CHECK(j.len == 5 && j.err == 0);
    job_free(&j);
}

static void test_async_h2_pool_flush_closes_sessions(void) {
    wtls_http_pool_flush();
    job a, b;
    job_start(&a, h2url(P_MUX, "/hello"), 16);
    CHECK(jobs_run(&a, 1, 10000, NULL, NULL));
    char first[32] = "";
    if (a.r && conn_of(&a)) snprintf(first, sizeof first, "%s", conn_of(&a));
    job_free(&a);
    wtls_http_pool_flush(); /* the idle session is closed */
    job_start(&b, h2url(P_MUX, "/hello"), 16);
    CHECK(jobs_run(&b, 1, 10000, NULL, NULL));
    CHECK(b.r && conn_of(&b) && strcmp(conn_of(&b), first) != 0);
    job_free(&b);
    /* a busy session is retired: it finishes its stream, then goes */
    job c, d;
    job_start(&c, h2url(P_MUX, "/slow?n=1000&delay=300"), 1001);
    CHECK(jobs_run(&c, 1, 100, NULL, NULL) == false); /* still waiting */
    wtls_http_pool_flush();
    CHECK(jobs_run(&c, 1, 10000, NULL, NULL));
    CHECK(c.err == 0 && c.len == 1000);
    char busy[32] = "";
    if (c.r && conn_of(&c)) snprintf(busy, sizeof busy, "%s", conn_of(&c));
    job_free(&c);
    job_start(&d, h2url(P_MUX, "/hello"), 16);
    CHECK(jobs_run(&d, 1, 10000, NULL, NULL));
    CHECK(d.r && conn_of(&d) && strcmp(conn_of(&d), busy) != 0);
    job_free(&d);
}

static void test_async_h2_many_requests_in_waves(void) {
    wtls_http_pool_flush();
    enum { N = 12 };
    job js[N];
    for (int i = 0; i < N; i++) {
        char path[64];
        snprintf(path, sizeof path, "/len?n=%d", 1000 + i * 7919);
        job_start(&js[i], h2url(P_MUX, path), (size_t)(1000 + i * 7919) + 1);
    }
    CHECK(jobs_run(js, N, 30000, NULL, NULL));
    for (int i = 0; i < N; i++) {
        CHECK_EQ_INT(js[i].err, 0);
        CHECK_EQ_INT((long)js[i].len, 1000 + i * 7919);
        CHECK(is_pattern(js[i].body, js[i].len));
    }
    for (int i = 0; i < N; i++) job_free(&js[i]);
}

static void test_async_h2_no_h2_option_uses_http11(void) {
    wtls_http_pool_flush();
    job j;
    wtls_http_request req = {0};
    req.url = h2url(P_H2, "/hello");
    req.no_h2 = true;
    memset(&j, 0, sizeof j);
    j.req = req;
    j.cap = 16;
    j.body = malloc(16);
    j.st = wtls_http_start(&j.r, &j.req);
    CHECK(jobs_run(&j, 1, 10000, NULL, NULL));
    wtls_http_info info;
    CHECK(j.r && wtls_http_get_info(j.r, &info) == WTLS_OK && !info.http2);
    CHECK(j.len == 5);
    job_free(&j);
}
#endif

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
#if WTLS_HTTP2
    RUN(test_async_h2_get_and_bodies);
    RUN(test_async_h2_uploads);
    RUN(test_async_h2_streams_share_one_connection);
    RUN(test_async_h2_small_answers_pass_a_stalled_big_one);
    RUN(test_async_h2_cancel_one_stream);
    RUN(test_async_h2_server_limit_of_two_streams);
    RUN(test_async_h2_goaway_and_refused_stream_are_retried);
    RUN(test_async_h2_trailers_keep_the_header_table_in_step);
    RUN(test_async_h2_pool_flush_closes_sessions);
    RUN(test_async_h2_many_requests_in_waves);
    RUN(test_async_h2_no_h2_option_uses_http11);
#endif
    wtls_shutdown();
}
