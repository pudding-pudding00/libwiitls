/* HTTP client tests, run on the host (tests/host/test_http.c) and on the Wii
 * (suite "http"). Server: tests/host/tls_test_server.py with --certs, HTTP
 * ports 4438/4439. Every test starts with wtls_http_pool_flush() so that no
 * connection left in the pool by an earlier test changes its result. */
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
#define P_EXPIRED 4434
#define P_HTTP 4438
#define P_HTTP2 4439
#define P_HTTP_PLAIN 4440
#define P_H2 4445
#define P_CLOSED 4499

/* ---- helpers ------------------------------------------------------------ */

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

/* Fetches test-ca.der from the server's plain port and trusts it. */
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

/* "<scheme>://<server>:<port><path>" in one of four rotating buffers. */
static const char *url_of(const char *scheme, uint16_t port, const char *path) {
    static char bufs[4][600];
    static unsigned next;
    char *b = bufs[next++ % 4];
    int n = snprintf(b, sizeof bufs[0], "%s://%s:%u%s", scheme, g_env.server_host, (unsigned)port, path);
    CHECK(n > 0 && (size_t)n < sizeof bufs[0]); /* test paths are short */
    return b;
}

static const char *url(const char *path) { return url_of("https", P_HTTP, path); }

static wtls_http_response *open_req(const wtls_http_request *req) {
    wtls_http_response *r = (wtls_http_response *)1;
    int st = wtls_http_open(&r, req);
    CHECK_EQ_INT(st, WTLS_OK);
    if (st != WTLS_OK) {
        TLOG("  open %s -> %s\n", req->url, wtls_strerror(st));
        CHECK(r == NULL);
        return NULL;
    }
    return r;
}

static wtls_http_response *get(const char *path) {
    wtls_http_request req = {0};
    req.url = url(path);
    return open_req(&req);
}

/* Reads until the end or an error in steps of at most step bytes. Returns the
 * byte count; *last gets the final return value (0 or an error), or 1 when
 * the buffer filled up first. */
static size_t read_all(wtls_http_response *r, uint8_t *buf, size_t cap, size_t step, int *last) {
    size_t n = 0;
    while (n < cap) {
        size_t want = cap - n < step ? cap - n : step;
        int k = wtls_http_read(r, buf + n, want);
        if (k <= 0) {
            *last = k;
            return n;
        }
        n += (size_t)k;
    }
    *last = 1;
    return n;
}

static bool is_pattern(const uint8_t *b, size_t n, size_t offset) {
    for (size_t i = 0; i < n; i++)
        if (b[i] != (uint8_t)((offset + i) % 251)) return false;
    return true;
}

/* Body as a NUL-terminated string (max 4095 bytes); *last as read_all. */
static const char *body_str(wtls_http_response *r, int *last) {
    static char buf[4096];
    size_t n = read_all(r, (uint8_t *)buf, sizeof buf - 1, sizeof buf, last);
    buf[n] = 0;
    return buf;
}

/* ---- streaming client ----------------------------------------------------- */

static void http_get_hello(void) {
    wtls_http_pool_flush();
    wtls_http_response *r = get("/hello");
    if (!r) return;
    CHECK_EQ_INT(wtls_http_status(r), 200);
    CHECK_EQ_INT(wtls_http_content_length(r), 5);
    const char *ct = wtls_http_get_header(r, "Content-Type");
    CHECK(ct && strcmp(ct, "text/plain") == 0);
    const char *name, *value;
    CHECK(wtls_http_header_at(r, 0, &name, &value) && strcmp(name, "content-type") == 0);
    CHECK(!wtls_http_header_at(r, 2, &name, &value));
    char buf[16];
    CHECK_EQ_INT(wtls_http_read(r, buf, sizeof buf), 5);
    CHECK_MEM(buf, "hello", 5);
    CHECK_EQ_INT(wtls_http_read(r, buf, sizeof buf), 0);
    CHECK_EQ_INT(wtls_http_read(r, buf, sizeof buf), 0);
    wtls_http_close(r);
}

static void http_len_big(void) {
    wtls_http_pool_flush();
    wtls_http_response *r = get("/len?n=1000000");
    if (!r) return;
    CHECK_EQ_INT(wtls_http_content_length(r), 1000000);
    uint8_t buf[4096];
    size_t total = 0;
    bool pat = true;
    int k;
    while ((k = wtls_http_read(r, buf, sizeof buf)) > 0) {
        if (!is_pattern(buf, (size_t)k, total)) pat = false;
        total += (size_t)k;
    }
    CHECK_EQ_INT(k, 0);
    CHECK_EQ_INT(total, 1000000);
    CHECK(pat);
    wtls_http_close(r);
}

static void http_chunked(void) {
    wtls_http_pool_flush();
    wtls_http_response *r = get("/chunked?n=100000&size=777");
    if (!r) return;
    CHECK_EQ_INT(wtls_http_content_length(r), -1);
    uint8_t *buf = malloc(100001);
    int last = 0;
    size_t n = read_all(r, buf, 100001, 3000, &last);
    CHECK_EQ_INT(last, 0);
    CHECK_EQ_INT(n, 100000);
    CHECK(is_pattern(buf, n, 0));
    free(buf);
    wtls_http_close(r);
}

static void http_close_delimited(void) {
    wtls_http_pool_flush();
    wtls_http_response *r = get("/close?n=5000");
    if (!r) return;
    CHECK_EQ_INT(wtls_http_content_length(r), -1);
    uint8_t buf[6000];
    int last = 1;
    size_t n = read_all(r, buf, sizeof buf, 1000, &last);
    CHECK_EQ_INT(n, 5000);
    CHECK_EQ_INT(last, 0);
    CHECK(is_pattern(buf, n, 0));
    wtls_http_close(r);
}

static void http_close_delimited_without_close_notify(void) {
    wtls_http_pool_flush();
    wtls_http_response *r = get("/close?n=100&notify=0");
    if (!r) return;
    uint8_t buf[200];
    int last = 0;
    size_t n = read_all(r, buf, sizeof buf, sizeof buf, &last);
    CHECK_EQ_INT(n, 100);
    CHECK_EQ_INT(last, WTLS_ERR_IO);
    CHECK_EQ_INT(wtls_http_read(r, buf, sizeof buf), WTLS_ERR_IO); /* sticky */
    wtls_http_close(r);
}

static void http_truncated_length(void) {
    wtls_http_pool_flush();
    wtls_http_response *r = get("/trunc?n=1000&cut=500");
    if (!r) return;
    uint8_t buf[2000];
    int last = 0;
    size_t n = read_all(r, buf, sizeof buf, sizeof buf, &last);
    CHECK_EQ_INT(n, 500);
    CHECK_EQ_INT(last, WTLS_ERR_IO);
    wtls_http_close(r);
}

static void http_truncated_chunked(void) {
    wtls_http_pool_flush();
    wtls_http_response *r = get("/chunked?n=1000&size=100&cut=1");
    if (!r) return;
    uint8_t buf[2000];
    int last = 0;
    size_t n = read_all(r, buf, sizeof buf, sizeof buf, &last);
    CHECK_EQ_INT(n, 1000);
    CHECK_EQ_INT(last, WTLS_ERR_IO);
    wtls_http_close(r);
}

static void http_trickle(void) {
    wtls_http_pool_flush();
    wtls_http_response *r = get("/trickle");
    if (!r) return;
    CHECK_EQ_INT(wtls_http_status(r), 200);
    int last = 1;
    const char *b = body_str(r, &last);
    CHECK_EQ_INT(last, 0);
    CHECK(strcmp(b, "hello trickle") == 0);
    wtls_http_close(r);
}

/* A pooled connection takes the io_timeout_ms of the request that reuses it,
 * not of the one that opened it. */
static void http_reused_takes_request_io_timeout(void) {
    wtls_http_pool_flush();
    wtls_options fast = {0}, slow = {0};
    fast.io_timeout_ms = 300;
    slow.io_timeout_ms = 5000;
    for (int round = 0; round < 2; round++) {
        /* round 0: opened slow, reused fast -> times out; round 1: the reverse -> body arrives */
        wtls_http_request req = {0};
        req.url = url("/hello");
        req.tls = round == 0 ? &slow : &fast;
        wtls_http_response *r = open_req(&req);
        if (!r) return;
        int last = 1;
        body_str(r, &last);
        CHECK_EQ_INT(last, 0);
        wtls_http_close(r);
        req.url = url("/slowbody?ms=1000");
        req.tls = round == 0 ? &fast : &slow;
        r = open_req(&req);
        if (!r) return;
        wtls_http_info info;
        CHECK_EQ_INT(wtls_http_get_info(r, &info), WTLS_OK);
        CHECK(info.reused_connection);
        char buf[8];
        CHECK_EQ_INT(wtls_http_read(r, buf, sizeof buf), (round == 0 ? WTLS_ERR_TIMEOUT : 2));
        wtls_http_close(r);
    }
    wtls_http_pool_flush();
}

static void http_head_request(void) {
    wtls_http_pool_flush();
    wtls_http_request req = {0};
    req.method = "HEAD";
    req.url = url("/len?n=100");
    wtls_http_response *r = open_req(&req);
    if (!r) return;
    CHECK_EQ_INT(wtls_http_content_length(r), 100);
    char buf[16];
    CHECK_EQ_INT(wtls_http_read(r, buf, sizeof buf), 0);
    wtls_http_close(r);
}

static void http_status_no_body(void) {
    wtls_http_pool_flush();
    static const char *const paths[] = {"/status?code=204", "/status?code=304"};
    for (size_t i = 0; i < 2; i++) {
        wtls_http_response *r = get(paths[i]);
        if (!r) continue;
        CHECK_EQ_INT(wtls_http_status(r), i ? 304 : 204);
        char buf[16];
        CHECK_EQ_INT(wtls_http_read(r, buf, sizeof buf), 0);
        wtls_http_close(r);
    }
    wtls_http_response *r = get("/status?code=404");
    if (!r) return;
    CHECK_EQ_INT(wtls_http_status(r), 404);
    wtls_http_close(r);
}

static void http_interim_100(void) {
    wtls_http_pool_flush();
    wtls_http_response *r = get("/continue");
    if (!r) return;
    CHECK_EQ_INT(wtls_http_status(r), 200);
    int last = 1;
    CHECK(strcmp(body_str(r, &last), "ok") == 0);
    CHECK_EQ_INT(last, 0);
    wtls_http_close(r);
}

static void http_bighead_ok(void) {
    wtls_http_pool_flush();
    wtls_http_response *r = get("/bighead?n=12000");
    if (!r) return;
    CHECK_EQ_INT(wtls_http_status(r), 200);
    const char *big = wtls_http_get_header(r, "X-Big");
    CHECK(big && strlen(big) > 11000);
    wtls_http_close(r);
}

static void http_bighead_limit(void) {
    wtls_http_pool_flush();
    wtls_http_request req = {0};
    req.url = url("/bighead?n=17000");
    wtls_http_response *r = (wtls_http_response *)1;
    CHECK_EQ_INT(wtls_http_open(&r, &req), WTLS_ERR_HTTP_LIMIT);
    CHECK(r == NULL);
}

static void http_header_timeout(void) {
    wtls_http_pool_flush();
    wtls_http_request req = {0};
    req.url = url("/slowhead");
    req.header_timeout_ms = 500;
    wtls_http_response *r = (wtls_http_response *)1;
    uint64_t t0 = wtls_plat_now_ms();
    CHECK_EQ_INT(wtls_http_open(&r, &req), WTLS_ERR_TIMEOUT);
    uint64_t dt = wtls_plat_now_ms() - t0;
    CHECK(dt < 2000);
    CHECK(r == NULL);
}

static void http_post_echo(void) {
    wtls_http_pool_flush();
    wtls_http_request req = {0};
    req.method = "POST";
    req.url = url("/echo");
    req.body = "abc";
    req.body_len = 3;
    wtls_http_response *r = open_req(&req);
    if (!r) return;
    int last = 1;
    CHECK(strcmp(body_str(r, &last), "abc") == 0);
    CHECK_EQ_INT(last, 0);
    wtls_http_close(r);
}

static void http_request_headers(void) {
    wtls_http_pool_flush();
    wtls_http_header h[] = {{"X-A", "1"}};
    wtls_http_request req = {0};
    req.url = url("/headers");
    req.headers = h;
    req.n_headers = 1;
    wtls_http_response *r = open_req(&req);
    if (!r) return;
    int last = 1;
    const char *b = body_str(r, &last);
    char host[300];
    snprintf(host, sizeof host, "Host: %s:%u\r\n", g_env.server_host, (unsigned)P_HTTP);
    CHECK(strstr(b, "X-A: 1\r\n") != NULL);
    CHECK(strstr(b, host) != NULL);
    CHECK(strstr(b, "User-Agent: libwiitls/" WTLS_VERSION "\r\n") != NULL);
    wtls_http_close(r);
}

static void http_get_info(void) {
    wtls_http_pool_flush();
    wtls_http_request req = {0};
    req.url = url("/hello");
    wtls_http_response *r = open_req(&req);
    if (!r) return;
    wtls_http_info info;
    CHECK_EQ_INT(wtls_http_get_info(r, &info), WTLS_OK);
    CHECK(info.tls.tls_version && strcmp(info.tls.tls_version, "TLSv1.3") == 0);
    CHECK(info.tls.alpn && strcmp(info.tls.alpn, "http/1.1") == 0);
    CHECK(info.url && strcmp(info.url, req.url) == 0);
    CHECK_EQ_INT(info.redirects, 0);
    CHECK(!info.reused_connection);
    CHECK(info.secure);
    CHECK_EQ_INT(wtls_http_get_info(NULL, &info), WTLS_ERR_ARG);
    wtls_http_close(r);
}

static void http_alpn_forced(void) {
    wtls_http_pool_flush();
    static const char *const h2[] = {"h2", NULL};
    wtls_options opt = {0};
    opt.alpn = h2;
    wtls_http_request req = {0};
    req.url = url("/hello");
    req.tls = &opt;
    wtls_http_response *r = open_req(&req);
    if (!r) return;
    wtls_http_info info;
    CHECK_EQ_INT(wtls_http_get_info(r, &info), WTLS_OK);
    CHECK(info.tls.alpn && strcmp(info.tls.alpn, "http/1.1") == 0);
    wtls_http_close(r);
}

static void http_bad_url(void) {
    wtls_http_pool_flush();
    static const char *const bad[] = {"ftp://x/", "https://", "https://a b/", NULL};
    for (size_t i = 0; i < 3; i++) {
        wtls_http_request req = {0};
        req.url = bad[i];
        wtls_http_response *r = (wtls_http_response *)1;
        CHECK_EQ_INT(wtls_http_open(&r, &req), WTLS_ERR_ARG);
        CHECK(r == NULL);
    }
    wtls_http_response *r = (wtls_http_response *)1;
    CHECK_EQ_INT(wtls_http_open(&r, NULL), WTLS_ERR_ARG);
    CHECK(r == NULL);
    CHECK_EQ_INT(wtls_http_open(NULL, NULL), WTLS_ERR_ARG);
    /* NULL handles are harmless */
    CHECK_EQ_INT(wtls_http_status(NULL), 0);
    CHECK(wtls_http_get_header(NULL, "x") == NULL);
    CHECK_EQ_INT(wtls_http_read(NULL, NULL, 0), WTLS_ERR_ARG);
    wtls_http_close(NULL);
}

static void http_errors_pass_through(void) {
    wtls_http_pool_flush();
    wtls_http_request req = {0};
    req.url = url_of("https", P_EXPIRED, "/");
    wtls_http_response *r = (wtls_http_response *)1;
    CHECK_EQ_INT(wtls_http_open(&r, &req), WTLS_ERR_CERT);
    CHECK(r == NULL);
    req.url = url_of("https", P_CLOSED, "/");
    CHECK_EQ_INT(wtls_http_open(&r, &req), WTLS_ERR_CONNECT);
    CHECK(r == NULL);
}

/* ---- keep-alive pool ------------------------------------------------------- */

/* GET path, body read to its end, closed; returns the status (0 on failure)
 * and copies the body (NUL-terminated) and the reuse flag. */
static int get_full(const char *path, const wtls_options *tls, char *body, size_t cap, bool *reused) {
    wtls_http_request req = {0};
    req.url = url(path);
    req.tls = tls;
    wtls_http_response *r = open_req(&req);
    if (!r) return 0;
    int last = 1;
    size_t n = read_all(r, (uint8_t *)body, cap - 1, cap, &last);
    body[n] = 0;
    CHECK_EQ_INT(last, 0);
    wtls_http_info info;
    wtls_http_get_info(r, &info);
    if (reused) *reused = info.reused_connection;
    int st = wtls_http_status(r);
    wtls_http_close(r);
    return st;
}

static long count_of(const char *id) {
    char path[64], body[32];
    snprintf(path, sizeof path, "/count?id=%s", id);
    if (get_full(path, NULL, body, sizeof body, NULL) != 200) return -1;
    return strtol(body, NULL, 10);
}

static void http_keepalive_reuse(void) {
    wtls_http_pool_flush();
    char b1[32], b2[32];
    bool reused = true;
    CHECK_EQ_INT(get_full("/conn", NULL, b1, sizeof b1, &reused), 200);
    CHECK(!reused);
    CHECK_EQ_INT(get_full("/conn", NULL, b2, sizeof b2, &reused), 200);
    CHECK(reused);
    int id1 = -1, n1 = -1, id2 = -2, n2 = -1;
    CHECK(sscanf(b1, "%d %d", &id1, &n1) == 2 && sscanf(b2, "%d %d", &id2, &n2) == 2);
    CHECK_EQ_INT(id1, id2);
    CHECK_EQ_INT(n1, 1);
    CHECK_EQ_INT(n2, 2);
}

static void http_partial_read_not_pooled(void) {
    wtls_http_pool_flush();
    wtls_http_response *r = get("/len?n=100000");
    if (!r) return;
    char buf[10];
    CHECK_EQ_INT(wtls_http_read(r, buf, sizeof buf), 10);
    wtls_http_close(r);
    char body[32];
    bool reused = true;
    CHECK_EQ_INT(get_full("/conn", NULL, body, sizeof body, &reused), 200);
    CHECK(!reused);
    int id = 0, n = 0;
    CHECK(sscanf(body, "%d %d", &id, &n) == 2 && n == 1);
}

static void http_no_keepalive_not_pooled(void) {
    wtls_http_pool_flush();
    wtls_http_request req = {0};
    req.url = url("/hello");
    req.no_keepalive = true;
    wtls_http_response *r = open_req(&req);
    if (!r) return;
    int last = 1;
    CHECK(strcmp(body_str(r, &last), "hello") == 0);
    CHECK_EQ_INT(last, 0);
    wtls_http_close(r);
    char body[32];
    bool reused = true;
    CHECK_EQ_INT(get_full("/hello", NULL, body, sizeof body, &reused), 200);
    CHECK(!reused);
}

static void stale_case(const char *idle_path) {
    wtls_http_pool_flush();
    char body[32];
    CHECK_EQ_INT(get_full(idle_path, NULL, body, sizeof body, NULL), 200);
    uint64_t until = wtls_plat_now_ms() + 500;
    while (wtls_plat_now_ms() < until) wtls_plat_poll(-1, false, false, 50);
    bool reused = true;
    CHECK_EQ_INT(get_full("/hello", NULL, body, sizeof body, &reused), 200);
    CHECK(strcmp(body, "hello") == 0);
    CHECK(!reused);
}

static void http_stale_after_server_close(void) { stale_case("/idle-close?ms=200"); }
static void http_stale_without_close_notify(void) { stale_case("/idle-close?ms=200&notify=0"); }

static void http_retry_idempotent(void) {
    wtls_http_pool_flush();
    char body[32];
    CHECK_EQ_INT(get_full("/drop-next", NULL, body, sizeof body, NULL), 200);
    bool reused = true;
    CHECK_EQ_INT(get_full("/hello?id=retry", NULL, body, sizeof body, &reused), 200);
    CHECK(strcmp(body, "hello") == 0);
    CHECK(!reused);
    CHECK_EQ_INT(count_of("retry"), 2);
}

static void http_post_not_retried(void) {
    wtls_http_pool_flush();
    char body[32];
    CHECK_EQ_INT(get_full("/drop-next", NULL, body, sizeof body, NULL), 200);
    wtls_http_request req = {0};
    req.method = "POST";
    req.url = url("/echo?id=noretry");
    req.body = "x";
    req.body_len = 1;
    wtls_http_response *r = (wtls_http_response *)1;
    CHECK_EQ_INT(wtls_http_open(&r, &req), WTLS_ERR_IO);
    CHECK(r == NULL);
    CHECK_EQ_INT(count_of("noretry"), 1);
}

static void http_insecure_not_shared(void) {
    wtls_http_pool_flush();
    wtls_options opt = {0};
    opt.insecure_skip_verify = true;
    char body[32];
    bool reused = true;
    CHECK_EQ_INT(get_full("/hello", &opt, body, sizeof body, &reused), 200);
    CHECK_EQ_INT(get_full("/hello", NULL, body, sizeof body, &reused), 200);
    CHECK(!reused);
    CHECK_EQ_INT(get_full("/hello", &opt, body, sizeof body, &reused), 200);
    CHECK(reused); /* the insecure one was still waiting in the pool */
}

static void http_shutdown_flushes_pool(void) {
    wtls_http_pool_flush();
    char body[32];
    CHECK_EQ_INT(get_full("/hello", NULL, body, sizeof body, NULL), 200);
    wtls_shutdown();
    CHECK_EQ_INT(wtls_init(), WTLS_OK);
    bool trusted = trust_test_ca();
    CHECK(trusted);
    if (!trusted) return;
    bool reused = true;
    CHECK_EQ_INT(get_full("/conn", NULL, body, sizeof body, &reused), 200);
    CHECK(!reused);
}

/* ---- redirects ---------------------------------------------------------------- */

/* "/redirect?code=C&to=<to percent-encoded>" */
static const char *redirect_path(int code, const char *to) {
    static char p[700];
    int n = snprintf(p, sizeof p, "/redirect?code=%d&to=", code);
    for (const unsigned char *s = (const unsigned char *)to; *s && n < (int)sizeof p - 4; s++) {
        if ((*s >= 'A' && *s <= 'Z') || (*s >= 'a' && *s <= 'z') || (*s >= '0' && *s <= '9') || *s == '-' ||
            *s == '.' || *s == '_' || *s == '~')
            p[n++] = (char)*s;
        else
            n += snprintf(p + n, sizeof p - (size_t)n, "%%%02X", *s);
    }
    p[n] = 0;
    return p;
}

static void http_redirect_chain(void) {
    wtls_http_pool_flush();
    wtls_http_response *r = get("/redirect-chain?n=3");
    if (!r) return;
    CHECK_EQ_INT(wtls_http_status(r), 200);
    wtls_http_info info;
    wtls_http_get_info(r, &info);
    CHECK_EQ_INT(info.redirects, 3);
    const char *tail = "/redirect-chain?n=0";
    CHECK(info.url && strlen(info.url) > strlen(tail) && strcmp(info.url + strlen(info.url) - strlen(tail), tail) == 0);
    int last = 1;
    CHECK(strcmp(body_str(r, &last), "done") == 0);
    wtls_http_close(r);
}

static void http_redirect_too_many(void) {
    wtls_http_pool_flush();
    wtls_http_request req = {0};
    req.url = url("/redirect-chain?n=6");
    wtls_http_response *r = (wtls_http_response *)1;
    CHECK_EQ_INT(wtls_http_open(&r, &req), WTLS_ERR_HTTP_REDIRECT);
    CHECK(r == NULL);
    req.max_redirects = 10;
    r = open_req(&req);
    if (!r) return;
    CHECK_EQ_INT(wtls_http_status(r), 200);
    wtls_http_close(r);
}

static void http_redirect_disabled(void) {
    wtls_http_pool_flush();
    wtls_http_request req = {0};
    req.url = url(redirect_path(302, "/hello"));
    req.max_redirects = -1;
    wtls_http_response *r = open_req(&req);
    if (!r) return;
    CHECK_EQ_INT(wtls_http_status(r), 302);
    const char *loc = wtls_http_get_header(r, "location");
    CHECK(loc && strcmp(loc, "/hello") == 0);
    wtls_http_close(r);
}

static void http_redirect_methods(void) {
    wtls_http_pool_flush();
    static const struct {
        int code;
        const char *want;
    } cases[] = {{303, "GET 0"}, {301, "GET 0"}, {302, "GET 0"}, {307, "POST 3"}, {308, "POST 3"}};
    for (size_t i = 0; i < sizeof cases / sizeof cases[0]; i++) {
        wtls_http_request req = {0};
        req.method = "POST";
        req.url = url(redirect_path(cases[i].code, "/method"));
        req.body = "abc";
        req.body_len = 3;
        wtls_http_response *r = open_req(&req);
        if (!r) continue;
        int last = 1;
        const char *b = body_str(r, &last);
        if (strcmp(b, cases[i].want) != 0) TLOG("  %d -> \"%s\"\n", cases[i].code, b);
        CHECK(strcmp(b, cases[i].want) == 0);
        wtls_http_close(r);
    }
}

static void http_redirect_relative(void) {
    wtls_http_pool_flush();
    wtls_http_response *r = get(redirect_path(302, "hello"));
    if (!r) return;
    CHECK_EQ_INT(wtls_http_status(r), 200);
    int last = 1;
    CHECK(strcmp(body_str(r, &last), "hello") == 0);
    wtls_http_close(r);
}

static void expect_open_err(const char *path, int want) {
    wtls_http_request req = {0};
    req.url = url(path);
    wtls_http_response *r = (wtls_http_response *)1;
    CHECK_EQ_INT(wtls_http_open(&r, &req), want);
    CHECK(r == NULL);
}

static void http_redirect_https_to_plain_refused(void) {
    wtls_http_pool_flush();
    expect_open_err(redirect_path(302, url_of("http", P_HTTP_PLAIN, "/hello")), WTLS_ERR_HTTP_REDIRECT);
}

/* ASCII case-insensitive substring search. */
static bool contains_ci(const char *hay, const char *needle) {
    size_t n = strlen(needle);
    for (; *hay; hay++) {
        size_t i = 0;
        while (i < n && hay[i] && (hay[i] | 0x20) == (needle[i] | 0x20)) i++;
        if (i == n) return true;
    }
    return false;
}

static const wtls_http_header k_cred_headers[] = {
    {"Authorization", "secret"}, {"Cookie", "c=1"}, {"Proxy-Authorization", "p"}, {"X-Keep", "1"}};

static const char *redirected_headers(const char *to) {
    wtls_http_request req = {0};
    req.url = url(redirect_path(302, to));
    req.headers = k_cred_headers;
    req.n_headers = 4;
    wtls_http_response *r = open_req(&req);
    if (!r) return "";
    int last = 1;
    const char *b = body_str(r, &last);
    CHECK_EQ_INT(last, 0);
    wtls_http_close(r);
    return b;
}

static void http_redirect_cross_origin_strips_credentials(void) {
    wtls_http_pool_flush();
    const char *b = redirected_headers(url_of("https", P_HTTP2, "/headers"));
    CHECK(!contains_ci(b, "authorization"));
    CHECK(!contains_ci(b, "cookie"));
    CHECK(!contains_ci(b, "proxy-authorization"));
    CHECK(strstr(b, "X-Keep: 1") != NULL);
}

static void http_redirect_same_origin_keeps_credentials(void) {
    wtls_http_pool_flush();
    const char *b = redirected_headers("/headers");
    CHECK(strstr(b, "Authorization: secret") != NULL);
    CHECK(strstr(b, "Cookie: c=1") != NULL);
}

static void http_redirect_without_location(void) {
    wtls_http_pool_flush();
    wtls_http_response *r = get("/status?code=302");
    if (!r) return;
    CHECK_EQ_INT(wtls_http_status(r), 302);
    wtls_http_info info;
    wtls_http_get_info(r, &info);
    CHECK_EQ_INT(info.redirects, 0);
    wtls_http_close(r);
}

static void http_redirect_bad_location(void) {
    wtls_http_pool_flush();
    expect_open_err(redirect_path(302, "https://[x"), WTLS_ERR_HTTP_REDIRECT);
}

static void http_redirect_reuses_connection(void) {
    wtls_http_pool_flush();
    char body[32];
    CHECK_EQ_INT(get_full(redirect_path(302, "/conn"), NULL, body, sizeof body, NULL), 200);
    int id = 0, n = 0;
    CHECK(sscanf(body, "%d %d", &id, &n) == 2);
    CHECK_EQ_INT(n, 2);
}

/* ---- fetch ---------------------------------------------------------------------- */

static int fetch(const char *path, size_t max_body, wtls_http_result *res) {
    wtls_http_request req = {0};
    req.url = url(path);
    return wtls_http_fetch(&req, max_body, res);
}

static void fetch_hello(void) {
    wtls_http_pool_flush();
    wtls_http_result res;
    CHECK_EQ_INT(fetch("/hello", 0, &res), WTLS_OK);
    CHECK_EQ_INT(res.status, 200);
    CHECK_EQ_INT(res.body_len, 5);
    CHECK(res.body && memcmp(res.body, "hello", 5) == 0 && res.body[5] == '\0');
    wtls_http_result_free(&res);
    CHECK(res.body == NULL);
}

static void fetch_404(void) {
    wtls_http_pool_flush();
    wtls_http_result res;
    CHECK_EQ_INT(fetch("/status?code=404", 0, &res), WTLS_OK);
    CHECK_EQ_INT(res.status, 404);
    CHECK_EQ_INT(res.body_len, 0);
    CHECK(res.body && res.body[0] == '\0');
    wtls_http_result_free(&res);
}

static void fetch_limit_by_length(void) {
    wtls_http_pool_flush();
    wtls_http_result res;
    CHECK_EQ_INT(fetch("/len?n=2000", 1000, &res), WTLS_ERR_HTTP_LIMIT);
    CHECK(res.body == NULL);
    CHECK_EQ_INT(res.status, 200);
    wtls_http_result_free(&res);
}

static void fetch_limit_chunked(void) {
    wtls_http_pool_flush();
    wtls_http_result res;
    CHECK_EQ_INT(fetch("/chunked?n=2000&size=100", 1000, &res), WTLS_ERR_HTTP_LIMIT);
    CHECK(res.body == NULL);
    wtls_http_result_free(&res);
    CHECK_EQ_INT(fetch("/chunked?n=1000&size=100", 1000, &res), WTLS_OK); /* exactly the limit */
    CHECK_EQ_INT(res.body_len, 1000);
    CHECK(res.body && is_pattern((const uint8_t *)res.body, 1000, 0));
    wtls_http_result_free(&res);
}

static void fetch_default_limit(void) {
    wtls_http_pool_flush();
    wtls_http_result res;
    CHECK_EQ_INT(fetch("/len?n=1048576", 0, &res), WTLS_OK);
    CHECK_EQ_INT(res.body_len, 1048576);
    CHECK(res.body && is_pattern((const uint8_t *)res.body, res.body_len, 0));
    wtls_http_result_free(&res);
    CHECK_EQ_INT(fetch("/len?n=1048577", 0, &res), WTLS_ERR_HTTP_LIMIT);
    CHECK(res.body == NULL);
    wtls_http_result_free(&res);
}

static void fetch_result_free_safe(void) {
    wtls_http_pool_flush();
    wtls_http_result_free(NULL);
    wtls_http_result res = {0};
    wtls_http_result_free(&res);
    CHECK(res.body == NULL);
    CHECK_EQ_INT(wtls_http_fetch(NULL, 0, &res), WTLS_ERR_ARG);
    CHECK(res.body == NULL);
}

/* ---- plain http:// ---------------------------------------------------------------- */

static wtls_http_response *get_url(const char *u) {
    wtls_http_request req = {0};
    req.url = u;
    return open_req(&req);
}

static void http_plain_get(void) {
    wtls_http_pool_flush();
    wtls_http_response *r = get_url(url_of("http", P_HTTP_PLAIN, "/hello"));
    if (!r) return;
    CHECK_EQ_INT(wtls_http_status(r), 200);
    wtls_http_info info;
    wtls_http_get_info(r, &info);
    CHECK(!info.secure);
    static const wtls_conn_info zero;
    CHECK(memcmp(&info.tls, &zero, sizeof zero) == 0);
    int last = 1;
    CHECK(strcmp(body_str(r, &last), "hello") == 0);
    CHECK_EQ_INT(last, 0);
    wtls_http_close(r);
    /* a body up to the end of the connection: the TCP end is the end */
    r = get_url(url_of("http", P_HTTP_PLAIN, "/close?n=300&notify=0"));
    if (!r) return;
    uint8_t buf[400];
    size_t n = read_all(r, buf, sizeof buf, 64, &last);
    CHECK_EQ_INT(n, 300);
    CHECK_EQ_INT(last, 0);
    CHECK(is_pattern(buf, n, 0));
    wtls_http_close(r);
}

static void http_plain_keepalive(void) {
    wtls_http_pool_flush();
    int first = -1;
    for (int i = 1; i <= 2; i++) {
        wtls_http_response *r = get_url(url_of("http", P_HTTP_PLAIN, "/conn"));
        if (!r) return;
        wtls_http_info info;
        wtls_http_get_info(r, &info);
        CHECK(info.reused_connection == (i == 2));
        int last = 1, id = 0, no = 0;
        CHECK(sscanf(body_str(r, &last), "%d %d", &id, &no) == 2);
        CHECK_EQ_INT(no, i);
        if (i == 1) first = id;
        else CHECK_EQ_INT(id, first);
        wtls_http_close(r);
    }
    /* a plain connection never serves an https request on the same host:port key */
    wtls_http_response *r = get("/conn");
    if (!r) return;
    wtls_http_info info;
    wtls_http_get_info(r, &info);
    CHECK(info.secure && !info.reused_connection);
    wtls_http_close(r);
}

static void http_redirect_plain_to_https_ok(void) {
    wtls_http_pool_flush();
    char path[700];
    snprintf(path, sizeof path, "%s", redirect_path(302, url("/hello")));
    wtls_http_response *r = get_url(url_of("http", P_HTTP_PLAIN, path));
    if (!r) return;
    CHECK_EQ_INT(wtls_http_status(r), 200);
    wtls_http_info info;
    wtls_http_get_info(r, &info);
    CHECK(info.secure);
    CHECK_EQ_INT(info.redirects, 1);
    int last = 1;
    CHECK(strcmp(body_str(r, &last), "hello") == 0);
    wtls_http_close(r);
}

/* ---- gzip ---------------------------------------------------------------------------- */

static wtls_http_response *gz_open(const char *path, bool no_gzip, const wtls_http_header *h, size_t n) {
    wtls_http_request req = {0};
    req.url = url(path);
    req.no_gzip = no_gzip;
    req.headers = h;
    req.n_headers = n;
    return open_req(&req);
}

static void expect_gzip_pattern(const char *path, size_t n) {
    wtls_http_response *r = gz_open(path, false, NULL, 0);
    if (!r) return;
    CHECK_EQ_INT(wtls_http_status(r), 200);
    CHECK(wtls_http_content_length(r) == -1);
    wtls_http_info info;
    wtls_http_get_info(r, &info);
    CHECK(info.gzip);
    static uint8_t buf[70000];
    int last = 1;
    size_t got = read_all(r, buf, sizeof buf, 777, &last);
    CHECK_EQ_INT(got, n);
    CHECK_EQ_INT(last, 0);
    CHECK(is_pattern(buf, got, 0));
    CHECK_EQ_INT(wtls_http_read(r, buf, 1), 0); /* stays at the end */
    wtls_http_close(r);
}

static void http_gzip_length(void) {
    wtls_http_pool_flush();
    expect_gzip_pattern("/gzip?n=60000", 60000);
    expect_gzip_pattern("/gzip?n=60000&enc=X-GZIP", 60000);
    expect_gzip_pattern("/gzip?n=0", 0);
    /* the decoded response was read to its end: the connection was pooled */
    wtls_http_response *r = get("/hello");
    if (!r) return;
    wtls_http_info info;
    wtls_http_get_info(r, &info);
    CHECK(info.reused_connection);
    CHECK(!info.gzip);
    wtls_http_close(r);
}

static void http_gzip_chunked(void) {
    wtls_http_pool_flush();
    expect_gzip_pattern("/gzip?n=60000&chunked=1", 60000);
    expect_gzip_pattern("/gzip?n=5000&members=2", 5000);
}

static void http_gzip_offered(void) {
    wtls_http_pool_flush();
    wtls_http_response *r = get("/headers");
    if (!r) return;
    int last = 1;
    CHECK(strstr(body_str(r, &last), "Accept-Encoding: gzip, deflate") != NULL);
    wtls_http_close(r);
    r = gz_open("/headers", true, NULL, 0);
    if (!r) return;
    CHECK(!contains_ci(body_str(r, &last), "accept-encoding"));
    wtls_http_close(r);
}

/* The body as sent: the gzip magic, Content-Length as on the wire. */
static void expect_raw_gzip(wtls_http_response *r) {
    if (!r) return;
    wtls_http_info info;
    wtls_http_get_info(r, &info);
    CHECK(!info.gzip);
    int64_t cl = wtls_http_content_length(r);
    CHECK(cl > 10);
    uint8_t buf[256];
    int last = 1;
    size_t n = read_all(r, buf, sizeof buf, sizeof buf, &last);
    CHECK(n == (size_t)cl && n >= 2 && buf[0] == 0x1f && buf[1] == 0x8b);
    wtls_http_close(r);
}

static void http_gzip_no_gzip_raw(void) {
    wtls_http_pool_flush();
    expect_raw_gzip(gz_open("/gzip?n=100", true, NULL, 0));
}

static void http_gzip_own_accept_encoding_raw(void) {
    wtls_http_pool_flush();
    static const wtls_http_header ae = {"Accept-Encoding", "gzip"};
    expect_raw_gzip(gz_open("/gzip?n=100", false, &ae, 1));
}

static void http_gzip_unknown_encoding(void) {
    wtls_http_pool_flush();
    expect_open_err("/encoding?name=compress", WTLS_ERR_HTTP); /* br and zstd are known with their build options */
    wtls_http_response *r = get("/encoding?name=identity");
    if (!r) return;
    int last = 1;
    CHECK(strcmp(body_str(r, &last), "raw") == 0);
    wtls_http_close(r);
    r = gz_open("/encoding?name=compress", true, NULL, 0); /* not offered: passed through */
    if (!r) return;
    CHECK(strcmp(body_str(r, &last), "raw") == 0);
    wtls_http_close(r);
}

static void expect_gzip_error(const char *path, int want) {
    wtls_http_response *r = gz_open(path, false, NULL, 0);
    if (!r) return;
    uint8_t buf[8192];
    int last = 1;
    read_all(r, buf, sizeof buf, sizeof buf, &last);
    CHECK_EQ_INT(last, want);
    CHECK_EQ_INT(wtls_http_read(r, buf, 1), want); /* sticky */
    wtls_http_close(r);
}

static void http_gzip_bad_crc(void) {
    wtls_http_pool_flush();
    expect_gzip_error("/gzip?n=3000&bad=1", WTLS_ERR_HTTP);
    expect_gzip_error("/gzip?n=3000&bad=1&chunked=1", WTLS_ERR_HTTP);
}

static void http_gzip_truncated(void) {
    wtls_http_pool_flush();
    expect_gzip_error("/gzip?n=3000&cut=1", WTLS_ERR_IO);
    expect_gzip_error("/gzip?n=3000&cut=1&chunked=1", WTLS_ERR_IO);
}

static void http_gzip_fetch_limit(void) {
    wtls_http_pool_flush();
    wtls_http_result res;
    /* 1000 compressed bytes would pass a Content-Length check: the decoded length counts */
    CHECK_EQ_INT(fetch("/gzip?n=50000", 10000, &res), WTLS_ERR_HTTP_LIMIT);
    CHECK(res.body == NULL);
    CHECK_EQ_INT(res.status, 200);
    wtls_http_result_free(&res);
    CHECK_EQ_INT(fetch("/gzip?n=50000", 50000, &res), WTLS_OK);
    CHECK_EQ_INT(res.body_len, 50000);
    CHECK(res.body && is_pattern((const uint8_t *)res.body, res.body_len, 0));
    wtls_http_result_free(&res);
}

/* ---- streaming uploads (body_cb) ------------------------------------------ */

/* Streams byte (off + i) % 251 in pieces of at most s->piece bytes.
 * premature_eof ends a fixed-length body early (returns 0), abort_after
 * makes the callback fail once that many bytes were streamed. */
typedef struct {
    size_t len, off, piece;
    bool premature_eof;
    int abort_after;
    int calls;
} up_state;

static int up_cb(void *ctx, void *buf, size_t len) {
    up_state *s = ctx;
    s->calls++;
    if (s->abort_after >= 0 && s->off >= (size_t)s->abort_after) return -1;
    if (s->premature_eof && s->off >= s->len / 2) return 0;
    if (s->off >= s->len) return 0; /* chunked: end of the body */
    size_t n = s->len - s->off;
    if (n > s->piece) n = s->piece;
    if (n > len) n = len;
    for (size_t i = 0; i < n; i++) ((uint8_t *)buf)[i] = (uint8_t)((s->off + i) % 251);
    s->off += n;
    return (int)n;
}

static void up_check(wtls_http_response *r, size_t len) {
    uint8_t buf[4096];
    size_t n = 0;
    int last = 1;
    while (n < len) {
        size_t want = len - n < sizeof buf ? len - n : sizeof buf;
        int k = wtls_http_read(r, buf, want);
        if (k <= 0) {
            last = k;
            break;
        }
        for (int i = 0; i < k; i++) CHECK_EQ_INT(buf[i], (uint8_t)((n + i) % 251));
        n += (size_t)k;
    }
    CHECK_EQ_INT((long long)n, (long long)len);
    if (n == len) { /* the end of the body is a normal event */
        CHECK_EQ_INT(wtls_http_read(r, buf, sizeof buf), 0);
        last = 0;
    }
    CHECK_EQ_INT(last, 0);
}

static void http_upload_body_cb_fixed(void) {
    wtls_http_pool_flush();
    up_state s = {.len = 1000, .piece = 61, .abort_after = -1};
    wtls_http_request req = {0};
    req.method = "POST";
    req.url = url("/echo");
    req.body_cb = up_cb;
    req.body_ctx = &s;
    req.body_len = 1000;
    wtls_http_response *r = open_req(&req);
    if (!r) return;
    CHECK_EQ_INT(wtls_http_status(r), 200);
    up_check(r, 1000);
    wtls_http_close(r);
}

static void http_upload_body_cb_chunked(void) {
    wtls_http_pool_flush();
    up_state s = {.len = 1000, .piece = 100, .abort_after = -1};
    wtls_http_request req = {0};
    req.method = "PUT";
    req.url = url("/echo");
    req.body_cb = up_cb;
    req.body_ctx = &s;
    req.body_chunked = true;
    wtls_http_response *r = open_req(&req);
    if (!r) return;
    CHECK_EQ_INT(wtls_http_status(r), 200);
    /* exactly ceil(1000/100) callback results, the last one shorter */
    CHECK_EQ_INT(s.calls, 11);
    up_check(r, 1000);
    wtls_http_close(r);
}

static void http_upload_empty_chunked(void) {
    wtls_http_pool_flush();
    up_state s = {.abort_after = -1};
    wtls_http_request req = {0};
    req.method = "POST";
    req.url = url("/echo");
    req.body_cb = up_cb;
    req.body_ctx = &s;
    req.body_chunked = true;
    wtls_http_response *r = open_req(&req);
    if (!r) return;
    int last = 1;
    CHECK(strcmp(body_str(r, &last), "") == 0);
    CHECK_EQ_INT(last, 0);
    CHECK_EQ_INT(s.calls, 1);
    wtls_http_close(r);
}

static void http_upload_empty_fixed(void) {
    wtls_http_pool_flush();
    up_state s = {.abort_after = -1};
    wtls_http_request req = {0};
    req.method = "POST";
    req.url = url("/echo");
    req.body_cb = up_cb;
    req.body_ctx = &s;
    req.body_len = 0;
    wtls_http_response *r = open_req(&req);
    if (!r) return;
    CHECK_EQ_INT(wtls_http_status(r), 200);
    int last = 1;
    CHECK(strcmp(body_str(r, &last), "") == 0);
    CHECK_EQ_INT(last, 0);
    CHECK_EQ_INT(s.calls, 0); /* 0-byte fixed-length body needs no callback read */
    wtls_http_close(r);
}

static void http_null_headers_nonzero_count(void) {
    wtls_http_request req = {0};
    req.url = url("/hello");
    req.headers = NULL;
    req.n_headers = 2;
    wtls_http_response *r = (wtls_http_response *)1;
    CHECK_EQ_INT(wtls_http_open(&r, &req), WTLS_ERR_ARG);
    CHECK(r == NULL);
}

static void http_upload_premature_eof(void) {
    wtls_http_pool_flush();
    up_state s = {.len = 100, .piece = 50, .premature_eof = true, .abort_after = -1};
    wtls_http_request req = {0};
    req.method = "PUT";
    req.url = url("/echo");
    req.body_cb = up_cb;
    req.body_ctx = &s;
    req.body_len = 100;
    wtls_http_response *r = (wtls_http_response *)1;
    CHECK_EQ_INT(wtls_http_open(&r, &req), WTLS_ERR_IO);
    CHECK(r == NULL);
    /* the aborted connection is not pooled: the next request is fresh */
    char ok[32];
    bool reused = true;
    CHECK_EQ_INT(get_full("/hello", NULL, ok, sizeof ok, &reused), 200);
    CHECK(!reused);
}

static void http_upload_callback_abort(void) {
    wtls_http_pool_flush();
    up_state s = {.len = 100, .piece = 50, .abort_after = 50};
    wtls_http_request req = {0};
    req.method = "POST";
    req.url = url("/echo");
    req.body_cb = up_cb;
    req.body_ctx = &s;
    req.body_len = 100;
    wtls_http_response *r = (wtls_http_response *)1;
    CHECK_EQ_INT(wtls_http_open(&r, &req), WTLS_ERR_IO);
    CHECK(r == NULL);
}

/* 307 keeps method and body: a stream cannot be rewound, so the request
 * aborts with WTLS_ERR_HTTP_REDIRECT instead of following the Location. */
static void http_upload_307_redirect(void) {
    wtls_http_pool_flush();
    up_state s = {.len = 10, .piece = 4, .abort_after = -1};
    wtls_http_request req = {0};
    req.method = "POST";
    req.url = url(redirect_path(307, "/hello"));
    req.body_cb = up_cb;
    req.body_ctx = &s;
    req.body_len = 10;
    wtls_http_response *r = (wtls_http_response *)1;
    CHECK_EQ_INT(wtls_http_open(&r, &req), WTLS_ERR_HTTP_REDIRECT);
    CHECK(r == NULL);
}

/* 302 turns POST into GET: the body (and the callback) is dropped for the
 * follow-up request, which must succeed. */
static void http_upload_302_post_becomes_get(void) {
    wtls_http_pool_flush();
    up_state s = {.len = 10, .piece = 4, .abort_after = -1};
    wtls_http_request req = {0};
    req.method = "POST";
    req.url = url(redirect_path(302, "/hello"));
    req.body_cb = up_cb;
    req.body_ctx = &s;
    req.body_len = 10;
    wtls_http_response *r = open_req(&req);
    if (!r) return;
    CHECK_EQ_INT(wtls_http_status(r), 200);
    int last = 1;
    CHECK(strcmp(body_str(r, &last), "hello") == 0);
    CHECK_EQ_INT(last, 0);
    CHECK_EQ_INT(s.calls, 3); /* first hop only: 4 + 4 + 2 bytes */
    wtls_http_close(r);
}

static void http_upload_256k(void) {
    wtls_http_pool_flush();
    up_state s = {.len = 256u * 1024u, .piece = 16u * 1024u, .abort_after = -1};
    wtls_http_request req = {0};
    req.method = "PUT";
    req.url = url("/echo");
    req.body_cb = up_cb;
    req.body_ctx = &s;
    req.body_chunked = true;
    wtls_http_response *r = open_req(&req);
    if (!r) return;
    CHECK_EQ_INT(wtls_http_status(r), 200);
    up_check(r, 256u * 1024u);
    wtls_http_close(r);
}

/* A streaming upload goes out over a pooled connection, and the connection
 * is pooled again afterwards. */
static void http_upload_keepalive_reuse(void) {
    wtls_http_pool_flush();
    char hello[32];
    CHECK_EQ_INT(get_full("/hello", NULL, hello, sizeof hello, NULL), 200);
    CHECK(strcmp(hello, "hello") == 0);

    up_state s = {.len = 500, .piece = 200, .abort_after = -1};
    wtls_http_request req = {0};
    req.method = "POST";
    req.url = url("/echo");
    req.body_cb = up_cb;
    req.body_ctx = &s;
    req.body_len = 500;
    wtls_http_response *r = open_req(&req);
    if (!r) return;
    wtls_http_info info;
    wtls_http_get_info(r, &info);
    CHECK(info.reused_connection);
    up_check(r, 500);
    wtls_http_close(r);

    s.off = 0;
    s.calls = 0;
    wtls_http_response *third = open_req(&req); /* the same request again */
    if (!third) return;
    wtls_http_info info2;
    wtls_http_get_info(third, &info2);
    CHECK(info2.reused_connection);
    up_check(third, 500);
    wtls_http_close(third);
}

/* A stale pooled connection must not re-run a streaming callback: once the
 * callback produced bytes there is no rewind, so the request fails with
 * WTLS_ERR_IO instead of being retried (the GET/HEAD equivalent retries). */
static void http_upload_stale_no_retry(void) {
    wtls_http_pool_flush();
    wtls_http_response *r = get("/drop-next");
    if (!r) return;
    int last = 1;
    CHECK(strcmp(body_str(r, &last), "ok") == 0); /* read to the end: pooled */
    CHECK_EQ_INT(last, 0);
    wtls_http_close(r); /* pooled; the next request on it is dropped */

    up_state s = {.len = 300, .piece = 40, .abort_after = -1};
    wtls_http_request req = {0};
    req.method = "PUT"; /* idempotent: only a never-started stream would retry */
    req.url = url("/echo");
    req.body_cb = up_cb;
    req.body_ctx = &s;
    req.body_len = 300;
    wtls_http_response *r2 = (wtls_http_response *)1;
    CHECK_EQ_INT(wtls_http_open(&r2, &req), WTLS_ERR_IO);
    CHECK(r2 == NULL);
    CHECK(s.calls > 0);
}

static void http_upload_args(void) {
    wtls_http_pool_flush();
    up_state s = {.len = 10, .piece = 10, .abort_after = -1};
    wtls_http_request req = {0};
    req.url = url("/echo");
    req.body = "x";
    req.body_len = 1;
    req.body_cb = up_cb;
    req.body_ctx = &s;
    wtls_http_response *r = (wtls_http_response *)1;
    CHECK_EQ_INT(wtls_http_open(&r, &req), WTLS_ERR_ARG); /* body + body_cb */
    CHECK(r == NULL);
    req.body = NULL;
    req.body_cb = NULL;
    req.body_chunked = true;
    CHECK_EQ_INT(wtls_http_open(&r, &req), WTLS_ERR_ARG); /* chunked without cb */
    CHECK(r == NULL);
}

/* ---- mutual TLS over HTTP -------------------------------------------------- */

#define P_MTLS_HTTP 4442
#define P_MTLS_REQ 4441

/* Fetches a client artifact (cert/key) from the server's plain port. */
static uint8_t *cred_fetch(const char *cmd, size_t *len) {
    *len = 0;
    uint32_t ip;
    int fd = -1;
    if (wtls_plat_resolve(g_env.server_host, &ip) != WTLS_OK) return NULL;
    if (wtls_plat_connect(ip, PLAIN_PORT, 3000, &fd) != WTLS_OK) return NULL;
    uint8_t *buf = NULL;
    char full[40];
    int n = snprintf(full, sizeof full, "%s\n", cmd);
    uint64_t deadline = wtls_plat_now_ms() + 3000;
    if (n > 0 && n < (int)sizeof full && wtls_plat_send(fd, (const uint8_t *)full, (size_t)n) == n) {
        char line[16] = {0};
        size_t i = 0;
        while (i < sizeof line - 1 && plain_recv_exact(fd, (uint8_t *)&line[i], 1, deadline) &&
               line[i] != '\n')
            i++;
        long want = strtol(line, NULL, 10);
        if (want > 0 && want < 16384 && (buf = malloc((size_t)want))) {
            if (plain_recv_exact(fd, buf, (size_t)want, deadline)) *len = (size_t)want;
            else {
                free(buf);
                buf = NULL;
            }
        }
    }
    wtls_plat_close(fd);
    return buf;
}

static wtls_client_cred *http_client_cred(const char *name) {
    char cmd[40];
    size_t clen = 0, klen = 0;
    snprintf(cmd, sizeof cmd, "CLIENTCERT %s", name);
    uint8_t *cert = cred_fetch(cmd, &clen);
    snprintf(cmd, sizeof cmd, "CLIENTKEY %s", name);
    uint8_t *key0 = cred_fetch(cmd, &klen);
    uint8_t *key = NULL;
    if (key0) {
        key = malloc(klen + 1); /* PEM: append the terminating NUL */
        if (key) {
            memcpy(key, key0, klen);
            key[klen] = 0;
            klen += 1;
        }
        free(key0);
    }
    wtls_client_cred *cred = NULL;
    if (cert && key) {
        CHECK_EQ_INT(wtls_client_cred_load(&cred, cert, clen, key, klen), WTLS_OK);
    } else {
        CHECK(false); /* plain fetch failed */
    }
    free(cert);
    free(key);
    return cred;
}

/* /who on the optional-mTLS port shows the client certificate CN. */
static void http_mtls_who(void) {
    wtls_http_pool_flush();
    wtls_client_cred *cred = http_client_cred("client-ec");
    CHECK(cred);
    if (!cred) return;
    wtls_options opt = {0};
    opt.client_cred = cred;
    wtls_http_request req = {0};
    req.url = url_of("https", P_MTLS_HTTP, "/who");
    req.tls = &opt;
    wtls_http_response *r = open_req(&req);
    if (r) {
        int last = 1;
        CHECK(strcmp(body_str(r, &last), "client-ec.test") == 0);
        CHECK_EQ_INT(last, 0);
        wtls_http_close(r);
    }
    wtls_client_cred_free(cred);
}

/* The pool key includes the client identity: a connection authenticated
 * with a certificate never serves a request without it. */
static void http_mtls_pool_isolated(void) {
    wtls_http_pool_flush();
    wtls_client_cred *a = http_client_cred("client-ec");
    CHECK(a);
    if (!a) return;
    wtls_options with_a = {0};
    with_a.client_cred = a;

    wtls_http_request cred_req = {0};
    cred_req.url = url_of("https", P_MTLS_HTTP, "/who");
    cred_req.tls = &with_a;
    wtls_http_response *r = open_req(&cred_req);
    if (!r) return;
    int last = 1;
    CHECK(strcmp(body_str(r, &last), "client-ec.test") == 0);
    CHECK_EQ_INT(last, 0);
    wtls_http_close(r); /* pooled under the client-ec identity */

    wtls_http_request plain = {0};
    plain.url = url_of("https", P_MTLS_HTTP, "/who");
    wtls_http_response *r2 = open_req(&plain);
    if (r2) {
        wtls_http_info info;
        wtls_http_get_info(r2, &info);
        CHECK(!info.reused_connection);
        last = 1;
        CHECK(strcmp(body_str(r2, &last), "none") == 0);
        wtls_http_close(r2);
    }

    wtls_http_response *r3 = open_req(&cred_req);
    if (r3) {
        wtls_http_info info;
        wtls_http_get_info(r3, &info);
        CHECK(info.reused_connection);
        last = 1;
        CHECK(strcmp(body_str(r3, &last), "client-ec.test") == 0);
        wtls_http_close(r3);
    }
    wtls_client_cred_free(a);
}

/* Session tickets of an mTLS connection are keyed by the client identity.
 * no_keepalive keeps the pool out of the way, so only tickets can make the
 * third request fast. (r1's own resumption state is irrelevant: an earlier
 * test may have left a ticket for client-ec; the point is that b never
 * consumes a's, and a's next one works.) */
static void http_mtls_tickets_isolated(void) {
    wtls_http_pool_flush();
    wtls_client_cred *a = http_client_cred("client-ec");
    wtls_client_cred *b = http_client_cred("client-rsa");
    CHECK(a && b);
    if (!a || !b) {
        wtls_client_cred_free(a);
        wtls_client_cred_free(b);
        return;
    }
    wtls_options oa = {0};
    oa.client_cred = a;
    wtls_options ob = {0};
    ob.client_cred = b;

    wtls_http_request ra = {0};
    ra.url = url_of("https", P_MTLS_HTTP, "/hello");
    ra.tls = &oa;
    ra.no_keepalive = true;
    wtls_http_request rb = ra;
    rb.tls = &ob;

    wtls_http_response *r = open_req(&ra); /* leaves a fresh ticket(a) */
    if (r) {
        int last = 1;
        CHECK(strcmp(body_str(r, &last), "hello") == 0);
        CHECK_EQ_INT(last, 0);
        wtls_http_close(r);
    }
    wtls_http_response *r2 = open_req(&rb);
    if (r2) {
        wtls_http_info info;
        wtls_http_get_info(r2, &info);
        CHECK(!info.tls.resumed); /* b must not resume a's ticket */
        wtls_http_close(r2);
    }
    wtls_http_response *r3 = open_req(&ra);
    if (r3) {
        wtls_http_info info;
        wtls_http_get_info(r3, &info);
        CHECK(info.tls.resumed); /* a's own ticket survived b's connection */
        wtls_http_close(r3);
    }
    wtls_client_cred_free(b);
    wtls_client_cred_free(a);
}

/* A cross-origin redirect strips the client certificate like the
 * Authorization header: the follow-up to the port that requires a client
 * certificate must fail with a handshake error. */
static void http_mtls_cross_origin_stripped(void) {
    wtls_http_pool_flush();
    wtls_client_cred *cred = http_client_cred("client-ec");
    CHECK(cred);
    if (!cred) return;
    wtls_options opt = {0};
    opt.client_cred = cred;
    char to[600];
    snprintf(to, sizeof to, "https://%s:%u/hello", g_env.server_host, (unsigned)P_MTLS_REQ);
    wtls_http_request req = {0};
    req.url = url(redirect_path(302, to));
    req.tls = &opt;
    wtls_http_response *r = (wtls_http_response *)1;
    int st = wtls_http_open(&r, &req);
    /* The certificate was stripped, so the required-cert port rejects us.
     * In TLS 1.3 that abort can surface during the connect or only at the
     * first read (the response head); both prove the stripping, because
     * with the certificate the follow-up would succeed. */
    CHECK(st == WTLS_ERR_HANDSHAKE || st == WTLS_ERR_IO);
    CHECK(r == NULL);
    wtls_client_cred_free(cred);
}

/* A streaming upload while presenting a client certificate. */
static void http_mtls_upload(void) {
    wtls_http_pool_flush();
    wtls_client_cred *cred = http_client_cred("client-ec");
    CHECK(cred);
    if (!cred) return;
    wtls_options opt = {0};
    opt.client_cred = cred;
    up_state s = {.len = 700, .piece = 128, .abort_after = -1};
    wtls_http_request req = {0};
    req.method = "PUT";
    req.url = url_of("https", P_MTLS_HTTP, "/echo");
    req.tls = &opt;
    req.body_cb = up_cb;
    req.body_ctx = &s;
    req.body_len = 700;
    wtls_http_response *r = open_req(&req);
    if (r) {
        up_check(r, 700);
        wtls_http_close(r);
    }
    wtls_client_cred_free(cred);
}

/* wtls_client_cred_free while a pooled connection still holds a reference:
 * flushing the pool releases it; nothing must crash or leak. */
static void http_mtls_free_while_pooled(void) {
    wtls_http_pool_flush();
    wtls_client_cred *cred = http_client_cred("client-ec");
    CHECK(cred);
    if (!cred) return;
    wtls_options opt = {0};
    opt.client_cred = cred;
    wtls_http_request req = {0};
    req.url = url_of("https", P_MTLS_HTTP, "/hello");
    req.tls = &opt;
    wtls_http_response *r = open_req(&req);
    if (!r) {
        wtls_client_cred_free(cred);
        return;
    }
    int last = 1;
    CHECK(strcmp(body_str(r, &last), "hello") == 0);
    CHECK_EQ_INT(last, 0);
    wtls_http_close(r);          /* pooled; the connection holds a reference */
    wtls_client_cred_free(cred); /* the application's reference */
    wtls_http_pool_flush();       /* releases the last one: destroyed here */
    /* the library still works */
    char hello[32];
    CHECK_EQ_INT(get_full("/hello", NULL, hello, sizeof hello, NULL), 200);
}

/* ---- cooperative abort_cb & download progress_cb ------------------------- */

typedef struct {
    int calls;
    int abort_at;
} http_abort_state;

static bool http_abort_cb(void *ctx) {
    http_abort_state *s = ctx;
    return ++s->calls >= s->abort_at;
}

static void http_abort_slowhead(void) {
    wtls_http_pool_flush();
    http_abort_state st = {.abort_at = 1000};
    wtls_options opt = {0};
    opt.abort_cb = http_abort_cb;
    opt.abort_ctx = &st;
    /* warm handshake first? no, abort during slowhead poll after handshake */
    st.abort_at = 20; /* allow connect+send, then abort inside read_head poll */
    wtls_http_request req = {0};
    req.url = url("/slowhead");
    req.header_timeout_ms = 5000;
    req.tls = &opt;
    wtls_http_response *r = (wtls_http_response *)1;
    uint64_t t0 = wtls_plat_now_ms();
    CHECK_EQ_INT(wtls_http_open(&r, &req), WTLS_ERR_CANCELLED);
    uint64_t dt = wtls_plat_now_ms() - t0;
    TLOG("    http slowhead abort took %u ms\n", (unsigned)dt);
    CHECK(dt < 1500);
    CHECK(r == NULL);
}

static void http_abort_plain(void) {
    wtls_http_pool_flush();
    http_abort_state st = {.abort_at = 6};
    wtls_options opt = {0};
    opt.abort_cb = http_abort_cb;
    opt.abort_ctx = &st;
    wtls_http_request req = {0};
    req.url = url_of("http", P_HTTP_PLAIN, "/slowhead");
    req.header_timeout_ms = 5000;
    req.tls = &opt;
    wtls_http_response *r = (wtls_http_response *)1;
    uint64_t t0 = wtls_plat_now_ms();
    CHECK_EQ_INT(wtls_http_open(&r, &req), WTLS_ERR_CANCELLED);
    CHECK(wtls_plat_now_ms() - t0 < 1500);
    CHECK(r == NULL);
}

static void http_abort_read_not_pooled(void) {
    wtls_http_pool_flush();
    http_abort_state st = {.abort_at = 1000};
    wtls_options opt = {0};
    opt.io_timeout_ms = 5000;
    opt.abort_cb = http_abort_cb;
    opt.abort_ctx = &st;
    wtls_http_request req = {0};
    req.url = url("/slowbody?ms=1000");
    req.tls = &opt;
    wtls_http_response *r = open_req(&req);
    if (!r) return;
    st.calls = 0;
    st.abort_at = 3;
    char buf[16];
    CHECK_EQ_INT(wtls_http_read(r, buf, sizeof buf), WTLS_ERR_CANCELLED);
    CHECK_EQ_INT(wtls_http_read(r, buf, sizeof buf), WTLS_ERR_CANCELLED); /* sticky */
    wtls_http_close(r);
    /* Cancelled connections must not go back into the pool. */
    char body[32];
    bool reused = true;
    CHECK_EQ_INT(get_full("/conn", NULL, body, sizeof body, &reused), 200);
    CHECK(!reused);

    /* Immediate abort at wtls_http_read() entry also marks TLS connection aborted. */
    st.calls = 0;
    st.abort_at = 1000;
    r = open_req(&req);
    if (!r) return;
    st.calls = 0;
    st.abort_at = 1;
    CHECK_EQ_INT(wtls_http_read(r, buf, sizeof buf), WTLS_ERR_CANCELLED);
    CHECK_EQ_INT(wtls_http_read(r, buf, sizeof buf), WTLS_ERR_CANCELLED);
    wtls_http_close(r);
    reused = true;
    CHECK_EQ_INT(get_full("/conn", NULL, body, sizeof body, &reused), 200);
    CHECK(!reused);
}

static bool http_abort_after_upload_chunks(void *ctx) {
    const up_state *us = ctx;
    return us->calls >= 4;
}

static void http_abort_upload(void) {
    wtls_http_pool_flush();
    up_state us = {.len = 128u * 1024u, .piece = 4096u, .abort_after = -1};
    wtls_options opt = {0};
    opt.abort_cb = http_abort_after_upload_chunks;
    opt.abort_ctx = &us;
    wtls_http_request req = {0};
    req.method = "PUT";
    req.url = url("/echo");
    req.tls = &opt;
    req.body_cb = up_cb;
    req.body_ctx = &us;
    req.body_len = us.len;
    wtls_http_response *r = (wtls_http_response *)1;
    CHECK_EQ_INT(wtls_http_open(&r, &req), WTLS_ERR_CANCELLED);
    CHECK_EQ_INT(us.calls, 4);
    CHECK(r == NULL);
}

static void http_net_reset_flushes_pool(void) {
    wtls_http_pool_flush();
    char body[32];
    bool reused = true;
    CHECK_EQ_INT(get_full("/conn", NULL, body, sizeof body, &reused), 200);
    CHECK(!reused);
    wtls_net_reset();
    CHECK_EQ_INT(get_full("/conn", NULL, body, sizeof body, &reused), 200);
    CHECK(!reused);
}

typedef struct {
    int calls;
    size_t last_done;
    int64_t last_total;
    bool monotonic;
    bool same_total;
} prog_state;

static void test_prog_cb(void *ctx, size_t done, int64_t total) {
    prog_state *p = ctx;
    if (p->calls == 0) p->last_total = total;
    if (total != p->last_total) p->same_total = false;
    if (done < p->last_done) p->monotonic = false;
    p->last_done = done;
    p->calls++;
}

static void http_fetch_progress(void) {
    wtls_http_pool_flush();
    prog_state ps = {.monotonic = true, .same_total = true};
    wtls_http_request req = {0};
    req.url = url("/len?n=40000");
    req.progress_cb = test_prog_cb;
    req.progress_ctx = &ps;
    wtls_http_result res;
    CHECK_EQ_INT(wtls_http_fetch(&req, 0, &res), WTLS_OK);
    CHECK(ps.calls >= 1 && ps.monotonic && ps.same_total);
    CHECK_EQ_INT((long long)ps.last_done, 40000);
    CHECK_EQ_INT((long long)ps.last_total, 40000);
    wtls_http_result_free(&res);

    /* chunked: unknown total (-1) */
    ps = (prog_state){.monotonic = true, .same_total = true};
    req.url = url("/chunked?n=20000&size=1234");
    CHECK_EQ_INT(wtls_http_fetch(&req, 0, &res), WTLS_OK);
    CHECK(ps.calls >= 1 && ps.monotonic && ps.same_total);
    CHECK_EQ_INT((long long)ps.last_done, 20000);
    CHECK_EQ_INT((long long)ps.last_total, -1);
    wtls_http_result_free(&res);

    /* empty 204: called once with (0, 0) */
    ps = (prog_state){.monotonic = true, .same_total = true};
    req.url = url("/status?code=204");
    CHECK_EQ_INT(wtls_http_fetch(&req, 0, &res), WTLS_OK);
    CHECK_EQ_INT(ps.calls, 1);
    CHECK_EQ_INT((long long)ps.last_done, 0);
    CHECK_EQ_INT((long long)ps.last_total, 0);
    wtls_http_result_free(&res);
}

/* ---- SPKI SHA-256 pinning over HTTP ------------------------------------ */

static bool http_fetch_spki(const char *name, uint8_t out[WTLS_SPKI_SHA256_LEN]) {
    char cmd[40];
    snprintf(cmd, sizeof cmd, "SPKI %s", name);
    size_t len = 0;
    uint8_t *buf = cred_fetch(cmd, &len);
    bool ok = buf && len == WTLS_SPKI_SHA256_LEN;
    if (ok) memcpy(out, buf, WTLS_SPKI_SHA256_LEN);
    free(buf);
    CHECK(ok);
    return ok;
}

static void http_spki_pin_ca_and_mismatch(void) {
    wtls_http_pool_flush();
    uint8_t pin_ca[WTLS_SPKI_SHA256_LEN];
    if (!http_fetch_spki("test-ca", pin_ca)) return;

    wtls_options opt = {0};
    memcpy(opt.spki_pins[0], pin_ca, WTLS_SPKI_SHA256_LEN);
    opt.n_spki_pins = 1;
    wtls_http_request req = {0};
    req.url = url("/hello");
    req.tls = &opt;
    wtls_http_response *r = open_req(&req);
    if (r) {
        int last = 1;
        CHECK(strcmp(body_str(r, &last), "hello") == 0);
        CHECK_EQ_INT(last, 0);
        wtls_http_close(r);
    }

    memset(opt.spki_pins[0], 0x55, WTLS_SPKI_SHA256_LEN);
    r = (wtls_http_response *)1;
    CHECK_EQ_INT(wtls_http_open(&r, &req), WTLS_ERR_CERT);
    CHECK(r == NULL);

    /* Backup pin in slot 1 recovers cleanly. */
    memcpy(opt.spki_pins[1], pin_ca, WTLS_SPKI_SHA256_LEN);
    opt.n_spki_pins = 2;
    r = open_req(&req);
    if (r) wtls_http_close(r);

    opt.n_spki_pins = WTLS_SPKI_MAX_PINS + 1;
    r = (wtls_http_response *)1;
    CHECK_EQ_INT(wtls_http_open(&r, &req), WTLS_ERR_ARG);
    CHECK(r == NULL);
}

static void http_spki_pin_pool_and_redirect(void) {
    wtls_http_pool_flush();
    uint8_t pin_ca[WTLS_SPKI_SHA256_LEN];
    if (!http_fetch_spki("test-ca", pin_ca)) return;

    wtls_options opt = {0};
    memcpy(opt.spki_pins[0], pin_ca, WTLS_SPKI_SHA256_LEN);
    opt.n_spki_pins = 1;
    wtls_http_request req = {0};
    req.url = url("/conn");
    req.tls = &opt;
    wtls_http_response *r = open_req(&req);
    if (r) {
        wtls_http_info info;
        wtls_http_get_info(r, &info);
        CHECK(!info.reused_connection);
        int last = 1;
        body_str(r, &last);
        wtls_http_close(r);
    }

    /* Unpinned request must not reuse a pinned pooled connection. */
    req.tls = NULL;
    r = open_req(&req);
    if (r) {
        wtls_http_info info;
        wtls_http_get_info(r, &info);
        CHECK(!info.reused_connection);
        int last = 1;
        body_str(r, &last);
        wtls_http_close(r);
    }

    /* Second pinned request reuses the pinned connection. */
    req.tls = &opt;
    r = open_req(&req);
    if (r) {
        wtls_http_info info;
        wtls_http_get_info(r, &info);
        CHECK(info.reused_connection);
        int last = 1;
        body_str(r, &last);
        wtls_http_close(r);
    }

    /* SPKI pins remain enforced across HTTP -> HTTPS redirects. */
    req.url = url_of("http", P_HTTP_PLAIN, redirect_path(302, url("/hello")));
    r = open_req(&req);
    if (r) {
        CHECK_EQ_INT(wtls_http_status(r), 200);
        wtls_http_close(r);
    }
    memset(opt.spki_pins[0], 0x55, WTLS_SPKI_SHA256_LEN);
    r = (wtls_http_response *)1;
    CHECK_EQ_INT(wtls_http_open(&r, &req), WTLS_ERR_CERT);
    CHECK(r == NULL);

    /* Plain http:// hops do not partition their keep-alive pool by TLS pins. */
    wtls_http_pool_flush();
    wtls_http_request preq = {0};
    preq.url = url_of("http", P_HTTP_PLAIN, "/conn");
    r = open_req(&preq);
    if (r) {
        int last = 1;
        body_str(r, &last);
        wtls_http_close(r);
    }
    preq.tls = &opt;
    r = open_req(&preq);
    if (r) {
        wtls_http_info info;
        wtls_http_get_info(r, &info);
        CHECK(!info.secure && info.reused_connection);
        int last = 1;
        body_str(r, &last);
        wtls_http_close(r);
    }
}

static void http_upgrade_rejected_without_flag(void) {
    wtls_http_pool_flush();
    wtls_http_request req = {0};
    req.url = url("/upgrade");
    wtls_http_response *r = (wtls_http_response *)1;
    CHECK_EQ_INT(wtls_http_open(&r, &req), WTLS_ERR_HTTP);
    CHECK(r == NULL);
}

static void http_upgrade_detach_tls_and_early(void) {
    wtls_http_pool_flush();
    static const wtls_http_header hd[] = {{"Upgrade", "echo"}};
    wtls_http_request req = {0};
    req.url = url("/upgrade?early=1");
    req.headers = hd;
    req.n_headers = 1;
    req.allow_upgrade = true;
    wtls_http_response *r = open_req(&req);
    if (!r) return;
    CHECK_EQ_INT(wtls_http_status(r), 101);
    const char *up = wtls_http_get_header(r, "Upgrade");
    CHECK(up && strcmp(up, "echo") == 0);

    wtls_conn *c = NULL;
    int fd = -1;
    CHECK_EQ_INT(wtls_http_detach(r, &c, &fd, NULL, 0, NULL), WTLS_OK);
    CHECK(c != NULL && fd >= 0 && fd == wtls_get_fd(c));
    /* Second detach fails cleanly; response accessors remain valid until close. */
    CHECK_EQ_INT(wtls_http_detach(r, &c, NULL, NULL, 0, NULL), WTLS_ERR_STATE);
    CHECK_EQ_INT(wtls_http_status(r), 101);
    wtls_http_close(r);

    /* Early bytes sent with the 101 response head are delivered first by wtls_read(). */
    CHECK(wtls_pending(c) == 6);
    char buf[16] = {0};
    CHECK_EQ_INT(wtls_read(c, buf, 6), 6);
    CHECK_MEM(buf, "EARLY!", 6);
    CHECK_EQ_INT(wtls_pending(c), 0);

    /* Upgraded full-duplex TLS traffic continues seamlessly. */
    CHECK_EQ_INT(wtls_write(c, "PING", 4), 4);
    size_t got = 0;
    while (got < 4) {
        int k = wtls_read(c, buf + got, 4 - got);
        CHECK(k > 0);
        if (k <= 0) break;
        got += (size_t)k;
    }
    CHECK_MEM(buf, "PING", 4);
    wtls_close(c);
}

static void http_upgrade_detach_plain_and_errors(void) {
    wtls_http_pool_flush();
    /* 200 response cannot be detached. */
    wtls_http_response *ok = get("/hello");
    if (ok) {
        wtls_conn *c = NULL;
        CHECK_EQ_INT(wtls_http_detach(ok, &c, NULL, NULL, 0, NULL), WTLS_ERR_STATE);
        wtls_http_close(ok);
    }

    /* Plain HTTP 101 with early bytes: size query, small buffer error, then detach. */
    static const wtls_http_header hd[] = {{"Upgrade", "echo"}};
    wtls_http_request req = {0};
    req.url = url_of("http", P_HTTP_PLAIN, "/upgrade?early=1");
    req.headers = hd;
    req.n_headers = 1;
    req.allow_upgrade = true;
    wtls_http_response *r = open_req(&req);
    if (!r) return;
    CHECK_EQ_INT(wtls_http_status(r), 101);

    size_t need = 0;
    CHECK_EQ_INT(wtls_http_detach(r, NULL, NULL, NULL, 0, &need), WTLS_ERR_ARG);
    int fd = -1;
    CHECK_EQ_INT(wtls_http_detach(r, NULL, &fd, NULL, 0, &need), WTLS_OK);
    CHECK_EQ_INT((int)need, 6);
    CHECK_EQ_INT(fd, -1); /* size query did not detach yet */

    char small[4];
    CHECK_EQ_INT(wtls_http_detach(r, NULL, &fd, small, sizeof small, &need), WTLS_ERR_HTTP_LIMIT);
    CHECK_EQ_INT((int)need, 6);
    /* Plain http:// without extra_buf refuses to drop unread early bytes. */
    CHECK_EQ_INT(wtls_http_detach(r, NULL, &fd, NULL, 0, NULL), WTLS_ERR_HTTP_LIMIT);

    wtls_conn *tls_out = (wtls_conn *)1;
    char extra[16];
    CHECK_EQ_INT(wtls_http_detach(r, &tls_out, &fd, extra, sizeof extra, &need), WTLS_OK);
    CHECK(tls_out == NULL && fd >= 0 && need == 6);
    CHECK_MEM(extra, "EARLY!", 6);
    wtls_http_close(r);

    CHECK_EQ_INT(wtls_plat_send(fd, (const uint8_t *)"WS", 2), 2);
    char echo[4] = {0};
    size_t got = 0;
    uint64_t deadline = wtls_plat_now_ms() + 3000;
    while (got < 2 && wtls_plat_now_ms() < deadline) {
        int k = wtls_plat_recv(fd, (uint8_t *)echo + got, 2 - got);
        if (k > 0) got += (size_t)k;
        else if (k == WTLS_WANT_READ) wtls_plat_poll(fd, true, false, 100);
        else break;
    }
    CHECK_EQ_INT((int)got, 2);
    CHECK_MEM(echo, "WS", 2);
    wtls_plat_close(fd);
}

static void http_deflate_length_and_chunked(void) {
    wtls_http_pool_flush();
    static const char *const paths[] = {"/gzip?n=30000&enc=deflate", "/gzip?n=30000&enc=deflate&chunked=1"};
    for (size_t i = 0; i < 2; i++) {
        wtls_http_response *r = get(paths[i]);
        if (!r) return;
        wtls_http_info info;
        wtls_http_get_info(r, &info);
        CHECK(!info.gzip && info.deflate);
        CHECK_EQ_INT((long long)wtls_http_content_length(r), -1);
        uint8_t *buf = malloc(30001);
        int last = 1;
        size_t n = read_all(r, buf, 30001, 4096, &last);
        CHECK_EQ_INT(last, 0);
        CHECK_EQ_INT((int)n, 30000);
        CHECK(is_pattern(buf, n, 0));
        free(buf);
        wtls_http_close(r);
    }
}

static void http_expect_100_continue(void) {
    wtls_http_pool_flush();
    /* 1. Server sends 100 Continue -> body_cb streams and gets 200 echo. */
    up_state us = {.len = 16384u, .piece = 4096u, .abort_after = -1};
    wtls_http_request req = {0};
    req.method = "PUT";
    req.url = url("/expect-accept");
    req.body_cb = up_cb;
    req.body_ctx = &us;
    req.body_len = us.len;
    req.expect_100_continue = true;
    wtls_http_result res;
    CHECK_EQ_INT(wtls_http_fetch(&req, 32768u, &res), WTLS_OK);
    CHECK_EQ_INT(res.status, 200);
    CHECK_EQ_INT((int)us.off, (int)us.len);
    CHECK(res.body && res.body_len == us.len && is_pattern((const uint8_t *)res.body, res.body_len, 0));
    wtls_http_result_free(&res);

    /* 2. Server rejects immediately with 413 -> body_cb is never invoked. */
    us = (up_state){.len = 65536u, .piece = 4096u, .abort_after = -1};
    req.url = url("/expect-reject");
    req.body_ctx = &us;
    CHECK_EQ_INT(wtls_http_fetch(&req, 1024u, &res), WTLS_OK);
    CHECK_EQ_INT(res.status, 413);
    CHECK_EQ_INT(us.calls, 0);
    CHECK(res.body && strcmp(res.body, "toobig") == 0);
    wtls_http_result_free(&res);

    /* 3. Server never sends 100 -> client waits ~1 s then sends body anyway. */
    us = (up_state){.len = 1024u, .piece = 512u, .abort_after = -1};
    req.url = url("/expect-silent");
    req.body_len = us.len;
    req.body_ctx = &us;
    CHECK_EQ_INT(wtls_http_fetch(&req, 4096u, &res), WTLS_OK);
    CHECK_EQ_INT(res.status, 200);
    CHECK_EQ_INT((int)res.body_len, 1024);
    CHECK(res.body && is_pattern((const uint8_t *)res.body, res.body_len, 0));
    wtls_http_result_free(&res);
}

static void http_open_streaming_progress(void) {
    wtls_http_pool_flush();
    prog_state ps = {.monotonic = true, .same_total = true};
    wtls_http_request req = {0};
    req.url = url("/len?n=30000");
    req.progress_cb = test_prog_cb;
    req.progress_ctx = &ps;
    wtls_http_response *r = open_req(&req);
    if (!r) return;
    uint8_t buf[4096];
    while (wtls_http_read(r, buf, sizeof buf) > 0) {}
    wtls_http_close(r);
    CHECK(ps.calls >= 2 && ps.monotonic && ps.same_total);
    CHECK_EQ_INT((long long)ps.last_done, 30000);
    CHECK_EQ_INT((long long)ps.last_total, 30000);
}

static void http_proxy_plain_and_connect(void) {
    wtls_http_pool_flush();
    char proxy[128];
    snprintf(proxy, sizeof proxy, "http://%s:4444", g_env.server_host);

    /* 1. Plain http:// through forward proxy (absolute-form request target). */
    wtls_http_request req = {0};
    req.url = url_of("http", P_HTTP_PLAIN, "/hello");
    req.proxy_url = proxy;
    wtls_http_result res;
    CHECK_EQ_INT(wtls_http_fetch(&req, 1024, &res), WTLS_OK);
    CHECK_EQ_INT(res.status, 200);
    CHECK(res.body && strcmp(res.body, "hello") == 0);
    wtls_http_result_free(&res);

    /* 2. https:// through CONNECT tunnel (verified against target hostname). */
    req.url = url("/hello");
    CHECK_EQ_INT(wtls_http_fetch(&req, 1024, &res), WTLS_OK);
    CHECK_EQ_INT(res.status, 200);
    CHECK(res.body && strcmp(res.body, "hello") == 0);
    wtls_http_result_free(&res);

    /* 3. Rejected CONNECT (403 from proxy) fails with WTLS_ERR_CONNECT. */
    req.url = url_of("https", 4440, "/hello");
    CHECK_EQ_INT(wtls_http_fetch(&req, 1024, &res), WTLS_ERR_CONNECT);

    /* 4. Invalid proxy URL is rejected with WTLS_ERR_ARG. */
    req.url = url("/hello");
    req.proxy_url = "https://proxy:4444";
    CHECK_EQ_INT(wtls_http_fetch(&req, 1024, &res), WTLS_ERR_ARG);
}

/* ---- br / zstd Content-Encoding ------------------------------------------ */

#if WTLS_BROTLI || WTLS_ZSTD
static int read_pattern(const char *file, const char *enc, size_t repeat_len, size_t want_len, wtls_http_info *info,
                        bool *pattern_ok) {
    char path[160];
    snprintf(path, sizeof path, "/fixture?f=%s&enc=%s", file, enc);
    wtls_http_request req = {0};
    req.url = url_of("http", P_HTTP_PLAIN, path);
    req.no_keepalive = true;
    wtls_http_response *r = NULL;
    int st = wtls_http_open(&r, &req);
    *pattern_ok = false;
    if (st != WTLS_OK) return st;
    wtls_http_get_info(r, info);
    size_t total = 0;
    bool ok = true;
    uint8_t buf[3000];
    int k;
    while ((k = wtls_http_read(r, buf, sizeof buf)) > 0) {
        for (int i = 0; i < k; i++) ok &= buf[i] == (uint8_t)((total + (size_t)i) % repeat_len % 251);
        total += (size_t)k;
    }
    wtls_http_close(r);
    *pattern_ok = ok && total == want_len;
    return k;
}
#endif

#if WTLS_BROTLI
static void http_brotli_decodes(void) {
    wtls_http_pool_flush();
    wtls_http_info info;
    bool ok;
    CHECK_EQ_INT(read_pattern("pattern1000.br", "br", 1000000, 1000, &info, &ok), 0);
    CHECK(ok && info.br && !info.gzip && !info.zstd);
    CHECK_EQ_INT(read_pattern("pattern100000.br", "br", 1000000, 100000, &info, &ok), 0);
    CHECK(ok);
}

static void http_brotli_window_too_big_limit(void) {
    wtls_http_info info;
    bool ok;
    CHECK_EQ_INT(read_pattern("pattern100000_bigwindow.br", "br", 1000000, 100000, &info, &ok), WTLS_ERR_HTTP_LIMIT);
}

static void http_brotli_truncated_is_io_error(void) {
    wtls_http_info info;
    bool ok;
    CHECK_EQ_INT(read_pattern("pattern1000_cut.br", "br", 1000000, 1000, &info, &ok), WTLS_ERR_IO);
}
#endif

#if WTLS_ZSTD
static void http_zstd_decodes(void) {
    wtls_http_pool_flush();
    wtls_http_info info;
    bool ok;
    CHECK_EQ_INT(read_pattern("pattern1000.zst", "zstd", 1000000, 1000, &info, &ok), 0);
    CHECK(ok && info.zstd && !info.gzip && !info.br);
    CHECK_EQ_INT(read_pattern("pattern100000.zst", "zstd", 1000000, 100000, &info, &ok), 0);
    CHECK(ok);
    /* two frames back to back are one body */
    CHECK_EQ_INT(read_pattern("pattern2x1000.zst", "zstd", 1000, 2000, &info, &ok), 0);
    CHECK(ok);
}

static void http_zstd_window_too_big_limit(void) {
    wtls_http_info info;
    bool ok;
    CHECK_EQ_INT(read_pattern("pattern100000_bigwindow.zst", "zstd", 1000000, 100000, &info, &ok), WTLS_ERR_HTTP_LIMIT);
}

static void http_zstd_truncated_and_corrupt(void) {
    wtls_http_info info;
    bool ok;
    CHECK_EQ_INT(read_pattern("pattern1000_cut.zst", "zstd", 1000000, 1000, &info, &ok), WTLS_ERR_IO);
    int rc = read_pattern("pattern1000_corrupt.zst", "zstd", 1000000, 1000, &info, &ok);
    CHECK(rc != 0 || !ok); /* damaged data never passes as the original */
}
#endif

#if WTLS_BROTLI || WTLS_ZSTD
static void http_accept_encoding_lists_codecs(void) {
    wtls_http_request req = {0};
    req.url = url_of("http", P_HTTP_PLAIN, "/headers");
    req.no_keepalive = true;
    wtls_http_result res;
    CHECK_EQ_INT(wtls_http_fetch(&req, 4096, &res), WTLS_OK);
    CHECK(res.body && contains_ci(res.body, "accept-encoding: gzip, deflate"));
#if WTLS_BROTLI
    CHECK(res.body && contains_ci(res.body, ", br"));
#endif
#if WTLS_ZSTD
    CHECK(res.body && contains_ci(res.body, "zstd"));
#endif
    wtls_http_result_free(&res);
}
#endif

/* ---- total deadline and retries ------------------------------------------- */

static int flaky_count(const char *id) {
    char path[80];
    snprintf(path, sizeof path, "/flaky-count?id=%s", id);
    wtls_http_request req = {0};
    req.url = url_of("http", P_HTTP_PLAIN, path);
    req.no_keepalive = true;
    wtls_http_result res;
    int n = -1;
    if (wtls_http_fetch(&req, 64, &res) == WTLS_OK) {
        n = atoi(res.body);
        wtls_http_result_free(&res);
    }
    return n;
}

static void http_retry_io_error_then_ok(void) {
    wtls_http_pool_flush();
    wtls_http_request req = {0};
    req.no_keepalive = true; /* every attempt on a fresh connection: no stale-socket retry mixed in */
    req.url = url_of("http", P_HTTP_PLAIN, "/flaky?id=r1&fails=2");
    req.max_retries = 2;
    req.retry_backoff_ms = 20;
    wtls_http_result res;
    CHECK_EQ_INT(wtls_http_fetch(&req, 64, &res), WTLS_OK);
    CHECK(res.body && strcmp(res.body, "ok") == 0);
    wtls_http_result_free(&res);
    CHECK_EQ_INT(flaky_count("r1"), 3);
    /* one retry is not enough for two failures */
    req.url = url_of("http", P_HTTP_PLAIN, "/flaky?id=r2&fails=2");
    req.max_retries = 1;
    CHECK_EQ_INT(wtls_http_fetch(&req, 64, &res), WTLS_ERR_IO);
    CHECK_EQ_INT(flaky_count("r2"), 2);
    /* default: no retries */
    req.url = url_of("http", P_HTTP_PLAIN, "/flaky?id=r3&fails=1");
    req.max_retries = 0;
    CHECK_EQ_INT(wtls_http_fetch(&req, 64, &res), WTLS_ERR_IO);
    CHECK_EQ_INT(flaky_count("r3"), 1);
}

static void http_retry_never_post(void) {
    wtls_http_pool_flush();
    wtls_http_request req = {0};
    req.no_keepalive = true;
    req.method = "POST";
    req.url = url_of("http", P_HTTP_PLAIN, "/flaky?id=p1&fails=1");
    req.body = "x";
    req.body_len = 1;
    req.max_retries = 3;
    req.retry_backoff_ms = 10;
    wtls_http_result res;
    CHECK(wtls_http_fetch(&req, 64, &res) != WTLS_OK);
    CHECK_EQ_INT(flaky_count("p1"), 1); /* a POST is not repeated */
}

/* Winsock retries the SYN to a closed port for about a second before it reports the refusal. */
#if defined(_WIN32)
#define REFUSED_ONE_MS 3000
#else
#define REFUSED_ONE_MS 150
#endif

static void http_retry_connect_refused_backs_off(void) {
    wtls_http_pool_flush();
    wtls_http_request req = {0};
    req.url = url_of("http", P_CLOSED, "/hello");
    req.max_retries = 2;
    req.retry_backoff_ms = 100; /* 75-125 ms, then 150-250 ms */
    wtls_http_result res;
    uint64_t t0 = wtls_plat_now_ms();
    CHECK_EQ_INT(wtls_http_fetch(&req, 64, &res), WTLS_ERR_CONNECT);
    uint64_t dt = wtls_plat_now_ms() - t0;
    CHECK(dt >= 200 && dt < 2000 + 3 * REFUSED_ONE_MS);
    req.max_retries = 0;
    t0 = wtls_plat_now_ms();
    CHECK_EQ_INT(wtls_http_fetch(&req, 64, &res), WTLS_ERR_CONNECT);
    CHECK(wtls_plat_now_ms() - t0 < REFUSED_ONE_MS);
}

static void http_retry_503_retry_after(void) {
    wtls_http_pool_flush();
    wtls_http_request req = {0};
    req.no_keepalive = true; /* every attempt on a fresh connection: no stale-socket retry mixed in */
    req.url = url_of("http", P_HTTP_PLAIN, "/flaky?id=s1&fails=1&mode=503&ra=1");
    wtls_http_result res;
    CHECK_EQ_INT(wtls_http_fetch(&req, 64, &res), WTLS_OK); /* not asked to retry: the 503 is the answer */
    CHECK_EQ_INT(res.status, 503);
    wtls_http_result_free(&res);
    req.url = url_of("http", P_HTTP_PLAIN, "/flaky?id=s2&fails=1&mode=503&ra=1");
    req.max_retries = 1;
    req.retry_on_503 = true;
    uint64_t t0 = wtls_plat_now_ms();
    CHECK_EQ_INT(wtls_http_fetch(&req, 64, &res), WTLS_OK);
    CHECK_EQ_INT(res.status, 200);
    CHECK(wtls_plat_now_ms() - t0 >= 900); /* waited the Retry-After second */
    wtls_http_result_free(&res);
    /* no time left for the wait: the 503 is returned */
    req.url = url_of("http", P_HTTP_PLAIN, "/flaky?id=s3&fails=5&mode=503&ra=30");
    req.total_timeout_ms = 2000;
    t0 = wtls_plat_now_ms();
    CHECK_EQ_INT(wtls_http_fetch(&req, 64, &res), WTLS_OK);
    CHECK_EQ_INT(res.status, 503);
    CHECK(wtls_plat_now_ms() - t0 < 1500);
    wtls_http_result_free(&res);
}

static void http_total_timeout_covers_retries(void) {
    wtls_http_pool_flush();
    wtls_http_request req = {0};
    req.url = url_of("http", P_CLOSED, "/hello");
    req.max_retries = 5;
    req.retry_backoff_ms = 1000;
    req.total_timeout_ms = 300;
    wtls_http_result res;
    uint64_t t0 = wtls_plat_now_ms();
    CHECK_EQ_INT(wtls_http_fetch(&req, 64, &res), WTLS_ERR_TIMEOUT);
    CHECK(wtls_plat_now_ms() - t0 < 700);
}

static void http_total_timeout_slow_body(void) {
    wtls_http_pool_flush();
    wtls_http_request req = {0};
    req.url = url_of("http", P_HTTP_PLAIN, "/slowbody?ms=2500");
    req.total_timeout_ms = 500;
    wtls_http_result res;
    uint64_t t0 = wtls_plat_now_ms();
    CHECK_EQ_INT(wtls_http_fetch(&req, 64, &res), WTLS_ERR_TIMEOUT);
    uint64_t dt = wtls_plat_now_ms() - t0;
    CHECK(dt >= 450 && dt < 1500);
    /* the same budget is plenty for a fast body */
    req.url = url_of("http", P_HTTP_PLAIN, "/hello");
    CHECK_EQ_INT(wtls_http_fetch(&req, 64, &res), WTLS_OK);
    wtls_http_result_free(&res);
}

static void http_total_timeout_slow_head(void) {
    wtls_http_pool_flush();
    wtls_http_request req = {0};
    req.url = url_of("http", P_HTTP_PLAIN, "/slowhead");
    req.total_timeout_ms = 400; /* the default header timeout is 15 s */
    wtls_http_result res;
    uint64_t t0 = wtls_plat_now_ms();
    CHECK_EQ_INT(wtls_http_fetch(&req, 64, &res), WTLS_ERR_TIMEOUT);
    CHECK(wtls_plat_now_ms() - t0 < 1500);
}

/* ---- proxy authentication and SOCKS5 ------------------------------------ */

static void fetch_via(const char *proxy, const char *target, int *status, int *rc, char *body, size_t cap) {
    wtls_http_request req = {0};
    req.url = target;
    req.proxy_url = proxy;
    wtls_http_result res;
    *rc = wtls_http_fetch(&req, 1024, &res);
    *status = *rc == WTLS_OK ? res.status : res.status;
    body[0] = '\0';
    if (*rc == WTLS_OK) {
        snprintf(body, cap, "%.*s", (int)(res.body_len < cap - 1 ? res.body_len : cap - 1), res.body);
        wtls_http_result_free(&res);
    }
}

static void http_proxy_authentication(void) {
    wtls_http_pool_flush();
    char proxy[200], body[64];
    int status, rc;
    snprintf(proxy, sizeof proxy, "http://%s:4446", g_env.server_host);
    fetch_via(proxy, url_of("http", P_HTTP_PLAIN, "/hello"), &status, &rc, body, sizeof body);
    CHECK_EQ_INT(rc, WTLS_OK);
    CHECK_EQ_INT(status, 407); /* plain request: the proxy's answer is the response */
    fetch_via(proxy, url("/hello"), &status, &rc, body, sizeof body);
    CHECK_EQ_INT(rc, WTLS_ERR_CONNECT); /* CONNECT refused with 407 */
    /* credentials in the URL, percent-encoded ("p@ss w0rd") */
    snprintf(proxy, sizeof proxy, "http://proxyuser:p%%40ss%%20w0rd@%s:4446", g_env.server_host);
    fetch_via(proxy, url_of("http", P_HTTP_PLAIN, "/hello"), &status, &rc, body, sizeof body);
    CHECK_EQ_INT(rc, WTLS_OK);
    CHECK_EQ_INT(status, 200);
    CHECK(strcmp(body, "hello") == 0);
    fetch_via(proxy, url("/hello"), &status, &rc, body, sizeof body);
    CHECK_EQ_INT(rc, WTLS_OK);
    CHECK_EQ_INT(status, 200);
    snprintf(proxy, sizeof proxy, "http://proxyuser:wrong@%s:4446", g_env.server_host);
    fetch_via(proxy, url("/hello"), &status, &rc, body, sizeof body);
    CHECK_EQ_INT(rc, WTLS_ERR_CONNECT);
}

static void http_proxy_url_forms_rejected(void) {
    char body[8];
    int status, rc;
    static const char *const bad[] = {"socks5://", "socks4://h:1080", "http://u@:80", "http://:p@h:80", "http://h:80/path",
                                      "socks5://h:99999", "http://u:p%zz@h:80", "http://u:p%4@h:80", "ftp://h"};
    for (size_t i = 0; i < sizeof bad / sizeof bad[0]; i++) {
        fetch_via(bad[i], url_of("http", P_HTTP_PLAIN, "/hello"), &status, &rc, body, sizeof body);
        if (rc != WTLS_ERR_ARG) TLOG("  proxy url %s -> %d\n", bad[i], rc);
        CHECK_EQ_INT(rc, WTLS_ERR_ARG);
    }
}

static int socks_atyp(void) {
    wtls_http_request req = {0};
    req.url = url_of("http", P_HTTP_PLAIN, "/socks-last");
    wtls_http_result res;
    int atyp = -1;
    if (wtls_http_fetch(&req, 1024, &res) == WTLS_OK) {
        const char *p = strstr(res.body, "'atyp': ");
        if (p) atyp = atoi(p + 8);
        wtls_http_result_free(&res);
    }
    return atyp;
}

static void http_socks5_connect(void) {
    wtls_http_pool_flush();
    char proxy[200], body[64];
    int status, rc;
    snprintf(proxy, sizeof proxy, "socks5h://%s:4447", g_env.server_host);
    fetch_via(proxy, url_of("http", P_HTTP_PLAIN, "/hello"), &status, &rc, body, sizeof body);
    CHECK_EQ_INT(rc, WTLS_OK);
    CHECK_EQ_INT(status, 200);
    CHECK(strcmp(body, "hello") == 0);
    uint32_t ip; /* socks5h: the proxy gets the name; an address (the Wii runner) still goes as IPv4 */
    CHECK_EQ_INT(socks_atyp(), wtls_plat_parse_ipv4(g_env.server_host, &ip) ? 1 : 3);
    fetch_via(proxy, url("/hello"), &status, &rc, body, sizeof body);
    CHECK_EQ_INT(rc, WTLS_OK); /* https through the tunnel, verified against the target name */
    CHECK(strcmp(body, "hello") == 0);
    snprintf(proxy, sizeof proxy, "socks5://%s:4447", g_env.server_host);
    fetch_via(proxy, url_of("http", P_HTTP_PLAIN, "/hello"), &status, &rc, body, sizeof body);
    CHECK_EQ_INT(rc, WTLS_OK);
    CHECK_EQ_INT(socks_atyp(), 1); /* socks5: resolved here, an IPv4 address goes out */
    /* a port the proxy refuses */
    fetch_via(proxy, url_of("http", 4431, "/hello"), &status, &rc, body, sizeof body);
    CHECK_EQ_INT(rc, WTLS_ERR_CONNECT);
}

static void http_socks5_authentication(void) {
    wtls_http_pool_flush();
    char proxy[200], body[64];
    int status, rc;
    snprintf(proxy, sizeof proxy, "socks5h://%s:4448", g_env.server_host);
    fetch_via(proxy, url_of("http", P_HTTP_PLAIN, "/hello"), &status, &rc, body, sizeof body);
    CHECK_EQ_INT(rc, WTLS_ERR_CONNECT); /* the proxy requires a user name */
    snprintf(proxy, sizeof proxy, "socks5h://sockuser:s0cks%%3Apw@%s:4448", g_env.server_host);
    fetch_via(proxy, url_of("http", P_HTTP_PLAIN, "/hello"), &status, &rc, body, sizeof body);
    CHECK_EQ_INT(rc, WTLS_OK);
    CHECK(strcmp(body, "hello") == 0);
    fetch_via(proxy, url("/hello"), &status, &rc, body, sizeof body);
    CHECK_EQ_INT(rc, WTLS_OK);
    snprintf(proxy, sizeof proxy, "socks5h://sockuser:nope@%s:4448", g_env.server_host);
    fetch_via(proxy, url_of("http", P_HTTP_PLAIN, "/hello"), &status, &rc, body, sizeof body);
    CHECK_EQ_INT(rc, WTLS_ERR_CONNECT);
}

#if WTLS_HTTP2
static void http2_get_and_info(void) {
    wtls_http_pool_flush();
    wtls_http_request req = {0};
    req.url = url_of("https", P_H2, "/hello");
    wtls_http_response *r = open_req(&req);
    if (!r) return;
    wtls_http_info info;
    CHECK_EQ_INT(wtls_http_get_info(r, &info), WTLS_OK);
    CHECK(info.http2);
    CHECK(info.secure);
    CHECK(!info.reused_connection);
    CHECK(info.tls.alpn && strcmp(info.tls.alpn, "h2") == 0);
    CHECK_EQ_INT(wtls_http_status(r), 200);
    CHECK_EQ_INT((long long)wtls_http_content_length(r), 5);
    int last = -1;
    CHECK(strcmp(body_str(r, &last), "hello") == 0);
    CHECK_EQ_INT(last, 0);
    wtls_http_close(r);

    /* Without Content-Length (END_STREAM terminates body) + HEAD + 204 */
    req.url = url_of("https", P_H2, "/hello?no_cl=1");
    r = open_req(&req);
    if (r) {
        CHECK_EQ_INT((long long)wtls_http_content_length(r), -1);
        CHECK(strcmp(body_str(r, &last), "hello") == 0);
        wtls_http_close(r);
    }

    req.method = "HEAD";
    req.url = url_of("https", P_H2, "/len?n=42");
    r = open_req(&req);
    if (r) {
        CHECK_EQ_INT(wtls_http_status(r), 200);
        CHECK_EQ_INT((long long)wtls_http_content_length(r), 42);
        uint8_t b[8];
        CHECK_EQ_INT(wtls_http_read(r, b, sizeof b), 0);
        wtls_http_close(r);
    }

    req.method = NULL;
    req.url = url_of("https", P_H2, "/status?code=204");
    r = open_req(&req);
    if (r) {
        CHECK_EQ_INT(wtls_http_status(r), 204);
        CHECK_EQ_INT((long long)wtls_http_content_length(r), 0);
        wtls_http_close(r);
    }
}

static void http2_trailers_keep_the_hpack_table_in_step(void) {
    wtls_http_pool_flush();
    wtls_http_request req = {0};
    req.url = url_of("https", P_H2, "/trailers?n=100");
    wtls_http_response *r = open_req(&req);
    if (!r) return;
    int last = -1;
    CHECK_EQ_INT((int)strlen(body_str(r, &last)), 100);
    CHECK_EQ_INT(last, 0);
    wtls_http_close(r);
    /* the same connection: the next head refers to the dynamic table entry the trailers made */
    req.url = url_of("https", P_H2, "/dynref");
    r = open_req(&req);
    if (!r) return;
    wtls_http_info info;
    CHECK_EQ_INT(wtls_http_get_info(r, &info), WTLS_OK);
    CHECK(info.http2 && info.reused_connection);
    const char *t = wtls_http_get_header(r, "x-trailer");
    CHECK(t && strcmp(t, "t1") == 0);
    CHECK(strcmp(body_str(r, &last), "ok") == 0);
    wtls_http_close(r);
}

static void http2_reuse_and_goaway(void) {
    wtls_http_pool_flush();
    wtls_http_request req = {0};
    req.url = url_of("https", P_H2, "/conn");
    wtls_http_response *r1 = open_req(&req);
    if (!r1) return;
    int last = -1;
    unsigned c1 = 0, s1 = 0;
    CHECK_EQ_INT(sscanf(body_str(r1, &last), "%u %u", &c1, &s1), 2);
    CHECK_EQ_INT((int)s1, 1);
    wtls_http_close(r1);

    wtls_http_response *r2 = open_req(&req);
    if (!r2) return;
    wtls_http_info info;
    CHECK_EQ_INT(wtls_http_get_info(r2, &info), WTLS_OK);
    CHECK(info.reused_connection);
    CHECK(info.http2);
    unsigned c2 = 0, s2 = 0;
    CHECK_EQ_INT(sscanf(body_str(r2, &last), "%u %u", &c2, &s2), 2);
    CHECK_EQ_INT((int)c2, (int)c1);
    CHECK_EQ_INT((int)s2, 3);
    wtls_http_close(r2);

    /* no_h2=true must NOT reuse the pooled h2 connection and must negotiate http/1.1 */
    req.no_h2 = true;
    wtls_http_response *r3 = open_req(&req);
    if (r3) {
        CHECK_EQ_INT(wtls_http_get_info(r3, &info), WTLS_OK);
        CHECK(!info.reused_connection);
        CHECK(!info.http2);
        CHECK(info.tls.alpn && strcmp(info.tls.alpn, "http/1.1") == 0);
        wtls_http_close(r3);
    }

    /* /goaway prevents further reuse */
    wtls_http_pool_flush();
    req.no_h2 = false;
    req.url = url_of("https", P_H2, "/goaway");
    wtls_http_response *rg = open_req(&req);
    if (rg) {
        CHECK(strcmp(body_str(rg, &last), "bye") == 0);
        wtls_http_close(rg);
    }
    req.url = url_of("https", P_H2, "/conn");
    wtls_http_response *rf = open_req(&req);
    if (rf) {
        CHECK_EQ_INT(wtls_http_get_info(rf, &info), WTLS_OK);
        CHECK(!info.reused_connection);
        wtls_http_close(rf);
    }
}

typedef struct {
    size_t sent;
    size_t total;
    bool chunked;
} h2_up_ctx;

static int h2_up_cb(void *ctx, void *buf, size_t max_len) {
    h2_up_ctx *u = ctx;
    if (u->sent >= u->total) return 0;
    size_t left = u->total - u->sent;
    size_t n = left < max_len ? left : max_len;
    if (n > 10000u) n = 10000u;
    uint8_t *p = buf;
    for (size_t i = 0; i < n; i++) p[i] = (uint8_t)('A' + ((u->sent + i) % 26));
    u->sent += n;
    return (int)n;
}

static void http2_flow_upload_expect_gzip_cont(void) {
    wtls_http_pool_flush();
    /* Big download exercising stream & connection WINDOW_UPDATE */
    wtls_http_request req = {0};
    req.url = url_of("https", P_H2, "/len?n=400000");
    wtls_http_result res;
    CHECK_EQ_INT(wtls_http_fetch(&req, 512u * 1024u, &res), WTLS_OK);
    CHECK_EQ_INT((int)res.body_len, 400000);
    wtls_http_result_free(&res);

    /* Big streaming upload (200 KiB) forcing server->client WINDOW_UPDATE */
    h2_up_ctx up = {0, 200u * 1024u, false};
    memset(&req, 0, sizeof req);
    req.method = "POST";
    req.url = url_of("https", P_H2, "/echo");
    req.body_cb = h2_up_cb;
    req.body_ctx = &up;
    req.body_len = up.total;
    CHECK_EQ_INT(wtls_http_fetch(&req, 256u * 1024u, &res), WTLS_OK);
    CHECK_EQ_INT((int)res.body_len, (int)up.total);
    CHECK(res.body[0] == 'A' && res.body[up.total - 1] == (char)('A' + ((up.total - 1) % 26)));
    wtls_http_result_free(&res);

    /* Streaming unknown-length upload (body_chunked=true without Content-Length) */
    up = (h2_up_ctx){0, 12345, true};
    memset(&req, 0, sizeof req);
    req.method = "PUT";
    req.url = url_of("https", P_H2, "/echo");
    req.body_cb = h2_up_cb;
    req.body_ctx = &up;
    req.body_chunked = true;
    CHECK_EQ_INT(wtls_http_fetch(&req, 32768u, &res), WTLS_OK);
    CHECK_EQ_INT((int)res.body_len, 12345);
    wtls_http_result_free(&res);

    /* Expect: 100-continue accept and reject */
    up = (h2_up_ctx){0, 5, false};
    memset(&req, 0, sizeof req);
    req.method = "POST";
    req.url = url_of("https", P_H2, "/echo");
    req.body = "hello";
    req.body_len = 5;
    req.expect_100_continue = true;
    CHECK_EQ_INT(wtls_http_fetch(&req, 1024u, &res), WTLS_OK);
    CHECK(res.body_len == 5 && memcmp(res.body, "hello", 5) == 0);
    wtls_http_result_free(&res);

    req.url = url_of("https", P_H2, "/expect-reject");
    CHECK_EQ_INT(wtls_http_fetch(&req, 1024u, &res), WTLS_OK);
    CHECK_EQ_INT(res.status, 417);
    CHECK(res.body_len == 6 && memcmp(res.body, "reject", 6) == 0);
    wtls_http_result_free(&res);

    /* CONTINUATION + HPACK dynamic table + Redirect */
    memset(&req, 0, sizeof req);
    req.url = url_of("https", P_H2, "/cont");
    wtls_http_response *rc = open_req(&req);
    if (rc) {
        const char *xv = wtls_http_get_header(rc, "x-custom");
        CHECK(xv && strcmp(xv, "hpack-dyn") == 0);
        int last = -1;
        CHECK(strcmp(body_str(rc, &last), "cont") == 0);
        wtls_http_close(rc);
    }

    req.url = url_of("https", P_H2, "/redirect?to=/hello");
    CHECK_EQ_INT(wtls_http_fetch(&req, 1024u, &res), WTLS_OK);
    CHECK(res.status == 200 && res.body_len == 5 && memcmp(res.body, "hello", 5) == 0);
    wtls_http_result_free(&res);

#if WTLS_GZIP
    req.url = url_of("https", P_H2, "/gzip?n=8192&enc=deflate");
    CHECK_EQ_INT(wtls_http_fetch(&req, 16384u, &res), WTLS_OK);
    CHECK_EQ_INT((int)res.body_len, 8192);
    wtls_http_result_free(&res);
#endif
}
#endif

/* ---- cookie jar --------------------------------------------------------- */

static void fetch_with_jar(const char *u, wtls_cookie_jar *jar, bool no_h2, char *out, size_t cap) {
    wtls_http_request req = {0};
    req.url = u;
    req.cookie_jar = jar;
    req.no_h2 = no_h2;
    wtls_http_result res;
    int st = wtls_http_fetch(&req, 0, &res);
    CHECK_EQ_INT(st, WTLS_OK);
    out[0] = '\0';
    if (st == WTLS_OK) {
        snprintf(out, cap, "%.*s", (int)(res.body_len < cap - 1 ? res.body_len : cap - 1), res.body);
        wtls_http_result_free(&res);
    }
}

static void http_cookie_jar_roundtrip(void) {
    wtls_http_pool_flush();
    wtls_cookie_jar *jar = wtls_cookie_jar_new(0);
    char body[2048];
    fetch_with_jar(url_of("http", P_HTTP_PLAIN, "/setcookie?c=sid%3Dabc%3B+Path%3D%2F&c2=theme%3Ddark"), jar, true, body, sizeof body);
    CHECK_EQ_INT((int)wtls_cookie_jar_count(jar), 2);
    fetch_with_jar(url_of("http", P_HTTP_PLAIN, "/headers"), jar, true, body, sizeof body);
    CHECK(strstr(body, "cookie: sid=abc; theme=dark") != NULL || strstr(body, "Cookie: sid=abc; theme=dark") != NULL);
    /* a Cookie header of your own wins */
    wtls_http_header h[] = {{"Cookie", "mine=1"}};
    wtls_http_request req = {0};
    req.url = url_of("http", P_HTTP_PLAIN, "/headers");
    req.cookie_jar = jar;
    req.headers = h;
    req.n_headers = 1;
    wtls_http_result res;
    CHECK_EQ_INT(wtls_http_fetch(&req, 0, &res), WTLS_OK);
    CHECK(res.body && strstr(res.body, "mine=1") != NULL && strstr(res.body, "sid=abc") == NULL);
    wtls_http_result_free(&res);
    wtls_cookie_jar_clear(jar);
    fetch_with_jar(url_of("http", P_HTTP_PLAIN, "/headers"), jar, true, body, sizeof body);
    CHECK(strstr(body, "sid=abc") == NULL);
    wtls_cookie_jar_free(jar);
}

static void http_cookie_jar_secure_and_redirect(void) {
    wtls_http_pool_flush();
    wtls_cookie_jar *jar = wtls_cookie_jar_new(0);
    char body[2048];
    /* set over https: a Secure cookie is stored and only sent back over https */
    fetch_with_jar(url_of("https", P_HTTP, "/setcookie?c=tok%3D1%3B+Secure"), jar, true, body, sizeof body);
    CHECK_EQ_INT((int)wtls_cookie_jar_count(jar), 1);
    fetch_with_jar(url_of("http", P_HTTP_PLAIN, "/headers"), jar, true, body, sizeof body);
    CHECK(strstr(body, "tok=1") == NULL);
    fetch_with_jar(url_of("https", P_HTTP, "/headers"), jar, true, body, sizeof body);
    CHECK(strstr(body, "tok=1") != NULL);
    /* the same host name on another port shares host-only cookies (cookies ignore ports); a cookie
     * set by an intermediate redirect hop is already sent on the next hop */
    wtls_cookie_jar_clear(jar);
    char target[160];
    snprintf(target, sizeof target, "/headers");
    char u[400];
    snprintf(u, sizeof u, "/cookie-redirect?c=hop%%3D1&to=%s", target);
    fetch_with_jar(url_of("http", P_HTTP_PLAIN, u), jar, true, body, sizeof body);
    CHECK(strstr(body, "hop=1") != NULL);
    CHECK_EQ_INT((int)wtls_cookie_jar_count(jar), 1);
    wtls_cookie_jar_free(jar);
}

void wtls_suite_http(void) {
    int r = wtls_init();
    CHECK_EQ_INT(r, WTLS_OK);
    if (r != WTLS_OK) return;
    bool trusted = trust_test_ca();
    CHECK(trusted);
    if (!trusted) {
        TLOG("  cannot fetch the test CA from %s:%d\n", g_env.server_host, PLAIN_PORT);
        return;
    }
    RUN(http_get_hello);
    RUN(http_cookie_jar_roundtrip);
    RUN(http_cookie_jar_secure_and_redirect);
    RUN(http_len_big);
    RUN(http_chunked);
    RUN(http_close_delimited);
    RUN(http_close_delimited_without_close_notify);
    RUN(http_truncated_length);
    RUN(http_truncated_chunked);
    RUN(http_trickle);
    RUN(http_reused_takes_request_io_timeout);
    RUN(http_head_request);
    RUN(http_status_no_body);
    RUN(http_interim_100);
    RUN(http_upgrade_rejected_without_flag);
    RUN(http_upgrade_detach_tls_and_early);
    RUN(http_upgrade_detach_plain_and_errors);
    RUN(http_bighead_ok);
    RUN(http_bighead_limit);
    RUN(http_header_timeout);
    RUN(http_post_echo);
    RUN(http_upload_body_cb_fixed);
    RUN(http_upload_body_cb_chunked);
    RUN(http_upload_empty_chunked);
    RUN(http_upload_empty_fixed);
    RUN(http_null_headers_nonzero_count);
    RUN(http_upload_premature_eof);
    RUN(http_upload_callback_abort);
    RUN(http_upload_307_redirect);
    RUN(http_upload_302_post_becomes_get);
    RUN(http_upload_256k);
    RUN(http_upload_keepalive_reuse);
    RUN(http_upload_stale_no_retry);
    RUN(http_upload_args);
    RUN(http_mtls_who);
    RUN(http_mtls_pool_isolated);
    RUN(http_mtls_tickets_isolated);
    RUN(http_mtls_cross_origin_stripped);
    RUN(http_mtls_upload);
    RUN(http_mtls_free_while_pooled);
    RUN(http_abort_slowhead);
    RUN(http_abort_plain);
    RUN(http_abort_read_not_pooled);
    RUN(http_abort_upload);
    RUN(http_fetch_progress);
    RUN(http_open_streaming_progress);
    RUN(http_expect_100_continue);
    RUN(http_proxy_plain_and_connect);
#if WTLS_BROTLI
    RUN(http_brotli_decodes);
    RUN(http_brotli_window_too_big_limit);
    RUN(http_brotli_truncated_is_io_error);
#endif
#if WTLS_ZSTD
    RUN(http_zstd_decodes);
    RUN(http_zstd_window_too_big_limit);
    RUN(http_zstd_truncated_and_corrupt);
#endif
#if WTLS_BROTLI || WTLS_ZSTD
    RUN(http_accept_encoding_lists_codecs);
#endif
    RUN(http_retry_io_error_then_ok);
    RUN(http_retry_never_post);
    RUN(http_retry_connect_refused_backs_off);
    RUN(http_retry_503_retry_after);
    RUN(http_total_timeout_covers_retries);
    RUN(http_total_timeout_slow_body);
    RUN(http_total_timeout_slow_head);
    RUN(http_proxy_authentication);
    RUN(http_proxy_url_forms_rejected);
    RUN(http_socks5_connect);
    RUN(http_socks5_authentication);
    RUN(http_net_reset_flushes_pool);
    RUN(http_spki_pin_ca_and_mismatch);
    RUN(http_spki_pin_pool_and_redirect);
    RUN(http_request_headers);
    RUN(http_get_info);
    RUN(http_alpn_forced);
    RUN(http_bad_url);
    RUN(http_errors_pass_through);
    RUN(http_keepalive_reuse);
    RUN(http_partial_read_not_pooled);
    RUN(http_no_keepalive_not_pooled);
    RUN(http_stale_after_server_close);
    RUN(http_stale_without_close_notify);
    RUN(http_retry_idempotent);
    RUN(http_post_not_retried);
    RUN(http_insecure_not_shared);
    RUN(http_shutdown_flushes_pool);
    RUN(http_redirect_chain);
    RUN(http_redirect_too_many);
    RUN(http_redirect_disabled);
    RUN(http_redirect_methods);
    RUN(http_redirect_relative);
    RUN(http_redirect_https_to_plain_refused);
    RUN(http_redirect_cross_origin_strips_credentials);
    RUN(http_redirect_same_origin_keeps_credentials);
    RUN(http_redirect_without_location);
    RUN(http_redirect_bad_location);
    RUN(http_redirect_reuses_connection);
    RUN(fetch_hello);
    RUN(fetch_404);
    RUN(fetch_limit_by_length);
    RUN(fetch_limit_chunked);
    RUN(fetch_default_limit);
    RUN(fetch_result_free_safe);
    RUN(http_plain_get);
    RUN(http_plain_keepalive);
    RUN(http_redirect_plain_to_https_ok);
#if WTLS_GZIP
    RUN(http_gzip_length);
    RUN(http_gzip_chunked);
    RUN(http_deflate_length_and_chunked);
    RUN(http_gzip_offered);
    RUN(http_gzip_no_gzip_raw);
    RUN(http_gzip_own_accept_encoding_raw);
    RUN(http_gzip_unknown_encoding);
    RUN(http_gzip_bad_crc);
    RUN(http_gzip_truncated);
    RUN(http_gzip_fetch_limit);
#endif
#if WTLS_HTTP2
    RUN(http2_get_and_info);
    RUN(http2_trailers_keep_the_hpack_table_in_step);
    RUN(http2_reuse_and_goaway);
    RUN(http2_flow_upload_expect_gzip_cont);
#endif
    wtls_shutdown();
}
