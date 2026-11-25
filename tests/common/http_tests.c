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
    snprintf(b, sizeof bufs[0], "%s://%s:%u%s", scheme, g_env.server_host, (unsigned)port, path);
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

static void http_redirect_downgrade_refused(void) {
    wtls_http_pool_flush();
    expect_open_err(redirect_path(302, url_of("http", PLAIN_PORT, "/")), WTLS_ERR_HTTP_REDIRECT);
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
    RUN(http_len_big);
    RUN(http_chunked);
    RUN(http_close_delimited);
    RUN(http_close_delimited_without_close_notify);
    RUN(http_truncated_length);
    RUN(http_truncated_chunked);
    RUN(http_trickle);
    RUN(http_head_request);
    RUN(http_status_no_body);
    RUN(http_interim_100);
    RUN(http_bighead_ok);
    RUN(http_bighead_limit);
    RUN(http_header_timeout);
    RUN(http_post_echo);
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
    RUN(http_redirect_downgrade_refused);
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
    wtls_shutdown();
}
