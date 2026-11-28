/* Logging and key log tests, run on the host (tests/host/test_log.c) and on the
 * Wii (suite "log"). Server: tests/host/tls_test_server.py with --certs. */
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
#define P_EXPIRED 4434
#define P_HTTP 4438

#define MAX_MSGS 128
#define MSG_LEN 256

typedef struct {
    int n;
    wtls_log_level level[MAX_MSGS];
    uint32_t cat[MAX_MSGS];
    char text[MAX_MSGS][MSG_LEN];
} log_sink;

static log_sink s_sink;

static void sink_cb(void *ctx, wtls_log_level level, uint32_t category, const char *msg) {
    log_sink *s = ctx;
    if (s->n >= MAX_MSGS) return;
    s->level[s->n] = level;
    s->cat[s->n] = category;
    snprintf(s->text[s->n], MSG_LEN, "%s", msg);
    s->n++;
}

static void sink_reset(wtls_log_level max_level, uint32_t cats) {
    memset(&s_sink, 0, sizeof s_sink);
    wtls_set_log_cb(sink_cb, &s_sink, max_level, cats);
}

static void sink_off(void) { wtls_set_log_cb(NULL, NULL, WTLS_LOG_ERROR, 0); }

/* First message of the category that contains needle, or -1. */
static int find_msg(uint32_t cat, const char *needle) {
    for (int i = 0; i < s_sink.n; i++)
        if ((s_sink.cat[i] & cat) && strstr(s_sink.text[i], needle)) return i;
    return -1;
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

static void test_log_handshake_events_reported(void) {
    sink_reset(WTLS_LOG_INFO, WTLS_LOG_CAT_ALL);
    wtls_conn *c = NULL;
    CHECK_EQ_INT(wtls_connect(&c, g_env.server_host, P_TLS13_ECDSA, NULL), WTLS_OK);
    wtls_close(c);
    sink_off();
    int i = find_msg(WTLS_LOG_CAT_HANDSHAKE, "TLSv1.3");
    CHECK(i >= 0);
    if (i >= 0) CHECK(s_sink.level[i] <= WTLS_LOG_INFO);
}

static void test_log_cert_failure_has_flags(void) {
    sink_reset(WTLS_LOG_INFO, WTLS_LOG_CAT_ALL);
    wtls_conn *c = NULL;
    CHECK_EQ_INT(wtls_connect(&c, g_env.server_host, P_EXPIRED, NULL), WTLS_ERR_CERT);
    sink_off();
    int i = find_msg(WTLS_LOG_CAT_CERT, "expired");
    CHECK(i >= 0);
    if (i >= 0) CHECK_EQ_INT(s_sink.level[i], WTLS_LOG_ERROR);
}

static void test_log_level_filter(void) {
    sink_reset(WTLS_LOG_ERROR, WTLS_LOG_CAT_ALL);
    wtls_conn *c = NULL;
    CHECK_EQ_INT(wtls_connect(&c, g_env.server_host, P_TLS13_ECDSA, NULL), WTLS_OK);
    wtls_close(c);
    CHECK_EQ_INT(s_sink.n, 0);
    sink_off();
}

static void test_log_category_filter(void) {
    sink_reset(WTLS_LOG_DEBUG, WTLS_LOG_CAT_CERT);
    wtls_conn *c = NULL;
    CHECK_EQ_INT(wtls_connect(&c, g_env.server_host, P_TLS13_ECDSA, NULL), WTLS_OK);
    wtls_close(c);
    sink_off();
    for (int i = 0; i < s_sink.n; i++) CHECK(s_sink.cat[i] & WTLS_LOG_CAT_CERT);
}

static void test_log_never_contains_authorization(void) {
    sink_reset(WTLS_LOG_DEBUG, WTLS_LOG_CAT_ALL);
    char url[128];
    snprintf(url, sizeof url, "https://%s:%u/hello?token=QUERYSECRET", g_env.server_host, (unsigned)P_HTTP);
    const wtls_http_header h[] = {{"Authorization", "Bearer SECRET123"}, {"Cookie", "sid=COOKIESECRET"}};
    wtls_http_request req = {0};
    req.url = url;
    req.headers = h;
    req.n_headers = 2;
    wtls_http_result res;
    CHECK_EQ_INT(wtls_http_fetch(&req, 0, &res), WTLS_OK);
    wtls_http_result_free(&res);
    sink_off();
    CHECK(find_msg(WTLS_LOG_CAT_HTTP, "GET") >= 0); /* it did log something */
    for (int i = 0; i < s_sink.n; i++) {
        CHECK(strstr(s_sink.text[i], "SECRET123") == NULL);
        CHECK(strstr(s_sink.text[i], "COOKIESECRET") == NULL);
        CHECK(strstr(s_sink.text[i], "QUERYSECRET") == NULL);
    }
}

#if defined(WTLS_KEYLOG) && WTLS_KEYLOG

#define MAX_KEYLINES 16
static char s_keylines[MAX_KEYLINES][256];
static int s_nkey;

static void keylog_sink(void *ctx, const char *line) {
    (void)ctx;
    if (s_nkey < MAX_KEYLINES) snprintf(s_keylines[s_nkey++], sizeof s_keylines[0], "%s", line);
}

static bool is_hex(const char *p, size_t n) {
    for (size_t i = 0; i < n; i++)
        if (!((p[i] >= '0' && p[i] <= '9') || (p[i] >= 'a' && p[i] <= 'f'))) return false;
    return true;
}

/* ^[A-Z_0-9]+ [0-9a-f]{64} [0-9a-f]{64,96}$ */
static bool keyline_ok(const char *l) {
    size_t i = 0;
    while ((l[i] >= 'A' && l[i] <= 'Z') || l[i] == '_' || (l[i] >= '0' && l[i] <= '9')) i++;
    if (i == 0 || l[i] != ' ' || !is_hex(l + i + 1, 64) || l[i + 65] != ' ') return false;
    size_t n = strlen(l + i + 66);
    return n >= 64 && n <= 96 && is_hex(l + i + 66, n);
}

static void test_keylog_lines_wireshark_format(void) {
    s_nkey = 0;
    CHECK_EQ_INT(wtls_set_keylog_cb(keylog_sink, NULL), WTLS_OK);
    wtls_conn *c = NULL;
    CHECK_EQ_INT(wtls_connect(&c, g_env.server_host, P_TLS13_ECDSA, NULL), WTLS_OK);
    wtls_close(c);
    CHECK_EQ_INT(wtls_set_keylog_cb(NULL, NULL), WTLS_OK);
    CHECK_EQ_INT(s_nkey, 4);
    static const char *const want[] = {"CLIENT_HANDSHAKE_TRAFFIC_SECRET ", "SERVER_HANDSHAKE_TRAFFIC_SECRET ",
                                       "CLIENT_TRAFFIC_SECRET_0 ", "SERVER_TRAFFIC_SECRET_0 "};
    for (size_t w = 0; w < 4; w++) {
        bool found = false;
        for (int i = 0; i < s_nkey; i++) found |= strncmp(s_keylines[i], want[w], strlen(want[w])) == 0;
        CHECK(found);
    }
    for (int i = 0; i < s_nkey; i++) CHECK(keyline_ok(s_keylines[i]));
}

static void test_keylog_removed_callback_silent(void) {
    s_nkey = 0;
    CHECK_EQ_INT(wtls_set_keylog_cb(keylog_sink, NULL), WTLS_OK);
    CHECK_EQ_INT(wtls_set_keylog_cb(NULL, NULL), WTLS_OK);
    wtls_conn *c = NULL;
    CHECK_EQ_INT(wtls_connect(&c, g_env.server_host, P_TLS13_ECDSA, NULL), WTLS_OK);
    wtls_close(c);
    CHECK_EQ_INT(s_nkey, 0);
}

#else

static void keylog_sink(void *ctx, const char *line) {
    (void)ctx;
    (void)line;
}

static void test_keylog_unsupported_in_release(void) {
    CHECK_EQ_INT(wtls_set_keylog_cb(keylog_sink, NULL), WTLS_ERR_UNSUPPORTED);
}

#endif

void wtls_suite_log(void) {
    int r = wtls_init();
    CHECK_EQ_INT(r, WTLS_OK);
    if (r != WTLS_OK) return;
    bool trusted = trust_test_ca();
    CHECK(trusted);
    if (!trusted) {
        TLOG("  cannot fetch the test CA from %s:%d\n", g_env.server_host, PLAIN_PORT);
        return;
    }
    RUN(test_log_handshake_events_reported);
    RUN(test_log_cert_failure_has_flags);
    RUN(test_log_level_filter);
    RUN(test_log_category_filter);
    RUN(test_log_never_contains_authorization);
#if defined(WTLS_KEYLOG) && WTLS_KEYLOG
    RUN(test_keylog_lines_wireshark_format);
    RUN(test_keylog_removed_callback_silent);
#else
    RUN(test_keylog_unsupported_in_release);
#endif
    wtls_shutdown();
}
