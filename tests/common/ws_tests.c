/* WebSocket client tests, run on the host (tests/host/test_ws.c) and on the Wii
 * (suite "ws"). Server: tests/host/tls_test_server.py, route /ws (TLS 4438, plain 4440). */
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <wiitls/websocket.h>

#include "check.h"
#include "env.h"
#include "plat/plat.h"

#define PLAIN_PORT 4430
#define P_HTTP 4438
#define P_HTTP_PLAIN 4440

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

static const char *ws_url(bool secure, const char *path) {
    static char b[4][200];
    static unsigned next;
    char *u = b[next++ % 4];
    snprintf(u, sizeof b[0], "%s://%s:%u%s", secure ? "wss" : "ws", g_env.server_host,
             (unsigned)(secure ? P_HTTP : P_HTTP_PLAIN), path);
    return u;
}

static wtls_ws *open_ws(bool secure, const char *path) {
    wtls_ws_options o = {0};
    o.url = ws_url(secure, path);
    wtls_ws *ws = NULL;
    CHECK_EQ_INT(wtls_ws_connect(&ws, &o), WTLS_OK);
    return ws;
}

/* Sends text, expects the same text back. */
static void expect_echo(wtls_ws *ws, int type, const void *data, size_t len) {
    CHECK_EQ_INT(wtls_ws_send(ws, type, data, len), (int)len);
    uint8_t *buf = malloc(len + 1);
    int t = 0;
    int n = wtls_ws_recv(ws, &t, buf, len + 1);
    CHECK_EQ_INT(n, (int)len);
    CHECK_EQ_INT(t, type);
    if (n == (int)len && len) CHECK_MEM(buf, data, len);
    free(buf);
}

static void send_cmd(wtls_ws *ws, const char *cmd) {
    CHECK_EQ_INT(wtls_ws_send(ws, WTLS_WS_TEXT, cmd, strlen(cmd)), (int)strlen(cmd));
}

static void echo_text(bool secure) {
    wtls_ws *ws = open_ws(secure, "/ws");
    if (!ws) return;
    expect_echo(ws, WTLS_WS_TEXT, "hello", 5);
    expect_echo(ws, WTLS_WS_TEXT, "gr\xC3\xBC\xC3\x9F" "e \xE2\x82\xAC", 11); /* valid UTF-8 */
    expect_echo(ws, WTLS_WS_TEXT, "", 0);
    wtls_ws_close(ws, 1000, "done");
}

static void test_ws_echo_text_wss(void) { echo_text(true); }
static void test_ws_echo_text_plain(void) { echo_text(false); }

static void test_ws_echo_binary_64k(void) {
    wtls_ws *ws = open_ws(true, "/ws");
    if (!ws) return;
    uint8_t *p = malloc(65536);
    for (size_t i = 0; i < 65536; i++) p[i] = (uint8_t)(i * 7 + 1);
    expect_echo(ws, WTLS_WS_BINARY, p, 65536);
    free(p);
    wtls_ws_close(ws, 1000, NULL);
}

static void test_ws_fragmented_reassembled(void) {
    wtls_ws *ws = open_ws(true, "/ws");
    if (!ws) return;
    send_cmd(ws, "frag");
    char buf[64];
    int t = 0, n = wtls_ws_recv(ws, &t, buf, sizeof buf);
    CHECK_EQ_INT(n, 16);
    CHECK_EQ_INT(t, WTLS_WS_TEXT);
    if (n == 16) CHECK_MEM(buf, "frag-mented-text", 16); /* the Ping between the fragments was answered on the way */
    expect_echo(ws, WTLS_WS_TEXT, "still alive", 11);
    wtls_ws_close(ws, 1000, NULL);
}

static void test_ws_ping_auto_pong(void) {
    wtls_ws *ws = open_ws(true, "/ws");
    if (!ws) return;
    send_cmd(ws, "ping"); /* the server pings, waits for our Pong, then says "pong-ok" */
    char buf[16];
    int t = 0, n = wtls_ws_recv(ws, &t, buf, sizeof buf);
    CHECK_EQ_INT(n, 7);
    if (n == 7) CHECK_MEM(buf, "pong-ok", 7);
    CHECK_EQ_INT(wtls_ws_ping(ws, "x", 1), WTLS_OK); /* the server answers with a Pong, which is swallowed */
    expect_echo(ws, WTLS_WS_TEXT, "after ping", 10);
    CHECK_EQ_INT(wtls_ws_ping(ws, buf, 126), WTLS_ERR_ARG);
    wtls_ws_close(ws, 1000, NULL);
}

static void test_ws_server_close_clean(void) {
    wtls_ws *ws = open_ws(true, "/ws");
    if (!ws) return;
    CHECK_EQ_INT((int)wtls_ws_close_code(ws), 0);
    send_cmd(ws, "close");
    char buf[16];
    int t = 0;
    CHECK_EQ_INT(wtls_ws_recv(ws, &t, buf, sizeof buf), WTLS_ERR_CLOSED);
    CHECK_EQ_INT((int)wtls_ws_close_code(ws), 1000);
    CHECK_EQ_INT(wtls_ws_recv(ws, &t, buf, sizeof buf), WTLS_ERR_CLOSED); /* stays closed */
    CHECK_EQ_INT(wtls_ws_send(ws, WTLS_WS_TEXT, "x", 1), WTLS_ERR_CLOSED);
    wtls_ws_close(ws, 0, NULL);
}

static void test_ws_bad_accept_rejected(void) {
    wtls_ws_options o = {0};
    o.url = ws_url(true, "/ws-badaccept");
    wtls_ws *ws = (wtls_ws *)1;
    CHECK_EQ_INT(wtls_ws_connect(&ws, &o), WTLS_ERR_WS);
    CHECK(ws == NULL);
}

static void protocol_error_case(const char *cmd) {
    wtls_ws *ws = open_ws(true, "/ws");
    if (!ws) return;
    send_cmd(ws, cmd);
    char buf[64];
    int t = 0;
    CHECK_EQ_INT(wtls_ws_recv(ws, &t, buf, sizeof buf), WTLS_ERR_WS);
    CHECK_EQ_INT(wtls_ws_recv(ws, &t, buf, sizeof buf), WTLS_ERR_WS); /* the connection stays failed */
    wtls_ws_close(ws, 0, NULL);
}

static void test_ws_masked_server_frame_protocol_error(void) { protocol_error_case("masked"); }
static void test_ws_invalid_utf8_1007(void) { protocol_error_case("badutf8"); }

static void test_ws_message_too_big_1009(void) {
    wtls_ws_options o = {0};
    o.url = ws_url(true, "/ws");
    o.max_message = 100;
    wtls_ws *ws = NULL;
    CHECK_EQ_INT(wtls_ws_connect(&ws, &o), WTLS_OK);
    if (!ws) return;
    CHECK_EQ_INT(wtls_ws_send(ws, WTLS_WS_BINARY, "0123456789", 10), 10);
    char buf[2000];
    int t = 0;
    CHECK_EQ_INT(wtls_ws_recv(ws, &t, buf, sizeof buf), 10); /* within the limit: fine */
    CHECK_EQ_INT(wtls_ws_send(ws, WTLS_WS_BINARY, buf, 101), WTLS_ERR_HTTP_LIMIT); /* sending is limited too */
    send_cmd(ws, "big:1000");
    CHECK_EQ_INT(wtls_ws_recv(ws, &t, buf, sizeof buf), WTLS_ERR_WS);
    wtls_ws_close(ws, 0, NULL);
}

static void test_ws_buffer_too_small_keeps_message(void) {
    wtls_ws *ws = open_ws(true, "/ws");
    if (!ws) return;
    CHECK_EQ_INT(wtls_ws_send(ws, WTLS_WS_TEXT, "hello", 5), 5);
    char buf[16];
    int t = 0;
    CHECK_EQ_INT(wtls_ws_recv(ws, &t, buf, 2), WTLS_ERR_HTTP_LIMIT);
    CHECK_EQ_INT(wtls_ws_recv(ws, &t, buf, sizeof buf), 5);
    if (t == WTLS_WS_TEXT) CHECK_MEM(buf, "hello", 5);
    wtls_ws_close(ws, 1000, NULL);
}

static void test_ws_subprotocol_negotiated(void) {
    static const char *const protos[] = {"other", "chat", NULL};
    wtls_ws_options o = {0};
    o.url = ws_url(true, "/ws?proto=chat");
    o.subprotocols = protos;
    wtls_ws *ws = NULL;
    CHECK_EQ_INT(wtls_ws_connect(&ws, &o), WTLS_OK);
    if (!ws) return;
    CHECK(wtls_ws_subprotocol(ws) && strcmp(wtls_ws_subprotocol(ws), "chat") == 0);
    wtls_ws_close(ws, 1000, NULL);
    ws = open_ws(true, "/ws"); /* none offered, none chosen */
    if (ws) {
        CHECK(wtls_ws_subprotocol(ws) == NULL);
        wtls_ws_close(ws, 1000, NULL);
    }
}

static void early_case(bool secure) {
    wtls_ws *ws = open_ws(secure, "/ws?early=1");
    if (!ws) return;
    char buf[8];
    int t = 0;
    CHECK_EQ_INT(wtls_ws_recv(ws, &t, buf, sizeof buf), 2); /* sent together with the 101 response */
    if (t == WTLS_WS_TEXT) CHECK_MEM(buf, "hi", 2);
    wtls_ws_close(ws, 1000, NULL);
}

static void test_ws_early_bytes_delivered_wss(void) { early_case(true); }
static void test_ws_early_bytes_delivered_plain(void) { early_case(false); }

static void test_ws_nonblocking_recv_want_read(void) {
    wtls_ws *ws = open_ws(true, "/ws");
    if (!ws) return;
    CHECK_EQ_INT(wtls_ws_set_nonblocking(ws, true), WTLS_OK);
    char buf[16];
    int t = 0;
    CHECK_EQ_INT(wtls_ws_recv(ws, &t, buf, sizeof buf), WTLS_WANT_READ);
    CHECK_EQ_INT(wtls_ws_send(ws, WTLS_WS_TEXT, "x", 1), 1);
    int n = WTLS_WANT_READ;
    for (int i = 0; i < 100 && n == WTLS_WANT_READ; i++) {
        if (!wtls_ws_pending(ws)) wtls_plat_poll(wtls_ws_get_fd(ws), true, false, 50);
        n = wtls_ws_recv(ws, &t, buf, sizeof buf);
    }
    CHECK_EQ_INT(n, 1);
    wtls_ws_close(ws, 1000, NULL);
}

static void test_ws_recv_timeout_keeps_connection(void) {
    wtls_options tls = {0};
    tls.io_timeout_ms = 300;
    wtls_ws_options o = {0};
    o.url = ws_url(true, "/ws");
    o.tls = &tls;
    wtls_ws *ws = NULL;
    CHECK_EQ_INT(wtls_ws_connect(&ws, &o), WTLS_OK);
    if (!ws) return;
    char buf[16];
    int t = 0;
    uint64_t t0 = wtls_plat_now_ms();
    CHECK_EQ_INT(wtls_ws_recv(ws, &t, buf, sizeof buf), WTLS_ERR_TIMEOUT);
    uint64_t dt = wtls_plat_now_ms() - t0;
    CHECK(dt >= 250 && dt < 1500);
    expect_echo(ws, WTLS_WS_TEXT, "later", 5);
    wtls_ws_close(ws, 1000, NULL);
}

static void test_ws_close_handshake_is_prompt(void) {
    wtls_ws *ws = open_ws(true, "/ws");
    if (!ws) return;
    uint64_t t0 = wtls_plat_now_ms();
    wtls_ws_close(ws, 1000, "bye");
    CHECK(wtls_plat_now_ms() - t0 < 900); /* the server echoes the Close at once */
}

static void test_ws_bad_arguments(void) {
    wtls_ws *ws = (wtls_ws *)1;
    wtls_ws_options o = {0};
    CHECK_EQ_INT(wtls_ws_connect(&ws, &o), WTLS_ERR_ARG);
    CHECK(ws == NULL);
    o.url = "http://example.com/";
    CHECK_EQ_INT(wtls_ws_connect(&ws, &o), WTLS_ERR_ARG);
    static const wtls_http_header bad[] = {{"Upgrade", "x"}};
    o.url = ws_url(true, "/ws");
    o.headers = bad;
    o.n_headers = 1;
    CHECK_EQ_INT(wtls_ws_connect(&ws, &o), WTLS_ERR_ARG);
    CHECK_EQ_INT(wtls_ws_send(NULL, WTLS_WS_TEXT, "x", 1), WTLS_ERR_ARG);
    wtls_ws_close(NULL, 0, NULL); /* allowed */
}

void wtls_suite_ws(void) {
    int r = wtls_init();
    CHECK_EQ_INT(r, WTLS_OK);
    if (r != WTLS_OK) return;
    bool trusted = trust_test_ca();
    CHECK(trusted);
    if (!trusted) return;
    RUN(test_ws_echo_text_wss);
    RUN(test_ws_echo_text_plain);
    RUN(test_ws_echo_binary_64k);
    RUN(test_ws_fragmented_reassembled);
    RUN(test_ws_ping_auto_pong);
    RUN(test_ws_server_close_clean);
    RUN(test_ws_bad_accept_rejected);
    RUN(test_ws_masked_server_frame_protocol_error);
    RUN(test_ws_invalid_utf8_1007);
    RUN(test_ws_message_too_big_1009);
    RUN(test_ws_buffer_too_small_keeps_message);
    RUN(test_ws_subprotocol_negotiated);
    RUN(test_ws_early_bytes_delivered_wss);
    RUN(test_ws_early_bytes_delivered_plain);
    RUN(test_ws_nonblocking_recv_want_read);
    RUN(test_ws_recv_timeout_keeps_connection);
    RUN(test_ws_close_handshake_is_prompt);
    RUN(test_ws_bad_arguments);
    wtls_shutdown();
}
