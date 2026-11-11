/* Platform socket layer tests, run on the host (tests/host/test_plat.c) and on
 * the Wii (suite "plat"). Server: tests/host/tls_test_server.py, plain echo on 4430. */
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <wiitls/wiitls.h>

#include "check.h"
#include "env.h"
#include "plat/plat.h"

#define ECHO_PORT 4430
#define CLOSED_PORT 4499
#define BIG_LEN 65536

static uint32_t server_ip(void) {
    uint32_t ip = 0;
    CHECK_EQ_INT(wtls_plat_resolve(g_env.server_host, &ip), WTLS_OK);
    return ip;
}

static int connect_echo(void) {
    int fd = -1;
    int r = wtls_plat_connect(server_ip(), ECHO_PORT, 3000, &fd);
    CHECK_EQ_INT(r, WTLS_OK);
    return r == WTLS_OK ? fd : -1;
}

static bool send_str(int fd, const char *s) {
    size_t len = strlen(s), off = 0;
    uint64_t deadline = wtls_plat_now_ms() + 3000;
    while (off < len && wtls_plat_now_ms() < deadline) {
        int r = wtls_plat_send(fd, (const uint8_t *)s + off, len - off);
        if (r > 0) off += (size_t)r;
        else if (r == WTLS_WANT_WRITE) wtls_plat_poll(fd, false, true, 100);
        else return false;
    }
    return off == len;
}

/* Reads exactly len bytes (poll + recv), 5 s budget. Returns bytes read. */
static size_t recv_exact(int fd, uint8_t *buf, size_t len) {
    size_t off = 0;
    uint64_t deadline = wtls_plat_now_ms() + 5000;
    while (off < len && wtls_plat_now_ms() < deadline) {
        int r = wtls_plat_recv(fd, buf + off, len - off);
        if (r > 0) off += (size_t)r;
        else if (r == WTLS_WANT_READ) wtls_plat_poll(fd, true, false, 100);
        else break;
    }
    return off;
}

static void test_echo_roundtrip(void) {
    int fd = connect_echo();
    if (fd < 0) return;
    CHECK(send_str(fd, "hello\n"));
    char buf[6];
    CHECK_EQ_INT(recv_exact(fd, (uint8_t *)buf, 6), 6);
    CHECK_MEM(buf, "hello\n", 6);
    wtls_plat_close(fd);
}

static void test_recv_without_data_wants_read(void) {
    int fd = connect_echo();
    if (fd < 0) return;
    uint8_t b[16];
    CHECK_EQ_INT(wtls_plat_recv(fd, b, sizeof b), WTLS_WANT_READ);
    wtls_plat_close(fd);
}

static void test_poll_timeout_duration(void) {
    int fd = connect_echo();
    if (fd < 0) return;
    CHECK(send_str(fd, "SILENT\n"));
    uint64_t t0 = wtls_plat_now_ms();
    CHECK_EQ_INT(wtls_plat_poll(fd, true, false, 100), 0);
    uint64_t dt = wtls_plat_now_ms() - t0;
    TLOG("    poll(100) took %u ms\n", (unsigned)dt);
    CHECK(dt >= 90 && dt <= 400);
    wtls_plat_close(fd);
}

static void test_eof_after_bye(void) {
    int fd = connect_echo();
    if (fd < 0) return;
    CHECK(send_str(fd, "BYE\n"));
    int r = WTLS_WANT_READ;
    uint64_t deadline = wtls_plat_now_ms() + 3000;
    while (r == WTLS_WANT_READ && wtls_plat_now_ms() < deadline) {
        wtls_plat_poll(fd, true, false, 100);
        uint8_t b[16];
        r = wtls_plat_recv(fd, b, sizeof b);
    }
    CHECK_EQ_INT(r, 0);
    wtls_plat_close(fd);
}

static void test_connect_refused(void) {
    int fd = -1;
    uint64_t t0 = wtls_plat_now_ms();
    CHECK_EQ_INT(wtls_plat_connect(server_ip(), CLOSED_PORT, 5000, &fd), WTLS_ERR_CONNECT);
    TLOG("    refused after %u ms\n", (unsigned)(wtls_plat_now_ms() - t0));
    CHECK_EQ_INT(fd, -1);
}

static void test_resolve_localhost(void) {
    uint32_t ip = 0;
    CHECK_EQ_INT(wtls_plat_resolve("localhost", &ip), WTLS_OK);
    const uint8_t *b = (const uint8_t *)&ip;
    CHECK(b[0] == 127 && b[1] == 0 && b[2] == 0 && b[3] == 1);
}

static void test_resolve_ip_literal_and_garbage(void) {
    uint32_t ip = 0;
    CHECK_EQ_INT(wtls_plat_resolve("10.1.2.3", &ip), WTLS_OK);
    const uint8_t *b = (const uint8_t *)&ip;
    CHECK(b[0] == 10 && b[1] == 1 && b[2] == 2 && b[3] == 3);
    CHECK_EQ_INT(wtls_plat_resolve("no-such-host.invalid", &ip), WTLS_ERR_DNS);
    CHECK_EQ_INT(wtls_plat_resolve("", &ip), WTLS_ERR_DNS);
}

/* 4 connections, each streaming 64 KiB, received round-robin: exercises the
 * shared IOS IPC heap (-22 retry) on the Wii. */
static void hw_four_parallel_connections(void) {
    enum { N = 4 };
    int fd[N];
    uint8_t *buf[N];
    size_t got[N];
    for (int i = 0; i < N; i++) {
        fd[i] = connect_echo();
        buf[i] = malloc(BIG_LEN);
        got[i] = 0;
        CHECK(fd[i] >= 0 && buf[i] != NULL);
    }
    for (int i = 0; i < N; i++)
        if (fd[i] >= 0) CHECK(send_str(fd[i], "BIG 65536\n"));
    uint64_t deadline = wtls_plat_now_ms() + 20000;
    bool all = false;
    while (!all && wtls_plat_now_ms() < deadline) {
        all = true;
        for (int i = 0; i < N; i++) {
            if (fd[i] < 0 || !buf[i] || got[i] == BIG_LEN) continue;
            all = false;
            int r = wtls_plat_recv(fd[i], buf[i] + got[i], BIG_LEN - got[i]);
            if (r > 0) got[i] += (size_t)r;
            else if (r == WTLS_WANT_READ) wtls_plat_poll(fd[i], true, false, 5);
            else {
                TLOG("    conn %d: recv %d at %u\n", i, r, (unsigned)got[i]);
                fd[i] = (wtls_plat_close(fd[i]), -1);
            }
        }
    }
    for (int i = 0; i < N; i++) {
        CHECK_EQ_INT(got[i], BIG_LEN);
        bool ok = buf[i] != NULL;
        for (size_t k = 0; ok && k < got[i]; k++) ok = buf[i][k] == (uint8_t)(k % 251);
        CHECK(ok);
        if (fd[i] >= 0) wtls_plat_close(fd[i]);
        free(buf[i]);
    }
}

void wtls_suite_plat(void) {
    CHECK_EQ_INT(wtls_plat_init(), WTLS_OK);
    RUN(test_echo_roundtrip);
    RUN(test_recv_without_data_wants_read);
    RUN(test_poll_timeout_duration);
    RUN(test_eof_after_bye);
    RUN(test_connect_refused);
    RUN(test_resolve_ip_literal_and_garbage);
    if (!g_env.is_hw) RUN(test_resolve_localhost);
    RUN(hw_four_parallel_connections);
}
