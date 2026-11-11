/* TLS connection tests, run on the host (tests/host/test_tls.c) and on the Wii
 * (suite "tls"). Server: tests/host/tls_test_server.py with --certs; the test CA
 * is fetched over the plain port (command CA) so the Wii needs no file access. */
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <mbedtls/x509.h>
#include <wiitls/wiitls.h>

#include "check.h"
#include "env.h"
#include "plat/plat.h"
#include "wtls_scache.h"

#define PLAIN_PORT 4430
#define P_TLS13_ECDSA 4431
#define P_TLS13_RSA 4432
#define P_TLS12_CHACHA 4433
#define P_EXPIRED 4434
#define P_UNTRUSTED 4435
#define P_WRONGHOST 4436
#define P_CLOSED 4499

static const char *const k_alpn[] = {"http/1.1", NULL};

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

static wtls_conn *open_tls(const char *host, uint16_t port, const wtls_options *opt) {
    wtls_conn *c = (wtls_conn *)1;
    int r = wtls_connect(&c, host, port, opt);
    CHECK_EQ_INT(r, WTLS_OK);
    if (r != WTLS_OK) {
        TLOG("  connect %s:%u -> %s (flags 0x%x)\n", host, port, wtls_strerror(r),
             (unsigned)wtls_last_verify_flags());
        CHECK(c == NULL);
        return NULL;
    }
    return c;
}

static bool send_str(wtls_conn *c, const char *s) {
    int len = (int)strlen(s);
    int r = wtls_write(c, s, (size_t)len);
    CHECK_EQ_INT(r, len);
    return r == len;
}

/* Reads one line (without '\n') into buf; returns its length or a wtls status. */
static int read_line(wtls_conn *c, char *buf, size_t cap) {
    size_t n = 0;
    while (n + 1 < cap) {
        int r = wtls_read(c, buf + n, 1);
        if (r < 0) return r;
        if (buf[n] == '\n') {
            buf[n] = 0;
            return (int)n;
        }
        n++;
    }
    buf[n] = 0;
    return (int)n;
}

static void expect_line(wtls_conn *c, const char *cmd, const char *want) {
    char line[128];
    if (!send_str(c, cmd)) return;
    int r = read_line(c, line, sizeof line);
    CHECK(r >= 0);
    if (r >= 0 && strcmp(line, want) != 0) {
        TLOG("  got \"%s\", want \"%s\"\n", line, want);
        CHECK(strcmp(line, want) == 0);
    }
}

static void expect_cert_error(uint16_t port, uint32_t flag) {
    wtls_conn *c = (wtls_conn *)1;
    CHECK_EQ_INT(wtls_connect(&c, g_env.server_host, port, NULL), WTLS_ERR_CERT);
    CHECK(c == NULL);
    uint32_t flags = wtls_last_verify_flags();
    if (!(flags & flag)) TLOG("  verify flags 0x%x lack 0x%x\n", (unsigned)flags, (unsigned)flag);
    CHECK(flags & flag);
    if (c && c != (wtls_conn *)1) wtls_close(c);
}

/* ---- tests -------------------------------------------------------------- */

static void test_tls13_ecdsa_echo(void) {
    wtls_options o = {0};
    o.alpn = k_alpn;
    wtls_conn *c = open_tls(g_env.server_host, P_TLS13_ECDSA, &o);
    if (!c) return;
    expect_line(c, "PING\n", "PING");
    wtls_conn_info info;
    CHECK_EQ_INT(wtls_get_info(c, &info), WTLS_OK);
    CHECK(strcmp(info.tls_version, "TLSv1.3") == 0);
    CHECK(info.alpn && strcmp(info.alpn, "http/1.1") == 0);
    CHECK(strstr(info.ciphersuite, "CHACHA20-POLY1305") != NULL);
    CHECK(!info.resumed);
    TLOG("  %s %s handshake %u ms\n", info.tls_version, info.ciphersuite, (unsigned)info.handshake_ms);
    wtls_close(c);
}

static void test_tls13_rsa(void) {
    wtls_conn *c = open_tls(g_env.server_host, P_TLS13_RSA, NULL);
    if (!c) return;
    wtls_conn_info info;
    CHECK_EQ_INT(wtls_get_info(c, &info), WTLS_OK);
    CHECK(strcmp(info.tls_version, "TLSv1.3") == 0);
    CHECK(info.alpn == NULL);
    expect_line(c, "PING\n", "PING");
    wtls_close(c);
}

static void test_tls12_chacha(void) {
    wtls_conn *c = open_tls(g_env.server_host, P_TLS12_CHACHA, NULL);
    if (!c) return;
    wtls_conn_info info;
    CHECK_EQ_INT(wtls_get_info(c, &info), WTLS_OK);
    CHECK(strcmp(info.tls_version, "TLSv1.2") == 0);
    CHECK(strstr(info.ciphersuite, "CHACHA20-POLY1305") != NULL);
    expect_line(c, "PING\n", "PING");
    wtls_close(c);
}

static void test_expired_cert(void) { expect_cert_error(P_EXPIRED, MBEDTLS_X509_BADCERT_EXPIRED); }
static void test_untrusted_ca(void) { expect_cert_error(P_UNTRUSTED, MBEDTLS_X509_BADCERT_NOT_TRUSTED); }
static void test_wrong_host(void) { expect_cert_error(P_WRONGHOST, MBEDTLS_X509_BADCERT_CN_MISMATCH); }

static void test_insecure_skip_verify(void) {
    wtls_options o = {0};
    o.insecure_skip_verify = true;
    wtls_conn *c = open_tls(g_env.server_host, P_EXPIRED, &o);
    if (!c) return;
    expect_line(c, "PING\n", "PING");
    wtls_close(c);
}

static void test_big_records(void) {
    enum { N = 65536 };
    wtls_conn *c = open_tls(g_env.server_host, P_TLS13_ECDSA, NULL);
    if (!c) return;
    uint8_t *buf = malloc(N);
    CHECK(buf != NULL);
    if (buf && send_str(c, "BIG 65536\n")) {
        size_t got = 0;
        while (got < N) {
            int r = wtls_read(c, buf + got, N - got);
            if (r <= 0) {
                TLOG("  read after %u bytes: %s\n", (unsigned)got, wtls_strerror(r));
                break;
            }
            got += (size_t)r;
        }
        CHECK_EQ_INT(got, N);
        size_t bad = 0;
        for (size_t i = 0; i < got; i++)
            if (buf[i] != (uint8_t)(i & 0xFF)) bad++;
        CHECK_EQ_INT(bad, 0);
    }
    free(buf);
    wtls_close(c);
}

static void test_clean_close(void) {
    wtls_conn *c = open_tls(g_env.server_host, P_TLS13_ECDSA, NULL);
    if (!c) return;
    char b[16];
    if (send_str(c, "CLOSE\n")) CHECK_EQ_INT(wtls_read(c, b, sizeof b), WTLS_ERR_CLOSED);
    wtls_close(c);
}

static void test_truncation_is_io_error(void) {
    wtls_conn *c = open_tls(g_env.server_host, P_TLS13_ECDSA, NULL);
    if (!c) return;
    char b[16];
    if (send_str(c, "TRUNC\n")) CHECK_EQ_INT(wtls_read(c, b, sizeof b), WTLS_ERR_IO);
    wtls_close(c);
}

static void test_read_timeout(void) {
    wtls_options o = {0};
    o.io_timeout_ms = 300;
    wtls_conn *c = open_tls(g_env.server_host, P_TLS13_ECDSA, &o);
    if (!c) return;
    char b[16];
    if (send_str(c, "SILENT\n")) {
        uint64_t t0 = wtls_plat_now_ms();
        CHECK_EQ_INT(wtls_read(c, b, sizeof b), WTLS_ERR_TIMEOUT);
        uint64_t dt = wtls_plat_now_ms() - t0;
        if (dt < 280 || dt > 1000) TLOG("  timeout took %u ms\n", (unsigned)dt);
        CHECK(dt >= 280 && dt <= 1000);
    }
    wtls_close(c);
}

static void test_connect_refused(void) {
    wtls_conn *c = (wtls_conn *)1;
    CHECK_EQ_INT(wtls_connect(&c, g_env.server_host, P_CLOSED, NULL), WTLS_ERR_CONNECT);
    CHECK(c == NULL);
}

static void test_connect_args(void) {
    wtls_conn *c = (wtls_conn *)1;
    CHECK_EQ_INT(wtls_connect(NULL, "localhost", 1, NULL), WTLS_ERR_ARG);
    CHECK_EQ_INT(wtls_connect(&c, NULL, 1, NULL), WTLS_ERR_ARG);
    CHECK_EQ_INT(wtls_connect(&c, "", 1, NULL), WTLS_ERR_ARG);
    CHECK_EQ_INT(wtls_connect(&c, "localhost", 0, NULL), WTLS_ERR_ARG);
    CHECK(c == NULL);
    char b[4];
    CHECK_EQ_INT(wtls_read(NULL, b, 4), WTLS_ERR_ARG);
    CHECK_EQ_INT(wtls_write(NULL, b, 4), WTLS_ERR_ARG);
    CHECK_EQ_INT(wtls_get_fd(NULL), -1);
    wtls_close(NULL);
}

/* Host only: the cert SANs are DNS:localhost and IP:127.0.0.1. */
static void test_hostname_normalization(void) {
    wtls_conn *c = open_tls("LOCALHOST.", P_TLS13_ECDSA, NULL);
    if (!c) return;
    expect_line(c, "SNI\n", "localhost");
    wtls_close(c);
}

static void test_ip_literal_no_sni(void) {
    wtls_conn *c = open_tls("127.0.0.1", P_TLS13_ECDSA, NULL);
    if (!c) return;
    expect_line(c, "SNI\n", "-");
    wtls_close(c);
}

/* The IP-SAN check must reject a leaf without a matching iPAddress SAN. */
static void test_ip_literal_wrong_san(void) {
    wtls_conn *c = (wtls_conn *)1;
    CHECK_EQ_INT(wtls_connect(&c, "127.0.0.1", P_WRONGHOST, NULL), WTLS_ERR_CERT);
    CHECK(c == NULL);
    CHECK(wtls_last_verify_flags() & MBEDTLS_X509_BADCERT_CN_MISMATCH);
}

static int conns_on_4431(void) {
    wtls_conn *c = open_tls(g_env.server_host, P_TLS13_ECDSA, NULL);
    if (!c) return -1;
    char line[32];
    int n = -1;
    if (send_str(c, "CONNS\n") && read_line(c, line, sizeof line) > 0) n = atoi(line);
    wtls_close(c);
    return n;
}

static void test_connect_refuses_with_bad_clock(void) {
    int before = conns_on_4431();
    wtls_plat_set_unix_time_offset(-30LL * 365 * 86400);
    wtls_conn *c = (wtls_conn *)1;
    CHECK_EQ_INT(wtls_connect(&c, g_env.server_host, P_TLS13_ECDSA, NULL), WTLS_ERR_CLOCK);
    CHECK(c == NULL);
    wtls_plat_set_unix_time_offset(0);
    int after = conns_on_4431();
    /* "after" includes its own connection: exactly one more than "before". */
    CHECK(before > 0);
    CHECK_EQ_INT(after, before + 1);
}

/* Connects to 4431, does one PING (tickets arrive with the first read) and
 * returns info.resumed; -1 on failure. */
static int ping_resumed(bool no_resumption) {
    wtls_options o = {0};
    o.no_resumption = no_resumption;
    wtls_conn *c = open_tls(g_env.server_host, P_TLS13_ECDSA, &o);
    if (!c) return -1;
    expect_line(c, "PING\n", "PING");
    wtls_conn_info info;
    CHECK_EQ_INT(wtls_get_info(c, &info), WTLS_OK);
    TLOG("  resumed=%d handshake %u ms\n", info.resumed, (unsigned)info.handshake_ms);
    wtls_close(c);
    return info.resumed ? 1 : 0;
}

static void test_resumption(void) {
    wtls_scache_clear();
    CHECK_EQ_INT(ping_resumed(false), 0);
    CHECK_EQ_INT(ping_resumed(false), 1);
}

static void test_no_resumption_flag(void) {
    wtls_scache_clear();
    CHECK_EQ_INT(ping_resumed(false), 0);
    CHECK_EQ_INT(ping_resumed(true), 0);
    CHECK_EQ_INT(ping_resumed(false), 1); /* the flag neither used nor dropped the ticket */
}

static void test_ticket_chain(void) {
    wtls_scache_clear();
    CHECK_EQ_INT(ping_resumed(false), 0);
    CHECK_EQ_INT(ping_resumed(false), 1);
    CHECK_EQ_INT(ping_resumed(false), 1); /* ticket stored by the resumed connection */
}

void wtls_suite_tls(void) {
    int r = wtls_init();
    CHECK_EQ_INT(r, WTLS_OK);
    CHECK_EQ_INT(wtls_init(), WTLS_OK); /* second call is a no-op */
    if (r != WTLS_OK) return;
    bool trusted = trust_test_ca();
    CHECK(trusted);
    if (!trusted) {
        TLOG("  cannot fetch the test CA from %s:%d\n", g_env.server_host, PLAIN_PORT);
        return;
    }
    RUN(test_tls13_ecdsa_echo);
    RUN(test_tls13_rsa);
    RUN(test_tls12_chacha);
    RUN(test_expired_cert);
    RUN(test_untrusted_ca);
    RUN(test_wrong_host);
    RUN(test_insecure_skip_verify);
    RUN(test_big_records);
    RUN(test_clean_close);
    RUN(test_truncation_is_io_error);
    RUN(test_read_timeout);
    RUN(test_connect_refused);
    RUN(test_connect_args);
    RUN(test_resumption);
    RUN(test_no_resumption_flag);
    RUN(test_ticket_chain);
    if (!g_env.is_hw) {
        RUN(test_hostname_normalization);
        RUN(test_ip_literal_no_sni);
        RUN(test_ip_literal_wrong_san);
        RUN(test_connect_refuses_with_bad_clock);
    } else {
        TLOG("SKIP host-only tests (hostname normalization, IP literal, bad clock)\n");
    }
    wtls_shutdown();
}
