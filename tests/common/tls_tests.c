/* TLS connection tests, run on the host (tests/host/test_tls.c) and on the Wii
 * (suite "tls"). Server: tests/host/tls_test_server.py with --certs; the test CA
 * is fetched over the plain port (command CA) so the Wii needs no file access. */
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <mbedtls/x509.h>
#include <wiitls/wiitls.h>

#include "check.h"
#include "env.h"
#include "plat/plat.h"
#include "wtls_prof.h"
#include "wtls_scache.h"

#define PLAIN_PORT 4430
#define P_TLS13_ECDSA 4431
#define P_TLS13_RSA 4432
#define P_TLS12_CHACHA 4433
#define P_EXPIRED 4434
#define P_UNTRUSTED 4435
#define P_WRONGHOST 4436
#define P_BAD_EKU 4437
#define P_MTLS 4441
#define P_MTLS12 4443
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
/* Rejected by the key-usage check, not by chain verification: still a CERT error. */
static void test_bad_eku(void) { expect_cert_error(P_BAD_EKU, MBEDTLS_X509_BADCERT_EXT_KEY_USAGE); }

static void test_insecure_skip_verify(void) {
    wtls_options o = {0};
    o.insecure_skip_verify = true;
    wtls_conn *c = open_tls(g_env.server_host, P_EXPIRED, &o);
    if (!c) return;
    expect_line(c, "PING\n", "PING");
    wtls_close(c);
}

/* A ticket from an unverified connection must never let a later verified
 * connection to the same host:port skip certificate verification. */
static void test_insecure_ticket_not_reused(void) {
    wtls_scache_clear();
    wtls_options o = {0};
    o.insecure_skip_verify = true;
    wtls_conn *c = open_tls(g_env.server_host, P_EXPIRED, &o);
    if (!c) return;
    expect_line(c, "PING\n", "PING"); /* the server's ticket arrives with the reply */
    wtls_close(c);
    expect_cert_error(P_EXPIRED, MBEDTLS_X509_BADCERT_EXPIRED);
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

/* "host." is the same name as "host"; "host.." is not a valid name at all. */
static void test_host_extra_dots_rejected(void) {
    wtls_conn *c = (wtls_conn *)1;
    CHECK_EQ_INT(wtls_connect(&c, "localhost..", P_TLS13_ECDSA, NULL), WTLS_ERR_ARG);
    CHECK(c == NULL);
    CHECK_EQ_INT(wtls_connect(&c, ".", P_TLS13_ECDSA, NULL), WTLS_ERR_ARG);
}

/* IPv4 literal of the test server: on the Wii server_host already is one. */
static const char *server_ip_literal(void) { return g_env.is_hw ? g_env.server_host : "127.0.0.1"; }

static void test_ip_literal_no_sni(void) {
    wtls_conn *c = open_tls(server_ip_literal(), P_TLS13_ECDSA, NULL);
    if (!c) return;
    expect_line(c, "SNI\n", "-");
    wtls_close(c);
}

/* The IP-SAN check must reject a leaf without a matching iPAddress SAN. */
static void test_ip_literal_wrong_san(void) {
    wtls_conn *c = (wtls_conn *)1;
    CHECK_EQ_INT(wtls_connect(&c, server_ip_literal(), P_WRONGHOST, NULL), WTLS_ERR_CERT);
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
    /* Keep the current offset: on the Wii it may come from an earlier SNTP sync. */
    int64_t saved = wtls_plat_unix_time() - (int64_t)time(NULL);
    wtls_plat_set_unix_time_offset(saved - 30LL * 365 * 86400);
    wtls_conn *c = (wtls_conn *)1;
    CHECK_EQ_INT(wtls_connect(&c, g_env.server_host, P_TLS13_ECDSA, NULL), WTLS_ERR_CLOCK);
    CHECK(c == NULL);
    wtls_plat_set_unix_time_offset(saved);
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

/* wtls_prof_last splits the last handshake into connect, setup and one entry
 * per handshake state; the parts fit inside the caller's wall time. */
static void check_profile(uint64_t wall_us) {
    const wtls_prof *p = &wtls_prof_last;
    uint64_t steps = 0, step_io = 0;
    uint32_t n = 0;
    for (int i = 0; i < WTLS_PROF_STATES; i++) {
        steps += p->step_us[i];
        step_io += p->step_io_us[i];
        n += p->step_n[i];
        CHECK(p->step_io_us[i] <= p->step_us[i]);
    }
    CHECK(n >= 5);                     /* ClientHello ... Finished */
    CHECK(p->io_calls >= 2);           /* at least one send and one recv */
    CHECK_EQ_INT(step_io, p->io_us);   /* every handshake IPC happens inside a step */
    CHECK_EQ_INT(p->send_calls + p->recv_calls + p->recv_empty_calls, p->io_calls);
    CHECK_EQ_INT(p->send_us + p->recv_us + p->recv_empty_us, p->io_us);
    CHECK(p->send_calls >= 1 && p->recv_calls >= 1);
    CHECK(p->connect_wait_us <= p->connect_us);
    CHECK(p->connect_us + p->setup_us + steps + p->wait_us <= wall_us + 1000); /* clock granularity */
}

static void test_handshake_profile(void) {
    wtls_options o = {0};
    o.no_resumption = true;
    memset(&wtls_prof_last, 0, sizeof wtls_prof_last);
    uint64_t t0 = wtls_plat_now_us();
    wtls_conn *c = open_tls(g_env.server_host, P_TLS13_ECDSA, &o);
    uint64_t wall = wtls_plat_now_us() - t0;
    if (!c) return;
    check_profile(wall);
    wtls_close(c);
    /* Resumed: the profile is rewritten, not added to. */
    wtls_scache_clear();
    CHECK_EQ_INT(ping_resumed(false), 0);
    t0 = wtls_plat_now_us();
    c = open_tls(g_env.server_host, P_TLS13_ECDSA, NULL);
    wall = wtls_plat_now_us() - t0;
    if (!c) return;
    wtls_conn_info info;
    CHECK_EQ_INT(wtls_get_info(c, &info), WTLS_OK);
    CHECK(info.resumed);
    check_profile(wall);
    wtls_close(c);
}

static void test_nonblocking_read_wants_read(void) {
    wtls_conn *c = open_tls(g_env.server_host, P_TLS13_ECDSA, NULL);
    if (!c) return;
    expect_line(c, "PING\n", "PING"); /* tickets consumed, connection idle */
    CHECK_EQ_INT(wtls_set_nonblocking(c, true), WTLS_OK);
    char b[16];
    uint64_t t0 = wtls_plat_now_ms();
    CHECK_EQ_INT(wtls_read(c, b, sizeof b), WTLS_WANT_READ);
    CHECK(wtls_plat_now_ms() - t0 < 50);
    wtls_close(c);
}

static void test_nonblocking_poll_then_read(void) {
    wtls_conn *c = open_tls(g_env.server_host, P_TLS13_ECDSA, NULL);
    if (!c) return;
    expect_line(c, "PING\n", "PING");
    CHECK_EQ_INT(wtls_set_nonblocking(c, true), WTLS_OK);
    CHECK_EQ_INT(wtls_write(c, "PING\n", 5), 5);
    char b[16];
    size_t got = 0;
    uint64_t deadline = wtls_plat_now_ms() + 1000;
    while (got < 5 && wtls_plat_now_ms() < deadline) {
        int r = wtls_read(c, b + got, sizeof b - got);
        if (r > 0) got += (size_t)r;
        else if (r == WTLS_WANT_READ) wtls_plat_poll(wtls_get_fd(c), true, false, 100);
        else break;
    }
    CHECK_EQ_INT(got, 5);
    CHECK_MEM(b, "PING\n", 5);
    wtls_close(c);
}

static void test_pending_counts_buffered(void) {
    wtls_conn *c = open_tls(g_env.server_host, P_TLS13_ECDSA, NULL);
    if (!c) return;
    expect_line(c, "PING\n", "PING");
    char b[10];
    if (send_str(c, "BIG 100\n")) {
        CHECK_EQ_INT(wtls_read(c, b, sizeof b), 10);
        CHECK_EQ_INT(wtls_pending(c), 90);
    }
    wtls_close(c);
}

static void test_set_nonblocking_null_is_arg_error(void) {
    CHECK_EQ_INT(wtls_set_nonblocking(NULL, true), WTLS_ERR_ARG);
    CHECK_EQ_INT(wtls_pending(NULL), 0);
}

/* ---- mutual TLS (client certificates, WP3) --------------------------------- */

/* Fetches an artifact (CA/CLIENTCERT/CLIENTKEY) from the server's plain port:
 * "<len>\n" followed by that many bytes. NULL on failure. */
static uint8_t *plain_fetch(const char *cmd, size_t *len) {
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

/* Loads a test client credential: cert and key fetched over the plain port,
 * so the Wii needs no file access either. The key is PEM: it is fetched with
 * its terminating NUL included, as the API requires. */
static wtls_client_cred *client_cred(const char *name) {
    char cmd[40];
    size_t clen = 0, klen = 0;
    snprintf(cmd, sizeof cmd, "CLIENTCERT %s", name);
    uint8_t *cert = plain_fetch(cmd, &clen);
    snprintf(cmd, sizeof cmd, "CLIENTKEY %s", name);
    uint8_t *key0 = plain_fetch(cmd, &klen);
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

static void test_mtls_connect_ecdsa(void) {
    wtls_client_cred *cred = client_cred("client-ec");
    CHECK(cred);
    if (!cred) return;
    wtls_options opt = {0};
    opt.client_cred = cred;
    wtls_conn *c = open_tls(g_env.server_host, P_MTLS, &opt);
    if (c) {
        expect_line(c, "PING\n", "PING");
        wtls_close(c);
    }
    wtls_client_cred_free(cred);
}

static void test_mtls_connect_rsa_tls12(void) {
    wtls_client_cred *cred = client_cred("client-rsa");
    CHECK(cred);
    if (!cred) return;
    wtls_options opt = {0};
    opt.client_cred = cred;
    wtls_conn *c = open_tls(g_env.server_host, P_MTLS12, &opt);
    if (c) {
        wtls_conn_info info;
        wtls_get_info(c, &info);
        CHECK(info.tls_version && strcmp(info.tls_version, "TLSv1.2") == 0);
        expect_line(c, "PING\n", "PING");
        wtls_close(c);
    }
    wtls_client_cred_free(cred);
}

/* A server that rejects our client identity aborts somewhere around the
 * client's last flight: in TLS 1.3 that can be only after it, so the
 * connect itself may look successful - the abort then surfaces on the
 * first write or read. Either way, no application data must flow. */
static void check_no_dataflow(int st, wtls_conn *c) {
    if (st == WTLS_OK) {
        int w = wtls_write(c, "PING\n", 5);
        if (w == 5) {
            char buf[8];
            CHECK(wtls_read(c, buf, sizeof buf) < 0);
        } else {
            CHECK(w < 0); /* the server aborted right after "accepting" */
        }
        wtls_close(c);
    } else {
        CHECK(st == WTLS_ERR_HANDSHAKE || st == WTLS_ERR_IO || st == WTLS_ERR_CERT);
        CHECK(c == NULL);
    }
}

static void test_mtls_missing_cert_rejected(void) {
    wtls_conn *c = (wtls_conn *)1;
    int st = wtls_connect(&c, g_env.server_host, P_MTLS, NULL);
    check_no_dataflow(st, c);
}

static void test_mtls_untrusted_client_rejected(void) {
    wtls_client_cred *cred = client_cred("client-untrusted");
    CHECK(cred);
    if (!cred) return;
    wtls_options opt = {0};
    opt.client_cred = cred;
    wtls_conn *c = (wtls_conn *)1;
    int st = wtls_connect(&c, g_env.server_host, P_MTLS, &opt);
    check_no_dataflow(st, c);
    wtls_client_cred_free(cred);
}

static void test_mtls_cert_key_mismatch(void) {
    size_t clen = 0, klen = 0;
    uint8_t *cert = plain_fetch("CLIENTCERT client-ec", &clen);
    uint8_t *key0 = plain_fetch("CLIENTKEY client-rsa", &klen);
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
    CHECK(cert && key);
    if (!cert || !key) {
        free(cert);
        free(key);
        return;
    }
    wtls_client_cred *cred = (wtls_client_cred *)1;
    CHECK_EQ_INT(wtls_client_cred_load(&cred, cert, clen, key, klen), WTLS_ERR_ARG);
    CHECK(cred == NULL);
    CHECK_EQ_INT(wtls_client_cred_load(NULL, cert, clen, key, klen), WTLS_ERR_ARG);
    CHECK_EQ_INT(wtls_client_cred_load(&cred, NULL, 0, key, klen), WTLS_ERR_ARG);
    wtls_client_cred_free(NULL); /* NULL is safe */
    free(cert);
    free(key);
}

/* The application may free the credential while a connection still uses it:
 * the connection holds its own reference. */
static void test_mtls_free_while_connected(void) {
    wtls_client_cred *cred = client_cred("client-ec");
    CHECK(cred);
    if (!cred) return;
    wtls_options opt = {0};
    opt.client_cred = cred;
    wtls_conn *c = open_tls(g_env.server_host, P_MTLS, &opt);
    wtls_client_cred_free(cred); /* drops the application's reference */
    if (c) {
        expect_line(c, "PING\n", "PING");
        wtls_close(c); /* releases the connection's reference: destroyed here */
    }
}

/* Session tickets of an mTLS connection are keyed by the client identity:
 * a different credential never resumes them. */
static void test_mtls_resumption_isolated(void) {
    wtls_client_cred *a = client_cred("client-ec");
    wtls_client_cred *b = client_cred("client-rsa");
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

    wtls_conn *c = open_tls(g_env.server_host, P_MTLS, &oa); /* stores ticket(a) */
    if (c) {
        expect_line(c, "PING\n", "PING");
        wtls_close(c);
    }
    wtls_conn *d = open_tls(g_env.server_host, P_MTLS, &ob); /* b must not resume a */
    if (d) {
        wtls_conn_info info;
        wtls_get_info(d, &info);
        CHECK(!info.resumed);
        expect_line(d, "PING\n", "PING");
        wtls_close(d);
    }
    wtls_conn *e = open_tls(g_env.server_host, P_MTLS, &oa); /* a's own ticket: resumed */
    if (e) {
        wtls_conn_info info;
        wtls_get_info(e, &info);
        CHECK(info.resumed);
        wtls_close(e);
    }
    wtls_client_cred_free(b);
    wtls_client_cred_free(a);
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
    RUN(test_bad_eku);
    RUN(test_insecure_skip_verify);
    RUN(test_insecure_ticket_not_reused);
    RUN(test_big_records);
    RUN(test_clean_close);
    RUN(test_truncation_is_io_error);
    RUN(test_read_timeout);
    RUN(test_connect_refused);
    RUN(test_connect_args);
    RUN(test_resumption);
    RUN(test_no_resumption_flag);
    RUN(test_ticket_chain);
    RUN(test_handshake_profile);
    RUN(test_nonblocking_read_wants_read);
    RUN(test_nonblocking_poll_then_read);
    RUN(test_pending_counts_buffered);
    RUN(test_set_nonblocking_null_is_arg_error);
    RUN(test_host_extra_dots_rejected);
    RUN(test_ip_literal_no_sni);
    RUN(test_ip_literal_wrong_san);
    RUN(test_connect_refuses_with_bad_clock);
    RUN(test_mtls_connect_ecdsa);
    RUN(test_mtls_connect_rsa_tls12);
    RUN(test_mtls_missing_cert_rejected);
    RUN(test_mtls_untrusted_client_rejected);
    RUN(test_mtls_cert_key_mismatch);
    RUN(test_mtls_free_while_connected);
    RUN(test_mtls_resumption_isolated);
    if (!g_env.is_hw) RUN(test_hostname_normalization); /* needs the name "localhost" */
    else TLOG("SKIP host-only test_hostname_normalization\n");
    wtls_shutdown();
}
