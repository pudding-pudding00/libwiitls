/* Suite "realworld" (hardware only): TLS against real Internet servers.
 * Needs Internet access from the Wii; the PC test server is not used.
 *
 * badssl.com is a third-party test service. When it is unreachable, or its own
 * certificate on the TLS 1.2 port has lapsed, the affected tests report SKIP
 * with the reason instead of passing. A badssl host whose bad certificate is
 * ACCEPTED is always a FAIL. */
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <mbedtls/x509.h>
#include <wiitls/wiitls.h>

#include "check.h"
#include "env.h"
#include "suites.h"

static const char *const k_alpn[] = {"http/1.1", NULL};
static bool s_clock_synced;

/* Errors that say "the remote service is not there", not "TLS is wrong". */
static bool unreachable(int r) {
    return r == WTLS_ERR_DNS || r == WTLS_ERR_CONNECT || r == WTLS_ERR_TIMEOUT;
}

/* wtls_connect, with one SNTP sync and retry when the Wii clock is not plausible. */
static int rw_connect(wtls_conn **c, const char *host, uint16_t port) {
    wtls_options opt = {0};
    opt.alpn = k_alpn;
    int r = wtls_connect(c, host, port, &opt);
    if (r == WTLS_ERR_CLOCK && !s_clock_synced) {
        TLOG("    clock not plausible, syncing via SNTP\n");
        int s = wtls_time_sync_sntp(NULL, 3000);
        TLOG("    sntp -> %s\n", wtls_strerror(s));
        s_clock_synced = s == WTLS_OK;
        if (s_clock_synced) r = wtls_connect(c, host, port, &opt);
    }
    if (r != WTLS_OK)
        TLOG("    connect %s:%u -> %s (verify flags 0x%x)\n", host, port, wtls_strerror(r),
             (unsigned)wtls_last_verify_flags());
    return r;
}

/* Sends GET / and reads the whole response (Connection: close). Reading to the
 * end also captures TLS 1.3 session tickets, which arrive after the handshake.
 * true if the response starts with "HTTP/1.1 ". */
static bool rw_get(wtls_conn *c, const char *host) {
    char req[320];
    int n = snprintf(req, sizeof req,
                     "GET / HTTP/1.1\r\nHost: %s\r\nUser-Agent: libwiitls-hwtest\r\n"
                     "Accept: */*\r\nConnection: close\r\n\r\n",
                     host);
    if (n <= 0 || (size_t)n >= sizeof req) return false;
    int w = wtls_write(c, req, (size_t)n);
    CHECK_EQ_INT(w, n);
    if (w != n) return false;

    char head[16] = {0};
    size_t got = 0, total = 0;
    uint8_t buf[2048];
    for (;;) {
        int r = wtls_read(c, buf, sizeof buf);
        if (r > 0) {
            for (int i = 0; i < r && got < sizeof head - 1; i++) head[got++] = (char)buf[i];
            total += (size_t)r;
            if (total > 512 * 1024) break; /* enough; the status line is what matters */
            continue;
        }
        /* Servers end with close_notify (CLOSED) or, less politely, a TCP close (IO). */
        if (r != WTLS_ERR_CLOSED && r != WTLS_ERR_IO) TLOG("    read -> %s\n", wtls_strerror(r));
        break;
    }
    TLOG("    response: %u bytes, starts \"%.9s\"\n", (unsigned)total, head);
    return got >= 9 && memcmp(head, "HTTP/1.1 ", 9) == 0;
}

static void log_info(const wtls_conn *c, wtls_conn_info *info) {
    memset(info, 0, sizeof *info);
    CHECK_EQ_INT(wtls_get_info(c, info), WTLS_OK);
    TLOG("    %s %s alpn=%s resumed=%s handshake=%u ms\n", info->tls_version ? info->tls_version : "?",
         info->ciphersuite ? info->ciphersuite : "?", info->alpn ? info->alpn : "-",
         info->resumed ? "yes" : "no", (unsigned)info->handshake_ms);
}

/* Full GET against host:port; expects the given TLS version. */
static void rw_expect_version(const char *host, uint16_t port, const char *version) {
    wtls_conn *c = NULL;
    int r = rw_connect(&c, host, port);
    CHECK_EQ_INT(r, WTLS_OK);
    if (r != WTLS_OK) return;
    wtls_conn_info info;
    log_info(c, &info);
    CHECK(info.tls_version && strcmp(info.tls_version, version) == 0);
    CHECK(rw_get(c, host));
    wtls_close(c);
}

static void rw_example_com_tls13(void) { rw_expect_version("example.com", 443, "TLSv1.3"); }
static void rw_google_tls13(void) { rw_expect_version("www.google.com", 443, "TLSv1.3"); }
static void rw_cloudflare_tls13(void) { rw_expect_version("www.cloudflare.com", 443, "TLSv1.3"); }

static void rw_tls12_only(void) {
    const char *host = "tls-v1-2.badssl.com";
    wtls_conn *c = NULL;
    int r = rw_connect(&c, host, 1012);
    if (unreachable(r)) {
        SKIP("badssl.com unreachable");
        return;
    }
    if (r == WTLS_ERR_CERT && (wtls_last_verify_flags() & MBEDTLS_X509_BADCERT_EXPIRED)) {
        SKIP("badssl.com's own certificate on port 1012 has expired");
        return;
    }
    CHECK_EQ_INT(r, WTLS_OK);
    if (r != WTLS_OK) return;
    wtls_conn_info info;
    log_info(c, &info);
    CHECK(info.tls_version && strcmp(info.tls_version, "TLSv1.2") == 0);
    CHECK(rw_get(c, host));
    wtls_close(c);
}

/* A host whose certificate must be rejected. */
static void rw_expect_cert_error(const char *host, uint32_t expected_flag) {
    wtls_conn *c = (wtls_conn *)1;
    int r = rw_connect(&c, host, 443);
    if (unreachable(r)) {
        SKIP("badssl.com unreachable");
        return;
    }
    CHECK_EQ_INT(r, WTLS_ERR_CERT);
    CHECK(c == NULL);
    CHECK((wtls_last_verify_flags() & expected_flag) != 0);
    if (r == WTLS_OK) wtls_close(c);
}

static void rw_expired(void) {
    rw_expect_cert_error("expired.badssl.com", MBEDTLS_X509_BADCERT_EXPIRED);
}

static void rw_wrong_host(void) {
    rw_expect_cert_error("wrong.host.badssl.com", MBEDTLS_X509_BADCERT_CN_MISMATCH);
}

static void rw_resumption_example_com(void) {
    const char *host = "example.com";
    for (int i = 0; i < 2; i++) {
        wtls_conn *c = NULL;
        int r = rw_connect(&c, host, 443);
        CHECK_EQ_INT(r, WTLS_OK);
        if (r != WTLS_OK) return;
        wtls_conn_info info;
        log_info(c, &info);
        CHECK(info.resumed == (i == 1));
        CHECK(rw_get(c, host));
        wtls_close(c);
    }
}

void wtls_suite_realworld(void) {
    int r = wtls_init();
    CHECK_EQ_INT(r, WTLS_OK);
    if (r != WTLS_OK) return;
    RUN(rw_example_com_tls13);
    RUN(rw_google_tls13);
    RUN(rw_cloudflare_tls13);
    RUN(rw_tls12_only);
    RUN(rw_expired);
    RUN(rw_wrong_host);
    RUN(rw_resumption_example_com);
    wtls_shutdown();
}
