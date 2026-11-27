/* wtls_http_download() tests, host only (they write files in the working
 * directory). Server: tests/host/tls_test_server.py, route /file. */
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <wiitls/http.h>
#include <wiitls/sig.h>
#include <wiitls/wiitls.h>

#include "check.h"
#include "env.h"
#include "plat/plat.h"
#include "sig_vectors.inc"
#include "sig_vectors_pattern.inc"

#define PLAIN_PORT 4430
#define P_HTTP 4438
#define OUT "wtls_dl_test.bin"

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

/* ---- helpers ------------------------------------------------------------ */

static const char *url_of(const char *query) {
    static char b[4][300];
    static unsigned next;
    char *u = b[next++ % 4];
    snprintf(u, sizeof b[0], "https://%s:%u/file?%s", g_env.server_host, (unsigned)P_HTTP, query);
    return u;
}

static void pattern(uint8_t *p, size_t n) {
    for (size_t i = 0; i < n; i++) p[i] = (uint8_t)(i % 251);
}

static void sha_of_pattern(size_t n, uint8_t out[32]) {
    uint8_t *p = malloc(n);
    pattern(p, n);
    wtls_sha256_ctx c;
    CHECK_EQ_INT(wtls_sha256_init(&c), WTLS_OK);
    CHECK_EQ_INT(wtls_sha256_update(&c, p, n), WTLS_OK);
    CHECK_EQ_INT(wtls_sha256_finish(&c, out), WTLS_OK);
    free(p);
}

static bool file_exists(const char *p) {
    FILE *f = fopen(p, "rb");
    if (f) fclose(f);
    return f != NULL;
}

static long file_size(const char *p) {
    FILE *f = fopen(p, "rb");
    if (!f) return -1;
    fseek(f, 0, SEEK_END);
    long n = ftell(f);
    fclose(f);
    return n;
}

static void write_file(const char *p, const void *data, size_t n) {
    FILE *f = fopen(p, "wb");
    CHECK(f != NULL);
    if (!f) return;
    if (n) fwrite(data, 1, n, f);
    fclose(f);
}

/* true if the file holds exactly the first n pattern bytes. */
static bool file_is_pattern(const char *p, size_t n) {
    FILE *f = fopen(p, "rb");
    if (!f) return false;
    bool ok = true;
    for (size_t i = 0; i < n && ok; i++) {
        int c = fgetc(f);
        ok = c == (int)(i % 251);
    }
    ok = ok && fgetc(f) == EOF;
    fclose(f);
    return ok;
}

static void cleanup(void) {
    remove(OUT);
    remove(OUT ".part");
    remove(OUT ".part.meta");
    remove(OUT ".old");
}

static void write_meta(const char *url, const char *etag) {
    FILE *f = fopen(OUT ".part.meta", "wb");
    CHECK(f != NULL);
    if (!f) return;
    fprintf(f, "WTLSDL1\n%s\n%s\n-\n", url, etag);
    fclose(f);
}

static int dl(const char *url, const wtls_http_download_opts *o, wtls_http_download_result *r) {
    wtls_http_request req = {0};
    req.url = url;
    return wtls_http_download(&req, OUT, o, r);
}

/* ---- tests -------------------------------------------------------------- */

static void test_download_fresh_ok_sha256(void) {
    cleanup();
    uint8_t want[32];
    sha_of_pattern(100000, want);
    wtls_http_download_opts o = {0};
    o.sha256 = want;
    wtls_http_download_result r;
    CHECK_EQ_INT(dl(url_of("n=100000"), &o, &r), WTLS_OK);
    CHECK_EQ_INT(r.status, 200);
    CHECK_EQ_INT((long)r.size, 100000);
    CHECK_EQ_INT((long)r.resumed_from, 0);
    CHECK_MEM(r.sha256, want, 32);
    CHECK(file_is_pattern(OUT, 100000));
    CHECK(!file_exists(OUT ".part") && !file_exists(OUT ".part.meta") && !file_exists(OUT ".old"));
    cleanup();
}

static void test_download_cut_then_resume(void) {
    cleanup();
    const char *u = url_of("n=100000&cut=40000&once=resume1");
    wtls_http_download_result r;
    CHECK_EQ_INT(dl(u, NULL, &r), WTLS_ERR_IO);
    long part = file_size(OUT ".part");
    CHECK(part > 0 && part <= 40000);
    CHECK(!file_exists(OUT));
    uint8_t want[32];
    sha_of_pattern(100000, want);
    wtls_http_download_opts o = {0};
    o.sha256 = want;
    CHECK_EQ_INT(dl(u, &o, &r), WTLS_OK);
    CHECK_EQ_INT(r.status, 206);
    CHECK_EQ_INT((long)r.resumed_from, part);
    CHECK_EQ_INT((long)r.size, 100000);
    CHECK(file_is_pattern(OUT, 100000));
    CHECK(!file_exists(OUT ".part") && !file_exists(OUT ".part.meta"));
    cleanup();
}

static void test_download_resume_etag_changed_restarts(void) {
    cleanup();
    const char *u = url_of("n=60000&cut=20000&once=etag1&etag=v1&etag2=v2");
    wtls_http_download_result r;
    CHECK_EQ_INT(dl(u, NULL, &r), WTLS_ERR_IO);
    CHECK(file_size(OUT ".part") > 0);
    CHECK_EQ_INT(dl(u, NULL, &r), WTLS_OK); /* If-Range "v1" no longer matches: 200 with the new file */
    CHECK_EQ_INT(r.status, 200);
    CHECK_EQ_INT((long)r.resumed_from, 0);
    CHECK(file_is_pattern(OUT, 60000));
    cleanup();
}

static void test_download_server_ignores_range_restarts(void) {
    cleanup();
    const char *u = url_of("n=50000&cut=15000&once=norange1&ranges=0");
    wtls_http_download_result r;
    CHECK_EQ_INT(dl(u, NULL, &r), WTLS_ERR_IO);
    CHECK_EQ_INT(dl(u, NULL, &r), WTLS_OK);
    CHECK_EQ_INT(r.status, 200);
    CHECK_EQ_INT((long)r.resumed_from, 0);
    CHECK(file_is_pattern(OUT, 50000));
    cleanup();
}

static void test_download_part_larger_than_total_restarts(void) {
    cleanup();
    const char *u = url_of("n=1000");
    static uint8_t junk[5000];
    write_file(OUT ".part", junk, sizeof junk);
    write_meta(u, "\"v1\"");
    wtls_http_download_result r;
    CHECK_EQ_INT(dl(u, NULL, &r), WTLS_OK); /* 416 with a total of 1000: start over */
    CHECK_EQ_INT((long)r.resumed_from, 0);
    CHECK(file_is_pattern(OUT, 1000));
    cleanup();
}

static void test_download_416_complete_part_verifies(void) {
    cleanup();
    const char *u = url_of("n=1000");
    uint8_t p[1000];
    pattern(p, sizeof p);
    write_file(OUT ".part", p, sizeof p);
    write_meta(u, "\"v1\"");
    uint8_t want[32];
    sha_of_pattern(1000, want);
    wtls_http_download_opts o = {0};
    o.sha256 = want;
    wtls_http_download_result r;
    CHECK_EQ_INT(dl(u, &o, &r), WTLS_OK);
    CHECK_EQ_INT(r.status, 416);
    CHECK_EQ_INT((long)r.resumed_from, 1000);
    CHECK_EQ_INT((long)r.size, 1000);
    CHECK(file_is_pattern(OUT, 1000));
    CHECK(!file_exists(OUT ".part") && !file_exists(OUT ".part.meta"));
    cleanup();
}

static void test_download_no_meta_means_no_resume(void) {
    cleanup();
    static uint8_t junk[300];
    write_file(OUT ".part", junk, sizeof junk); /* no validators on record: cannot be trusted */
    wtls_http_download_result r;
    CHECK_EQ_INT(dl(url_of("n=1000"), NULL, &r), WTLS_OK);
    CHECK_EQ_INT((long)r.resumed_from, 0);
    CHECK(file_is_pattern(OUT, 1000));
    cleanup();
}

static void test_download_digest_mismatch_integrity(void) {
    cleanup();
    write_file(OUT, "old", 3);
    uint8_t wrong[32] = {1};
    wtls_http_download_opts o = {0};
    o.sha256 = wrong;
    wtls_http_download_result r;
    CHECK_EQ_INT(dl(url_of("n=1000"), &o, &r), WTLS_ERR_INTEGRITY);
    CHECK_EQ_INT(file_size(OUT), 3); /* untouched */
    CHECK(!file_exists(OUT ".part") && !file_exists(OUT ".part.meta"));
    cleanup();
}

static void test_download_signature_ok_and_bad(void) {
    cleanup();
    uint8_t pub[65], sig[80];
    size_t pl = 0, sl = 0;
    for (size_t i = 0; i * 2 < strlen(k_sig_pub); i++, pl++) {
        unsigned b;
        sscanf(k_sig_pub + 2 * i, "%2x", &b);
        pub[i] = (uint8_t)b;
    }
    for (size_t i = 0; i * 2 < strlen(k_sig_pattern1000_der); i++, sl++) {
        unsigned b;
        sscanf(k_sig_pattern1000_der + 2 * i, "%2x", &b);
        sig[i] = (uint8_t)b;
    }
    wtls_http_download_opts o = {0};
    o.sig = sig;
    o.sig_len = sl;
    o.sig_format = WTLS_SIG_DER;
    o.sig_pubkey = pub;
    o.sig_pubkey_len = pl;
    wtls_http_download_result r;
    CHECK_EQ_INT(dl(url_of("n=1000"), &o, &r), WTLS_OK);
    CHECK(file_is_pattern(OUT, 1000));
    cleanup();
    write_file(OUT, "old", 3);
    CHECK_EQ_INT(dl(url_of("n=1001"), &o, &r), WTLS_ERR_INTEGRITY); /* another file than the signed one */
    CHECK_EQ_INT(file_size(OUT), 3);
    CHECK(!file_exists(OUT ".part"));
    cleanup();
}

static void test_download_replaces_existing_file(void) {
    cleanup();
    write_file(OUT, "old content", 11);
    wtls_http_download_result r;
    CHECK_EQ_INT(dl(url_of("n=2000"), NULL, &r), WTLS_OK);
    CHECK(file_is_pattern(OUT, 2000));
    CHECK(!file_exists(OUT ".old"));
    cleanup();
}

static void test_download_recover_each_crash_point(void) {
    cleanup();
    /* crashed between the two renames: only .old and .part exist */
    write_file(OUT ".old", "OLD", 3);
    write_file(OUT ".part", "NEW", 3);
    CHECK_EQ_INT(wtls_http_download_recover(OUT), WTLS_OK);
    CHECK_EQ_INT(file_size(OUT), 3);
    CHECK(!file_exists(OUT ".old"));
    CHECK(file_exists(OUT ".part"));
    cleanup();
    /* crashed after the second rename: the new file and .old exist */
    write_file(OUT, "NEW", 3);
    write_file(OUT ".old", "OLDER", 5);
    CHECK_EQ_INT(wtls_http_download_recover(OUT), WTLS_OK);
    CHECK_EQ_INT(file_size(OUT), 3);
    CHECK(!file_exists(OUT ".old"));
    cleanup();
    /* nothing to repair */
    CHECK_EQ_INT(wtls_http_download_recover(OUT), WTLS_OK);
    CHECK(!file_exists(OUT));
}

static void test_download_recovers_before_starting(void) {
    cleanup();
    write_file(OUT ".old", "OLD", 3); /* a previous run died after moving the old file aside */
    wtls_http_download_result r;
    CHECK_EQ_INT(dl(url_of("n=1000&etag=x"), NULL, &r), WTLS_OK);
    CHECK(file_is_pattern(OUT, 1000));
    CHECK(!file_exists(OUT ".old"));
    cleanup();
}

static void test_download_max_size_limit(void) {
    cleanup();
    wtls_http_download_opts o = {0};
    o.max_size = 1000;
    wtls_http_download_result r;
    CHECK_EQ_INT(dl(url_of("n=100000"), &o, &r), WTLS_ERR_HTTP_LIMIT);
    CHECK(!file_exists(OUT) && !file_exists(OUT ".part"));
    cleanup();
}

typedef struct {
    size_t first;
    size_t last;
    int calls;
} prog;

static void on_progress(void *ctx, size_t done, int64_t total) {
    prog *p = ctx;
    if (p->calls++ == 0) p->first = done;
    p->last = done;
    (void)total;
}

static void test_download_progress_includes_offset(void) {
    cleanup();
    const char *u = url_of("n=80000&cut=30000&once=prog1");
    wtls_http_download_result r;
    CHECK_EQ_INT(dl(u, NULL, &r), WTLS_ERR_IO);
    long part = file_size(OUT ".part");
    prog p = {0, 0, 0};
    wtls_http_request req = {0};
    req.url = u;
    req.progress_cb = on_progress;
    req.progress_ctx = &p;
    CHECK_EQ_INT(wtls_http_download(&req, OUT, NULL, &r), WTLS_OK);
    CHECK(p.calls > 0);
    CHECK(p.first > (size_t)part); /* counts the bytes taken over, not just the new ones */
    CHECK_EQ_INT((long)p.last, 80000);
    cleanup();
}

static void test_download_http_error_status(void) {
    cleanup();
    wtls_http_request req = {0};
    char u[200];
    snprintf(u, sizeof u, "https://%s:%u/status?code=404", g_env.server_host, (unsigned)P_HTTP);
    req.url = u;
    wtls_http_download_result r;
    CHECK_EQ_INT(wtls_http_download(&req, OUT, NULL, &r), WTLS_ERR_HTTP);
    CHECK_EQ_INT(r.status, 404);
    CHECK(!file_exists(OUT));
    cleanup();
}

static void test_download_bad_arguments(void) {
    wtls_http_download_result r;
    wtls_http_request req = {0};
    CHECK_EQ_INT(wtls_http_download(&req, OUT, NULL, &r), WTLS_ERR_ARG); /* no url */
    req.url = url_of("n=1");
    req.method = "POST";
    CHECK_EQ_INT(wtls_http_download(&req, OUT, NULL, &r), WTLS_ERR_ARG);
    req.method = NULL;
    CHECK_EQ_INT(wtls_http_download(&req, NULL, NULL, &r), WTLS_ERR_ARG);
    wtls_http_download_opts o = {0};
    static const uint8_t sig[8] = {0};
    o.sig = sig;
    o.sig_len = sizeof sig; /* no public key */
    CHECK_EQ_INT(wtls_http_download(&req, OUT, &o, &r), WTLS_ERR_ARG);
}

void wtls_suite_download(void) {
    int r = wtls_init();
    CHECK_EQ_INT(r, WTLS_OK);
    if (r != WTLS_OK) return;
    bool trusted = trust_test_ca();
    CHECK(trusted);
    if (!trusted) return;
    RUN(test_download_fresh_ok_sha256);
    RUN(test_download_cut_then_resume);
    RUN(test_download_resume_etag_changed_restarts);
    RUN(test_download_server_ignores_range_restarts);
    RUN(test_download_part_larger_than_total_restarts);
    RUN(test_download_416_complete_part_verifies);
    RUN(test_download_no_meta_means_no_resume);
    RUN(test_download_digest_mismatch_integrity);
    RUN(test_download_signature_ok_and_bad);
    RUN(test_download_replaces_existing_file);
    RUN(test_download_recover_each_crash_point);
    RUN(test_download_recovers_before_starting);
    RUN(test_download_max_size_limit);
    RUN(test_download_progress_includes_offset);
    RUN(test_download_http_error_status);
    RUN(test_download_bad_arguments);
    wtls_shutdown();
}
