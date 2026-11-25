/* Response head parser and message framing (src/http/wtls_http_parse.c). */
#include <stdlib.h>
#include <string.h>

#include "check.h"
#include "http/wtls_http_parse.h"

WTLS_CHECK_DEFINE_COUNTERS;

/* Parses a NUL-free copy of s (heap, so ASan sees overreads). */
static int parse(const char *s, size_t len, wtls_http_head *h, char **keep) {
    char *b = malloc(len ? len : 1);
    memcpy(b, s, len);
    int r = wtls_http_parse_head(b, len, h);
    *keep = b;
    return r;
}

static int parse_str(const char *s, wtls_http_head *h, char **keep) { return parse(s, strlen(s), h, keep); }

static void test_head_end(void) {
    CHECK_EQ_INT(wtls_http_head_end("HTTP/1.1 200 OK\r\n\r\n", 19), 19);
    CHECK_EQ_INT(wtls_http_head_end("HTTP/1.1 200 OK\n\n", 17), 17);
    CHECK_EQ_INT(wtls_http_head_end("HTTP/1.1 200 OK\r\n\r\nbody", 23), 19);
    CHECK_EQ_INT(wtls_http_head_end("HTTP/1.1 200 OK\n\nbody\n\n", 23), 17);
    const char *full = "HTTP/1.1 200 OK\r\nA: b\r\n\r\n";
    for (size_t i = 0; i < strlen(full); i++) CHECK_EQ_INT(wtls_http_head_end(full, i), 0);
}

static void test_head_end_limit(void) {
    size_t n = 20000;
    char *b = malloc(n);
    memset(b, 'x', n);
    memcpy(b, "HTTP/1.1 200 OK\r\nX: ", 20);
    memcpy(b + 11996, "\r\n\r\n", 4);
    CHECK_EQ_INT(wtls_http_head_end(b, n), 12000);
    memset(b + 11996, 'x', 4);
    memcpy(b + 19996, "\r\n\r\n", 4);
    CHECK_EQ_INT(wtls_http_head_end(b, n), 20000);
    free(b);
}

static void test_parse_status_line(void) {
    static const struct {
        const char *line;
        int status, minor;
    } ok[] = {
        {"HTTP/1.1 200 OK", 200, 1},
        {"HTTP/1.0 404 Not Found", 404, 0},
        {"HTTP/1.1 204", 204, 1},
        {"HTTP/1.1 204 ", 204, 1},
    };
    static const char *const bad[] = {
        "HTTP/2 200 OK", "HTTP/1.1 20 OK", "HTTP/1.1 2000 OK", "HTTP/1.1 099 x",
        "HTTP/1.1 600 x", "ICY 200 OK",    "HTTP/1.1  200 OK",
    };
    wtls_http_head h;
    char buf[64], *keep;
    for (size_t i = 0; i < sizeof ok / sizeof ok[0]; i++) {
        snprintf(buf, sizeof buf, "%s\r\n\r\n", ok[i].line);
        CHECK_EQ_INT(parse_str(buf, &h, &keep), WTLS_OK);
        CHECK_EQ_INT(h.status, ok[i].status);
        CHECK_EQ_INT(h.minor, ok[i].minor);
        free(keep);
    }
    for (size_t i = 0; i < sizeof bad / sizeof bad[0]; i++) {
        snprintf(buf, sizeof buf, "%s\r\n\r\n", bad[i]);
        int r = parse_str(buf, &h, &keep);
        if (r != WTLS_ERR_HTTP) TLOG("  accepted '%s'\n", bad[i]);
        CHECK_EQ_INT(r, WTLS_ERR_HTTP);
        free(keep);
    }
}

static void test_parse_fields(void) {
    wtls_http_head h;
    char *keep;
    CHECK_EQ_INT(parse_str("HTTP/1.1 200 OK\r\nContent-Type:  text/html \r\nX-Empty:\r\n"
                           "Set-Cookie: a=1\r\nSet-Cookie: b=2\r\n\r\n",
                           &h, &keep),
                 WTLS_OK);
    CHECK_EQ_INT(h.n_fields, 4);
    const char *v = wtls_http_head_get(&h, "CONTENT-TYPE");
    CHECK(v && strcmp(v, "text/html") == 0);
    v = wtls_http_head_get(&h, "x-empty");
    CHECK(v && strcmp(v, "") == 0);
    v = wtls_http_head_get(&h, "set-cookie");
    CHECK(v && strcmp(v, "a=1") == 0);
    CHECK(strcmp(h.fields[2].name, "set-cookie") == 0 && strcmp(h.fields[2].value, "a=1") == 0);
    CHECK(strcmp(h.fields[3].name, "set-cookie") == 0 && strcmp(h.fields[3].value, "b=2") == 0);
    CHECK(wtls_http_head_get(&h, "missing") == NULL);
    free(keep);
}

static void test_parse_obs_fold(void) {
    wtls_http_head h;
    char *keep;
    CHECK_EQ_INT(parse_str("HTTP/1.1 200 OK\r\nX-Long: a\r\n  b\r\nY: c\r\n\r\n", &h, &keep), WTLS_OK);
    const char *v = wtls_http_head_get(&h, "x-long");
    CHECK(v && strcmp(v, "a b") == 0);
    v = wtls_http_head_get(&h, "y");
    CHECK(v && strcmp(v, "c") == 0);
    free(keep);
    CHECK_EQ_INT(parse_str("HTTP/1.1 200 OK\r\n b\r\n\r\n", &h, &keep), WTLS_ERR_HTTP);
    free(keep);
}

static void test_parse_rejects(void) {
    static const char *const bad[] = {"Bad Name: x", "Name : x", "NoColon", ": x", "X: a\x01"};
    wtls_http_head h;
    char buf[64], *keep;
    for (size_t i = 0; i < sizeof bad / sizeof bad[0]; i++) {
        snprintf(buf, sizeof buf, "HTTP/1.1 200 OK\r\n%s\r\n\r\n", bad[i]);
        int r = parse_str(buf, &h, &keep);
        if (r != WTLS_ERR_HTTP) TLOG("  accepted field %u\n", (unsigned)i);
        CHECK_EQ_INT(r, WTLS_ERR_HTTP);
        free(keep);
    }
    static const char nul[] = "HTTP/1.1 200 OK\r\nX: a\0b\r\n\r\n";
    CHECK_EQ_INT(parse(nul, sizeof nul - 1, &h, &keep), WTLS_ERR_HTTP);
    free(keep);
    static const char cr[] = "HTTP/1.1 200 OK\r\nX: a\rb\r\n\r\n";
    CHECK_EQ_INT(parse(cr, sizeof cr - 1, &h, &keep), WTLS_ERR_HTTP);
    free(keep);
}

static void test_parse_field_limit(void) {
    wtls_http_head h;
    char *keep;
    for (int n = 100; n <= 101; n++) {
        char *b = malloc(32 + (size_t)n * 8);
        size_t len = (size_t)sprintf(b, "HTTP/1.1 200 OK\r\n");
        for (int i = 0; i < n; i++) len += (size_t)sprintf(b + len, "X: %03d\r\n", i);
        len += (size_t)sprintf(b + len, "\r\n");
        CHECK_EQ_INT(parse(b, len, &h, &keep), n == 100 ? WTLS_OK : WTLS_ERR_HTTP_LIMIT);
        free(keep);
        free(b);
    }
}

/* Frames "HTTP/1.<minor> <status> x\r\n<fields>\r\n". */
static int frame(int minor, int status, const char *fields, bool head_req, bool keepalive, wtls_http_framing *f) {
    char buf[512], *keep;
    wtls_http_head h;
    snprintf(buf, sizeof buf, "HTTP/1.%d %d x\r\n%s\r\n", minor, status, fields);
    int r = parse_str(buf, &h, &keep);
    if (r == WTLS_OK) r = wtls_http_frame(&h, head_req, keepalive, f);
    free(keep);
    return r;
}

static void expect_frame(int minor, int status, const char *fields, bool head_req, bool keepalive,
                         wtls_body_kind kind, uint64_t length, bool reusable) {
    wtls_http_framing f;
    int r = frame(minor, status, fields, head_req, keepalive, &f);
    bool good = r == WTLS_OK && f.kind == kind && (kind != WTLS_BODY_LENGTH || f.length == length) &&
                f.reusable == reusable;
    if (!good) TLOG("  frame %d '%s': r=%d kind=%d len=%llu reuse=%d\n", status, fields, r, (int)f.kind,
                    (unsigned long long)f.length, (int)f.reusable);
    CHECK(good);
}

static void expect_frame_err(const char *fields) {
    wtls_http_framing f;
    int r = frame(1, 200, fields, false, true, &f);
    if (r != WTLS_ERR_HTTP) TLOG("  framed '%s'\n", fields);
    CHECK_EQ_INT(r, WTLS_ERR_HTTP);
}

static void test_frame_table(void) {
    expect_frame(1, 200, "Content-Length: 5\r\n", false, true, WTLS_BODY_LENGTH, 5, true);
    expect_frame(1, 200, "Content-Length: 5, 5\r\n", false, true, WTLS_BODY_LENGTH, 5, true);
    expect_frame(1, 200, "Content-Length: 5\r\nContent-Length: 5\r\n", false, true, WTLS_BODY_LENGTH, 5, true);
    expect_frame(1, 200, "Content-Length: 0\r\n", false, true, WTLS_BODY_LENGTH, 0, true);
    expect_frame_err("Content-Length: 5, 6\r\n");
    expect_frame_err("Content-Length: 5\r\nContent-Length: 6\r\n");
    expect_frame_err("Content-Length: -1\r\n");
    expect_frame_err("Content-Length: \r\n");
    expect_frame_err("Content-Length: 5a\r\n");
    expect_frame_err("Content-Length: +5\r\n");
    expect_frame_err("Content-Length: 99999999999999999999\r\n");

    expect_frame(1, 200, "Transfer-Encoding: chunked\r\n", false, true, WTLS_BODY_CHUNKED, 0, true);
    expect_frame(1, 200, "Transfer-Encoding: Chunked\r\n", false, true, WTLS_BODY_CHUNKED, 0, true);
    expect_frame_err("Transfer-Encoding: gzip, chunked\r\n");
    expect_frame_err("Transfer-Encoding: chunked, gzip\r\n");
    expect_frame_err("Transfer-Encoding: identity\r\n");
    expect_frame(1, 200, "Transfer-Encoding: chunked\r\nContent-Length: 5\r\n", false, true, WTLS_BODY_CHUNKED, 0,
                 false);

    expect_frame(1, 200, "", false, true, WTLS_BODY_CLOSE, 0, false);

    expect_frame(1, 200, "Content-Length: 100\r\n", true, true, WTLS_BODY_NONE, 0, true);
    expect_frame(1, 204, "", false, true, WTLS_BODY_NONE, 0, true);
    expect_frame(1, 204, "Content-Length: 7\r\n", false, true, WTLS_BODY_NONE, 0, true);
    expect_frame(1, 304, "Content-Length: 7\r\n", false, true, WTLS_BODY_NONE, 0, true);
    expect_frame(1, 100, "", false, true, WTLS_BODY_NONE, 0, true);

    expect_frame(1, 200, "Connection: keep-alive, Close\r\nContent-Length: 1\r\n", false, true, WTLS_BODY_LENGTH,
                 1, false);
    expect_frame(0, 200, "Content-Length: 1\r\n", false, true, WTLS_BODY_LENGTH, 1, false);
    expect_frame(1, 200, "Content-Length: 1\r\n", false, false, WTLS_BODY_LENGTH, 1, false);
}

int main(void) {
    RUN(test_head_end);
    RUN(test_head_end_limit);
    RUN(test_parse_status_line);
    RUN(test_parse_fields);
    RUN(test_parse_obs_fold);
    RUN(test_parse_rejects);
    RUN(test_parse_field_limit);
    RUN(test_frame_table);
    return CHECK_DONE();
}
