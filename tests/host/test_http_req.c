/* Request head building and validation (src/http/wtls_http_req.c). */
#include <stdlib.h>
#include <string.h>

#include "check.h"
#include "http/wtls_http_req.h"

WTLS_CHECK_DEFINE_COUNTERS;

static char *build(const char *method, const char *url, const wtls_http_header *h, size_t n, bool has_body,
                   size_t body_len, bool no_keepalive, bool gzip, int *status) {
    wtls_url u;
    char *out = NULL;
    size_t len = 0;
    if (wtls_url_parse(url, &u) != WTLS_OK) {
        *status = -1000;
        return NULL;
    }
    *status = wtls_http_build_head(method, &u, h, n, has_body, body_len, no_keepalive, gzip, &out, &len);
    if (*status == WTLS_OK) CHECK_EQ_INT(strlen(out), len);
    return out;
}

static void test_req_get_default(void) {
    int st;
    char *h = build("GET", "https://example.com/a?b", NULL, 0, false, 0, false, false, &st);
    CHECK_EQ_INT(st, WTLS_OK);
    if (!h) return;
    const char *want = "GET /a?b HTTP/1.1\r\nHost: example.com\r\nUser-Agent: libwiitls/" WTLS_VERSION
                       "\r\nAccept: */*\r\n\r\n";
    CHECK(strcmp(h, want) == 0);
    if (strcmp(h, want) != 0) TLOG("  got: %s\n", h);
    free(h);
}

static void test_req_port_in_host(void) {
    int st;
    char *h = build("GET", "https://example.com:8443/", NULL, 0, false, 0, false, false, &st);
    CHECK(h && strstr(h, "Host: example.com:8443\r\n"));
    free(h);
    h = build("GET", "http://example.com/", NULL, 0, false, 0, false, false, &st);
    CHECK(h && strstr(h, "Host: example.com\r\n"));
    free(h);
    h = build("GET", "http://example.com:443/", NULL, 0, false, 0, false, false, &st);
    CHECK(h && strstr(h, "Host: example.com:443\r\n"));
    free(h);
}

static void test_req_content_length(void) {
    int st;
    char *h = build("POST", "https://h/", NULL, 0, true, 5, false, false, &st);
    CHECK(h && strstr(h, "Content-Length: 5\r\n"));
    free(h);
    h = build("POST", "https://h/", NULL, 0, false, 0, false, false, &st);
    CHECK(h && strstr(h, "Content-Length: 0\r\n"));
    free(h);
    h = build("GET", "https://h/", NULL, 0, false, 0, false, false, &st);
    CHECK(h && !strstr(h, "Content-Length"));
    free(h);
}

static void test_req_user_headers(void) {
    wtls_http_header hd[] = {{"X-A", "1"}, {"user-agent", "mine"}};
    int st;
    char *h = build("GET", "https://h/", hd, 2, false, 0, false, false, &st);
    CHECK_EQ_INT(st, WTLS_OK);
    if (!h) return;
    char *ua = strstr(h, "user-agent: mine\r\n");
    CHECK(ua && !strstr(ua + 1, "user-agent: mine"));
    CHECK(!strstr(h, "User-Agent: libwiitls"));
    char *xa = strstr(h, "X-A: 1\r\n"), *acc = strstr(h, "Accept: */*\r\n");
    CHECK(xa && acc && xa > acc);
    free(h);
}

static void test_req_no_keepalive(void) {
    int st;
    char *h = build("GET", "https://h/", NULL, 0, false, 0, true, false, &st);
    CHECK(h && strstr(h, "Connection: close\r\n"));
    free(h);
}

static void test_req_gzip(void) {
    int st;
    char *h = build("GET", "https://h/", NULL, 0, false, 0, false, true, &st);
    CHECK(h && strstr(h, "Accept-Encoding: gzip\r\n"));
    free(h);
    wtls_http_header hd[] = {{"accept-encoding", "identity"}};
    h = build("GET", "https://h/", hd, 1, false, 0, false, true, &st);
    CHECK(h && !strstr(h, "Accept-Encoding: gzip") && strstr(h, "accept-encoding: identity\r\n"));
    free(h);
    CHECK(wtls_http_headers_have(hd, 1, "Accept-Encoding"));
    CHECK(!wtls_http_headers_have(hd, 1, "Accept"));
    CHECK(!wtls_http_headers_have(NULL, 0, "Accept"));
}

static void test_req_rejects(void) {
    int st;
    char *h;
    static const char *const bad_methods[] = {"GE T", ""};
    for (size_t i = 0; i < 2; i++) {
        h = build(bad_methods[i], "https://h/", NULL, 0, false, 0, false, false, &st);
        CHECK_EQ_INT(st, WTLS_ERR_ARG);
        CHECK(h == NULL);
    }
    static const wtls_http_header bad[] = {
        {"Bad Name", "x"}, {"", "x"}, {"X", "a\rb"}, {"X", "a\nb"}, {"X", "a\x01"},
        {"host", "x"}, {"Content-Length", "1"}, {"TRANSFER-ENCODING", "chunked"}, {"connection", "close"},
        {NULL, "x"}, {"X", NULL},
    };
    for (size_t i = 0; i < sizeof bad / sizeof bad[0]; i++) {
        h = build("GET", "https://h/", &bad[i], 1, false, 0, false, false, &st);
        if (st != WTLS_ERR_ARG) TLOG("  accepted header %u\n", (unsigned)i);
        CHECK_EQ_INT(st, WTLS_ERR_ARG);
        free(h);
    }
    wtls_http_header many[65];
    for (int i = 0; i < 65; i++) many[i] = (wtls_http_header){"X-N", "1"};
    h = build("GET", "https://h/", many, 64, false, 0, false, false, &st);
    CHECK_EQ_INT(st, WTLS_OK);
    free(h);
    h = build("GET", "https://h/", many, 65, false, 0, false, false, &st);
    CHECK_EQ_INT(st, WTLS_ERR_ARG);
    char *v = malloc(16384);
    if (!v) return;
    memset(v, 'v', 16383);
    v[16383] = 0;
    wtls_http_header big = {"X-Big", v};
    h = build("GET", "https://h/", &big, 1, false, 0, false, false, &st);
    CHECK_EQ_INT(st, WTLS_ERR_ARG);
    v[16200] = 0; /* fits */
    h = build("GET", "https://h/", &big, 1, false, 0, false, false, &st);
    CHECK_EQ_INT(st, WTLS_OK);
    free(h);
    free(v);
}

static void test_req_idempotent(void) {
    static const char *const yes[] = {"GET", "HEAD", "PUT", "DELETE", "OPTIONS"};
    static const char *const no[] = {"POST", "PATCH", "get"};
    for (size_t i = 0; i < 5; i++) CHECK(wtls_http_method_idempotent(yes[i]));
    for (size_t i = 0; i < 3; i++) CHECK(!wtls_http_method_idempotent(no[i]));
}

int main(void) {
    RUN(test_req_get_default);
    RUN(test_req_port_in_host);
    RUN(test_req_content_length);
    RUN(test_req_user_headers);
    RUN(test_req_no_keepalive);
    RUN(test_req_gzip);
    RUN(test_req_rejects);
    RUN(test_req_idempotent);
    return CHECK_DONE();
}
