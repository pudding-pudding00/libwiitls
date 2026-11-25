/* URL parsing and reference resolution (src/http/wtls_url.c). */
#include <stdlib.h>
#include <string.h>

#include "check.h"
#include "http/wtls_url.h"

WTLS_CHECK_DEFINE_COUNTERS;

static void expect_target(const wtls_url *u, const char *want) {
    char buf[256];
    size_t n = 0;
    if (u->target_needs_slash) buf[n++] = '/';
    memcpy(buf + n, u->target, u->target_len);
    buf[n + u->target_len] = 0;
    CHECK(strcmp(buf, want) == 0);
    if (strcmp(buf, want) != 0) TLOG("  target '%s' != '%s'\n", buf, want);
}

static void test_url_basic(void) {
    wtls_url u;
    CHECK_EQ_INT(wtls_url_parse("https://example.com/", &u), WTLS_OK);
    CHECK(u.secure);
    CHECK(strcmp(u.host, "example.com") == 0);
    CHECK_EQ_INT(u.port, 443);
    expect_target(&u, "/");
}

static void test_url_no_path(void) {
    wtls_url u;
    CHECK_EQ_INT(wtls_url_parse("https://example.com", &u), WTLS_OK);
    expect_target(&u, "/");
}

static void test_url_port_query_fragment(void) {
    wtls_url u;
    CHECK_EQ_INT(wtls_url_parse("https://Example.COM.:8443/a/b?x=1#frag", &u), WTLS_OK);
    CHECK(strcmp(u.host, "example.com") == 0);
    CHECK_EQ_INT(u.port, 8443);
    expect_target(&u, "/a/b?x=1");
}

static void test_url_query_without_path(void) {
    wtls_url u;
    CHECK_EQ_INT(wtls_url_parse("https://h?x", &u), WTLS_OK);
    expect_target(&u, "/?x");
}

static void test_url_scheme_case(void) {
    wtls_url u;
    CHECK_EQ_INT(wtls_url_parse("HTTPS://h/", &u), WTLS_OK);
    CHECK(u.secure);
}

static void test_url_ipv4(void) {
    wtls_url u;
    CHECK_EQ_INT(wtls_url_parse("https://10.0.0.1:4438/x", &u), WTLS_OK);
    CHECK(strcmp(u.host, "10.0.0.1") == 0);
    CHECK_EQ_INT(u.port, 4438);
    expect_target(&u, "/x");
}

static void test_url_plain_http(void) {
    wtls_url u;
    CHECK_EQ_INT(wtls_url_parse("http://example.com/a", &u), WTLS_OK);
    CHECK(!u.secure);
    CHECK_EQ_INT(u.port, 80);
    expect_target(&u, "/a");
    CHECK_EQ_INT(wtls_url_parse("HTTP://h:8080", &u), WTLS_OK);
    CHECK(!u.secure);
    CHECK_EQ_INT(u.port, 8080);
}

static void test_url_rejects(void) {
    static const char *const bad[] = {
        "ftp://x/", "https://", "https:///x", "https://user@host/", "https://[::1]/",
        "https://host:0/", "https://host:65536/", "https://host:12a/", "https://host:/",
        "https://ho st/", "https://host/a b", "https://host/\x7f", "https://host/\xc3\xa4",
        "example.com/", "https:/host/", "https://host../", "",
    };
    wtls_url u;
    for (size_t i = 0; i < sizeof bad / sizeof bad[0]; i++) {
        int r = wtls_url_parse(bad[i], &u);
        if (r != WTLS_ERR_ARG) TLOG("  accepted '%s'\n", bad[i]);
        CHECK_EQ_INT(r, WTLS_ERR_ARG);
    }
    CHECK_EQ_INT(wtls_url_parse(NULL, &u), WTLS_ERR_ARG);
    char *big = malloc(8194);
    if (!big) return;
    memcpy(big, "https://h/", 10);
    memset(big + 10, 'a', 8193 - 10);
    big[8193] = 0; /* 8193 bytes */
    CHECK_EQ_INT(wtls_url_parse(big, &u), WTLS_ERR_ARG);
    big[8192] = 0; /* 8192 bytes: allowed */
    CHECK_EQ_INT(wtls_url_parse(big, &u), WTLS_OK);
    free(big);
}

static void test_url_resolve_rfc3986(void) {
    static const char *const cases[][2] = {
        {"g", "https://a/b/c/g"},       {"./g", "https://a/b/c/g"},     {"g/", "https://a/b/c/g/"},
        {"/g", "https://a/g"},          {"//g", "https://g"},           {"?y", "https://a/b/c/d;p?y"},
        {"g?y", "https://a/b/c/g?y"},   {"#s", "https://a/b/c/d;p?q"},  {";x", "https://a/b/c/;x"},
        {"", "https://a/b/c/d;p?q"},    {".", "https://a/b/c/"},        {"..", "https://a/b/"},
        {"../g", "https://a/b/g"},      {"../..", "https://a/"},        {"../../g", "https://a/g"},
        {"../../../g", "https://a/g"},  {"/./g", "https://a/g"},        {"g/../h", "https://a/b/c/h"},
        {"g#s", "https://a/b/c/g"},     {"g;x?y#s", "https://a/b/c/g;x?y"},
        {"https://o:8443/x", "https://o:8443/x"}, {"http://o/", "http://o/"},
        {"HTTP://o/", "http://o/"},
    };
    for (size_t i = 0; i < sizeof cases / sizeof cases[0]; i++) {
        char *out = NULL;
        int r = wtls_url_resolve("https://a/b/c/d;p?q", cases[i][0], &out);
        CHECK_EQ_INT(r, WTLS_OK);
        if (r == WTLS_OK && strcmp(out, cases[i][1]) != 0) {
            TLOG("  resolve '%s' -> '%s', want '%s'\n", cases[i][0], out, cases[i][1]);
            CHECK(0);
        }
        free(out);
    }
}

static void test_url_same_origin(void) {
    wtls_url a, b;
    wtls_url_parse("https://a/x", &a);
    wtls_url_parse("https://a:443/y", &b);
    CHECK(wtls_url_same_origin(&a, &b));
    wtls_url_parse("https://a:8443/", &b);
    CHECK(!wtls_url_same_origin(&a, &b));
    wtls_url_parse("https://b/", &b);
    CHECK(!wtls_url_same_origin(&a, &b));
    wtls_url_parse("http://a:443/", &b);
    CHECK(!wtls_url_same_origin(&a, &b));
}

int main(void) {
    RUN(test_url_basic);
    RUN(test_url_no_path);
    RUN(test_url_port_query_fragment);
    RUN(test_url_query_without_path);
    RUN(test_url_scheme_case);
    RUN(test_url_ipv4);
    RUN(test_url_plain_http);
    RUN(test_url_rejects);
    RUN(test_url_resolve_rfc3986);
    RUN(test_url_same_origin);
    return CHECK_DONE();
}
