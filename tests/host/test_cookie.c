/* Unit tests for the cookie jar (RFC 6265 behaviour, explicit clock). */
#include <stdlib.h>
#include <string.h>

#include "check.h"
#include "http/wtls_cookie.h"
#include "wtls_mem.h"

WTLS_CHECK_DEFINE_COUNTERS;

#define T0 1800000000LL

static char *hdr(wtls_cookie_jar *j, const char *host, const char *path, bool secure, int64_t now) {
    return wtls_cookie_jar_header(j, host, path, secure, now);
}

static bool hdr_is(wtls_cookie_jar *j, const char *host, const char *path, bool secure, int64_t now, const char *want) {
    char *h = hdr(j, host, path, secure, now);
    bool ok = want ? (h && strcmp(h, want) == 0) : h == NULL;
    wtls_free(h);
    return ok;
}

static void test_cookie_basic_host_only(void) {
    wtls_cookie_jar *j = wtls_cookie_jar_new(0);
    CHECK_EQ_INT(wtls_cookie_jar_set(j, "sid=abc", "example.com", "/", false, T0), WTLS_OK);
    CHECK(hdr_is(j, "example.com", "/x", false, T0, "sid=abc"));
    CHECK(hdr_is(j, "www.example.com", "/", false, T0, NULL)); /* host-only: no subdomains */
    CHECK(hdr_is(j, "other.org", "/", false, T0, NULL));
    wtls_cookie_jar_free(j);
}

static void test_cookie_domain_attribute(void) {
    wtls_cookie_jar *j = wtls_cookie_jar_new(0);
    CHECK_EQ_INT(wtls_cookie_jar_set(j, "a=1; Domain=.Example.COM", "www.example.com", "/", false, T0), WTLS_OK);
    CHECK(hdr_is(j, "example.com", "/", false, T0, "a=1"));
    CHECK(hdr_is(j, "x.y.example.com", "/", false, T0, "a=1"));
    CHECK(hdr_is(j, "badexample.com", "/", false, T0, NULL)); /* suffix must start at a label */
    CHECK_EQ_INT(wtls_cookie_jar_set(j, "b=1; Domain=other.com", "www.example.com", "/", false, T0), WTLS_ERR_ARG);
    CHECK_EQ_INT(wtls_cookie_jar_set(j, "c=1; Domain=com", "www.example.com", "/", false, T0), WTLS_ERR_ARG); /* no dot */
    CHECK_EQ_INT(wtls_cookie_jar_set(j, "d=1; Domain=sub.example.com", "example.com", "/", false, T0), WTLS_ERR_ARG); /* wrong direction */
    CHECK_EQ_INT(wtls_cookie_jar_set(j, "e=1; Domain=1.2.3.4", "1.2.3.4", "/", false, T0), WTLS_ERR_ARG); /* IP literal */
    CHECK_EQ_INT(wtls_cookie_jar_set(j, "f=1", "1.2.3.4", "/", false, T0), WTLS_OK); /* host-only for an IP is fine */
    wtls_cookie_jar_free(j);
}

static void test_cookie_path_rules(void) {
    wtls_cookie_jar *j = wtls_cookie_jar_new(0);
    CHECK_EQ_INT(wtls_cookie_jar_set(j, "p=1; Path=/foo", "h.com", "/", false, T0), WTLS_OK);
    CHECK(hdr_is(j, "h.com", "/foo", false, T0, "p=1"));
    CHECK(hdr_is(j, "h.com", "/foo/bar", false, T0, "p=1"));
    CHECK(hdr_is(j, "h.com", "/foobar", false, T0, NULL)); /* not at a path boundary */
    CHECK(hdr_is(j, "h.com", "/", false, T0, NULL));
    /* default path: the directory of the request path */
    CHECK_EQ_INT(wtls_cookie_jar_set(j, "d=1", "h.com", "/a/b/c", false, T0), WTLS_OK);
    CHECK(hdr_is(j, "h.com", "/a/b/x", false, T0, "d=1"));
    CHECK(hdr_is(j, "h.com", "/a/other", false, T0, NULL));
    CHECK_EQ_INT(wtls_cookie_jar_set(j, "r=1", "h.com", "/single", false, T0), WTLS_OK); /* default path "/" */
    CHECK(hdr_is(j, "h.com", "/zzz", false, T0, "r=1"));
    wtls_cookie_jar_free(j);
}

static void test_cookie_secure(void) {
    wtls_cookie_jar *j = wtls_cookie_jar_new(0);
    CHECK_EQ_INT(wtls_cookie_jar_set(j, "s=1; Secure", "h.com", "/", false, T0), WTLS_ERR_ARG); /* Secure over plain http */
    CHECK_EQ_INT(wtls_cookie_jar_set(j, "s=1; Secure", "h.com", "/", true, T0), WTLS_OK);
    CHECK(hdr_is(j, "h.com", "/", true, T0, "s=1"));
    CHECK(hdr_is(j, "h.com", "/", false, T0, NULL)); /* never sent in clear */
    wtls_cookie_jar_free(j);
}

static void test_cookie_expiry(void) {
    wtls_cookie_jar *j = wtls_cookie_jar_new(0);
    CHECK_EQ_INT(wtls_cookie_jar_set(j, "m=1; Max-Age=60", "h.com", "/", false, T0), WTLS_OK);
    CHECK_EQ_INT(wtls_cookie_jar_set(j, "e=1; Expires=Fri, 15 Jan 2038 08:00:00 GMT", "h.com", "/", false, T0), WTLS_OK);
    CHECK(hdr_is(j, "h.com", "/", false, T0 + 59, "m=1; e=1"));
    CHECK(hdr_is(j, "h.com", "/", false, T0 + 61, "e=1")); /* Max-Age elapsed */
    int64_t exp = wtls_cookie_parse_date("Fri, 15 Jan 2038 08:00:00 GMT");
    CHECK(hdr_is(j, "h.com", "/", false, exp - 1, "e=1"));
    CHECK(hdr_is(j, "h.com", "/", false, exp, NULL));
    CHECK_EQ_INT((int)wtls_cookie_jar_count(j), 0); /* purged on lookup */
    /* Max-Age wins over Expires */
    CHECK_EQ_INT(wtls_cookie_jar_set(j, "w=1; Expires=Fri, 15 Jan 2038 08:00:00 GMT; Max-Age=10", "h.com", "/", false, T0), WTLS_OK);
    CHECK(hdr_is(j, "h.com", "/", false, T0 + 11, NULL));
    wtls_cookie_jar_free(j);
}

static void test_cookie_deletion_and_replace(void) {
    wtls_cookie_jar *j = wtls_cookie_jar_new(0);
    CHECK_EQ_INT(wtls_cookie_jar_set(j, "k=1", "h.com", "/", false, T0), WTLS_OK);
    CHECK_EQ_INT(wtls_cookie_jar_set(j, "k=2", "h.com", "/", false, T0), WTLS_OK); /* same name, domain, path: replaced */
    CHECK_EQ_INT((int)wtls_cookie_jar_count(j), 1);
    CHECK(hdr_is(j, "h.com", "/", false, T0, "k=2"));
    CHECK_EQ_INT(wtls_cookie_jar_set(j, "k=; Max-Age=0", "h.com", "/", false, T0), WTLS_OK);
    CHECK_EQ_INT((int)wtls_cookie_jar_count(j), 0);
    CHECK_EQ_INT(wtls_cookie_jar_set(j, "k=1", "h.com", "/", false, T0), WTLS_OK);
    CHECK_EQ_INT(wtls_cookie_jar_set(j, "k=x; Expires=Thu, 01 Jan 1970 00:00:01 GMT", "h.com", "/", false, T0), WTLS_OK);
    CHECK_EQ_INT((int)wtls_cookie_jar_count(j), 0);
    /* different path = different cookie */
    CHECK_EQ_INT(wtls_cookie_jar_set(j, "k=1; Path=/a", "h.com", "/", false, T0), WTLS_OK);
    CHECK_EQ_INT(wtls_cookie_jar_set(j, "k=2; Path=/b", "h.com", "/", false, T0), WTLS_OK);
    CHECK_EQ_INT((int)wtls_cookie_jar_count(j), 2);
    wtls_cookie_jar_clear(j);
    CHECK_EQ_INT((int)wtls_cookie_jar_count(j), 0);
    wtls_cookie_jar_free(j);
}

static void test_cookie_rejects_garbage(void) {
    wtls_cookie_jar *j = wtls_cookie_jar_new(0);
    CHECK_EQ_INT(wtls_cookie_jar_set(j, "novalue", "h.com", "/", false, T0), WTLS_ERR_ARG);
    CHECK_EQ_INT(wtls_cookie_jar_set(j, "=v", "h.com", "/", false, T0), WTLS_ERR_ARG);
    CHECK_EQ_INT(wtls_cookie_jar_set(j, "a b=v", "h.com", "/", false, T0), WTLS_ERR_ARG);
    CHECK_EQ_INT(wtls_cookie_jar_set(j, "a=v\x01x", "h.com", "/", false, T0), WTLS_ERR_ARG);
    CHECK_EQ_INT(wtls_cookie_jar_set(NULL, "a=b", "h.com", "/", false, T0), WTLS_ERR_ARG);
    char *big = malloc(5000);
    memset(big, 'x', 4999);
    memcpy(big, "a=", 2);
    big[4999] = '\0';
    CHECK_EQ_INT(wtls_cookie_jar_set(j, big, "h.com", "/", false, T0), WTLS_ERR_ARG);
    free(big);
    CHECK_EQ_INT((int)wtls_cookie_jar_count(j), 0);
    CHECK_EQ_INT(wtls_cookie_jar_set(j, "ok=1; HttpOnly; SameSite=Lax; Unknown=attr; Max-Age=abc", "h.com", "/", false, T0), WTLS_OK);
    CHECK(hdr_is(j, "h.com", "/", false, T0, "ok=1")); /* bad Max-Age ignored: session cookie */
    wtls_cookie_jar_free(j);
}

static void test_cookie_order_and_limit(void) {
    wtls_cookie_jar *j = wtls_cookie_jar_new(3);
    wtls_cookie_jar_set(j, "root=1", "h.com", "/", false, T0);
    wtls_cookie_jar_set(j, "deep=2; Path=/a/b", "h.com", "/", false, T0);
    wtls_cookie_jar_set(j, "mid=3; Path=/a", "h.com", "/", false, T0);
    CHECK(hdr_is(j, "h.com", "/a/b/c", false, T0, "deep=2; mid=3; root=1")); /* longest path first */
    wtls_cookie_jar_set(j, "new=4", "h.com", "/", false, T0); /* evicts the oldest: root */
    CHECK_EQ_INT((int)wtls_cookie_jar_count(j), 3);
    CHECK(hdr_is(j, "h.com", "/", false, T0, "new=4"));
    wtls_cookie_jar_free(j);
}

static void test_cookie_dates(void) {
    CHECK_EQ_INT((long long)wtls_cookie_parse_date("Thu, 01 Jan 1970 00:00:00 GMT"), 0);
    CHECK_EQ_INT((long long)wtls_cookie_parse_date("Wed, 21 Oct 2015 07:28:00 GMT"), 1445412480);
    CHECK_EQ_INT((long long)wtls_cookie_parse_date("Wednesday, 21-Oct-15 07:28:00 GMT"), 1445412480);
    CHECK_EQ_INT((long long)wtls_cookie_parse_date("Wed Oct 21 07:28:00 2015"), 1445412480);
    CHECK_EQ_INT((long long)wtls_cookie_parse_date("21 Oct 2015 07:28:00"), 1445412480);
    CHECK_EQ_INT((long long)wtls_cookie_parse_date("Wed, 21 Oct 99 07:28:00 GMT") > 0, 1); /* two-digit years */
    CHECK_EQ_INT((long long)wtls_cookie_parse_date("garbage"), -1);
    CHECK_EQ_INT((long long)wtls_cookie_parse_date("Wed, 32 Oct 2015 07:28:00 GMT"), -1);
    CHECK_EQ_INT((long long)wtls_cookie_parse_date("Wed, 21 Oct 2015 25:28:00 GMT"), -1);
    CHECK_EQ_INT((long long)wtls_cookie_parse_date(""), -1);
}

int main(void) {
    RUN(test_cookie_basic_host_only);
    RUN(test_cookie_domain_attribute);
    RUN(test_cookie_path_rules);
    RUN(test_cookie_secure);
    RUN(test_cookie_expiry);
    RUN(test_cookie_deletion_and_replace);
    RUN(test_cookie_rejects_garbage);
    RUN(test_cookie_order_and_limit);
    RUN(test_cookie_dates);
    return CHECK_DONE();
}
