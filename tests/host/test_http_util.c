/* Host unit tests for the stateless HTTP helpers (WP4):
 * wtls_http_url_encode and wtls_http_parse_content_range. */
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <wiitls/http.h>

#include "check.h"

WTLS_CHECK_DEFINE_COUNTERS;

/* ---- url_encode ---------------------------------------------------------- */

static void enc_ok(const char *in, size_t in_len, const char *want) {
    size_t need = 1;
    /* size query first: must not write anything and report the exact need */
    CHECK_EQ_INT(wtls_http_url_encode(in, in_len, NULL, 0, &need), WTLS_OK);
    CHECK_EQ_INT((long long)need, (long long)strlen(want));
    char buf[256];
    memset(buf, 'x', sizeof buf);
    CHECK_EQ_INT(wtls_http_url_encode(in, in_len, buf, sizeof buf, &need), WTLS_OK);
    CHECK_EQ_INT((long long)need, (long long)strlen(want));
    CHECK_MEM(buf, want, strlen(want) + 1); /* including the NUL */
    /* one byte short is refused and leaves a fresh buffer untouched */
    if (need > 0) {
        memset(buf, 'y', sizeof buf);
        CHECK_EQ_INT(wtls_http_url_encode(in, in_len, buf, need, &need), WTLS_ERR_HTTP_LIMIT);
        CHECK_EQ_INT(buf[0], 'y');
    }
}

#define ENC(in, want) enc_ok(in, sizeof(in) - 1, want)

static void test_url_encode_vectors(void) {
    ENC("", "");
    ENC("abcXYZ019-_.~", "abcXYZ019-_.~");
    ENC(" ", "%20");
    ENC("%", "%25");
    ENC("/", "%2F");
    ENC("\x7f", "%7F");
    ENC("\x0f", "%0F"); /* upper case hex */
    ENC("K\xC3\xB6ln", "K%C3%B6ln");  /* UTF-8 stays byte-wise */
    ENC("\x00\x01\xfe\xff", "%00%01%FE%FF");
    ENC("a b&c=d/e?f", "a%20b%26c%3Dd%2Fe%3Ff");
}

static void test_url_encode_args(void) {
    size_t need = 99;
    CHECK_EQ_INT(wtls_http_url_encode(NULL, 0, NULL, 0, &need), WTLS_ERR_ARG);
    CHECK_EQ_INT(wtls_http_url_encode("a", 1, NULL, 0, NULL), WTLS_ERR_ARG);
    char buf[4];
    /* exactly fitting buffer is fine, empty input included */
    CHECK_EQ_INT(wtls_http_url_encode("abc", 3, buf, 4, &need), WTLS_OK);
    CHECK_MEM(buf, "abc", 4);
    CHECK_EQ_INT(wtls_http_url_encode("", 0, buf, 1, &need), WTLS_OK);
    CHECK_EQ_INT(buf[0], '\0');
}

static void test_url_encode_all_bytes(void) {
    /* Reference: everything outside A-Z a-z 0-9 - _ . ~ must be %XX. */
    uint8_t in[256];
    for (int i = 0; i < 256; i++) in[i] = (uint8_t)i;
    static const char hex[] = "0123456789ABCDEF";
    char want[256 * 3 + 1];
    size_t n = 0;
    for (int i = 0; i < 256; i++) {
        unsigned char c = (unsigned char)i;
        if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
            c == '-' || c == '_' || c == '.' || c == '~') {
            want[n++] = (char)c;
        } else {
            want[n++] = '%';
            want[n++] = hex[c >> 4];
            want[n++] = hex[c & 15];
        }
    }
    want[n] = '\0';
    size_t need = 0;
    CHECK_EQ_INT(wtls_http_url_encode((const char *)in, sizeof in, NULL, 0, &need), WTLS_OK);
    CHECK_EQ_INT((long long)need, (long long)n);
    static char out[256 * 3 + 1];
    CHECK_EQ_INT(wtls_http_url_encode((const char *)in, sizeof in, out, sizeof out, &need), WTLS_OK);
    CHECK_MEM(out, want, n + 1);
}

/* ---- parse_content_range ------------------------------------------------- */

static void cr_ok(const char *in, uint64_t start, uint64_t end, int64_t total) {
    wtls_http_content_range cr = {1, 2, 3};
    CHECK_EQ_INT(wtls_http_parse_content_range(in, &cr), WTLS_OK);
    CHECK_EQ_INT((long long)cr.start, (long long)start);
    CHECK_EQ_INT((long long)cr.end, (long long)end);
    CHECK_EQ_INT((long long)cr.total, (long long)total);
}

static void cr_bad(const char *in) {
    wtls_http_content_range cr;
    CHECK_EQ_INT(wtls_http_parse_content_range(in, &cr), WTLS_ERR_HTTP);
}

static void test_content_range_ok(void) {
    cr_ok("bytes 0-0/1", 0, 0, 1);
    cr_ok("bytes 0-99/*", 0, 99, -1);
    cr_ok("bytes 212-1063/44032", 212, 1063, 44032);
    cr_ok("bytes 0-9223372036854775806/9223372036854775807",
          0, 9223372036854775806u, INT64_MAX); /* the largest total that fits */
    cr_ok(" bytes 0-10/20 ", 0, 10, 20);     /* leading/trailing spaces tolerated */
    cr_ok("bytes 0-10/20\t", 0, 10, 20);
    cr_ok("bytes  0-10/20", 0, 10, 20);     /* extra spaces tolerated */
}

static void test_content_range_bad(void) {
    wtls_http_content_range cr;
    CHECK_EQ_INT(wtls_http_parse_content_range(NULL, &cr), WTLS_ERR_ARG);
    CHECK_EQ_INT(wtls_http_parse_content_range("bytes 0-0/1", NULL), WTLS_ERR_ARG);
    cr_bad("bytes */1230");            /* unsatisfied range */
    cr_bad("bytes 5-4/10");            /* start > end */
    cr_bad("bytes 0-10/10");           /* end >= total */
    cr_bad("bytes 0-10/0");            /* total 0 */
    cr_bad("bytes 0-10");              /* no total */
    cr_bad("bytes 0/10-20");           /* wrong shape */
    cr_bad("bytes=0-10/20");           /* request-header style */
    cr_bad("bytes0-10/20");            /* missing space */
    cr_bad("bytes 0 - 10/20");         /* spaces inside the range */
    cr_bad("bytes 0-10/20x");          /* trailing garbage */
    cr_bad("bytes 0-10/20 9");         /* trailing number */
    cr_bad("byte 0-10/20");            /* wrong unit */
    cr_bad("bytes -1-10/20");          /* no sign allowed */
    cr_bad("bytes 0-18446744073709551616/20"); /* end overflows uint64 */
    cr_bad("bytes 0-10/18446744073709551616"); /* total overflows uint64 */
    cr_bad("bytes 0-20/18446744073709551615"); /* total does not fit int64 */
    cr_bad("");
}

int main(void) {
    RUN(test_url_encode_vectors);
    RUN(test_url_encode_args);
    RUN(test_url_encode_all_bytes);
    RUN(test_content_range_ok);
    RUN(test_content_range_bad);
    return CHECK_DONE();
}
