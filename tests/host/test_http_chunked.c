/* In-place chunked decoder (src/http/wtls_http_chunked.c). */
#include <stdlib.h>
#include <string.h>

#include "check.h"
#include "http/wtls_http_chunked.h"

WTLS_CHECK_DEFINE_COUNTERS;

/* Feeds s in pieces of at most step bytes (0: all at once) starting with a
 * first piece of `first` bytes (0: none). Collects the payload into pay.
 * Returns the last status; *rest from the last call. */
static int run(const char *s, size_t n, size_t first, size_t step, char *pay, size_t *pay_len, size_t *rest) {
    wtls_chunked d;
    wtls_chunked_init(&d);
    *pay_len = 0;
    *rest = 0;
    size_t pos = 0;
    int r = WTLS_WANT_READ;
    while (pos < n) {
        size_t take = n - pos;
        if (pos == 0 && first) take = first;
        else if (step && take > step) take = step;
        uint8_t *b = malloc(take);
        memcpy(b, s + pos, take);
        size_t out = 0;
        r = wtls_chunked_decode(&d, b, take, &out, rest);
        if (r == WTLS_OK || r == WTLS_WANT_READ) {
            memcpy(pay + *pay_len, b, out);
            *pay_len += out;
        }
        free(b);
        pos += take;
        if (r != WTLS_WANT_READ) break;
        if (pos < n && step == 1) CHECK_EQ_INT(r, WTLS_WANT_READ);
    }
    return r;
}

static void expect(const char *s, const char *want) {
    char pay[256];
    size_t pl, rest;
    int r = run(s, strlen(s), 0, 0, pay, &pl, &rest);
    CHECK_EQ_INT(r, WTLS_OK);
    CHECK_EQ_INT(rest, 0);
    CHECK_EQ_INT(pl, strlen(want));
    if (pl == strlen(want)) CHECK_MEM(pay, want, pl);
}

static const char *const k_ext = "3;ext=1\r\nabc\r\nA\r\n0123456789\r\n0\r\nX-T: 1\r\n\r\n";

static void test_chunked_basic(void) { expect("5\r\nhello\r\n0\r\n\r\n", "hello"); }

static void test_chunked_ext_trailer(void) { expect(k_ext, "abc0123456789"); }

static void test_chunked_bytewise(void) {
    char pay[256];
    size_t pl, rest;
    CHECK_EQ_INT(run(k_ext, strlen(k_ext), 0, 1, pay, &pl, &rest), WTLS_OK);
    CHECK_EQ_INT(pl, 13);
    CHECK_MEM(pay, "abc0123456789", 13);
}

static void test_chunked_every_split(void) {
    size_t n = strlen(k_ext);
    for (size_t k = 1; k < n; k++) {
        char pay[256];
        size_t pl, rest;
        int r = run(k_ext, n, k, 0, pay, &pl, &rest);
        CHECK_EQ_INT(r, WTLS_OK);
        CHECK_EQ_INT(pl, 13);
        if (pl == 13) CHECK_MEM(pay, "abc0123456789", 13);
    }
}

static void test_chunked_rest(void) {
    const char *s = "5\r\nhello\r\n0\r\n\r\nXYZ";
    size_t n = strlen(s);
    uint8_t b[64];
    memcpy(b, s, n);
    wtls_chunked d;
    wtls_chunked_init(&d);
    size_t out, rest;
    CHECK_EQ_INT(wtls_chunked_decode(&d, b, n, &out, &rest), WTLS_OK);
    CHECK_EQ_INT(out, 5);
    CHECK_MEM(b, "hello", 5);
    CHECK_EQ_INT(rest, 3);
    CHECK_MEM(b + n - 3, "XYZ", 3);
}

static void test_chunked_lf_only(void) { expect("5\nhello\n0\n\n", "hello"); }
static void test_chunked_leading_zeros(void) { expect("0005\r\nhello\r\n0\r\n\r\n", "hello"); }
static void test_chunked_upper_hex(void) { expect("A\r\n0123456789\r\n0\r\n\r\n", "0123456789"); }

static int decode_all(const char *s, size_t n) {
    uint8_t *b = malloc(n ? n : 1);
    memcpy(b, s, n);
    wtls_chunked d;
    wtls_chunked_init(&d);
    size_t out, rest;
    int r = wtls_chunked_decode(&d, b, n, &out, &rest);
    free(b);
    return r;
}

static void test_chunked_rejects(void) {
    static const char *const bad[] = {"g\r\n", "-1\r\n", "\r\n", "5\r\nhelloX\r\n", "10000000000000000\r\n"};
    for (size_t i = 0; i < sizeof bad / sizeof bad[0]; i++) {
        int r = decode_all(bad[i], strlen(bad[i]));
        if (r != WTLS_ERR_HTTP) TLOG("  case %u -> %d\n", (unsigned)i, r);
        CHECK_EQ_INT(r, WTLS_ERR_HTTP);
    }
    char *big = malloc(20000);
    big[0] = '1';
    big[1] = ';';
    memset(big + 2, 'x', 1023); /* 1025 bytes before the line end */
    memcpy(big + 1025, "\r\n", 2);
    CHECK_EQ_INT(decode_all(big, 1027), WTLS_ERR_HTTP_LIMIT);
    memcpy(big, "0\r\nX: ", 6);
    memset(big + 6, 'y', 16500);
    memcpy(big + 16506, "\r\n\r\n", 4);
    CHECK_EQ_INT(decode_all(big, 16510), WTLS_ERR_HTTP_LIMIT);
    free(big);
}

static void test_chunked_after_done(void) {
    uint8_t b[32];
    memcpy(b, "0\r\n\r\n", 5);
    wtls_chunked d;
    wtls_chunked_init(&d);
    size_t out, rest;
    CHECK_EQ_INT(wtls_chunked_decode(&d, b, 5, &out, &rest), WTLS_OK);
    CHECK_EQ_INT(out, 0);
    memcpy(b, "abc", 3);
    CHECK_EQ_INT(wtls_chunked_decode(&d, b, 3, &out, &rest), WTLS_OK);
    CHECK_EQ_INT(out, 0);
    CHECK_EQ_INT(rest, 3);
}

int main(void) {
    RUN(test_chunked_basic);
    RUN(test_chunked_ext_trailer);
    RUN(test_chunked_bytewise);
    RUN(test_chunked_every_split);
    RUN(test_chunked_rest);
    RUN(test_chunked_lf_only);
    RUN(test_chunked_leading_zeros);
    RUN(test_chunked_upper_hex);
    RUN(test_chunked_rejects);
    RUN(test_chunked_after_done);
    return CHECK_DONE();
}
