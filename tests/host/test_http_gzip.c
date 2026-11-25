/* gzip decoder (src/http/wtls_http_gzip.c) with embedded vectors made by
 * Python's gzip.compress(..., mtime=0). */
#include <string.h>

#include "check.h"
#include "http/wtls_http_gzip.h"

WTLS_CHECK_DEFINE_COUNTERS;

/* "hello, wii" */
static const uint8_t k_one[] = {0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x0a, 0xcb, 0x48, 0xcd, 0xc9, 0xc9,
                                0xd7, 0x51, 0x28, 0xcf, 0xcc, 0x04, 0x00, 0x0f, 0xdc, 0x52, 0x70, 0x0a, 0x00, 0x00, 0x00};
/* "abc" + "defg" as two members */
static const uint8_t k_two[] = {0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x0a, 0x4b, 0x4c, 0x4a, 0x06, 0x00, 0xc2,
                                0x41, 0x24, 0x35, 0x03, 0x00, 0x00, 0x00, 0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
                                0x0a, 0x4b, 0x49, 0x4d, 0x4b, 0x07, 0x00, 0x59, 0x8e, 0x6d, 0x3b, 0x04, 0x00, 0x00, 0x00};
/* "" */
static const uint8_t k_empty[] = {0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x0a,
                                  0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
/* k_one with one CRC bit flipped */
static const uint8_t k_badcrc[] = {0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x0a, 0xcb, 0x48, 0xcd, 0xc9, 0xc9,
                                   0xd7, 0x51, 0x28, 0xcf, 0xcc, 0x04, 0x00, 0x0e, 0xdc, 0x52, 0x70, 0x0a, 0x00, 0x00, 0x00};

/* Decodes in with input pieces of in_step bytes and output room of out_step
 * bytes; returns the first error, else wtls_gzip_finish(). */
static int decode(const uint8_t *in, size_t len, size_t in_step, size_t out_step, char *out, size_t cap,
                  size_t *out_len) {
    wtls_gzip *g = wtls_gzip_new();
    CHECK(g != NULL);
    if (!g) return WTLS_ERR_NOMEM;
    size_t off = 0, fill = 0;
    int st = WTLS_OK;
    for (int guard = 0; guard < 100000 && st == WTLS_OK; guard++) {
        size_t n = len - off < in_step ? len - off : in_step;
        size_t room = cap - fill < out_step ? cap - fill : out_step;
        size_t used = 0, produced = 0;
        st = wtls_gzip_inflate(g, in + off, n, &used, (uint8_t *)out + fill, room, &produced);
        CHECK(used <= n && produced <= room);
        if (st == WTLS_OK) CHECK(produced > 0 || used == n); /* the contract: output, or all input taken */
        off += used;
        fill += produced;
        if (st == WTLS_OK && off == len && produced == 0) break;
    }
    if (st == WTLS_OK) st = wtls_gzip_finish(g);
    wtls_gzip_free(g);
    *out_len = fill;
    return st;
}

static void expect_text(const uint8_t *in, size_t len, const char *want) {
    static const size_t steps[][2] = {{100000, 100000}, {1, 1}, {1, 100000}, {100000, 1}, {7, 3}};
    for (size_t i = 0; i < sizeof steps / sizeof steps[0]; i++) {
        char out[64];
        size_t n = 0;
        CHECK_EQ_INT(decode(in, len, steps[i][0], steps[i][1], out, sizeof out, &n), WTLS_OK);
        CHECK_EQ_INT(n, strlen(want));
        CHECK(n == strlen(want) && memcmp(out, want, n) == 0);
    }
}

static void gzip_one_member(void) { expect_text(k_one, sizeof k_one, "hello, wii"); }

static void gzip_two_members(void) { expect_text(k_two, sizeof k_two, "abcdefg"); }

static void gzip_empty_content(void) { expect_text(k_empty, sizeof k_empty, ""); }

static void gzip_no_input_is_empty(void) {
    char out[8];
    size_t n = 1;
    CHECK_EQ_INT(decode(k_one, 0, 1, 1, out, sizeof out, &n), WTLS_OK);
    CHECK_EQ_INT(n, 0);
}

static void gzip_bad_crc(void) {
    char out[64];
    size_t n;
    CHECK_EQ_INT(decode(k_badcrc, sizeof k_badcrc, 100000, 100000, out, sizeof out, &n), WTLS_ERR_HTTP);
    CHECK_EQ_INT(decode(k_badcrc, sizeof k_badcrc, 1, 1, out, sizeof out, &n), WTLS_ERR_HTTP);
}

static void gzip_truncated(void) {
    char out[64];
    size_t n;
    for (size_t cut = 1; cut < sizeof k_one; cut++)
        CHECK_EQ_INT(decode(k_one, sizeof k_one - cut, 3, 5, out, sizeof out, &n), WTLS_ERR_IO);
    /* a second member cut inside its header */
    CHECK_EQ_INT(decode(k_two, 23 + 4, 100000, 100000, out, sizeof out, &n), WTLS_ERR_IO);
}

static void gzip_not_gzip(void) {
    char out[64];
    size_t n;
    static const uint8_t plain[] = "hello world";
    CHECK_EQ_INT(decode(plain, sizeof plain - 1, 100000, 100000, out, sizeof out, &n), WTLS_ERR_HTTP);
}

static void gzip_trailing_garbage(void) {
    uint8_t in[sizeof k_one + 3];
    memcpy(in, k_one, sizeof k_one);
    memcpy(in + sizeof k_one, "xyz", 3);
    char out[64];
    size_t n;
    CHECK_EQ_INT(decode(in, sizeof in, 100000, 100000, out, sizeof out, &n), WTLS_ERR_HTTP);
}

int main(void) {
    RUN(gzip_one_member);
    RUN(gzip_two_members);
    RUN(gzip_empty_content);
    RUN(gzip_no_input_is_empty);
    RUN(gzip_bad_crc);
    RUN(gzip_truncated);
    RUN(gzip_not_gzip);
    RUN(gzip_trailing_garbage);
    wtls_gzip_free(NULL);
    return CHECK_DONE();
}
