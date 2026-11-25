/* Mutation test for the HTTP head parser, framing and chunked decoder:
 * valid templates, 1..8 random mutations each, deterministic (xorshift32,
 * seed 1). WTLS_FUZZ_ITERS overrides the iteration count (200000). Checks
 * the return-value set and the output bounds; ASan/UBSan (CI job host-asan)
 * catch memory errors. */
#include <stdlib.h>
#include <string.h>

#include "check.h"
#include "http/wtls_http_chunked.h"
#include "http/wtls_http_parse.h"

WTLS_CHECK_DEFINE_COUNTERS;

static uint32_t s_rng = 1;

static uint32_t rnd(void) {
    uint32_t x = s_rng;
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    return s_rng = x;
}

static const char *const k_templates[] = {
    "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello",
    "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n",
    "HTTP/1.0 404 Not Found\r\nX-Long: a\r\n  b\r\nContent-Length: 0\r\n\r\n",
    "HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n",
    "HTTP/1.1 301 Moved\r\nLocation: /x\r\nContent-Length: 5, 5\r\n\r\n",
    "HTTP/1.1 200 OK\nContent-Type: text/plain\nTransfer-Encoding: Chunked\n\n",
    "3;ext=1\r\nabc\r\nA\r\n0123456789\r\n0\r\nX-T: 1\r\n\r\n",
    "0005\r\nhello\r\n1a;q=\"x\"\r\n0123456789abcdef0123456789\r\n0\r\n\r\nrest",
    "5\nhello\n0\nTrailer-A: 1\nTrailer-B: 2\n\n",
    "HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok",
};

#define MAXBUF 1024

static size_t mutate(uint8_t *b, size_t n) {
    int count = 1 + (int)(rnd() % 8);
    for (int m = 0; m < count; m++) {
        uint32_t op = rnd() % 5;
        size_t at = n ? rnd() % n : 0;
        switch (op) {
        case 0: /* flip */
            if (n) b[at] ^= (uint8_t)(1u << (rnd() % 8));
            break;
        case 1: /* insert */
            if (n < MAXBUF) {
                memmove(b + at + 1, b + at, n - at);
                static const uint8_t interesting[] = {'\r', '\n', ':', ';', ' ', '\t', '0', 'f', ',', 0};
                b[at] = (rnd() & 1) ? interesting[rnd() % sizeof interesting] : (uint8_t)rnd();
                n++;
            }
            break;
        case 2: /* delete */
            if (n) {
                memmove(b + at, b + at + 1, n - at - 1);
                n--;
            }
            break;
        case 3: { /* duplicate a range */
            size_t len = n ? 1 + rnd() % 16 : 0;
            if (at + len > n) len = n - at;
            if (n + len <= MAXBUF) {
                memmove(b + at + len, b + at, n - at);
                n += len;
            }
            break;
        }
        default: /* truncate */
            n = at;
            break;
        }
    }
    return n;
}

/* Outcome counters: every class must occur, or the mutations never reach the deep paths. */
static long s_head_ok, s_head_err, s_frame_ok, s_chunk_ok, s_chunk_err;

static bool status_ok(int r) {
    return r == WTLS_OK || r == WTLS_WANT_READ || r == WTLS_ERR_HTTP || r == WTLS_ERR_HTTP_LIMIT;
}

static void check_head(const uint8_t *in, size_t n) {
    size_t end = wtls_http_head_end((const char *)in, n);
    CHECK(end <= n);
    if (!end) return;
    char *copy = malloc(end);
    memcpy(copy, in, end);
    static wtls_http_head h;
    int r = wtls_http_parse_head(copy, end, &h);
    CHECK(status_ok(r) && r != WTLS_WANT_READ);
    if (r == WTLS_OK) s_head_ok++;
    else s_head_err++;
    if (r == WTLS_OK) {
        CHECK(h.status >= 100 && h.status <= 599 && h.n_fields <= WTLS_HTTP_MAX_FIELDS);
        wtls_http_framing f;
        int fr = wtls_http_frame(&h, rnd() & 1, rnd() & 1, &f);
        CHECK(fr == WTLS_OK || fr == WTLS_ERR_HTTP);
        if (fr == WTLS_OK) s_frame_ok++;
    }
    free(copy);
}

static void check_chunked(const uint8_t *in, size_t n) {
    wtls_chunked d;
    wtls_chunked_init(&d);
    size_t pos = 0;
    while (pos < n) {
        size_t take = 1 + rnd() % (n - pos);
        uint8_t *piece = malloc(take);
        memcpy(piece, in + pos, take);
        size_t out = 0, rest = 0;
        int r = wtls_chunked_decode(&d, piece, take, &out, &rest);
        free(piece);
        CHECK(status_ok(r));
        CHECK(out <= take && rest <= take && out + rest <= take);
        if (r == WTLS_OK) s_chunk_ok++;
        else if (r != WTLS_WANT_READ) s_chunk_err++;
        if (r != WTLS_WANT_READ) return;
        pos += take;
    }
}

static void test_fuzz(void) {
    long iters = 200000;
    const char *env = getenv("WTLS_FUZZ_ITERS");
    if (env && atol(env) > 0) iters = atol(env);
    static uint8_t buf[MAXBUF];
    size_t nt = sizeof k_templates / sizeof k_templates[0];
    for (long i = 0; i < iters && !wtls_t_cur_failed; i++) {
        const char *t = k_templates[rnd() % nt];
        size_t n = strlen(t);
        memcpy(buf, t, n);
        n = mutate(buf, n);
        check_head(buf, n);
        check_chunked(buf, n);
        /* the body part of a template whose head survived */
        size_t end = wtls_http_head_end((const char *)buf, n);
        if (end) check_chunked(buf + end, n - end);
    }
    TLOG("  %ld iterations: head ok %ld err %ld, framed %ld, chunked ok %ld err %ld\n", iters, s_head_ok,
         s_head_err, s_frame_ok, s_chunk_ok, s_chunk_err);
    CHECK(s_head_ok > 0 && s_head_err > 0 && s_frame_ok > 0 && s_chunk_ok > 0 && s_chunk_err > 0);
}

int main(void) {
    RUN(test_fuzz);
    return CHECK_DONE();
}
