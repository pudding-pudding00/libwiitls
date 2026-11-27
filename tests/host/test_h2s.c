/* Unit tests of the HTTP/2 session engine (wtls_h2s.c) against scripted server bytes. */
#include <stdlib.h>
#include <string.h>

#include "check.h"
#include "http/wtls_h2s.h"

WTLS_CHECK_DEFINE_COUNTERS;

#define BUFSZ (1u << 20)

typedef struct {
    uint8_t *in;
    size_t in_len, in_off;
    uint8_t *out;
    size_t out_len;
    bool block_write, closed;
    const void *last_ptr; /* of a write answered with WANT_WRITE: the retry must repeat it */
    size_t last_len;
    bool retry_mismatch;
    size_t max_write;     /* 0 = unlimited, else bytes accepted per call */
} tp;

static int t_read(void *c, void *buf, size_t len) {
    tp *t = c;
    if (t->in_off < t->in_len) {
        size_t n = t->in_len - t->in_off;
        if (n > len) n = len;
        memcpy(buf, t->in + t->in_off, n);
        t->in_off += n;
        return (int)n;
    }
    return t->closed ? WTLS_ERR_CLOSED : WTLS_WANT_READ;
}

static int t_write(void *c, const void *buf, size_t len) {
    tp *t = c;
    if (t->last_ptr && (buf != t->last_ptr || len != t->last_len)) t->retry_mismatch = true;
    if (t->block_write) {
        t->last_ptr = buf;
        t->last_len = len;
        return WTLS_WANT_WRITE;
    }
    t->last_ptr = NULL;
    if (t->max_write && len > t->max_write) len = t->max_write;
    memcpy(t->out + t->out_len, buf, len);
    t->out_len += len;
    return (int)len;
}

static const h2s_io IO = {t_read, t_write};

typedef struct {
    tp t;
    h2s_session *s;
} fx;

static void fx_init(fx *f, uint32_t max_streams, uint32_t window) {
    memset(f, 0, sizeof *f);
    f->t.in = malloc(BUFSZ);
    f->t.out = malloc(BUFSZ);
    f->s = h2s_create(&IO, &f->t, max_streams, window);
}

static void fx_free(fx *f) {
    h2s_destroy(f->s);
    free(f->t.in);
    free(f->t.out);
}

/* ---- server side frame builders ---- */

static void sf(fx *f, uint8_t type, uint8_t flags, uint32_t id, const void *p, size_t len) {
    uint8_t *d = f->t.in + f->t.in_len;
    d[0] = (uint8_t)(len >> 16);
    d[1] = (uint8_t)(len >> 8);
    d[2] = (uint8_t)len;
    d[3] = type;
    d[4] = flags;
    d[5] = (uint8_t)(id >> 24);
    d[6] = (uint8_t)(id >> 16);
    d[7] = (uint8_t)(id >> 8);
    d[8] = (uint8_t)id;
    if (len) memcpy(d + 9, p, len);
    f->t.in_len += 9 + len;
}

static void sf_u32(fx *f, uint8_t type, uint32_t id, uint32_t v) {
    uint8_t p[4] = {(uint8_t)(v >> 24), (uint8_t)(v >> 16), (uint8_t)(v >> 8), (uint8_t)v};
    sf(f, type, 0, id, p, 4);
}

static void sf_setting(fx *f, uint16_t id, uint32_t v) {
    uint8_t p[6] = {(uint8_t)(id >> 8), (uint8_t)id, (uint8_t)(v >> 24), (uint8_t)(v >> 16), (uint8_t)(v >> 8), (uint8_t)v};
    sf(f, 4, 0, 0, p, 6);
}

static void sf_goaway(fx *f, uint32_t last, uint32_t code) {
    uint8_t p[8] = {(uint8_t)(last >> 24), (uint8_t)(last >> 16), (uint8_t)(last >> 8), (uint8_t)last, 0, 0, 0, (uint8_t)code};
    sf(f, 7, 0, 0, p, 8);
}

/* :status 200 (indexed), optionally content-length as a literal. */
static void sf_head(fx *f, uint32_t id, bool end_stream) {
    static const uint8_t b[] = {0x88};
    sf(f, 1, (uint8_t)(0x04 | (end_stream ? 1 : 0)), id, b, sizeof b);
}

static void sf_data(fx *f, uint32_t id, const void *p, size_t len, bool end_stream) {
    sf(f, 0, end_stream ? 1 : 0, id, p, len);
}

/* ---- client output inspection ---- */

typedef struct {
    uint8_t type, flags;
    uint32_t id, len;
    const uint8_t *p;
} cf;

/* The n-th frame after the 24 byte preface; false past the end. */
static bool out_frame(const fx *f, size_t n, cf *o) {
    size_t off = 24;
    for (size_t i = 0;; i++) {
        if (off + 9 > f->t.out_len) return false;
        const uint8_t *d = f->t.out + off;
        uint32_t len = ((uint32_t)d[0] << 16) | ((uint32_t)d[1] << 8) | d[2];
        if (off + 9 + len > f->t.out_len) return false;
        if (i == n) {
            o->type = d[3];
            o->flags = d[4];
            o->id = (((uint32_t)d[5] << 24) | ((uint32_t)d[6] << 16) | ((uint32_t)d[7] << 8) | d[8]) & 0x7fffffffu;
            o->len = len;
            o->p = d + 9;
            return true;
        }
        off += 9 + len;
    }
}

static size_t count_frames(const fx *f, uint8_t type, uint32_t id) {
    cf c;
    size_t n = 0;
    for (size_t i = 0; out_frame(f, i, &c); i++)
        if (c.type == type && (id == UINT32_MAX || c.id == id)) n++;
    return n;
}

static bool find_frame(const fx *f, uint8_t type, uint32_t id, cf *o) {
    for (size_t i = 0; out_frame(f, i, o); i++)
        if (o->type == type && o->id == id) return true;
    return false;
}

static uint32_t sum_window_updates(const fx *f, uint32_t id) {
    cf c;
    uint32_t sum = 0;
    for (size_t i = 0; out_frame(f, i, &c); i++)
        if (c.type == 8 && c.id == id && c.len == 4)
            sum += (((uint32_t)c.p[0] << 24) | ((uint32_t)c.p[1] << 16) | ((uint32_t)c.p[2] << 8) | c.p[3]);
    return sum;
}

/* ---- helpers ---- */

static wtls_url URL;

static h2s_stream *get(fx *f, const char *path) {
    h2s_stream *st = NULL;
    CHECK_EQ_INT(h2s_stream_open(f->s, &st), WTLS_OK);
    static char raw[128]; /* URL fields point into it */
    strcpy(raw, "https://example.test");
    strcat(raw, path);
    CHECK_EQ_INT(wtls_url_parse(raw, &URL), WTLS_OK);
    CHECK_EQ_INT(h2s_stream_send_headers(st, "GET", &URL, NULL, 0, false, 0, false, false), WTLS_OK);
    return st;
}

static void take_head(h2s_stream *st, int status) {
    wtls_http_head h;
    char *arena = NULL;
    CHECK_EQ_INT(h2s_stream_head(st, &h, &arena), WTLS_OK);
    CHECK_EQ_INT(h.status, status);
    free(arena);
}

static void pump_ok(fx *f) { CHECK_EQ_INT(h2s_pump(f->s), WTLS_OK); }

static void test_h2s_basic(void) {
    fx f;
    fx_init(&f, 4, 32768);
    CHECK(f.s != NULL);
    pump_ok(&f);
    CHECK(memcmp(f.t.out, "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n", 24) == 0);
    cf c;
    CHECK(out_frame(&f, 0, &c) && c.type == 4 && c.len == 18);
    CHECK(out_frame(&f, 1, &c) && c.type == 8 && c.id == 0);
    CHECK_EQ_INT((int)sum_window_updates(&f, 0), 4 * 32768 - 65535);

    sf(&f, 4, 0, 0, NULL, 0);
    h2s_stream *st = get(&f, "/a");
    CHECK(find_frame(&f, 1, 1, &c) == false); /* queued, not yet written */
    pump_ok(&f);
    bool acked = false;
    for (size_t i = 0; out_frame(&f, i, &c); i++) acked |= c.type == 4 && (c.flags & 1);
    CHECK(acked); /* SETTINGS ACK */
    CHECK(find_frame(&f, 1, 1, &c) && c.flags == 5);  /* END_STREAM | END_HEADERS */

    wtls_http_head h;
    char *arena;
    CHECK_EQ_INT(h2s_stream_head(st, &h, &arena), WTLS_WANT_READ);
    sf_head(&f, 1, false);
    sf_data(&f, 1, "hello", 5, true);
    pump_ok(&f);
    take_head(st, 200);
    char buf[16];
    bool eof;
    CHECK_EQ_INT(h2s_stream_read(st, buf, sizeof buf, &eof), 5);
    CHECK(memcmp(buf, "hello", 5) == 0 && !eof);
    CHECK_EQ_INT(h2s_stream_read(st, buf, sizeof buf, &eof), 0);
    CHECK(eof);
    CHECK(h2s_stream_ended(st));
    h2s_stream_release(st);
    CHECK_EQ_INT((int)h2s_active(f.s), 0);
    CHECK_EQ_INT((int)count_frames(&f, 3, UINT32_MAX), 0); /* finished: no RST_STREAM */
    fx_free(&f);
}

static void test_h2s_interleaved(void) {
    fx f;
    fx_init(&f, 4, 32768);
    sf(&f, 4, 0, 0, NULL, 0);
    h2s_stream *a = get(&f, "/a"), *b = get(&f, "/b");
    sf_head(&f, 3, false);
    sf_head(&f, 1, false);
    sf_data(&f, 1, "AA", 2, false);
    sf_data(&f, 3, "bbb", 3, false);
    sf_data(&f, 1, "AA", 2, true);
    sf_data(&f, 3, "bbb", 3, true);
    pump_ok(&f);
    cf c;
    CHECK(find_frame(&f, 1, 1, &c) && find_frame(&f, 1, 3, &c));
    take_head(a, 200);
    take_head(b, 200);
    char buf[16];
    bool eof;
    CHECK_EQ_INT(h2s_stream_read(a, buf, sizeof buf, &eof), 4);
    CHECK(memcmp(buf, "AAAA", 4) == 0);
    CHECK_EQ_INT(h2s_stream_read(b, buf, sizeof buf, &eof), 6);
    CHECK(memcmp(buf, "bbbbbb", 6) == 0);
    h2s_stream_release(a);
    h2s_stream_release(b);
    fx_free(&f);
}

static void test_h2s_stream_limits(void) {
    fx f;
    fx_init(&f, 2, 32768);
    sf(&f, 4, 0, 0, NULL, 0);
    pump_ok(&f);
    h2s_stream *a = get(&f, "/a"), *b = get(&f, "/b"), *x = NULL;
    CHECK_EQ_INT(h2s_stream_open(f.s, &x), WTLS_WANT_READ); /* client cap */
    h2s_stream_release(b);
    CHECK_EQ_INT(h2s_stream_open(f.s, &x), WTLS_OK);
    h2s_stream_release(x);
    h2s_stream_release(a);
    fx_free(&f);

    fx_init(&f, 4, 32768);
    sf_setting(&f, 3, 1); /* server: one concurrent stream */
    pump_ok(&f);
    CHECK_EQ_INT((int)h2s_capacity(f.s), 1);
    a = get(&f, "/a");
    CHECK_EQ_INT(h2s_stream_open(f.s, &x), WTLS_WANT_READ);
    sf_head(&f, 1, false);
    sf_data(&f, 1, "x", 1, true);
    pump_ok(&f);
    CHECK(h2s_stream_ended(a));
    CHECK_EQ_INT(h2s_stream_open(f.s, &x), WTLS_OK); /* a is closed on the wire, still held by the application */
    h2s_stream_release(x);
    h2s_stream_release(a);
    fx_free(&f);
}

static void test_h2s_limit_lowered_by_settings(void) {
    fx f;
    fx_init(&f, 4, 32768);
    sf(&f, 4, 0, 0, NULL, 0);
    h2s_stream *a = get(&f, "/a"), *b = get(&f, "/b"), *x = NULL;
    CHECK_EQ_INT(h2s_stream_open(f.s, &x), WTLS_OK);
    sf_setting(&f, 3, 2);
    pump_ok(&f);
    CHECK_EQ_INT(h2s_stream_send_headers(x, "GET", &URL, NULL, 0, false, 0, false, false), WTLS_WANT_READ);
    sf_head(&f, 1, true);
    pump_ok(&f);
    CHECK_EQ_INT(h2s_stream_send_headers(x, "GET", &URL, NULL, 0, false, 0, false, false), WTLS_OK);
    cf c;
    pump_ok(&f);
    CHECK(find_frame(&f, 1, 5, &c)); /* ids stay in order: a=1, b=3, x=5 */
    h2s_stream_release(a);
    h2s_stream_release(b);
    h2s_stream_release(x);
    fx_free(&f);
}

static void test_h2s_flow_control_bounded(void) {
    fx f;
    fx_init(&f, 4, 16384);
    sf(&f, 4, 0, 0, NULL, 0);
    h2s_stream *a = get(&f, "/a");
    static uint8_t blob[16384];
    memset(blob, 'z', sizeof blob);
    sf_head(&f, 1, false);
    sf_data(&f, 1, blob, sizeof blob, false);
    pump_ok(&f);
    CHECK_EQ_INT((int)h2s_stream_buffered(a), 16384);
    CHECK_EQ_INT((int)sum_window_updates(&f, 1), 0); /* nobody read: no credit */
    take_head(a, 200);
    char buf[4096];
    bool eof;
    for (int i = 0; i < 3; i++) CHECK_EQ_INT(h2s_stream_read(a, buf, sizeof buf, &eof), 4096);
    pump_ok(&f);
    CHECK_EQ_INT((int)sum_window_updates(&f, 1), 8192); /* announced in steps of half a window */
    CHECK_EQ_INT((int)h2s_stream_read(a, buf, sizeof buf, &eof), 4096);
    CHECK_EQ_INT((int)h2s_stream_read(a, buf, sizeof buf, &eof), WTLS_WANT_READ);
    pump_ok(&f);
    CHECK_EQ_INT((int)sum_window_updates(&f, 1), 16384);
    sf_data(&f, 1, blob, sizeof blob, false); /* a whole window again is fine */
    pump_ok(&f);
    CHECK_EQ_INT((int)h2s_stream_buffered(a), 16384);
    sf_data(&f, 1, blob, 1, false); /* one byte more than announced */
    CHECK(h2s_pump(f.s) != WTLS_OK);
    h2s_stream_release(a);
    fx_free(&f);

    fx_init(&f, 4, 16384);
    sf(&f, 4, 0, 0, NULL, 0);
    a = get(&f, "/a");
    sf_head(&f, 1, false);
    sf_data(&f, 1, blob, sizeof blob, false);
    sf_data(&f, 1, blob, 1, false); /* one byte over the stream window */
    CHECK(h2s_pump(f.s) != WTLS_OK);
    CHECK(h2s_stream_error(a) != 0);
    h2s_stream_release(a);
    fx_free(&f);
}

static void test_h2s_stalled_reader_does_not_block_others(void) {
    fx f;
    fx_init(&f, 2, 16384);
    sf(&f, 4, 0, 0, NULL, 0);
    h2s_stream *a = get(&f, "/a"), *b = get(&f, "/b");
    static uint8_t blob[16384];
    memset(blob, 'q', sizeof blob);
    sf_head(&f, 1, false);
    sf_head(&f, 3, false);
    sf_data(&f, 1, blob, sizeof blob, false); /* a fills its window, nobody reads it */
    sf_data(&f, 3, blob, 8192, false);
    pump_ok(&f);
    take_head(b, 200);
    char buf[8192];
    bool eof;
    CHECK_EQ_INT(h2s_stream_read(b, buf, sizeof buf, &eof), 8192);
    pump_ok(&f);
    CHECK(sum_window_updates(&f, 3) > 0); /* b is credited although a is stuck */
    CHECK_EQ_INT((int)sum_window_updates(&f, 1), 0);
    h2s_stream_release(a);
    h2s_stream_release(b);
    fx_free(&f);
}

static void test_h2s_goaway(void) {
    fx f;
    fx_init(&f, 4, 32768);
    sf(&f, 4, 0, 0, NULL, 0);
    h2s_stream *a = get(&f, "/a"), *b = get(&f, "/b"), *x = NULL;
    sf_goaway(&f, 1, 0);
    sf_head(&f, 1, false);
    sf_data(&f, 1, "ok", 2, true);
    pump_ok(&f);
    CHECK(!h2s_usable(f.s));
    CHECK_EQ_INT(h2s_stream_open(f.s, &x), WTLS_ERR_IO);
    CHECK(h2s_stream_error(b) != 0 && h2s_stream_retryable(b));
    CHECK_EQ_INT(h2s_stream_error(a), 0);
    take_head(a, 200);
    char buf[8];
    bool eof;
    CHECK_EQ_INT(h2s_stream_read(a, buf, sizeof buf, &eof), 2);
    CHECK_EQ_INT(h2s_stream_read(a, buf, sizeof buf, &eof), 0);
    CHECK(eof);
    CHECK_EQ_INT((int)count_frames(&f, 3, 3), 0); /* nothing to reset on a stream the server never saw */
    h2s_stream_release(a);
    h2s_stream_release(b);
    fx_free(&f);
}

static void test_h2s_rst(void) {
    fx f;
    fx_init(&f, 4, 32768);
    sf(&f, 4, 0, 0, NULL, 0);
    h2s_stream *a = get(&f, "/a"), *b = get(&f, "/b"), *c3 = get(&f, "/c");
    sf_u32(&f, 3, 1, 7); /* REFUSED_STREAM */
    sf_u32(&f, 3, 3, 8); /* CANCEL */
    sf_head(&f, 5, true);
    pump_ok(&f);
    CHECK(h2s_stream_error(a) != 0 && h2s_stream_retryable(a));
    CHECK(h2s_stream_error(b) != 0 && !h2s_stream_retryable(b));
    CHECK_EQ_INT(h2s_stream_error(c3), 0);
    take_head(c3, 200);
    CHECK(h2s_stream_ended(c3));
    h2s_stream_release(a);
    h2s_stream_release(b);
    h2s_stream_release(c3);
    fx_free(&f);
}

static void test_h2s_cancel_and_late_frames(void) {
    fx f;
    fx_init(&f, 4, 32768);
    sf(&f, 4, 0, 0, NULL, 0);
    h2s_stream *a = get(&f, "/a"), *b = get(&f, "/b");
    pump_ok(&f);
    h2s_stream_release(a); /* unfinished: reset this stream only */
    pump_ok(&f);
    cf c;
    CHECK(find_frame(&f, 3, 1, &c) && c.len == 4 && c.p[3] == 8);
    CHECK_EQ_INT((int)count_frames(&f, 3, 3), 0);
    /* the server's response for the cancelled stream is still on its way: dropped, but credited to the connection */
    static uint8_t blob[16384];
    sf_head(&f, 1, false);
    sf_data(&f, 1, blob, sizeof blob, false);
    sf_head(&f, 3, false);
    sf_data(&f, 3, "b", 1, true);
    pump_ok(&f);
    CHECK(sum_window_updates(&f, 0) >= 16384 + (uint32_t)(4 * 32768 - 65535));
    take_head(b, 200);
    char buf[4];
    bool eof;
    CHECK_EQ_INT(h2s_stream_read(b, buf, sizeof buf, &eof), 1);
    h2s_stream_release(b);
    fx_free(&f);
}

static void test_h2s_hpack_table_shared_with_cancelled_stream(void) {
    fx f;
    fx_init(&f, 4, 32768);
    sf(&f, 4, 0, 0, NULL, 0);
    h2s_stream *a = get(&f, "/a"), *b = get(&f, "/b");
    pump_ok(&f);
    h2s_stream_release(a);
    /* stream 1's head adds "x-a: 1" to the dynamic table; stream 3 then refers to it by index */
    static const uint8_t blk1[] = {0x88, 0x40, 3, 'x', '-', 'a', 1, '1'};
    sf(&f, 1, 4, 1, blk1, sizeof blk1);
    static const uint8_t blk3[] = {0x88, 0xbe};
    sf(&f, 1, 4 | 1, 3, blk3, sizeof blk3);
    pump_ok(&f);
    wtls_http_head h;
    char *arena;
    CHECK_EQ_INT(h2s_stream_head(b, &h, &arena), WTLS_OK);
    CHECK_EQ_INT(h.status, 200);
    CHECK(h.n_fields == 1 && strcmp(h.fields[0].name, "x-a") == 0 && strcmp(h.fields[0].value, "1") == 0);
    free(arena);
    h2s_stream_release(b);
    fx_free(&f);
}

static void test_h2s_trailers(void) {
    fx f;
    fx_init(&f, 4, 32768);
    sf(&f, 4, 0, 0, NULL, 0);
    h2s_stream *a = get(&f, "/a"), *b = get(&f, "/b");
    sf_head(&f, 1, false);
    sf_data(&f, 1, "t", 1, false);
    static const uint8_t tr[] = {0x40, 3, 'x', '-', 't', 1, '2'}; /* trailers, adds a table entry */
    sf(&f, 1, 4 | 1, 1, tr, sizeof tr);
    static const uint8_t blk3[] = {0x88, 0xbe};
    sf(&f, 1, 4 | 1, 3, blk3, sizeof blk3);
    pump_ok(&f);
    CHECK(h2s_stream_ended(a));
    take_head(a, 200);
    char buf[4];
    bool eof;
    CHECK_EQ_INT(h2s_stream_read(a, buf, sizeof buf, &eof), 1);
    CHECK_EQ_INT(h2s_stream_read(a, buf, sizeof buf, &eof), 0);
    CHECK(eof);
    wtls_http_head h;
    char *arena;
    CHECK_EQ_INT(h2s_stream_head(b, &h, &arena), WTLS_OK); /* decoded: the table stayed in step */
    CHECK(h.n_fields == 1 && strcmp(h.fields[0].name, "x-t") == 0);
    free(arena);
    h2s_stream_release(a);
    h2s_stream_release(b);
    fx_free(&f);

    /* trailers without END_STREAM are a stream error */
    fx_init(&f, 4, 32768);
    sf(&f, 4, 0, 0, NULL, 0);
    a = get(&f, "/a");
    sf_head(&f, 1, false);
    sf(&f, 1, 4, 1, tr, sizeof tr);
    pump_ok(&f);
    CHECK(h2s_stream_error(a) != 0);
    h2s_stream_release(a);
    fx_free(&f);
}

static void test_h2s_padding_and_continuation_and_1xx(void) {
    fx f;
    fx_init(&f, 4, 32768);
    sf(&f, 4, 0, 0, NULL, 0);
    h2s_stream *a = get(&f, "/a");
    static const uint8_t i100[] = {0x08, 3, '1', '0', '0'}; /* :status 100 */
    sf(&f, 1, 4, 1, i100, sizeof i100);
    static const uint8_t part1[] = {0x88};
    static const uint8_t part2[] = {0x40, 3, 'x', '-', 'c', 1, 'c'};
    sf(&f, 1, 0, 1, part1, sizeof part1); /* no END_HEADERS */
    sf(&f, 9, 4, 1, part2, sizeof part2);
    uint8_t padded[1 + 3 + 10];
    padded[0] = 10;
    memcpy(padded + 1, "abc", 3);
    memset(padded + 4, 0, 10);
    sf(&f, 0, 8 | 1, 1, padded, sizeof padded);
    pump_ok(&f);
    wtls_http_head h;
    char *arena;
    CHECK_EQ_INT(h2s_stream_head(a, &h, &arena), WTLS_OK);
    CHECK_EQ_INT(h.status, 200);
    CHECK(h.n_fields == 1 && strcmp(h.fields[0].name, "x-c") == 0);
    free(arena);
    char buf[8];
    bool eof;
    CHECK_EQ_INT(h2s_stream_read(a, buf, sizeof buf, &eof), 3);
    CHECK(memcmp(buf, "abc", 3) == 0);
    h2s_stream_release(a);
    fx_free(&f);

    /* another frame between HEADERS and its CONTINUATION ends the session */
    fx_init(&f, 4, 32768);
    a = get(&f, "/a");
    sf(&f, 1, 0, 1, part1, sizeof part1);
    sf(&f, 6, 0, 0, "12345678", 8);
    CHECK(h2s_pump(f.s) != WTLS_OK);
    CHECK(h2s_stream_error(a) != 0);
    h2s_stream_release(a);
    fx_free(&f);
}

static void test_h2s_ping_and_protocol_errors(void) {
    fx f;
    fx_init(&f, 4, 32768);
    sf(&f, 6, 0, 0, "abcdefgh", 8);
    pump_ok(&f);
    cf c;
    CHECK(find_frame(&f, 6, 0, &c) && (c.flags & 1) && memcmp(c.p, "abcdefgh", 8) == 0);
    fx_free(&f);

    struct {
        uint8_t type, flags;
        uint32_t id;
        const char *pay;
        size_t len;
    } bad[] = {
        {5, 4, 1, "\0\0\0\2", 4},      /* PUSH_PROMISE */
        {0, 0, 7, "x", 1},             /* DATA on an idle stream */
        {8, 0, 0, "\0\0\0\0", 4},      /* WINDOW_UPDATE 0 */
        {8, 0, 0, "\x7f\xff\xff\xff", 4}, /* connection window overflow */
        {4, 0, 3, NULL, 0},            /* SETTINGS on a stream */
        {4, 0, 0, "\0\1\0", 3},        /* SETTINGS of odd size */
        {6, 0, 0, "x", 1},             /* PING of wrong size */
        {7, 0, 0, "x", 1},             /* GOAWAY too short */
        {1, 4, 2, "\x88", 1},          /* HEADERS on an even stream */
        {9, 4, 1, "\x88", 1},          /* CONTINUATION without HEADERS */
        {3, 0, 0, "\0\0\0\0", 4},      /* RST_STREAM on stream 0 */
    };
    for (size_t i = 0; i < sizeof bad / sizeof bad[0]; i++) {
        fx_init(&f, 4, 32768);
        sf(&f, bad[i].type, bad[i].flags, bad[i].id, bad[i].pay, bad[i].len);
        CHECK(h2s_pump(f.s) != WTLS_OK);
        CHECK(!h2s_usable(f.s));
        CHECK_EQ_INT(h2s_pump(f.s), h2s_error(f.s)); /* sticky */
        fx_free(&f);
    }
    /* frame over 16384 bytes */
    fx_init(&f, 4, 32768);
    memcpy(f.t.in, "\x00\x40\x01\x00\x00\x00\x00\x00\x00", 9);
    f.t.in_len = 9;
    CHECK(h2s_pump(f.s) != WTLS_OK);
    fx_free(&f);
    /* DATA before the response head: the stream is reset, the session lives on */
    fx_init(&f, 4, 32768);
    sf(&f, 4, 0, 0, NULL, 0);
    h2s_stream *a = get(&f, "/a");
    sf_data(&f, 1, "x", 1, false);
    pump_ok(&f);
    CHECK(h2s_stream_error(a) != 0);
    CHECK(find_frame(&f, 3, 1, &c) && c.p[3] == 1);
    h2s_stream_release(a);
    fx_free(&f);
}

static void test_h2s_upload_flow_control(void) {
    fx f;
    fx_init(&f, 4, 32768);
    sf(&f, 4, 0, 0, NULL, 0);
    pump_ok(&f);
    h2s_stream *st = NULL;
    CHECK_EQ_INT(h2s_stream_open(f.s, &st), WTLS_OK);
    CHECK_EQ_INT(wtls_url_parse("https://example.test/up", &URL), WTLS_OK);
    wtls_http_header hdr[1] = {{"x-k", "v"}};
    (void)hdr;
    CHECK_EQ_INT(h2s_stream_send_headers(st, "POST", &URL, NULL, 0, true, 100000, true, false), WTLS_OK);
    static uint8_t body[100000];
    memset(body, 'u', sizeof body);
    size_t sent = 0;
    for (int guard = 0; guard < 100 && sent < sizeof body; guard++) {
        int n = h2s_stream_send_data(st, body + sent, sizeof body - sent, true);
        CHECK(n >= 0);
        if (n <= 0) break;
        sent += (size_t)n;
        pump_ok(&f);
    }
    CHECK_EQ_INT((int)sent, 65535); /* the default window of the stream and of the connection */
    CHECK_EQ_INT(h2s_stream_send_data(st, body + sent, sizeof body - sent, true), 0);
    sf_u32(&f, 8, 1, 65535);
    sf_u32(&f, 8, 0, 65535);
    pump_ok(&f);
    while (sent < sizeof body) {
        int n = h2s_stream_send_data(st, body + sent, sizeof body - sent, true);
        CHECK(n > 0);
        if (n <= 0) break;
        sent += (size_t)n;
    }
    pump_ok(&f);
    size_t total = 0;
    cf c;
    bool last_end = false;
    for (size_t i = 0; out_frame(&f, i, &c); i++)
        if (c.type == 0 && c.id == 1) {
            total += c.len;
            last_end = (c.flags & 1) != 0;
            CHECK(c.len <= 16384);
        }
    CHECK_EQ_INT((int)total, 100000);
    CHECK(last_end);
    h2s_stream_release(st);
    fx_free(&f);
}

static void test_h2s_settings_window_change(void) {
    fx f;
    fx_init(&f, 4, 32768);
    sf_setting(&f, 4, 100);
    sf(&f, 4, 0, 0, NULL, 0);
    pump_ok(&f);
    h2s_stream *st = NULL;
    CHECK_EQ_INT(h2s_stream_open(f.s, &st), WTLS_OK);
    CHECK_EQ_INT(wtls_url_parse("https://example.test/up", &URL), WTLS_OK);
    CHECK_EQ_INT(h2s_stream_send_headers(st, "POST", &URL, NULL, 0, true, 300, true, false), WTLS_OK);
    static uint8_t body[300];
    CHECK_EQ_INT(h2s_stream_send_data(st, body, 300, true), 100);
    sf_setting(&f, 4, 50); /* the window of a started stream shrinks: 0 - 50 */
    pump_ok(&f);
    CHECK_EQ_INT(h2s_stream_send_data(st, body, 200, true), 0);
    sf_u32(&f, 8, 1, 60); /* -50 + 60 = 10 */
    pump_ok(&f);
    CHECK_EQ_INT(h2s_stream_send_data(st, body, 200, true), 10);
    h2s_stream_release(st);
    fx_free(&f);
}

static void test_h2s_output_backpressure(void) {
    fx f;
    fx_init(&f, 4, 32768);
    sf_setting(&f, 4, 1u << 20);
    sf_u32(&f, 8, 0, 1u << 20);
    sf(&f, 4, 0, 0, NULL, 0);
    pump_ok(&f);
    f.t.block_write = true;
    h2s_stream *st = NULL;
    CHECK_EQ_INT(h2s_stream_open(f.s, &st), WTLS_OK);
    CHECK_EQ_INT(wtls_url_parse("https://example.test/up", &URL), WTLS_OK);
    CHECK_EQ_INT(h2s_stream_send_headers(st, "POST", &URL, NULL, 0, true, 60000, true, false), WTLS_OK);
    static uint8_t body[16384];
    size_t queued = 0;
    for (int i = 0; i < 20; i++) {
        int n = h2s_stream_send_data(st, body, sizeof body, false);
        if (n <= 0) break;
        queued += (size_t)n;
    }
    CHECK(queued >= 65536 && queued <= 65536 + 16384); /* bounded by the soft cap, not by the window */
    CHECK_EQ_INT(h2s_stream_send_data(st, body, sizeof body, false), 0);
    CHECK(h2s_wants(f.s) & 2u);
    pump_ok(&f);
    pump_ok(&f);
    f.t.block_write = false;
    pump_ok(&f);
    CHECK(!f.t.retry_mismatch); /* a blocked write is retried with the same buffer and length */
    CHECK(!(h2s_wants(f.s) & 2u));
    CHECK(h2s_stream_send_data(st, body, sizeof body, false) > 0);
    h2s_stream_release(st);
    fx_free(&f);
}

static void test_h2s_partial_writes(void) {
    fx f;
    fx_init(&f, 4, 32768);
    f.t.max_write = 7;
    sf(&f, 4, 0, 0, NULL, 0);
    h2s_stream *a = get(&f, "/a");
    for (int i = 0; i < 200; i++) pump_ok(&f);
    cf c;
    CHECK(find_frame(&f, 1, 1, &c));
    h2s_stream_release(a);
    fx_free(&f);
}

static void test_h2s_connection_lost(void) {
    fx f;
    fx_init(&f, 4, 32768);
    sf(&f, 4, 0, 0, NULL, 0);
    h2s_stream *a = get(&f, "/a"), *b = get(&f, "/b"), *c3 = get(&f, "/c");
    sf_head(&f, 3, false);
    sf_data(&f, 3, "part", 4, false);
    sf_head(&f, 5, true);
    pump_ok(&f);
    f.t.closed = true;
    CHECK(h2s_pump(f.s) != WTLS_OK);
    CHECK(h2s_stream_error(a) != 0 && h2s_stream_retryable(a)); /* nothing was received: another connection may do it */
    CHECK(h2s_stream_error(b) != 0 && !h2s_stream_retryable(b)); /* it was answered in part */
    CHECK_EQ_INT(h2s_stream_error(c3), 0);                     /* complete before the loss */
    char buf[8];
    bool eof;
    take_head(b, 200);
    CHECK_EQ_INT(h2s_stream_read(b, buf, sizeof buf, &eof), 4); /* what arrived can still be read */
    CHECK(h2s_stream_read(b, buf, sizeof buf, &eof) < 0);
    take_head(c3, 200);
    CHECK_EQ_INT(h2s_stream_read(c3, buf, sizeof buf, &eof), 0);
    CHECK(eof);
    h2s_stream_release(a);
    h2s_stream_release(b);
    h2s_stream_release(c3);
    fx_free(&f);
}

static void test_h2s_work_budget(void) {
    fx f;
    fx_init(&f, 4, 32768);
    for (int i = 0; i < 200; i++) sf(&f, 6, 0, 0, "12345678", 8);
    pump_ok(&f);
    CHECK(h2s_pending(f.s)); /* stopped at the budget with input left */
    for (int i = 0; i < 10 && h2s_pending(f.s); i++) pump_ok(&f);
    CHECK(!h2s_pending(f.s));
    CHECK_EQ_INT((int)count_frames(&f, 6, 0), 200);
    fx_free(&f);
}

static void test_h2s_stream_ids_in_send_order(void) {
    fx f;
    fx_init(&f, 4, 32768);
    sf(&f, 4, 0, 0, NULL, 0);
    h2s_stream *a = NULL, *b = NULL;
    CHECK_EQ_INT(h2s_stream_open(f.s, &a), WTLS_OK);
    CHECK_EQ_INT(h2s_stream_open(f.s, &b), WTLS_OK);
    CHECK_EQ_INT(wtls_url_parse("https://example.test/", &URL), WTLS_OK);
    CHECK_EQ_INT(h2s_stream_send_headers(b, "GET", &URL, NULL, 0, false, 0, false, false), WTLS_OK);
    CHECK_EQ_INT(h2s_stream_send_headers(a, "GET", &URL, NULL, 0, false, 0, false, false), WTLS_OK);
    pump_ok(&f);
    cf c;
    CHECK(out_frame(&f, 2, &c) && c.type == 1 && c.id == 1); /* b went first and got id 1 */
    CHECK(out_frame(&f, 3, &c) && c.type == 1 && c.id == 3);
    h2s_stream_release(a);
    h2s_stream_release(b);
    fx_free(&f);
}

int main(void) {
    RUN(test_h2s_basic);
    RUN(test_h2s_interleaved);
    RUN(test_h2s_stream_limits);
    RUN(test_h2s_limit_lowered_by_settings);
    RUN(test_h2s_flow_control_bounded);
    RUN(test_h2s_stalled_reader_does_not_block_others);
    RUN(test_h2s_goaway);
    RUN(test_h2s_rst);
    RUN(test_h2s_cancel_and_late_frames);
    RUN(test_h2s_hpack_table_shared_with_cancelled_stream);
    RUN(test_h2s_trailers);
    RUN(test_h2s_padding_and_continuation_and_1xx);
    RUN(test_h2s_ping_and_protocol_errors);
    RUN(test_h2s_upload_flow_control);
    RUN(test_h2s_settings_window_change);
    RUN(test_h2s_output_backpressure);
    RUN(test_h2s_partial_writes);
    RUN(test_h2s_connection_lost);
    RUN(test_h2s_work_budget);
    RUN(test_h2s_stream_ids_in_send_order);
    return CHECK_DONE();
}
