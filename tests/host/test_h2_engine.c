/* Unit tests of the blocking HTTP/2 engine (wtls_http2.c) against scripted server bytes. */
#include <stdlib.h>
#include <string.h>

#include "check.h"
#include "http/wtls_http2.h"
#include "http/wtls_url.h"

WTLS_CHECK_DEFINE_COUNTERS;

typedef struct {
    uint8_t in[4096];
    size_t in_len, in_off;
    unsigned writes;       /* write calls */
    unsigned split_frames; /* writes that did not end on a frame boundary */
    size_t out_len;
    size_t frame_left;     /* bytes of the current outgoing frame still to come */
    bool preface_done;
} tp;

/* Walks the client's bytes frame by frame so a frame split across two writes is seen. */
static void track(tp *t, const uint8_t *p, size_t len) {
    static uint8_t hdr[9];
    static size_t hdr_have;
    size_t i = 0;
    if (!t->preface_done) { /* the 24-byte preface is not a frame */
        i = len < 24 ? len : 24;
        t->preface_done = true;
    }
    while (i < len) {
        if (t->frame_left) {
            size_t n = len - i < t->frame_left ? len - i : t->frame_left;
            t->frame_left -= n;
            i += n;
            continue;
        }
        hdr[hdr_have++] = p[i++];
        if (hdr_have == 9) {
            t->frame_left = ((size_t)hdr[0] << 16) | ((size_t)hdr[1] << 8) | hdr[2];
            hdr_have = 0;
        }
    }
    if (t->frame_left || hdr_have) t->split_frames++;
}

static int t_read(void *ctx, void *buf, size_t len, uint32_t max_wait_ms) {
    (void)max_wait_ms;
    tp *t = ctx;
    if (t->in_off >= t->in_len) return WTLS_ERR_CLOSED;
    size_t n = t->in_len - t->in_off;
    if (n > len) n = len;
    memcpy(buf, t->in + t->in_off, n);
    t->in_off += n;
    return (int)n;
}

static int t_write(void *ctx, const void *buf, size_t len) {
    tp *t = ctx;
    t->writes++;
    t->out_len += len;
    track(t, buf, len);
    return WTLS_OK;
}

static bool t_readable(void *ctx) {
    tp *t = ctx;
    return t->in_off < t->in_len;
}

static int t_read_nowait(void *ctx, void *buf, size_t len) {
    tp *t = ctx;
    if (t->in_off >= t->in_len) return WTLS_WANT_READ;
    return t_read(ctx, buf, len, 0);
}

static const wtls_h2_io IO = {t_read, t_write, t_readable, t_read_nowait};

static void sf(tp *t, uint8_t type, uint8_t flags, uint32_t id, const void *p, size_t len) {
    uint8_t *d = t->in + t->in_len;
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
    t->in_len += 9 + len;
}

/* Server SETTINGS, then for each stream: HEADERS ":status 200" and DATA "hello" with END_STREAM. */
static void script(tp *t, unsigned streams) {
    sf(t, 0x4, 0, 0, NULL, 0);
    static const uint8_t status200 = 0x88;
    for (unsigned k = 0; k < streams; k++) {
        uint32_t id = 1u + 2u * k;
        sf(t, 0x1, 0x4, id, &status200, 1);
        sf(t, 0x0, 0x1, id, "hello", 5);
    }
}

static int one_get(wtls_h2_conn *c, const wtls_url *u) {
    int st = wtls_h2_begin_stream(c);
    if (st != WTLS_OK) return st;
    st = wtls_h2_send_headers(c, "GET", u, NULL, 0, false, 0, false, false, false);
    if (st != WTLS_OK) return st;
    wtls_http_head head;
    char *arena = NULL;
    bool got = false;
    st = wtls_h2_read_head(c, 1000, &head, &arena, &got);
    if (st != WTLS_OK) return st;
    free(arena);
    if (head.status != 200) return WTLS_ERR_HTTP;
    uint8_t buf[64];
    bool eof = false;
    while (!eof) {
        int n = wtls_h2_read_data(c, buf, sizeof buf, &eof);
        if (n < 0) return n;
        if (n == 0) break;
    }
    return WTLS_OK;
}

/* The Wii cannot turn Nagle off (IOS rejects TCP_NODELAY): a frame split
 * over two writes, or two small writes in a row, wait for the server's
 * delayed ACK (~60 ms per request measured). A request must leave in one
 * write, together with any control frames queued before it. */
static void test_get_leaves_in_one_write(void) {
    tp t;
    memset(&t, 0, sizeof t);
    script(&t, 2);
    wtls_url u;
    CHECK_EQ_INT(wtls_url_parse("https://example.com/x", &u), WTLS_OK);
    wtls_h2_conn *c = NULL;
    CHECK_EQ_INT(wtls_h2_create_io(&IO, &t, &c), WTLS_OK);
    if (!c) return;
    unsigned before = t.writes;
    CHECK_EQ_INT(one_get(c, &u), WTLS_OK);
    unsigned first = t.writes - before;
    before = t.writes;
    CHECK_EQ_INT(one_get(c, &u), WTLS_OK);
    unsigned second = t.writes - before;
    TLOG("    writes: first request %u, second %u, split frames %u\n", first, second, t.split_frames);
    CHECK(first <= 2);  /* SETTINGS ACK may go with the HEADERS or not, but in at most one more write */
    CHECK_EQ_INT((int)second, 1);
    CHECK_EQ_INT((int)t.split_frames, 0);
    wtls_h2_free(c);
}

/* Frames queued by the idle check (SETTINGS/PING ACK) are sent at once, not
 * held until the next request. */
static void test_alive_sends_its_acks(void) {
    tp t;
    memset(&t, 0, sizeof t);
    wtls_h2_conn *c = NULL;
    CHECK_EQ_INT(wtls_h2_create_io(&IO, &t, &c), WTLS_OK);
    if (!c) return;
    static const uint8_t ping[8] = {1, 2, 3, 4, 5, 6, 7, 8};
    sf(&t, 0x6, 0, 0, ping, sizeof ping);
    size_t before = t.out_len;
    CHECK(wtls_h2_alive(c));
    CHECK_EQ_INT((int)(t.out_len - before), 9 + 8); /* the PING ACK */
    wtls_h2_free(c);
}

int main(void) {
    RUN(test_get_leaves_in_one_write);
    RUN(test_alive_sends_its_acks);
    return CHECK_DONE();
}
