/* Fuzzer for the HTTP/2 frame engine: the bytes of a hostile server are fed to
 * a client that sends one request and reads the response, with no socket.
 *
 * Input: [0] mode, rest = the server's byte stream (frames, HPACK blocks).
 *   bit 0: POST with a 20000-byte body (exercises the send windows)
 *   bit 1: Expect: 100-continue
 *   bit 2: offer gzip
 *   bit 3: finish with the idle liveness check
 *   bit 4: deliver the stream in tiny reads (1..5 bytes) */
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "http/wtls_http2.h"
#include "http/wtls_url.h"
#include "wtls_mem.h"

typedef struct {
    const uint8_t *data;
    size_t len, off;
    bool tiny;
} feed;

static int feed_read(void *ctx, void *buf, size_t len, uint32_t max_wait_ms) {
    (void)max_wait_ms;
    feed *f = ctx;
    if (f->off >= f->len) return WTLS_ERR_CLOSED;
    size_t n = f->len - f->off;
    if (n > len) n = len;
    if (f->tiny && n > 1u + f->off % 5u) n = 1u + f->off % 5u;
    memcpy(buf, f->data + f->off, n);
    f->off += n;
    return (int)n;
}

static int feed_write(void *ctx, const void *buf, size_t len) {
    (void)ctx;
    (void)buf;
    (void)len;
    return WTLS_OK;
}

static bool feed_readable(void *ctx) {
    feed *f = ctx;
    return f->off < f->len;
}

static int feed_read_nowait(void *ctx, void *buf, size_t len) {
    feed *f = ctx;
    if (f->off >= f->len) return WTLS_WANT_READ;
    return feed_read(ctx, buf, len, 0);
}

static const wtls_h2_io k_io = {feed_read, feed_write, feed_readable, feed_read_nowait};

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 1) return 0;
    const uint8_t mode = data[0];
    feed f = {data + 1, size - 1, 0, (mode & 16) != 0};

    wtls_url u;
    if (wtls_url_parse("https://example.com/x", &u) != WTLS_OK) abort();
    wtls_h2_conn *c = NULL;
    if (wtls_h2_create_io(&k_io, &f, &c) != WTLS_OK) return 0;
    if (wtls_h2_begin_stream(c) != WTLS_OK) goto done;

    static const uint8_t zeros[20000];
    const bool body = (mode & 1) != 0;
    if (wtls_h2_send_headers(c, body ? "POST" : "GET", &u, NULL, 0, body, body ? sizeof zeros : 0, body,
                             (mode & 4) != 0, (mode & 2) != 0) != WTLS_OK)
        goto done;

    wtls_http_head head;
    char *arena = NULL;
    bool got = false, early = false;
    if (mode & 2) {
        if (wtls_h2_wait_continue(c, 100, 1000, &early, &head, &arena, &got) != WTLS_OK) goto done;
        if (early && got) {
            wtls_free(arena);
            arena = NULL;
        }
    }
    if (body && !early) {
        arena = NULL;
        got = false;
        int st = wtls_h2_send_data(c, zeros, sizeof zeros, true, &early, &head, &arena, &got);
        if (early && got) {
            wtls_free(arena);
            arena = NULL;
        }
        if (st != WTLS_OK) goto done;
    }
    arena = NULL;
    got = false;
    if (wtls_h2_read_head(c, 1000, &head, &arena, &got) == WTLS_OK) {
        volatile size_t sum = 0;
        for (size_t i = 0; i < head.n_fields; i++) sum += strlen(head.fields[i].name) + strlen(head.fields[i].value);
        (void)sum;
        wtls_free(arena);
        uint8_t buf[4096];
        for (int i = 0; i < 400; i++) {
            bool eof = false;
            int n = wtls_h2_read_data(c, buf, sizeof buf, &eof);
            if (n < 0 || eof || (n == 0 && f.off >= f.len)) break;
        }
    }
    if (mode & 8) (void)wtls_h2_alive(c);
done:
    wtls_h2_free(c);
    return 0;
}
