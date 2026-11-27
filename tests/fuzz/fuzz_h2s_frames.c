/* Fuzzer for the HTTP/2 session engine (multiplexing): the bytes of a hostile server are fed to a session that
 * opens streams, sends requests, reads the answers and cancels streams, with no socket.
 *
 * Input: [0] mode, rest = the server's byte stream.
 *   bit 0: deliver the stream in tiny reads (1..7 bytes)
 *   bit 1: POST bodies of 20000 bytes (send windows)
 *   bit 2: the transport refuses every other write (WANT_WRITE)
 *   bits 3..4: stream cap 1..4
 *   bit 5: release streams early (cancel) */
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "http/wtls_h2s.h"
#include "http/wtls_url.h"
#include "wtls_mem.h"

typedef struct {
    const uint8_t *data;
    size_t len, off;
    bool tiny, flaky;
    unsigned writes;
} feed;

static int feed_read(void *ctx, void *buf, size_t len) {
    feed *f = ctx;
    if (f->off >= f->len) return WTLS_WANT_READ;
    size_t n = f->len - f->off;
    if (n > len) n = len;
    if (f->tiny && n > 1u + f->off % 7u) n = 1u + f->off % 7u;
    memcpy(buf, f->data + f->off, n);
    f->off += n;
    return (int)n;
}

static int feed_write(void *ctx, const void *buf, size_t len) {
    feed *f = ctx;
    (void)buf;
    if (f->flaky && (f->writes++ & 1u)) return WTLS_WANT_WRITE;
    return (int)len;
}

static const h2s_io k_io = {feed_read, feed_write};

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 1) return 0;
    const uint8_t mode = data[0];
    feed f = {data + 1, size - 1, 0, (mode & 1) != 0, (mode & 4) != 0, 0};
    const uint32_t cap = 1u + ((mode >> 3) & 3u);
    const bool post = (mode & 2) != 0, cancel = (mode & 32) != 0;

    wtls_url u;
    if (wtls_url_parse("https://example.com/x", &u) != WTLS_OK) abort();
    h2s_session *s = h2s_create(&k_io, &f, cap, 16384);
    if (!s) return 0;

    static const uint8_t zeros[20000];
    h2s_stream *st[4] = {0};
    size_t sent[4] = {0};
    bool headed[4] = {0}, taken[4] = {0};
    uint32_t rnd = (uint32_t)size * 2654435761u + mode;
    for (int round = 0; round < 400; round++) {
        h2s_pump(s);
        if (h2s_active(s) > cap) abort();
        for (unsigned i = 0; i < cap; i++) {
            if (!st[i]) {
                if (round < 200 && h2s_stream_open(s, &st[i]) == WTLS_OK) {
                    headed[i] = taken[i] = false;
                    sent[i] = 0;
                } else {
                    continue;
                }
            }
            if (!headed[i]) {
                int r = h2s_stream_send_headers(st[i], post ? "POST" : "GET", &u, NULL, 0, post, post ? sizeof zeros : 0,
                                                post, false);
                if (r == WTLS_OK) headed[i] = true;
                else if (r != WTLS_WANT_READ) {
                    h2s_stream_release(st[i]);
                    st[i] = NULL;
                    continue;
                }
            }
            if (headed[i] && post && sent[i] < sizeof zeros) {
                int n = h2s_stream_send_data(st[i], zeros + sent[i], sizeof zeros - sent[i], true);
                if (n > 0) sent[i] += (size_t)n;
            }
            if (headed[i] && !taken[i]) {
                wtls_http_head h;
                char *arena = NULL;
                if (h2s_stream_head(st[i], &h, &arena) == WTLS_OK) {
                    taken[i] = true;
                    for (size_t k = 0; k < h.n_fields; k++)
                        if (!h.fields[k].name || !h.fields[k].value) abort();
                    wtls_free(arena);
                }
            }
            if (taken[i]) {
                uint8_t buf[300];
                bool eof = false;
                int k = h2s_stream_read(st[i], buf, sizeof buf, &eof);
                if (k > (int)sizeof buf) abort();
                if (h2s_stream_buffered(st[i]) > 16384u) abort();
                if (eof || (k < 0 && k != WTLS_WANT_READ)) {
                    h2s_stream_release(st[i]);
                    st[i] = NULL;
                    continue;
                }
            }
            rnd = rnd * 1103515245u + 12345u;
            if (cancel && ((rnd >> 16) & 15u) == 0) {
                h2s_stream_release(st[i]);
                st[i] = NULL;
            }
        }
    }
    for (unsigned i = 0; i < cap; i++) h2s_stream_release(st[i]);
    h2s_destroy(s);
    return 0;
}
