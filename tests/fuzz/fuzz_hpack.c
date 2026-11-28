/* Fuzzer for the HPACK decoder (RFC 7541): header blocks decoded in sequence
 * against one dynamic table, plus the integer and string primitives and an
 * integer encode/decode round trip.
 *
 * Input: [0] mode, rest = data.
 *   mode & 1 == 0: the rest is split into 1 + (mode >> 1) % 4 header blocks
 *                  decoded one after the other on the same context
 *   mode & 1 == 1: rest[0] selects the prefix size, the primitives decode the
 *                  remainder; the next 8 bytes (below 2^48) round-trip as an integer */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "http/wtls_hpack.h"
#include "wtls_mem.h"

static void touch_head(const wtls_http_head *h) {
    volatile size_t sum = 0;
    for (size_t i = 0; i < h->n_fields; i++) sum += strlen(h->fields[i].name) + strlen(h->fields[i].value);
    (void)sum;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 2) return 0;
    const uint8_t mode = data[0];
    const uint8_t *rest = data + 1;
    size_t rest_len = size - 1;

    if (mode & 1) {
        unsigned prefix = 1u + rest[0] % 8u;
        const uint8_t *p = rest + 1, *end = rest + rest_len;
        uint64_t v;
        (void)wtls_hpack_decode_int(&p, end, prefix, &v);
        p = rest + 1;
        char *s = NULL;
        size_t sl = 0;
        if (wtls_hpack_decode_str(&p, end, 1u + (size_t)rest[0] * 64u, &s, &sl) == WTLS_OK) {
            if (s[sl] != '\0') abort(); /* documented NUL termination */
            wtls_free(s);
        }
        if (rest_len >= 9) {
            uint64_t val = 0;
            for (int i = 0; i < 8; i++) val = (val << 8) | rest[1 + i];
            val &= (1ull << 48) - 1u; /* the decoder refuses values near 2^64 on purpose */
            uint8_t buf[16];
            size_t off = 0;
            if (wtls_hpack_encode_int(buf, sizeof buf, &off, 0, prefix, val) == WTLS_OK) {
                const uint8_t *q = buf;
                uint64_t back = ~val;
                if (wtls_hpack_decode_int(&q, buf + off, prefix, &back) != WTLS_OK || back != val ||
                    q != buf + off)
                    abort();
            }
        }
        return 0;
    }

    wtls_hpack_ctx ctx;
    wtls_hpack_init(&ctx, WTLS_HPACK_DEFAULT_TABLE);
    size_t nblocks = 1u + (mode >> 1) % 4u;
    size_t per = rest_len / nblocks;
    for (size_t b = 0; b < nblocks; b++) {
        size_t start = b * per;
        size_t len = b + 1 == nblocks ? rest_len - start : per;
        wtls_http_head head;
        char *arena = NULL;
        if (wtls_hpack_decode_head(&ctx, rest + start, len, &head, &arena) == WTLS_OK) {
            touch_head(&head);
            wtls_free(arena);
        }
    }
    wtls_hpack_free(&ctx);
    return 0;
}
