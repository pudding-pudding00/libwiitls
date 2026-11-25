#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "http/wtls_http_chunked.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size == 0) return 0;
    size_t step_max = 1u + (data[0] & 63u);
    const uint8_t *p = data + 1;
    size_t rem = size - 1;
    wtls_chunked d;
    wtls_chunked_init(&d);
    size_t pos = 0;
    while (pos < rem) {
        size_t take = rem - pos;
        if (take > step_max) take = step_max;
        uint8_t *piece = malloc(take);
        if (!piece) break;
        memcpy(piece, p + pos, take);
        size_t out = 0, rest = 0;
        int r = wtls_chunked_decode(&d, piece, take, &out, &rest);
        free(piece);
        assert(out <= take && rest <= take && out + rest <= take);
        if (r != WTLS_WANT_READ) break;
        pos += take;
        step_max = 1u + ((step_max + pos) & 63u);
    }
    return 0;
}
