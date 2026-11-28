#include <assert.h>
#include <stdint.h>
#include <stdlib.h>

#include "http/wtls_http_gzip.h"

#define FUZZ_ZSTD_MAX_OUT 65536u

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    wtls_gzip *g = wtls_zstd_new();
    if (!g) return 0;
    uint8_t out[4096];
    size_t off = 0, total_out = 0;
    size_t step = size ? (1u + (data[0] & 127u)) : 1u;
    int st = WTLS_OK;
    while (st == WTLS_OK && total_out < FUZZ_ZSTD_MAX_OUT) {
        size_t chunk = size - off < step ? size - off : step;
        size_t used = 0, produced = 0;
        st = wtls_gzip_inflate(g, data + off, chunk, &used, out, sizeof out, &produced);
        assert(used <= chunk && produced <= sizeof out);
        off += used;
        total_out += produced;
        if (off == size && produced == 0) break;
        if (used == 0 && produced == 0) break;
    }
    if (st == WTLS_OK && total_out < FUZZ_ZSTD_MAX_OUT) (void)wtls_gzip_finish(g);
    wtls_gzip_free(g);
    return 0;
}
