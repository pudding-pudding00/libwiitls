#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "http/wtls_http_parse.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size > WTLS_HTTP_MAX_HEAD * 2u) size = WTLS_HTTP_MAX_HEAD * 2u;
    size_t end = wtls_http_head_end((const char *)data, size);
    assert(end <= size);
    if (end > 0 && end <= WTLS_HTTP_MAX_HEAD) {
        char *copy = malloc(end);
        if (!copy) return 0;
        memcpy(copy, data, end);
        wtls_http_head h;
        int r = wtls_http_parse_head(copy, end, &h);
        if (r == WTLS_OK) {
            assert(h.status >= 100 && h.status <= 599);
            assert(h.n_fields <= WTLS_HTTP_MAX_FIELDS);
            wtls_http_framing f;
            wtls_http_frame(&h, (data[0] & 1) != 0, (data[0] & 2) != 0, &f);
        }
        free(copy);
    }
    /* Also feed raw truncated/unterminated slices directly to parse_head. */
    size_t plen = size > WTLS_HTTP_MAX_HEAD ? WTLS_HTTP_MAX_HEAD : size;
    if (plen > 0) {
        char *copy = malloc(plen);
        if (copy) {
            memcpy(copy, data, plen);
            wtls_http_head h;
            (void)wtls_http_parse_head(copy, plen, &h);
            free(copy);
        }
    }
    return 0;
}
