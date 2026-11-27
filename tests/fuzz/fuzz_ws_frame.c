/* Fuzzer for the WebSocket frame layer: header parsing on arbitrary bytes,
 * masking (applying a mask twice restores the data, in any split), UTF-8 and
 * header build/parse round trips. */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "ws/wtls_ws_frame.h"
#include <wiitls/wiitls.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size > 4096) size = 4096;
    /* walk the input as a stream of frames */
    size_t off = 0;
    while (off < size) {
        wtls_ws_hdr h;
        int r = wtls_ws_parse_header(data + off, size - off, &h);
        if (r != WTLS_OK) break;
        if (h.hdr_len > size - off) abort();
        if (h.opcode >= 8 && h.len > WTLS_WS_MAX_CONTROL) abort();
        /* the header must survive a rebuild */
        uint8_t again[WTLS_WS_MAX_HDR];
        size_t n = wtls_ws_build_header(again, h.fin, h.opcode, h.len, h.masked ? h.mask : NULL);
        if (n != h.hdr_len || memcmp(again, data + off, n) != 0) abort();
        if (h.len > size - off - h.hdr_len) break;
        off += h.hdr_len + (size_t)h.len;
    }
    (void)wtls_ws_valid_utf8(data, size);

    if (size >= 5) {
        uint8_t buf[512];
        size_t n = size - 4 < sizeof buf ? size - 4 : sizeof buf;
        memcpy(buf, data + 4, n);
        size_t split = data[0] % (n + 1);
        wtls_ws_mask(buf, split, data, 0);
        wtls_ws_mask(buf + split, n - split, data, split);
        wtls_ws_mask(buf, n, data, 0);
        if (memcmp(buf, data + 4, n) != 0) abort();
    }
    return 0;
}
