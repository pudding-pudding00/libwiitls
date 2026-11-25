#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <wiitls/http.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size > 512) size = 512;
    char s[513];
    memcpy(s, data, size);
    s[size] = '\0';

    wtls_http_content_range cr;
    if (wtls_http_parse_content_range(s, &cr) == WTLS_OK) {
        assert(cr.start <= cr.end);
        assert(cr.total == -1 || (cr.total > 0 && (uint64_t)cr.total > cr.end));
    }

    size_t needed = 0;
    if (wtls_http_url_encode((const char *)data, size, NULL, 0, &needed) == WTLS_OK) {
        char *enc = malloc(needed + 1);
        if (enc) {
            size_t out_len = 0;
            int r = wtls_http_url_encode((const char *)data, size, enc, needed + 1, &out_len);
            assert(r == WTLS_OK && out_len == needed && enc[out_len] == '\0');
            free(enc);
        }
    }
    return 0;
}
