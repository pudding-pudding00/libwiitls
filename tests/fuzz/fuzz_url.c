#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "http/wtls_url.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size > WTLS_HTTP_MAX_URL + 64u) size = WTLS_HTTP_MAX_URL + 64u;
    char *s = malloc(size + 1);
    if (!s) return 0;
    memcpy(s, data, size);
    s[size] = '\0';

    wtls_url u;
    (void)wtls_url_parse(s, &u);

    char *resolved = NULL;
    if (wtls_url_resolve("https://example.com:8443/a/b/c?x=1", s, &resolved) == WTLS_OK) {
        wtls_url u2;
        (void)wtls_url_parse(resolved, &u2);
        free(resolved);
    }

    /* Split at first NUL or midpoint to exercise arbitrary base + ref pairs. */
    size_t split = size / 2;
    const void *nul = memchr(data, '\0', size);
    if (nul) split = (size_t)((const uint8_t *)nul - data);
    if (split < size) {
        s[split] = '\0';
        const char *ref = s + split + 1;
        char *out = NULL;
        if (wtls_url_resolve(s, ref, &out) == WTLS_OK) {
            wtls_url u3;
            (void)wtls_url_parse(out, &u3);
            free(out);
        }
    }
    free(s);
    return 0;
}
