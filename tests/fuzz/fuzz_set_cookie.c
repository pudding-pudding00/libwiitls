/* Fuzzer for the cookie jar: arbitrary Set-Cookie values for a few hosts and
 * paths, then lookups. Property: nothing crashes and every header produced
 * contains only bytes the parser accepted. */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "http/wtls_cookie.h"
#include "wtls_mem.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size > 2048) size = 2048;
    char *s = malloc(size + 1);
    if (!s) return 0;
    memcpy(s, data, size);
    s[size] = '\0';
    static const char *const hosts[] = {"example.com", "a.b.example.com", "1.2.3.4", "localhost"};
    static const char *const paths[] = {"/", "/a/b/c", "/x"};
    wtls_cookie_jar *j = wtls_cookie_jar_new(8);
    if (!j) {
        free(s);
        return 0;
    }
    int64_t now = 1800000000;
    size_t off = 0;
    for (int round = 0; round < 6 && off <= size; round++) { /* the input as several fields, split at newlines */
        char *nl = strchr(s + off, '\n');
        if (nl) *nl = '\0';
        (void)wtls_cookie_jar_set(j, s + off, hosts[round % 4], paths[round % 3], round & 1, now + round);
        off += strlen(s + off) + 1;
    }
    for (int h = 0; h < 4; h++) {
        for (int sec = 0; sec < 2; sec++) {
            char *hd = wtls_cookie_jar_header(j, hosts[h], paths[h % 3], sec, now + 10);
            if (hd && (strchr(hd, '\r') || strchr(hd, '\n'))) abort(); /* header injection */
            wtls_free(hd);
        }
    }
    (void)wtls_cookie_parse_date(s);
    wtls_cookie_jar_free(j);
    free(s);
    return 0;
}
