/* Platform-independent helpers of the platform layer. */
#include "plat.h"

#include <string.h>

bool wtls_plat_parse_ipv4(const char *s, uint32_t *ipv4_be) {
    uint8_t b[4];
    if (!s) return false;
    for (int part = 0; part < 4; part++) {
        unsigned v = 0, digits = 0;
        while (*s >= '0' && *s <= '9') {
            v = v * 10 + (unsigned)(*s++ - '0');
            if (++digits > 3 || v > 255) return false;
        }
        if (digits == 0) return false;
        b[part] = (uint8_t)v;
        if (part < 3 && *s++ != '.') return false;
    }
    if (*s != '\0') return false;
    if (ipv4_be) memcpy(ipv4_be, b, 4); /* b[0] first in memory = network order */
    return true;
}
