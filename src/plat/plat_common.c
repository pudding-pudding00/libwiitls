/* Platform-independent helpers of the platform layer. */
#include "plat.h"

#include <string.h>
#include <time.h>

/* Correction set by SNTP; the Wii RTC is often wrong. Single-thread model. */
static int64_t g_unix_offset;

int64_t wtls_plat_unix_time(void) { return (int64_t)time(NULL) + g_unix_offset; }

void wtls_plat_set_unix_time_offset(int64_t delta_s) { g_unix_offset = delta_s; }

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
