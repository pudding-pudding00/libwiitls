#include "plat.h"

#include <wiitls/wiitls.h>

#if defined(_WIN32)
#include <windows.h>
#include <bcrypt.h>

int wtls_plat_os_entropy(uint8_t *out, size_t len) {
    if (len > 0xFFFFFFFFu) return WTLS_ERR_ARG;
    NTSTATUS st = BCryptGenRandom(NULL, out, (ULONG)len, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    return BCRYPT_SUCCESS(st) ? WTLS_OK : WTLS_ERR_ENTROPY;
}
#else
#include <errno.h>
#include <sys/random.h>
#include <sys/types.h>

int wtls_plat_os_entropy(uint8_t *out, size_t len) {
    while (len > 0) {
        ssize_t n = getrandom(out, len, 0);
        if (n < 0) {
            if (errno == EINTR) continue;
            return WTLS_ERR_ENTROPY;
        }
        out += n;
        len -= (size_t)n;
    }
    return WTLS_OK;
}
#endif
