/* Entropy driver for TF-PSA-Crypto (MBEDTLS_PSA_DRIVER_GET_ENTROPY). */
#include <mbedtls/platform.h>
#include <psa/crypto.h>

#include "plat/plat.h"
#include "wtls_internal.h"

int mbedtls_platform_get_entropy(psa_driver_get_entropy_flags_t flags,
                                 size_t *estimate_bits,
                                 unsigned char *output, size_t output_size) {
    if (flags != 0) return PSA_ERROR_NOT_SUPPORTED;
#if defined(WTLS_PLATFORM_HOST)
    if (wtls_plat_os_entropy(output, output_size) != WTLS_OK)
        return PSA_ERROR_INSUFFICIENT_ENTROPY;
    *estimate_bits = 8 * output_size;
    return 0;
#else
    /* Wii: the timebase-jitter source arrives in Task 3; fail closed until then. */
    (void)output;
    (void)output_size;
    *estimate_bits = 0;
    return PSA_ERROR_INSUFFICIENT_ENTROPY;
#endif
}
