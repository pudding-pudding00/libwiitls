/* Platform abstraction: Wii (libogc) or host (POSIX/Winsock, tests only). */
#ifndef WTLS_PLAT_H
#define WTLS_PLAT_H

#include <stddef.h>
#include <stdint.h>

/* Fills out with OS entropy. Host: BCryptGenRandom/getrandom. Wii: WTLS_ERR_ENTROPY. */
int wtls_plat_os_entropy(uint8_t *out, size_t len);

#if defined(WTLS_PLATFORM_OGC)
/* One timebase-jitter sample: delta of mftb across the disturbance chosen in
 * Task 2 (variant b: cache-hostile stride walk over a 256 KiB buffer). The
 * buffer is allocated on first use; wtls_plat_jitter_release() frees it.
 * Returns 0 forever if the buffer cannot be allocated (the health tests then
 * fail closed). */
uint32_t wtls_plat_jitter_sample(void);
void     wtls_plat_jitter_release(void);
#endif

#endif
