/* Platform abstraction: Wii (libogc) or host (POSIX/Winsock, tests only). */
#ifndef WTLS_PLAT_H
#define WTLS_PLAT_H

#include <stddef.h>
#include <stdint.h>

/* Fills out with OS entropy. Host: BCryptGenRandom/getrandom. Wii: WTLS_ERR_ENTROPY. */
int wtls_plat_os_entropy(uint8_t *out, size_t len);

#endif
