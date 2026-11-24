/* Benchmark probe: p256-m's raw ECDSA verify, compiled here because the PSA
 * driver cannot be enabled with Mbed TLS 4.1.1 + PK (docs/benchmarks.md), so
 * the library's own p256-m object is empty. Only used to compare speeds. */
#define MBEDTLS_PSA_P256M_DRIVER_ENABLED
#include "p256-m.c"
