/* Differential fuzzer: the 32-bit-limb X25519 (src/accel) against Everest, the
 * implementation it replaces. Both must return the same 32 bytes for every
 * scalar and point, including low-order points and non-canonical encodings.
 *
 * Input (65+ bytes): [0] mode, [1..33) scalar, [33..65) point.
 *   mode & 3: 0 raw | 1 point from the edge table | 2 scalar from the edge
 *             table | 3 both from the edge tables
 * Compiled to a no-op when the accelerator is disabled. */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(WTLS_ACCEL_X25519)
#include "accel/wtls_x25519.h"

void Hacl_Curve25519_crypto_scalarmult(uint8_t *mypublic, uint8_t *secret, uint8_t *basepoint);

/* u-coordinates, little endian, as 32 hex digit pairs. */
static const char *const k_points[] = {
    "0000000000000000000000000000000000000000000000000000000000000000", /* 0 */
    "0100000000000000000000000000000000000000000000000000000000000000", /* 1 */
    "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", /* p-1 */
    "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", /* p (non-canonical 0) */
    "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", /* p+1 (non-canonical 1) */
    "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", /* 2^255-1 */
    "0000000000000000000000000000000000000000000000000000000000000080", /* bit 255 only */
    "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800", /* order 8 */
    "5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157", /* order 8 */
    "0900000000000000000000000000000000000000000000000000000000000000", /* base point */
};
static const char *const k_scalars[] = {
    "0000000000000000000000000000000000000000000000000000000000000000",
    "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    "f8ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", /* clamped maximum */
    "0000000000000000000000000000000000000000000000000000000000000040", /* clamped minimum */
    "0800000000000000000000000000000000000000000000000000000000000040",
};
#define NPOINTS (sizeof k_points / sizeof k_points[0])
#define NSCALARS (sizeof k_scalars / sizeof k_scalars[0])

static void unhex32(uint8_t out[32], const char *hex) {
    for (int i = 0; i < 32; i++) {
        unsigned b;
        sscanf(hex + 2 * i, "%2x", &b);
        out[i] = (uint8_t)b;
    }
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 65) return 0;
    uint8_t k[32], u[32];
    memcpy(k, data + 1, 32);
    memcpy(u, data + 33, 32);
    if (data[0] & 1) {
        unhex32(u, k_points[data[33] % NPOINTS]);
        if (data[34] & 1) u[31] ^= 0x80; /* the top bit must be ignored */
    }
    if (data[0] & 2) unhex32(k, k_scalars[data[1] % NSCALARS]);

    uint8_t kc[32], uc[32], want[32], got[32];
    memcpy(kc, k, 32); /* HACL takes non-const pointers and may not modify them: keep copies */
    memcpy(uc, u, 32);
    Hacl_Curve25519_crypto_scalarmult(want, kc, uc);
    wtls_x25519(got, k, u);
    if (memcmp(want, got, 32) != 0) {
        fprintf(stderr, "x25519 mismatch\n");
        abort();
    }
    return 0;
}
#else
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    (void)data;
    (void)size;
    return 0;
}
#endif
