/* Differential fuzzer: the 32-bit-limb P-256 verify (src/accel) against the
 * builtin mbedtls_ecdsa_verify and the PSA verify path the hook sits in. All
 * three must make the same accept/reject decision.
 *
 * Input (227 bytes, shorter inputs are zero padded):
 *   [0]        mode: bits 0-1 signature, bits 2-3 public key
 *   [1..33)    private key (PSA rejects 0 and >= n: the input is skipped)
 *   [33]       hash length - 1, modulo 64
 *   [34..98)   hash bytes
 *   [98..162)  raw signature bytes / mutation parameters
 *   [162..227) raw public key bytes / mutation parameters
 * Signature modes: 0 valid | 1 valid with one flipped bit | 2 valid with r or
 * s replaced by an edge value | 3 raw bytes.
 * Public key modes: 0 valid | 1 valid with one flipped bit | 2 raw bytes |
 * 3 valid y with a raw x.
 * Compiled to a no-op when the accelerator is disabled. */
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(WTLS_ACCEL_P256)
#define MBEDTLS_DECLARE_PRIVATE_IDENTIFIERS
#include <psa/crypto.h>

#include <mbedtls/private/bignum.h>
#include <mbedtls/private/ecdsa.h>
#include <mbedtls/private/ecp.h>
#include <wiitls/wiitls.h>

#include "accel/wtls_p256.h"

#define INPUT_LEN 227

/* Edge values for r and s (big endian): 0, 1, n-1, n, n+1, p, 2^256-1, 2^255. */
static const char *const k_edges[] = {
    "0000000000000000000000000000000000000000000000000000000000000000",
    "0000000000000000000000000000000000000000000000000000000000000001",
    "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632550",
    "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
    "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632552",
    "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
    "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    "8000000000000000000000000000000000000000000000000000000000000000",
};
#define NEDGES (sizeof k_edges / sizeof k_edges[0])

static void unhex32(uint8_t out[32], const char *hex) {
    for (int i = 0; i < 32; i++) {
        unsigned b;
        sscanf(hex + 2 * i, "%2x", &b);
        out[i] = (uint8_t)b;
    }
}

/* The builtin implementation the hook replaces: 0 = valid. */
static int builtin_verify(const uint8_t pub[65], const uint8_t *hash, size_t hash_len, const uint8_t sig[64]) {
    mbedtls_ecp_group grp;
    mbedtls_ecp_point q;
    mbedtls_mpi r, s;
    int ret = -1;
    mbedtls_ecp_group_init(&grp);
    mbedtls_ecp_point_init(&q);
    mbedtls_mpi_init(&r);
    mbedtls_mpi_init(&s);
    if (mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256R1) == 0 &&
        mbedtls_ecp_point_read_binary(&grp, &q, pub, 65) == 0 &&
        mbedtls_mpi_read_binary(&r, sig, 32) == 0 && mbedtls_mpi_read_binary(&s, sig + 32, 32) == 0)
        ret = mbedtls_ecdsa_verify(&grp, hash, hash_len, &q, &r, &s);
    mbedtls_ecp_group_free(&grp);
    mbedtls_ecp_point_free(&q);
    mbedtls_mpi_free(&r);
    mbedtls_mpi_free(&s);
    return ret;
}

static void fail(const char *what) {
    fprintf(stderr, "p256 verify mismatch: %s\n", what);
    abort();
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    static bool init_done;
    if (!init_done) {
        if (wtls_init() != WTLS_OK) return 0;
        init_done = true;
    }
    uint8_t in[INPUT_LEN] = {0};
    memcpy(in, data, size < INPUT_LEN ? size : INPUT_LEN);
    const uint8_t mode = in[0];
    const size_t hl = 1u + in[33] % 64u;
    const uint8_t *hash = in + 34;

    psa_key_attributes_t a = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_type(&a, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
    psa_set_key_bits(&a, 256);
    psa_set_key_usage_flags(&a, PSA_KEY_USAGE_SIGN_HASH);
    psa_set_key_algorithm(&a, PSA_ALG_ECDSA(PSA_ALG_ANY_HASH));
    psa_key_id_t priv = 0;
    if (psa_import_key(&a, in + 1, 32, &priv) != PSA_SUCCESS) return 0;

    uint8_t pub[65], sig[64];
    size_t n = 0;
    if (psa_export_public_key(priv, pub, sizeof pub, &n) != PSA_SUCCESS || n != 65) {
        psa_destroy_key(priv);
        return 0;
    }
    bool have_sig = psa_sign_hash(priv, PSA_ALG_ECDSA(PSA_ALG_ANY_HASH), hash, hl, sig, sizeof sig, &n) ==
                        PSA_SUCCESS && n == 64;
    psa_destroy_key(priv);
    if (!have_sig) memset(sig, 0, sizeof sig);

    switch (mode & 3) {
    case 1: sig[in[98] % 64] ^= (uint8_t)(1u << (in[99] % 8)); break;
    case 2: unhex32(sig + (in[99] & 1 ? 32 : 0), k_edges[in[98] % NEDGES]); break;
    case 3: memcpy(sig, in + 98, 64); break;
    default: break;
    }
    switch ((mode >> 2) & 3) {
    case 1: pub[1 + in[162] % 64] ^= (uint8_t)(1u << (in[163] % 8)); break;
    case 2: memcpy(pub, in + 162, 65); break;
    case 3: memcpy(pub + 1, in + 163, 32); break;
    default: break;
    }

    bool ours = wtls_p256_verify(pub, hash, hl, sig) == PSA_SUCCESS;
    bool ref = builtin_verify(pub, hash, hl, sig) == 0;
    if (ours != ref) fail("accelerator vs builtin");

    psa_key_attributes_t pa = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_type(&pa, PSA_KEY_TYPE_ECC_PUBLIC_KEY(PSA_ECC_FAMILY_SECP_R1));
    psa_set_key_usage_flags(&pa, PSA_KEY_USAGE_VERIFY_HASH);
    psa_set_key_algorithm(&pa, PSA_ALG_ECDSA(PSA_ALG_ANY_HASH));
    psa_key_id_t pid = 0;
    if (psa_import_key(&pa, pub, sizeof pub, &pid) == PSA_SUCCESS) {
        bool via_psa = psa_verify_hash(pid, PSA_ALG_ECDSA(PSA_ALG_ANY_HASH), hash, hl, sig, sizeof sig) == PSA_SUCCESS;
        psa_destroy_key(pid);
        if (via_psa != ref) fail("PSA path vs builtin");
    } else if (ref) {
        fail("PSA refused a public key the builtin accepts");
    }
    return 0;
}
#else
#include <stddef.h>
#include <stdint.h>
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    (void)data;
    (void)size;
    return 0;
}
#endif
