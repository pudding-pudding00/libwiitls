/* Known-answer tests for the primitives the build options swap (X25519 via
 * builtin or Everest), run on the host (tests/host/test_crypto.c) and on the
 * Wii (suite "crypto"): the benchmarks time them but do not check results,
 * and a big-endian CPU can break code that is only tested on little-endian. */
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <psa/crypto.h>
#include <wiitls/wiitls.h>

#include "check.h"

/* RFC 7748 section 6.1. */
static const uint8_t k_alice_priv[32] = {
    0x77, 0x07, 0x6d, 0x0a, 0x73, 0x18, 0xa5, 0x7d, 0x3c, 0x16, 0xc1, 0x72, 0x51, 0xb2, 0x66, 0x45,
    0xdf, 0x4c, 0x2f, 0x87, 0xeb, 0xc0, 0x99, 0x2a, 0xb1, 0x77, 0xfb, 0xa5, 0x1d, 0xb9, 0x2c, 0x2a};
static const uint8_t k_alice_pub[32] = {
    0x85, 0x20, 0xf0, 0x09, 0x89, 0x30, 0xa7, 0x54, 0x74, 0x8b, 0x7d, 0xdc, 0xb4, 0x3e, 0xf7, 0x5a,
    0x0d, 0xbf, 0x3a, 0x0d, 0x26, 0x38, 0x1a, 0xf4, 0xeb, 0xa4, 0xa9, 0x8e, 0xaa, 0x9b, 0x4e, 0x6a};
static const uint8_t k_bob_priv[32] = {
    0x5d, 0xab, 0x08, 0x7e, 0x62, 0x4a, 0x8a, 0x4b, 0x79, 0xe1, 0x7f, 0x8b, 0x83, 0x80, 0x0e, 0xe6,
    0x6f, 0x3b, 0xb1, 0x29, 0x26, 0x18, 0xb6, 0xfd, 0x1c, 0x2f, 0x8b, 0x27, 0xff, 0x88, 0xe0, 0xeb};
static const uint8_t k_bob_pub[32] = {
    0xde, 0x9e, 0xdb, 0x7d, 0x7b, 0x7d, 0xc1, 0xb4, 0xd3, 0x5b, 0x61, 0xc2, 0xec, 0xe4, 0x35, 0x37,
    0x3f, 0x83, 0x43, 0xc8, 0x5b, 0x78, 0x67, 0x4d, 0xad, 0xfc, 0x7e, 0x14, 0x6f, 0x88, 0x2b, 0x4f};
static const uint8_t k_shared[32] = {
    0x4a, 0x5d, 0x9d, 0x5b, 0xa4, 0xce, 0x2d, 0xe1, 0x72, 0x8e, 0x3b, 0xf4, 0x80, 0x35, 0x0f, 0x25,
    0xe0, 0x7e, 0x21, 0xc9, 0x47, 0xd1, 0x9e, 0x33, 0x76, 0xf0, 0x9b, 0x3c, 0x1e, 0x16, 0x17, 0x42};

static psa_key_id_t import_x25519(const uint8_t priv[32]) {
    psa_key_attributes_t a = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_type(&a, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_MONTGOMERY));
    psa_set_key_bits(&a, 255);
    psa_set_key_usage_flags(&a, PSA_KEY_USAGE_DERIVE);
    psa_set_key_algorithm(&a, PSA_ALG_ECDH);
    psa_key_id_t id = 0;
    CHECK_EQ_INT(psa_import_key(&a, priv, 32, &id), PSA_SUCCESS);
    return id;
}

static void x25519_party(const uint8_t priv[32], const uint8_t pub[32], const uint8_t peer_pub[32]) {
    psa_key_id_t id = import_x25519(priv);
    uint8_t out[32];
    size_t n = 0;
    CHECK_EQ_INT(psa_export_public_key(id, out, sizeof out, &n), PSA_SUCCESS);
    CHECK_EQ_INT(n, 32);
    CHECK_MEM(out, pub, 32);
    memset(out, 0, sizeof out);
    n = 0;
    CHECK_EQ_INT(psa_raw_key_agreement(PSA_ALG_ECDH, id, peer_pub, 32, out, sizeof out, &n), PSA_SUCCESS);
    CHECK_EQ_INT(n, 32);
    CHECK_MEM(out, k_shared, 32);
    psa_destroy_key(id);
}

static void test_x25519_rfc7748_alice(void) { x25519_party(k_alice_priv, k_alice_pub, k_bob_pub); }

static void test_x25519_rfc7748_bob(void) { x25519_party(k_bob_priv, k_bob_pub, k_alice_pub); }

/* Fresh key pairs (the path TLS takes): both sides must agree. */
static void test_x25519_generated_pairs_agree(void) {
    psa_key_attributes_t a = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_type(&a, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_MONTGOMERY));
    psa_set_key_bits(&a, 255);
    psa_set_key_usage_flags(&a, PSA_KEY_USAGE_DERIVE);
    psa_set_key_algorithm(&a, PSA_ALG_ECDH);
    psa_key_id_t x = 0, y = 0;
    CHECK_EQ_INT(psa_generate_key(&a, &x), PSA_SUCCESS);
    CHECK_EQ_INT(psa_generate_key(&a, &y), PSA_SUCCESS);
    uint8_t px[32], py[32], sx[32], sy[32];
    size_t n = 0;
    CHECK_EQ_INT(psa_export_public_key(x, px, sizeof px, &n), PSA_SUCCESS);
    CHECK_EQ_INT(psa_export_public_key(y, py, sizeof py, &n), PSA_SUCCESS);
    CHECK_EQ_INT(psa_raw_key_agreement(PSA_ALG_ECDH, x, py, 32, sx, sizeof sx, &n), PSA_SUCCESS);
    CHECK_EQ_INT(psa_raw_key_agreement(PSA_ALG_ECDH, y, px, 32, sy, sizeof sy, &n), PSA_SUCCESS);
    CHECK_MEM(sx, sy, 32);
    psa_destroy_key(x);
    psa_destroy_key(y);
}

#if defined(WTLS_ACCEL_X25519)
/* The 32-bit-limb X25519 (src/accel), called directly. */
#include "accel/wtls_x25519.h"

/* Everest's implementation, the reference for random inputs. */
void Hacl_Curve25519_crypto_scalarmult(uint8_t *mypublic, uint8_t *secret, uint8_t *basepoint);

static void fast_vector(const char *k_hex, const char *u_hex, const char *out_hex) {
    uint8_t k[32], u[32], want[32], out[32];
    for (int i = 0; i < 32; i++) {
        unsigned a, b, c;
        sscanf(k_hex + 2 * i, "%2x", &a);
        sscanf(u_hex + 2 * i, "%2x", &b);
        sscanf(out_hex + 2 * i, "%2x", &c);
        k[i] = (uint8_t)a;
        u[i] = (uint8_t)b;
        want[i] = (uint8_t)c;
    }
    wtls_x25519(out, k, u);
    CHECK_MEM(out, want, 32);
}

/* RFC 7748 section 5.2: the two single vectors (the second has the top bit of
 * u set, which must be ignored). */
static void test_x25519_fast_rfc7748_5_2(void) {
    fast_vector("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4",
                "e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c",
                "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552");
    fast_vector("4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d",
                "e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493",
                "95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957");
}

/* RFC 7748 section 5.2, iterated: k = X25519(k, u), u = old k, from k = u = 9. */
static void test_x25519_fast_rfc7748_iterated(void) {
    static const uint8_t after1[32] = {
        0x42, 0x2c, 0x8e, 0x7a, 0x62, 0x27, 0xd7, 0xbc, 0xa1, 0x35, 0x0b, 0x3e, 0x2b, 0xb7, 0x27, 0x9f,
        0x78, 0x97, 0xb8, 0x7b, 0xb6, 0x85, 0x4b, 0x78, 0x3c, 0x60, 0xe8, 0x03, 0x11, 0xae, 0x30, 0x79};
    static const uint8_t after1000[32] = {
        0x68, 0x4c, 0xf5, 0x9b, 0xa8, 0x33, 0x09, 0x55, 0x28, 0x00, 0xef, 0x56, 0x6f, 0x2f, 0x4d, 0x3c,
        0x1c, 0x38, 0x87, 0xc4, 0x93, 0x60, 0xe3, 0x87, 0x5f, 0x2e, 0xb9, 0x4d, 0x99, 0x53, 0x2c, 0x51};
    uint8_t k[32] = {9}, u[32] = {9}, out[32];
    for (int i = 1; i <= 1000; i++) {
        wtls_x25519(out, k, u);
        memcpy(u, k, 32);
        memcpy(k, out, 32);
        if (i == 1) {
            CHECK_MEM(k, after1, 32);
        }
    }
    CHECK_MEM(k, after1000, 32);
}

/* RFC 7748 section 6.1 through the direct call: public keys and shared secret. */
static void test_x25519_fast_rfc7748_6_1(void) {
    static const uint8_t base[32] = {9};
    uint8_t out[32];
    wtls_x25519(out, k_alice_priv, base);
    CHECK_MEM(out, k_alice_pub, 32);
    wtls_x25519(out, k_bob_priv, base);
    CHECK_MEM(out, k_bob_pub, 32);
    wtls_x25519(out, k_alice_priv, k_bob_pub);
    CHECK_MEM(out, k_shared, 32);
}

static uint32_t xorshift32(uint32_t *s) {
    *s ^= *s << 13;
    *s ^= *s >> 17;
    *s ^= *s << 5;
    return *s;
}

static void same_as_everest(const uint8_t k[32], const uint8_t u[32]) {
    uint8_t kc[32], uc[32], want[32], out[32];
    memcpy(kc, k, 32); /* HACL takes non-const pointers */
    memcpy(uc, u, 32);
    Hacl_Curve25519_crypto_scalarmult(want, kc, uc);
    wtls_x25519(out, k, u);
    CHECK_MEM(out, want, 32);
}

/* Edge points (0, 1, p-1, p, p+1, 2^255-1: non-canonical and top bit set) and
 * random scalar/point pairs (fixed seed): identical to Everest. */
static void test_x25519_fast_matches_everest(void) {
    static const uint8_t edges[][32] = {
        {0},
        {1},
        {0xec, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
         0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f},
        {0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
         0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f},
        {0xee, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
         0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f},
        {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
         0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
    };
    uint8_t k[32], u[32];
    uint32_t s = 0x2545f491u;
    for (size_t e = 0; e < sizeof edges / sizeof edges[0]; e++) {
        for (int i = 0; i < 32; i++) k[i] = (uint8_t)xorshift32(&s);
        same_as_everest(k, edges[e]);
    }
#if defined(GEKKO)
    const int n = 100; /* Everest's emulated 128-bit arithmetic is slow here */
#else
    const int n = 1000;
#endif
    for (int r = 0; r < n; r++) {
        for (int i = 0; i < 32; i++) {
            k[i] = (uint8_t)xorshift32(&s);
            u[i] = (uint8_t)xorshift32(&s);
        }
        same_as_everest(k, u);
    }
}

/* Base point 9 takes the fixed-base path (Edwards comb); it must agree with
 * Everest for every scalar, including all-zero and all-one bytes (clamped). */
static void test_x25519_fast_base_matches_everest(void) {
    static const uint8_t base[32] = {9};
    uint8_t k[32];
    memset(k, 0, 32);
    same_as_everest(k, base);
    memset(k, 0xff, 32);
    same_as_everest(k, base);
    uint32_t s = 0x9e3779b9u;
#if defined(GEKKO)
    const int n = 100;
#else
    const int n = 1000;
#endif
    for (int r = 0; r < n; r++) {
        for (int i = 0; i < 32; i++) k[i] = (uint8_t)xorshift32(&s);
        same_as_everest(k, base);
    }
}
#endif /* WTLS_ACCEL_X25519 */

void wtls_suite_crypto(void) {
    CHECK_EQ_INT(wtls_init(), WTLS_OK);
#if defined(WTLS_ACCEL_X25519)
    RUN(test_x25519_fast_rfc7748_5_2);
    RUN(test_x25519_fast_rfc7748_iterated);
    RUN(test_x25519_fast_rfc7748_6_1);
    RUN(test_x25519_fast_matches_everest);
    RUN(test_x25519_fast_base_matches_everest);
#endif
    RUN(test_x25519_rfc7748_alice);
    RUN(test_x25519_rfc7748_bob);
    RUN(test_x25519_generated_pairs_agree);
    wtls_shutdown();
}
