/* Known-answer tests for the primitives the build options swap (X25519 via
 * builtin or Everest), run on the host (tests/host/test_crypto.c) and on the
 * Wii (suite "crypto"): the benchmarks time them but do not check results,
 * and a big-endian CPU can break code that is only tested on little-endian. */
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#if defined(WTLS_ACCEL_P256)
/* The builtin ECDSA implementation the P-256 tests use as their differential
 * oracle is private API in Mbed TLS 4.1.1 (tf-psa-crypto): its headers declare
 * nothing unless this is defined before the first private header is included
 * - and psa/crypto.h below pulls some of them in itself. */
#define MBEDTLS_DECLARE_PRIVATE_IDENTIFIERS
#endif

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

#if defined(WTLS_ACCEL_P256)
/* The 32-bit-limb P-256 verify (src/accel/p256_verify.c), called directly and
 * through the psa_verify_hash path the hook covers, with the builtin
 * mbedtls_ecdsa_verify as the differential oracle. */
#include "accel/wtls_p256.h"

/* Private driver headers, with MBEDTLS_DECLARE_PRIVATE_IDENTIFIERS defined
 * at the top of this file (see the note there). */
#include <mbedtls/private/bignum.h>
#include <mbedtls/private/ecdsa.h>
#include <mbedtls/private/ecp.h>

/* RFC 6979 appendix A.2.5 (NIST P-256) key pair; the messages are the UTF-8
 * strings "sample" and "test", hashed with the listed digest. */
static const uint8_t k_p256_pub[65] = {
    0x04,
    0x60, 0xfe, 0xd4, 0xba, 0x25, 0x5a, 0x9d, 0x31, 0xc9, 0x61, 0xeb, 0x74, 0xc6, 0x35, 0x6d, 0x68,
    0xc0, 0x49, 0xb8, 0x92, 0x3b, 0x61, 0xfa, 0x6c, 0xe6, 0x69, 0x62, 0x2e, 0x60, 0xf2, 0x9f, 0xb6,
    0x79, 0x03, 0xfe, 0x10, 0x08, 0xb8, 0xbc, 0x99, 0xa4, 0x1a, 0xe9, 0xe9, 0x56, 0x28, 0xbc, 0x64,
    0xf2, 0xf1, 0xb2, 0x0c, 0x2d, 0x7e, 0x9f, 0x51, 0x77, 0xa3, 0xc2, 0x94, 0xd4, 0x46, 0x22, 0x99};
static const uint8_t k_p256_priv[32] = {
    0xc9, 0xaf, 0xa9, 0xd8, 0x45, 0xba, 0x75, 0x16, 0x6b, 0x5c, 0x21, 0x57, 0x67, 0xb1, 0xd6, 0x93,
    0x4e, 0x50, 0xc3, 0xdb, 0x36, 0xe8, 0x9b, 0x12, 0x7b, 0x8a, 0x62, 0x2b, 0x12, 0x0f, 0x67, 0x21};

static const struct {
    const char *hash;
    size_t hash_len;
    const char *r, *s;
} k_p6979[] = {
    {"8151325dcdbae9e0ff95f9f9658432dbedfdb209", 20,
     "61340c88c3aaebeb4f6d667f672ca9759a6ccaa9fa8811313039ee4a35471d32",
     "6d7f147dac089441bb2e2fe8f7a3fa264b9c475098fdcf6e00d7c996e1b8b7eb"},
    {"af2bdbe1aa9b6ec1e2ade1d694f41fc71a831d0268e9891562113d8a62add1bf", 32,
     "efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716",
     "f7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda8"},
    {"9a9083505bc92276aec4be312696ef7bf3bf603f4bbd381196a029f340585312"
     "313bca4a9b5b890efee42c77b1ee25fe", 48,
     "0eafea039b20e9b42309fb1d89e213057cbf973dc0cfc8f129edddc800ef7719",
     "4861f0491e6998b9455193e34e7b0d284ddd7149a74b95b9261f13abde940954"},
    {"39a5e04aaff7455d9850c605364f514c11324ce64016960d23d5dc57d3ffd8f4"
     "9a739468ab8049bf18eef820cdb1ad6c9015f838556bc7fad4138b23fdf986c7", 64,
     "8496a60b5e9b47c825488827e0495b0e3fa109ec4568fd3f8d1097678eb97f00",
     "2362ab1adbe2b8adf9cb9edab740ea6049c028114f2460f96554f61fae3302fe"},
    {"9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08", 32,
     "f1abb023518351cd71d881567b1ea663ed3efcf6c5132b354f28d3b0b7d38367",
     "019f4113742a2b14bd25926b49c649155f267e60d3814b4c0cc84250e46f0083"},
};

/* Wrap-around vector (tools/gen_p256.py --wrap-vector): x_R = r + n with
 * r + n < p, so only the projective (r+n)*Z^2 comparison accepts it. */
static const uint8_t k_p256_wrap_pub[65] = {
    0x04, 0x55, 0x38, 0x35, 0xed, 0x8a, 0x65, 0x79, 0xbd, 0x60, 0x0d, 0x4c, 0x0e, 0xfe, 0x79, 0x09,
    0x91, 0x2f, 0x55, 0xe3, 0x48, 0xc9, 0xc7, 0xc4, 0x3d, 0x12, 0xec, 0x7c, 0xb2, 0xd8, 0x99, 0xe9,
    0xf0, 0xc8, 0x10, 0x88, 0x9a, 0x2b, 0xa3, 0x15, 0x46, 0xba, 0x93, 0xa9, 0x31, 0xf2, 0xe4, 0x17,
    0x37, 0x8d, 0x4d, 0xbc, 0x52, 0x3c, 0xca, 0xce, 0xd6, 0x26, 0x46, 0x55, 0xcb, 0xbd, 0xb0, 0xab,
    0x44};
static const uint8_t k_p256_wrap_hash[32] = {
    0x40, 0x06, 0xdb, 0x04, 0xa6, 0x9b, 0xa4, 0xed, 0xf5, 0x1e, 0xb7, 0xcd, 0xec, 0xee, 0xfa, 0x5f,
    0x52, 0x1d, 0x2a, 0x29, 0x89, 0x0f, 0xc8, 0xbb, 0xd8, 0x94, 0x47, 0x87, 0xfe, 0xbc, 0x73, 0x21};
static const uint8_t k_p256_wrap_sig[64] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x43, 0x19, 0x05, 0x53, 0x58, 0xe8, 0x61, 0x7b, 0x0c, 0x46, 0x35, 0x3d, 0x03, 0x9c, 0xda, 0xab,
    0x00, 0x53, 0x53, 0xaa, 0x3b, 0xb1, 0xbb, 0xa1, 0xcc, 0xdd, 0xaa, 0xdd, 0xee, 0xff, 0x0f, 0x0f,
    0x0f, 0xab, 0xcd, 0xef, 0xab, 0xcd, 0xef, 0xab, 0xcd, 0xef, 0xab, 0xcd, 0xef, 0x0f, 0x0f, 0x12};

/* Identity vector (tools/gen_p256.py --identity-vector): e = -r*d (mod n),
 * so R = u1*G + u2*Q is the point at infinity; R = O must be rejected. */
static const uint8_t k_p256_ident_pub[65] = {
    0x04, 0x81, 0x7c, 0x32, 0xbf, 0xfc, 0xf0, 0xb7, 0xe5, 0xfa, 0x00, 0x0e, 0x72, 0x88, 0x00, 0xcb,
    0x3b, 0x8a, 0xd1, 0x99, 0xd1, 0xc3, 0xe1, 0xc3, 0xdb, 0x9a, 0x27, 0x8f, 0x0d, 0x2d, 0x05, 0xeb,
    0xcb, 0xc8, 0x9e, 0x3d, 0x09, 0xbf, 0x31, 0xa8, 0xf5, 0xe8, 0x35, 0x77, 0x97, 0x06, 0x4d, 0xc7,
    0xc6, 0x64, 0x92, 0x6f, 0x26, 0x65, 0x4d, 0xad, 0x75, 0x7d, 0x6d, 0x52, 0xdf, 0x92, 0xf3, 0x67,
    0xbd};
static const uint8_t k_p256_ident_hash[32] = {
    0xb0, 0xbf, 0xe5, 0x71, 0x0e, 0x1a, 0x1d, 0x1e, 0xae, 0x06, 0xad, 0xc5, 0x47, 0x20, 0xa9, 0x54,
    0xa2, 0xb2, 0xb0, 0xfd, 0x51, 0x9d, 0x82, 0xc9, 0xdb, 0x72, 0xb2, 0x7a, 0x05, 0xdd, 0x48, 0x00};
static const uint8_t k_p256_ident_sig[64] = {
    0x0c, 0x0f, 0xfe, 0xe1, 0x23, 0x45, 0x67, 0x89, 0x0a, 0xbc, 0xde, 0xf0, 0x12, 0x34, 0x56, 0x78,
    0x9d, 0xea, 0xdb, 0xee, 0xfc, 0xaf, 0xeb, 0xab, 0xe0, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde,
    0x00, 0x53, 0x53, 0xaa, 0x3b, 0xb1, 0xbb, 0xa1, 0xcc, 0xdd, 0xaa, 0xdd, 0xee, 0xff, 0x0f, 0x0f,
    0x0f, 0xab, 0xcd, 0xef, 0xab, 0xcd, 0xef, 0xab, 0xcd, 0xef, 0xab, 0xcd, 0xef, 0x0f, 0x0f, 0x12};

static void unhex(uint8_t *out, size_t n, const char *hex) {
    for (size_t i = 0; i < n; i++) {
        unsigned b;
        sscanf(hex + 2 * i, "%2x", &b);
        out[i] = (uint8_t)b;
    }
}

/* The builtin implementation the hook replaces: 0 = valid, < 0 = invalid; the
 * caller compares only the accept/reject decision. */
static int builtin_p256_verify(const uint8_t pub[65], const uint8_t *hash,
                               size_t hash_len, const uint8_t sig[64]) {
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
        mbedtls_mpi_read_binary(&r, sig, 32) == 0 &&
        mbedtls_mpi_read_binary(&s, sig + 32, 32) == 0) {
        ret = mbedtls_ecdsa_verify(&grp, hash, hash_len, &q, &r, &s);
    }
    mbedtls_ecp_group_free(&grp);
    mbedtls_ecp_point_free(&q);
    mbedtls_mpi_free(&r);
    mbedtls_mpi_free(&s);
    return ret;
}

/* RFC 6979 A.2.5, all five published signatures over "sample" and "test":
 * hash lengths 20, 32, 48, 64 cover the SEC 1 4.1.4 truncation rules. */
static void test_p256_rfc6979(void) {
    for (size_t v = 0; v < sizeof k_p6979 / sizeof k_p6979[0]; v++) {
        uint8_t hash[64], sig[64];
        unhex(hash, k_p6979[v].hash_len, k_p6979[v].hash);
        unhex(sig, 32, k_p6979[v].r);
        unhex(sig + 32, 32, k_p6979[v].s);
        CHECK_EQ_INT(wtls_p256_verify(k_p256_pub, hash, k_p6979[v].hash_len, sig), PSA_SUCCESS);
        CHECK_EQ_INT(builtin_p256_verify(k_p256_pub, hash, k_p6979[v].hash_len, sig), 0);
    }
}

/* Sign/verify roundtrip through PSA, plus the hook-covered psa_verify_hash
 * path exactly as the X.509/TLS stack calls it. */
static void test_p256_psa_roundtrip(void) {
    uint8_t hash[32], sig[64], pub[65];
    size_t n = 0;
    unhex(hash, 32, k_p6979[1].hash);
    psa_key_attributes_t a = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_type(&a, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
    psa_set_key_bits(&a, 256);
    psa_set_key_usage_flags(&a, PSA_KEY_USAGE_SIGN_HASH | PSA_KEY_USAGE_VERIFY_HASH);
    psa_set_key_algorithm(&a, PSA_ALG_ECDSA(PSA_ALG_SHA_256));
    psa_key_id_t kp = 0;
    CHECK_EQ_INT(psa_import_key(&a, k_p256_priv, 32, &kp), PSA_SUCCESS);
    n = 0;
    CHECK_EQ_INT(psa_sign_hash(kp, PSA_ALG_ECDSA(PSA_ALG_SHA_256), hash, 32,
                               sig, sizeof sig, &n), PSA_SUCCESS);
    CHECK_EQ_INT(n, 64);
    n = 0;
    CHECK_EQ_INT(psa_export_public_key(kp, pub, sizeof pub, &n), PSA_SUCCESS);
    CHECK_EQ_INT(n, 65);
    CHECK_MEM(pub, k_p256_pub, 65); /* xG with x from RFC 6979 A.2.5 */
    CHECK_EQ_INT(wtls_p256_verify(pub, hash, 32, sig), PSA_SUCCESS);

    psa_key_attributes_t pub_a = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_type(&pub_a, PSA_KEY_TYPE_ECC_PUBLIC_KEY(PSA_ECC_FAMILY_SECP_R1));
    psa_set_key_bits(&pub_a, 256);
    psa_set_key_usage_flags(&pub_a, PSA_KEY_USAGE_VERIFY_HASH);
    psa_set_key_algorithm(&pub_a, PSA_ALG_ECDSA(PSA_ALG_SHA_256));
    psa_key_id_t pub_id = 0;
    CHECK_EQ_INT(psa_import_key(&pub_a, pub, 65, &pub_id), PSA_SUCCESS);
    CHECK_EQ_INT(psa_verify_hash(pub_id, PSA_ALG_ECDSA(PSA_ALG_SHA_256),
                                 hash, 32, sig, 64), PSA_SUCCESS);
    sig[63] ^= 1;
    CHECK_EQ_INT(psa_verify_hash(pub_id, PSA_ALG_ECDSA(PSA_ALG_SHA_256),
                                 hash, 32, sig, 64), PSA_ERROR_INVALID_SIGNATURE);
    psa_destroy_key(pub_id);

    /* An off-curve point must never verify, whichever layer rejects it. */
    uint8_t bad_pub[65];
    memcpy(bad_pub, pub, 65);
    bad_pub[33] ^= 1;
    psa_key_id_t bad_id = 0;
    if (psa_import_key(&pub_a, bad_pub, 65, &bad_id) == PSA_SUCCESS) {
        CHECK(psa_verify_hash(bad_id, PSA_ALG_ECDSA(PSA_ALG_SHA_256),
                              hash, 32, sig, 64) != PSA_SUCCESS);
        psa_destroy_key(bad_id);
    }
    psa_destroy_key(kp);
}

/* Wycheproof-style rejections built from the valid SHA-256("sample") vector:
 * r/s ranges, point validation, truncation and mutation handling. */
static void test_p256_rejects_malformed(void) {
    uint8_t hash[32], sig[64], t[64], hs[32], pub[65];
    unhex(hash, 32, k_p6979[1].hash);
    unhex(sig, 32, k_p6979[1].r);
    unhex(sig + 32, 32, k_p6979[1].s);

    /* r = 0 and s = 0 */
    memcpy(t, sig, 64);
    memset(t, 0, 32);
    CHECK_EQ_INT(wtls_p256_verify(k_p256_pub, hash, 32, t), PSA_ERROR_INVALID_SIGNATURE);
    memcpy(t, sig, 64);
    memset(t + 32, 0, 32);
    CHECK_EQ_INT(wtls_p256_verify(k_p256_pub, hash, 32, t), PSA_ERROR_INVALID_SIGNATURE);

    /* r = n and s = n (out of range) */
    static const uint8_t n_be[32] = {
        0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x51};
    memcpy(t, sig, 64);
    memcpy(t, n_be, 32);
    CHECK_EQ_INT(wtls_p256_verify(k_p256_pub, hash, 32, t), PSA_ERROR_INVALID_SIGNATURE);
    memcpy(t, sig, 64);
    memcpy(t + 32, n_be, 32);
    CHECK_EQ_INT(wtls_p256_verify(k_p256_pub, hash, 32, t), PSA_ERROR_INVALID_SIGNATURE);

    /* r and s swapped */
    memcpy(t, sig, 32);
    memcpy(t, sig + 32, 32);
    memcpy(t + 32, sig, 32);
    CHECK_EQ_INT(wtls_p256_verify(k_p256_pub, hash, 32, t), PSA_ERROR_INVALID_SIGNATURE);

    /* one flipped bit anywhere in the signature */
    for (int i = 0; i < 64; i++) {
        memcpy(t, sig, 64);
        t[i] ^= 0x01;
        CHECK_EQ_INT(wtls_p256_verify(k_p256_pub, hash, 32, t), PSA_ERROR_INVALID_SIGNATURE);
    }
    /* one flipped byte in the hash */
    for (int i = 0; i < 32; i += 7) {
        memcpy(hs, hash, 32);
        hs[i] ^= 0x80;
        CHECK_EQ_INT(wtls_p256_verify(k_p256_pub, hs, 32, sig), PSA_ERROR_INVALID_SIGNATURE);
    }

    /* public key: x >= p */
    memcpy(pub, k_p256_pub, 65);
    memset(pub + 1, 0, 32);
    pub[1] = 0xff; pub[2] = 0xff; pub[3] = 0xff; pub[4] = 0xff;
    pub[5] = 0x00; pub[6] = 0x00; pub[7] = 0x00; pub[8] = 0x01;
    CHECK_EQ_INT(wtls_p256_verify(pub, hash, 32, sig), PSA_ERROR_INVALID_ARGUMENT);
    /* public key: off the curve (y + 1) */
    memcpy(pub, k_p256_pub, 65);
    pub[33] ^= 1;
    CHECK_EQ_INT(wtls_p256_verify(pub, hash, 32, sig), PSA_ERROR_INVALID_ARGUMENT);
    /* public key: not the uncompressed form */
    memcpy(pub, k_p256_pub, 65);
    pub[0] = 0x02;
    CHECK_EQ_INT(wtls_p256_verify(pub, hash, 32, sig), PSA_ERROR_INVALID_ARGUMENT);
    /* a different valid key must not accept the signature */
    CHECK_EQ_INT(wtls_p256_verify(k_p256_wrap_pub, hash, 32, sig), PSA_ERROR_INVALID_SIGNATURE);

    /* empty hash (the hook routes it to the builtin; the direct call
     * rejects) and a one-byte hash */
    CHECK_EQ_INT(wtls_p256_verify(k_p256_pub, hash, 0, sig), PSA_ERROR_INVALID_ARGUMENT);
    CHECK_EQ_INT(wtls_p256_verify(k_p256_pub, hash, 1, sig), PSA_ERROR_INVALID_SIGNATURE);
}

/* Wrap-around vector from tools/gen_p256.py --wrap-vector: the signature is
 * constructed so that x_R = r + n with r + n < p. Only the second, projective
 * comparison can accept it. */
static void test_p256_wrap(void) {
    CHECK_EQ_INT(wtls_p256_verify(k_p256_wrap_pub, k_p256_wrap_hash, 32, k_p256_wrap_sig),
                PSA_SUCCESS);
    CHECK_EQ_INT(builtin_p256_verify(k_p256_wrap_pub, k_p256_wrap_hash, 32, k_p256_wrap_sig), 0);
    /* the same signature with an unrelated key must fail */
    CHECK_EQ_INT(wtls_p256_verify(k_p256_pub, k_p256_wrap_hash, 32, k_p256_wrap_sig),
                PSA_ERROR_INVALID_SIGNATURE);
    /* and one flipped bit in r or s breaks the wrap case too */
    uint8_t t[64];
    memcpy(t, k_p256_wrap_sig, 64);
    t[20] ^= 0x01;
    CHECK_EQ_INT(wtls_p256_verify(k_p256_wrap_pub, k_p256_wrap_hash, 32, t),
                 PSA_ERROR_INVALID_SIGNATURE);
}

/* R = O must be rejected (tools/gen_p256.py --identity-vector: e = -r*d
 * (mod n), so u1*G + u2*Q is the point at infinity). */
static void test_p256_identity(void) {
    CHECK_EQ_INT(wtls_p256_verify(k_p256_ident_pub, k_p256_ident_hash, 32, k_p256_ident_sig),
                 PSA_ERROR_INVALID_SIGNATURE);
    CHECK(builtin_p256_verify(k_p256_ident_pub, k_p256_ident_hash, 32, k_p256_ident_sig) != 0);
}

/* Random keys, four hash lengths (20/32/48/64 bytes), randomized signatures
 * and bit-flip mutations: the accelerated verify must always agree with the
 * builtin oracle. */
static void test_p256_matches_builtin(void) {
    static const psa_algorithm_t halgs[4] = {
        PSA_ALG_SHA_1, PSA_ALG_SHA_256, PSA_ALG_SHA_384, PSA_ALG_SHA_512
    };
#if defined(GEKKO)
    const int rounds = 4; /* the builtin is slow on the Wii */
#else
    const int rounds = 16;
#endif
    uint32_t seed = 0x9e3779b9u;
    for (int round = 0; round < rounds; round++) {
        psa_algorithm_t halg = halgs[round & 3];
        psa_key_attributes_t a = PSA_KEY_ATTRIBUTES_INIT;
        psa_set_key_type(&a, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
        psa_set_key_bits(&a, 256);
        psa_set_key_usage_flags(&a, PSA_KEY_USAGE_SIGN_HASH | PSA_KEY_USAGE_VERIFY_HASH);
        psa_set_key_algorithm(&a, PSA_ALG_ECDSA(halg));
        psa_key_id_t id = 0;
        CHECK_EQ_INT(psa_generate_key(&a, &id), PSA_SUCCESS);
        uint8_t pub[65], msg[16], hash[64], sig[64];
        size_t hlen = 0, n = 0;
        CHECK_EQ_INT(psa_export_public_key(id, pub, sizeof pub, &n), PSA_SUCCESS);
        CHECK_EQ_INT(n, 65);
        for (int i = 0; i < (int)sizeof msg; i++) {
            msg[i] = (uint8_t)xorshift32(&seed);
        }
        CHECK_EQ_INT(psa_hash_compute(halg, msg, sizeof msg, hash, sizeof hash, &hlen), PSA_SUCCESS);
        n = 0;
        CHECK_EQ_INT(psa_sign_hash(id, PSA_ALG_ECDSA(halg), hash, hlen, sig, sizeof sig, &n), PSA_SUCCESS);
        CHECK_EQ_INT(n, 64);
        CHECK_EQ_INT(wtls_p256_verify(pub, hash, hlen, sig), PSA_SUCCESS);
        CHECK_EQ_INT(builtin_p256_verify(pub, hash, hlen, sig), 0);
        for (int m = 0; m < 4; m++) {
            uint8_t bad[64];
            memcpy(bad, sig, 64);
            bad[(m * 17 + 3) & 63] ^= (uint8_t)(1 << (m & 7));
            CHECK_EQ_INT(wtls_p256_verify(pub, hash, hlen, bad), PSA_ERROR_INVALID_SIGNATURE);
            CHECK(builtin_p256_verify(pub, hash, hlen, bad) != 0);
        }
        psa_destroy_key(id);
    }
}
#endif /* WTLS_ACCEL_P256 */

/* ---- Project Wycheproof vectors (tools/gen_wycheproof.py) ---------------- */

#include "wycheproof_p256.inc"
#include "wycheproof_x25519.inc"

static size_t wp_unhex(uint8_t *out, size_t cap, const char *hex) {
    size_t n = strlen(hex) / 2;
    if (n > cap) return 0;
    for (size_t i = 0; i < n; i++) {
        unsigned b = 0;
        sscanf(hex + 2 * i, "%2x", &b);
        out[i] = (uint8_t)b;
    }
    return n;
}

/* Every vector must give the expected shared secret through the PSA path
 * (what TLS uses) and, with the accelerator, through the direct call. Only
 * "acceptable" vectors (low-order and non-canonical points) may be refused
 * by PSA; they must never produce a different secret. */
static void test_wycheproof_x25519(void) {
    const size_t n = sizeof k_wp_x25519 / sizeof k_wp_x25519[0];
    TLOG("  %u X25519 vectors\n", (unsigned)n);
    for (size_t i = 0; i < n; i++) {
        uint8_t priv[32], pub[32], want[32], out[32];
        bool parsed = wp_unhex(priv, 32, k_wp_x25519[i].priv) == 32 && wp_unhex(pub, 32, k_wp_x25519[i].pub) == 32 &&
                      wp_unhex(want, 32, k_wp_x25519[i].shared) == 32;
        CHECK(parsed);
        if (!parsed) continue;
#if defined(WTLS_ACCEL_X25519)
        wtls_x25519(out, priv, pub);
        if (memcmp(out, want, 32) != 0) TLOG("  direct call differs, tcId %d\n", k_wp_x25519[i].tc);
        CHECK_MEM(out, want, 32);
#endif
        psa_key_id_t id = import_x25519(priv);
        size_t olen = 0;
        psa_status_t st = psa_raw_key_agreement(PSA_ALG_ECDH, id, pub, 32, out, sizeof out, &olen);
        if (st == PSA_SUCCESS) {
            bool same = olen == 32 && memcmp(out, want, 32) == 0;
            if (!same) TLOG("  PSA differs, tcId %d\n", k_wp_x25519[i].tc);
            CHECK(same);
        } else {
            if (k_wp_x25519[i].result != 2) TLOG("  PSA refused a valid vector, tcId %d\n", k_wp_x25519[i].tc);
            CHECK_EQ_INT(k_wp_x25519[i].result, 2);
        }
        psa_destroy_key(id);
    }
}

/* ECDSA P-256 / SHA-256: valid vectors verify, invalid ones are rejected, on
 * the PSA path; with the accelerator also the direct call and (host only, the
 * builtin is slow on the Wii) the builtin oracle must agree. */
static void test_wycheproof_p256_sha256(void) {
    const size_t n = sizeof k_wp_p256 / sizeof k_wp_p256[0];
    TLOG("  %u ECDSA P-256 vectors\n", (unsigned)n);
    for (size_t i = 0; i < n; i++) {
        uint8_t pub[65], sig[64], hash[32];
        static uint8_t msg[1024];
        size_t hl = 0;
        size_t mlen = wp_unhex(msg, sizeof msg, k_wp_p256[i].msg);
        bool parsed = wp_unhex(pub, 65, k_wp_p256[i].pub) == 65 && wp_unhex(sig, 64, k_wp_p256[i].sig) == 64 &&
                      (mlen > 0 || k_wp_p256[i].msg[0] == 0);
        CHECK(parsed);
        if (!parsed) continue;
        CHECK_EQ_INT(psa_hash_compute(PSA_ALG_SHA_256, msg, mlen, hash, sizeof hash, &hl), PSA_SUCCESS);
        const bool want = k_wp_p256[i].result == 1;

        psa_key_attributes_t a = PSA_KEY_ATTRIBUTES_INIT;
        psa_set_key_type(&a, PSA_KEY_TYPE_ECC_PUBLIC_KEY(PSA_ECC_FAMILY_SECP_R1));
        psa_set_key_usage_flags(&a, PSA_KEY_USAGE_VERIFY_HASH);
        psa_set_key_algorithm(&a, PSA_ALG_ECDSA(PSA_ALG_SHA_256));
        psa_key_id_t id = 0;
        CHECK_EQ_INT(psa_import_key(&a, pub, sizeof pub, &id), PSA_SUCCESS);
        bool got = psa_verify_hash(id, PSA_ALG_ECDSA(PSA_ALG_SHA_256), hash, hl, sig, sizeof sig) == PSA_SUCCESS;
        psa_destroy_key(id);
        if (got != want) TLOG("  PSA verify differs, tcId %d\n", k_wp_p256[i].tc);
        CHECK(got == want);
#if defined(WTLS_ACCEL_P256)
        bool ours = wtls_p256_verify(pub, hash, hl, sig) == PSA_SUCCESS;
        if (ours != want) TLOG("  accelerator differs, tcId %d\n", k_wp_p256[i].tc);
        CHECK(ours == want);
#if !defined(GEKKO)
        bool ref = builtin_p256_verify(pub, hash, hl, sig) == 0;
        if (ref != ours) TLOG("  builtin disagrees, tcId %d\n", k_wp_p256[i].tc);
        CHECK(ref == ours);
#endif
#endif
    }
}

void wtls_suite_crypto(void) {
    CHECK_EQ_INT(wtls_init(), WTLS_OK);
#if defined(WTLS_ACCEL_X25519)
    RUN(test_x25519_fast_rfc7748_5_2);
    RUN(test_x25519_fast_rfc7748_iterated);
    RUN(test_x25519_fast_rfc7748_6_1);
    RUN(test_x25519_fast_matches_everest);
    RUN(test_x25519_fast_base_matches_everest);
#endif
#if defined(WTLS_ACCEL_P256)
    RUN(test_p256_rfc6979);
    RUN(test_p256_psa_roundtrip);
    RUN(test_p256_rejects_malformed);
    RUN(test_p256_wrap);
    RUN(test_p256_identity);
    RUN(test_p256_matches_builtin);
#endif
    RUN(test_wycheproof_x25519);
    RUN(test_wycheproof_p256_sha256);
    RUN(test_x25519_rfc7748_alice);
    RUN(test_x25519_rfc7748_bob);
    RUN(test_x25519_generated_pairs_agree);
    wtls_shutdown();
}
