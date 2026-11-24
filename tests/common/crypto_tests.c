/* Known-answer tests for the primitives the build options swap (X25519 via
 * builtin or Everest), run on the host (tests/host/test_crypto.c) and on the
 * Wii (suite "crypto"): the benchmarks time them but do not check results,
 * and a big-endian CPU can break code that is only tested on little-endian. */
#include <stdint.h>
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

void wtls_suite_crypto(void) {
    CHECK_EQ_INT(wtls_init(), WTLS_OK);
    RUN(test_x25519_rfc7748_alice);
    RUN(test_x25519_rfc7748_bob);
    RUN(test_x25519_generated_pairs_agree);
    wtls_shutdown();
}
