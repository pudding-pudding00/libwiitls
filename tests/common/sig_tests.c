/* SHA-256 and P-256 signature verification tests (suite "sig", host and Wii). */
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <wiitls/sig.h>
#include <wiitls/wiitls.h>

#include "check.h"
#include "sig_vectors.inc"

static size_t unhex(uint8_t *out, size_t cap, const char *hex) {
    size_t n = strlen(hex) / 2;
    if (n > cap) return 0;
    for (size_t i = 0; i < n; i++) {
        unsigned b = 0;
        sscanf(hex + 2 * i, "%2x", &b);
        out[i] = (uint8_t)b;
    }
    return n;
}

typedef struct {
    uint8_t pub[65], spki[91], msg[64], der[80], raw[64], nc[80];
    size_t msg_len, der_len, nc_len;
} vec;

static vec v;

static void load(void) {
    CHECK_EQ_INT(unhex(v.pub, sizeof v.pub, k_sig_pub), 65);
    CHECK_EQ_INT(unhex(v.spki, sizeof v.spki, k_sig_spki), 91);
    v.msg_len = unhex(v.msg, sizeof v.msg, k_sig_msg);
    v.der_len = unhex(v.der, sizeof v.der, k_sig_der);
    CHECK_EQ_INT(unhex(v.raw, sizeof v.raw, k_sig_raw), 64);
    v.nc_len = unhex(v.nc, sizeof v.nc, k_sig_der_noncanonical);
    CHECK(v.msg_len > 0 && v.der_len > 0 && v.nc_len > v.der_len);
}

static void test_sha256_nist_abc(void) {
    static const uint8_t want[32] = {0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
                                     0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad};
    wtls_sha256_ctx c;
    uint8_t out[32];
    CHECK_EQ_INT(wtls_sha256_init(&c), WTLS_OK);
    CHECK_EQ_INT(wtls_sha256_update(&c, "abc", 3), WTLS_OK);
    CHECK_EQ_INT(wtls_sha256_finish(&c, out), WTLS_OK);
    CHECK_MEM(out, want, 32);
}

static void test_sha256_incremental_equals_oneshot(void) {
    uint8_t data[1000], a[32], b[32];
    for (size_t i = 0; i < sizeof data; i++) data[i] = (uint8_t)(i * 7 + 3);
    wtls_sha256_ctx c;
    CHECK_EQ_INT(wtls_sha256_init(&c), WTLS_OK);
    CHECK_EQ_INT(wtls_sha256_finish(&c, a), WTLS_OK); /* empty */
    static const uint8_t empty[32] = {0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
                                      0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55};
    CHECK_MEM(a, empty, 32);
    CHECK_EQ_INT(wtls_sha256_init(&c), WTLS_OK);
    for (size_t off = 0; off < sizeof data; off += 37) {
        size_t n = sizeof data - off < 37 ? sizeof data - off : 37;
        CHECK_EQ_INT(wtls_sha256_update(&c, data + off, n), WTLS_OK);
    }
    CHECK_EQ_INT(wtls_sha256_finish(&c, a), WTLS_OK);
    CHECK_EQ_INT(wtls_sha256_init(&c), WTLS_OK);
    CHECK_EQ_INT(wtls_sha256_update(&c, data, sizeof data), WTLS_OK);
    CHECK_EQ_INT(wtls_sha256_finish(&c, b), WTLS_OK);
    CHECK_MEM(a, b, 32);
}

static void test_sig_p256_raw_ok(void) {
    CHECK_EQ_INT(wtls_sig_verify_p256(v.pub, 65, v.msg, v.msg_len, v.raw, 64, WTLS_SIG_RAW), WTLS_OK);
}

static void test_sig_p256_der_ok(void) {
    CHECK_EQ_INT(wtls_sig_verify_p256(v.pub, 65, v.msg, v.msg_len, v.der, v.der_len, WTLS_SIG_DER), WTLS_OK);
}

static void test_sig_p256_spki_key_ok(void) {
    CHECK_EQ_INT(wtls_sig_verify_p256(v.spki, 91, v.msg, v.msg_len, v.der, v.der_len, WTLS_SIG_DER), WTLS_OK);
}

static void test_sig_p256_bitflip_msg_integrity(void) {
    uint8_t m[64];
    memcpy(m, v.msg, v.msg_len);
    m[v.msg_len / 2] ^= 1;
    CHECK_EQ_INT(wtls_sig_verify_p256(v.pub, 65, m, v.msg_len, v.raw, 64, WTLS_SIG_RAW), WTLS_ERR_INTEGRITY);
}

static void test_sig_p256_bitflip_sig_integrity(void) {
    for (size_t i = 0; i < 64; i += 9) {
        uint8_t s[64];
        memcpy(s, v.raw, 64);
        s[i] ^= 0x10;
        CHECK_EQ_INT(wtls_sig_verify_p256(v.pub, 65, v.msg, v.msg_len, s, 64, WTLS_SIG_RAW), WTLS_ERR_INTEGRITY);
    }
}

static void test_sig_p256_wrong_key_integrity(void) {
    uint8_t other[65];
    memcpy(other, v.pub, 65);
    /* the generator point: a valid key that did not sign */
    static const uint8_t g[65] = {
        0x04, 0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42, 0x47, 0xf8, 0xbc, 0xe6, 0xe5, 0x63, 0xa4, 0x40, 0xf2, 0x77,
        0x03, 0x7d, 0x81, 0x2d, 0xeb, 0x33, 0xa0, 0xf4, 0xa1, 0x39, 0x45, 0xd8, 0x98, 0xc2, 0x96, 0x4f, 0xe3, 0x42,
        0xe2, 0xfe, 0x1a, 0x7f, 0x9b, 0x8e, 0xe7, 0xeb, 0x4a, 0x7c, 0x0f, 0x9e, 0x16, 0x2b, 0xce, 0x33, 0x57, 0x6b,
        0x31, 0x5e, 0xce, 0xcb, 0xb6, 0x40, 0x68, 0x37, 0xbf, 0x51, 0xf5};
    CHECK_EQ_INT(wtls_sig_verify_p256(g, 65, v.msg, v.msg_len, v.raw, 64, WTLS_SIG_RAW), WTLS_ERR_INTEGRITY);
}

static void test_sig_p256_r_s_out_of_range_integrity(void) {
    uint8_t s[64];
    memcpy(s, v.raw, 64);
    memset(s, 0, 32); /* r = 0 */
    CHECK_EQ_INT(wtls_sig_verify_p256(v.pub, 65, v.msg, v.msg_len, s, 64, WTLS_SIG_RAW), WTLS_ERR_INTEGRITY);
    memcpy(s, v.raw, 64);
    memset(s + 32, 0, 32); /* s = 0 */
    CHECK_EQ_INT(wtls_sig_verify_p256(v.pub, 65, v.msg, v.msg_len, s, 64, WTLS_SIG_RAW), WTLS_ERR_INTEGRITY);
    memset(s, 0xff, 64); /* r, s >= n */
    CHECK_EQ_INT(wtls_sig_verify_p256(v.pub, 65, v.msg, v.msg_len, s, 64, WTLS_SIG_RAW), WTLS_ERR_INTEGRITY);
}

static void test_sig_p256_noncanonical_der_integrity(void) {
    CHECK_EQ_INT(wtls_sig_verify_p256(v.pub, 65, v.msg, v.msg_len, v.nc, v.nc_len, WTLS_SIG_DER), WTLS_ERR_INTEGRITY);
    uint8_t t[80];
    memcpy(t, v.der, v.der_len);
    t[v.der_len] = 0; /* trailing byte */
    CHECK_EQ_INT(wtls_sig_verify_p256(v.pub, 65, v.msg, v.msg_len, t, v.der_len + 1, WTLS_SIG_DER), WTLS_ERR_INTEGRITY);
}

static void test_sig_p256_bad_arguments(void) {
    CHECK_EQ_INT(wtls_sig_verify_p256(NULL, 65, v.msg, v.msg_len, v.raw, 64, WTLS_SIG_RAW), WTLS_ERR_ARG);
    CHECK_EQ_INT(wtls_sig_verify_p256(v.pub, 64, v.msg, v.msg_len, v.raw, 64, WTLS_SIG_RAW), WTLS_ERR_ARG);
    CHECK_EQ_INT(wtls_sig_verify_p256(v.pub, 65, v.msg, v.msg_len, v.raw, 63, WTLS_SIG_RAW), WTLS_ERR_ARG);
    uint8_t off_curve[65];
    memcpy(off_curve, v.pub, 65);
    off_curve[64] ^= 1;
    CHECK_EQ_INT(wtls_sig_verify_p256(off_curve, 65, v.msg, v.msg_len, v.raw, 64, WTLS_SIG_RAW), WTLS_ERR_ARG);
    uint8_t cut[91];
    memcpy(cut, v.spki, 91);
    cut[10] ^= 1; /* wrong curve OID */
    CHECK_EQ_INT(wtls_sig_verify_p256(cut, 91, v.msg, v.msg_len, v.der, v.der_len, WTLS_SIG_DER), WTLS_ERR_ARG);
}

static void test_sig_p256_digest_matches_msg_variant(void) {
    wtls_sha256_ctx c;
    uint8_t d[32];
    CHECK_EQ_INT(wtls_sha256_init(&c), WTLS_OK);
    CHECK_EQ_INT(wtls_sha256_update(&c, v.msg, v.msg_len), WTLS_OK);
    CHECK_EQ_INT(wtls_sha256_finish(&c, d), WTLS_OK);
    CHECK_EQ_INT(wtls_sig_verify_p256_digest(v.pub, 65, d, v.raw, 64, WTLS_SIG_RAW), WTLS_OK);
    d[0] ^= 1;
    CHECK_EQ_INT(wtls_sig_verify_p256_digest(v.pub, 65, d, v.raw, 64, WTLS_SIG_RAW), WTLS_ERR_INTEGRITY);
}

static void test_sig_requires_init(void) {
    wtls_shutdown();
    wtls_sha256_ctx c;
    CHECK_EQ_INT(wtls_sha256_init(&c), WTLS_ERR_STATE);
    CHECK_EQ_INT(wtls_sig_verify_p256(v.pub, 65, v.msg, v.msg_len, v.raw, 64, WTLS_SIG_RAW), WTLS_ERR_STATE);
    CHECK_EQ_INT(wtls_init(), WTLS_OK);
}

void wtls_suite_sig(void) {
    CHECK_EQ_INT(wtls_init(), WTLS_OK);
    load();
    RUN(test_sha256_nist_abc);
    RUN(test_sha256_incremental_equals_oneshot);
    RUN(test_sig_p256_raw_ok);
    RUN(test_sig_p256_der_ok);
    RUN(test_sig_p256_spki_key_ok);
    RUN(test_sig_p256_bitflip_msg_integrity);
    RUN(test_sig_p256_bitflip_sig_integrity);
    RUN(test_sig_p256_wrong_key_integrity);
    RUN(test_sig_p256_r_s_out_of_range_integrity);
    RUN(test_sig_p256_noncanonical_der_integrity);
    RUN(test_sig_p256_bad_arguments);
    RUN(test_sig_p256_digest_matches_msg_variant);
    RUN(test_sig_requires_init);
    wtls_shutdown();
}
