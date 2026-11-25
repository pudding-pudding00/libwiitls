#include <string.h>

#include <wiitls/wiitls.h>

#include "check.h"
#include "wtls_scache.h"

WTLS_CHECK_DEFINE_COUNTERS;

static uint8_t blob[WTLS_SESSION_BLOB_MAX + 1];

static void test_put_take_roundtrip(void) {
    wtls_scache_clear();
    memset(blob, 0xAB, 300);
    CHECK_EQ_INT(wtls_scache_put("example.com", 443, false, NULL, blob, 300, 1000), WTLS_OK);
    uint8_t out[WTLS_SESSION_BLOB_MAX];
    size_t len = 0;
    CHECK_EQ_INT(wtls_scache_take("example.com", 443, false, NULL, out, sizeof out, &len, 2000),
                 WTLS_OK);
    CHECK_EQ_INT(len, 300);
    CHECK_MEM(out, blob, 300);
    CHECK_EQ_INT(wtls_scache_take("example.com", 444, false, NULL, out, sizeof out, &len, 2000),
                 WTLS_ERR_STATE);
}

static void test_take_removes(void) {
    wtls_scache_clear();
    CHECK_EQ_INT(wtls_scache_put("a.test", 1, false, NULL, blob, 10, 0), WTLS_OK);
    uint8_t out[64];
    size_t len;
    CHECK_EQ_INT(wtls_scache_take("a.test", 1, false, NULL, out, sizeof out, &len, 0), WTLS_OK);
    CHECK_EQ_INT(wtls_scache_take("a.test", 1, false, NULL, out, sizeof out, &len, 0),
                 WTLS_ERR_STATE);
}

/* A session offered with a client certificate (or none) must never serve a
 * connection with a different identity: resumption skips the certificate
 * work, so the identity is part of the key. */
static void test_client_identity_isolation(void) {
    static const uint8_t fp_a[WTLS_SCACHE_FP_LEN] = {1};
    static const uint8_t fp_b[WTLS_SCACHE_FP_LEN] = {2};
    wtls_scache_clear();
    blob[0] = 0x11;
    CHECK_EQ_INT(wtls_scache_put("a.test", 1, false, NULL, blob, 10, 0), WTLS_OK);
    blob[0] = 0x22;
    CHECK_EQ_INT(wtls_scache_put("a.test", 1, true, fp_a, blob, 10, 0), WTLS_OK);
    blob[0] = 0x33;
    CHECK_EQ_INT(wtls_scache_put("a.test", 1, true, fp_b, blob, 10, 0), WTLS_OK);

    uint8_t out[64];
    size_t len;
    /* no client cert: only the no-cred entry matches */
    memset(out, 0, sizeof out);
    CHECK_EQ_INT(wtls_scache_take("a.test", 1, false, NULL, out, sizeof out, &len, 0), WTLS_OK);
    CHECK_EQ_INT(out[0], 0x11);
    /* fp_a: only its own entry */
    CHECK_EQ_INT(wtls_scache_take("a.test", 1, true, fp_a, out, sizeof out, &len, 0), WTLS_OK);
    CHECK_EQ_INT(out[0], 0x22);
    CHECK_EQ_INT(wtls_scache_take("a.test", 1, true, fp_a, out, sizeof out, &len, 0),
                 WTLS_ERR_STATE);
    /* fp_b: still there, untouched by the fp_a takes */
    CHECK_EQ_INT(wtls_scache_take("a.test", 1, true, fp_b, out, sizeof out, &len, 0), WTLS_OK);
    CHECK_EQ_INT(out[0], 0x33);
    /* bad arguments */
    CHECK_EQ_INT(wtls_scache_take("a.test", 1, true, NULL, out, sizeof out, &len, 0), WTLS_ERR_ARG);
    CHECK_EQ_INT(wtls_scache_put("a.test", 1, true, NULL, blob, 10, 0), WTLS_ERR_ARG);
}

static void test_lru_evicts_oldest(void) {
    wtls_scache_clear();
    char host[32];
    for (int i = 0; i < WTLS_SCACHE_SLOTS + 1; i++) {
        snprintf(host, sizeof host, "h%d.test", i);
        blob[0] = (uint8_t)i;
        CHECK_EQ_INT(wtls_scache_put(host, 443, false, NULL, blob, 1, (uint64_t)i), WTLS_OK);
    }
    uint8_t out[8];
    size_t len;
    CHECK_EQ_INT(wtls_scache_take("h0.test", 443, false, NULL, out, sizeof out, &len, 100),
                 WTLS_ERR_STATE);
    for (int i = 1; i < WTLS_SCACHE_SLOTS + 1; i++) {
        snprintf(host, sizeof host, "h%d.test", i);
        CHECK_EQ_INT(wtls_scache_take(host, 443, false, NULL, out, sizeof out, &len, 100),
                     WTLS_OK);
        CHECK_EQ_INT(out[0], i);
    }
}

static void test_expired_entry_is_miss(void) {
    wtls_scache_clear();
    CHECK_EQ_INT(wtls_scache_put("a.test", 1, false, NULL, blob, 10, 5), WTLS_OK);
    uint8_t out[64];
    size_t len;
    CHECK_EQ_INT(
        wtls_scache_take("a.test", 1, false, NULL, out, sizeof out, &len, 5 + WTLS_SESSION_MAX_AGE_MS + 1),
        WTLS_ERR_STATE);
}

static void test_oversize_rejected(void) {
    wtls_scache_clear();
    CHECK_EQ_INT(wtls_scache_put("a.test", 1, false, NULL, blob, WTLS_SESSION_BLOB_MAX + 1, 0),
                 WTLS_ERR_ARG);
    CHECK_EQ_INT(wtls_scache_put("a.test", 1, false, NULL, blob, WTLS_SESSION_BLOB_MAX, 0),
                 WTLS_OK);
    uint8_t small[16];
    size_t len;
    /* Too small a buffer: miss, and the (unusable) entry is consumed. */
    CHECK_EQ_INT(wtls_scache_take("a.test", 1, false, NULL, small, sizeof small, &len, 0),
                 WTLS_ERR_STATE);
}

static void test_host_case_insensitive(void) {
    wtls_scache_clear();
    CHECK_EQ_INT(wtls_scache_put("Example.COM", 443, false, NULL, blob, 5, 0), WTLS_OK);
    uint8_t out[8];
    size_t len;
    CHECK_EQ_INT(wtls_scache_take("example.com", 443, false, NULL, out, sizeof out, &len, 0),
                 WTLS_OK);
}

static void test_put_replaces_same_key(void) {
    wtls_scache_clear();
    blob[0] = 1;
    CHECK_EQ_INT(wtls_scache_put("a.test", 1, false, NULL, blob, 1, 0), WTLS_OK);
    blob[0] = 2;
    CHECK_EQ_INT(wtls_scache_put("a.test", 1, false, NULL, blob, 1, 1), WTLS_OK);
    uint8_t out[8];
    size_t len;
    CHECK_EQ_INT(wtls_scache_take("a.test", 1, false, NULL, out, sizeof out, &len, 2), WTLS_OK);
    CHECK_EQ_INT(out[0], 2);
    CHECK_EQ_INT(wtls_scache_take("a.test", 1, false, NULL, out, sizeof out, &len, 2),
                 WTLS_ERR_STATE);
}

int main(void) {
    RUN(test_put_take_roundtrip);
    RUN(test_take_removes);
    RUN(test_client_identity_isolation);
    RUN(test_lru_evicts_oldest);
    RUN(test_expired_entry_is_miss);
    RUN(test_oversize_rejected);
    RUN(test_host_case_insensitive);
    RUN(test_put_replaces_same_key);
    return CHECK_DONE();
}
