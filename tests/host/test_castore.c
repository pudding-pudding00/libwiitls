#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <mbedtls/platform.h>
#include <mbedtls/x509_crt.h>
#include <psa/crypto.h>
#include <wiitls/wiitls.h>

#include "check.h"
#include "wtls_castore.h"

WTLS_CHECK_DEFINE_COUNTERS;

#ifndef WTLS_TEST_CERT_DIR
#error "WTLS_TEST_CERT_DIR not set"
#endif
#ifndef WTLS_TEST_FIXTURE_DIR
#error "WTLS_TEST_FIXTURE_DIR not set"
#endif

/* Reads a whole file; appends a '\0' (counted in *len when nul is true, as PEM parsing needs). */
static uint8_t *load(const char *dir, const char *name, size_t *len, int nul) {
    char path[512];
    snprintf(path, sizeof path, "%s/%s", dir, name);
    FILE *f = fopen(path, "rb");
    if (!f) {
        printf("  cannot open %s\n", path);
        return NULL;
    }
    fseek(f, 0, SEEK_END);
    long n = ftell(f);
    fseek(f, 0, SEEK_SET);
    uint8_t *buf = malloc((size_t)n + 1);
    if (buf && fread(buf, 1, (size_t)n, f) != (size_t)n) {
        free(buf);
        buf = NULL;
    }
    fclose(f);
    if (buf) {
        buf[n] = 0;
        *len = (size_t)n + (nul ? 1 : 0);
    }
    return buf;
}

static int parse_file(mbedtls_x509_crt *crt, const char *dir, const char *name) {
    size_t len;
    uint8_t *buf = load(dir, name, &len, 0);
    if (!buf) return -1;
    int r = mbedtls_x509_crt_parse_der(crt, buf, len);
    free(buf);
    return r;
}

static void free_list(mbedtls_x509_crt *list) {
    mbedtls_x509_crt_free(list);
    mbedtls_free(list);
}

static int list_len(const mbedtls_x509_crt *c) {
    int n = 0;
    for (; c; c = c->next) n++;
    return n;
}

#if WTLS_EMBED_CA
static void test_bundle_sorted_and_parseable(void) {
    CHECK(wtls_ca_bundle_count >= 100);
    int unparsable = 0;
    for (size_t i = 0; i < wtls_ca_bundle_count; i++) {
        const wtls_ca_entry *e = &wtls_ca_bundle[i];
        if (i > 0) CHECK(wtls_ca_bundle[i - 1].subject_hash <= e->subject_hash);
        CHECK(e->subject_hash == wtls_fnv1a32(e->der + e->subj_off, e->subj_len));
        mbedtls_x509_crt crt;
        mbedtls_x509_crt_init(&crt);
        int r = mbedtls_x509_crt_parse_der_nocopy(&crt, e->der, e->der_len);
        if (r != 0) {
            printf("  entry %u does not parse: -0x%04x\n", (unsigned)i, (unsigned)-r);
            unparsable++;
        } else {
            CHECK(crt.subject_raw.p == e->der + e->subj_off);
            CHECK_EQ_INT(crt.subject_raw.len, e->subj_len);
        }
        mbedtls_x509_crt_free(&crt);
    }
    CHECK_EQ_INT(unparsable, 0);
}

static void test_lookup_finds_isrg_root_x1(void) {
    mbedtls_x509_crt child;
    mbedtls_x509_crt_init(&child);
    CHECK_EQ_INT(parse_file(&child, WTLS_TEST_FIXTURE_DIR, "r12_intermediate.der"), 0);
    mbedtls_x509_crt *cands = (mbedtls_x509_crt *)1;
    CHECK_EQ_INT(wtls_castore_ca_cb(NULL, &child, &cands), 0);
    CHECK_EQ_INT(list_len(cands), 1);
    if (cands) {
        char dn[256];
        mbedtls_x509_dn_gets(dn, sizeof dn, &cands->subject);
        CHECK(strstr(dn, "ISRG Root X1") != NULL);
        free_list(cands);
    }
    /* Suppressing the built-in bundle drops ISRG Root X1 until restored. */
    wtls_castore_reset(false);
    cands = (mbedtls_x509_crt *)1;
    CHECK_EQ_INT(wtls_castore_ca_cb(NULL, &child, &cands), 0);
    CHECK(cands == NULL);
    wtls_castore_reset(true);
    cands = (mbedtls_x509_crt *)1;
    CHECK_EQ_INT(wtls_castore_ca_cb(NULL, &child, &cands), 0);
    CHECK_EQ_INT(list_len(cands), 1);
    if (cands) free_list(cands);
    mbedtls_x509_crt_free(&child);
}
#endif

static void test_lookup_unknown_issuer_returns_null(void) {
    mbedtls_x509_crt child;
    mbedtls_x509_crt_init(&child);
    CHECK_EQ_INT(parse_file(&child, WTLS_TEST_CERT_DIR, "untrusted.der"), 0);
    mbedtls_x509_crt *cands = (mbedtls_x509_crt *)1;
    CHECK_EQ_INT(wtls_castore_ca_cb(NULL, &child, &cands), 0);
    CHECK(cands == NULL);
    mbedtls_x509_crt_free(&child);
}

static void test_extra_ca_pem_and_der(void) {
    mbedtls_x509_crt child;
    mbedtls_x509_crt_init(&child);
    CHECK_EQ_INT(parse_file(&child, WTLS_TEST_CERT_DIR, "ecdsa.der"), 0);

    mbedtls_x509_crt *cands = (mbedtls_x509_crt *)1;
    CHECK_EQ_INT(wtls_castore_ca_cb(NULL, &child, &cands), 0);
    CHECK(cands == NULL); /* not trusted before it is added */

    size_t len;
    uint8_t *pem = load(WTLS_TEST_CERT_DIR, "test-ca.pem", &len, 1);
    CHECK(pem != NULL);
    if (pem) CHECK_EQ_INT(wtls_castore_add(pem, len), WTLS_OK);
    free(pem);
    CHECK_EQ_INT(wtls_castore_ca_cb(NULL, &child, &cands), 0);
    CHECK_EQ_INT(list_len(cands), 1);
    if (cands) {
        CHECK(cands->subject_raw.len == child.issuer_raw.len &&
              memcmp(cands->subject_raw.p, child.issuer_raw.p, child.issuer_raw.len) == 0);
        free_list(cands);
    }

    wtls_castore_free();
    uint8_t *der = load(WTLS_TEST_CERT_DIR, "test-ca.der", &len, 0);
    CHECK(der != NULL);
    if (der) CHECK_EQ_INT(wtls_castore_add(der, len), WTLS_OK);
    free(der);
    CHECK_EQ_INT(wtls_castore_ca_cb(NULL, &child, &cands), 0);
    CHECK_EQ_INT(list_len(cands), 1);
    if (cands) free_list(cands);

    static const uint8_t junk[] = "not a certificate";
    CHECK_EQ_INT(wtls_castore_add(junk, sizeof junk), WTLS_ERR_ARG);
    CHECK_EQ_INT(wtls_castore_add(NULL, 10), WTLS_ERR_ARG);

    wtls_castore_free();
    mbedtls_x509_crt_free(&child);
}

static void test_lookup_counter_increments(void) {
    mbedtls_x509_crt child;
    mbedtls_x509_crt_init(&child);
    CHECK_EQ_INT(parse_file(&child, WTLS_TEST_CERT_DIR, "untrusted.der"), 0);
    uint32_t before = wtls_castore_lookups;
    mbedtls_x509_crt *cands;
    wtls_castore_ca_cb(NULL, &child, &cands);
    wtls_castore_ca_cb(NULL, &child, &cands);
    CHECK_EQ_INT(wtls_castore_lookups - before, 2);
    mbedtls_x509_crt_free(&child);
}

int main(void) {
    if (psa_crypto_init() != PSA_SUCCESS) return 1; /* PK parsing uses PSA */
#if WTLS_EMBED_CA
    RUN(test_bundle_sorted_and_parseable);
    RUN(test_lookup_finds_isrg_root_x1);
#endif
    RUN(test_lookup_unknown_issuer_returns_null);
    RUN(test_extra_ca_pem_and_der);
    RUN(test_lookup_counter_increments);
    return CHECK_DONE();
}
