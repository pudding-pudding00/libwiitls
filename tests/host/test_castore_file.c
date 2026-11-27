/* wtls_load_ca_bundle_file() / _signed(): bundles from files. Host only. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <mbedtls/platform.h>
#include <mbedtls/x509_crt.h>
#include <wiitls/wiitls.h>

#include "check.h"
#include "sig_vectors.inc"
#include "ca_file_vectors.inc"
#include "wtls_castore.h"

WTLS_CHECK_DEFINE_COUNTERS;

#ifndef WTLS_TEST_FIXTURE_DIR
#error "WTLS_TEST_FIXTURE_DIR not set"
#endif
#ifndef WTLS_TEST_DATA_DIR
#error "WTLS_TEST_DATA_DIR not set"
#endif

#define TMP_PEM "wtls_cafile_test.pem"
#define TMP_SIG "wtls_cafile_test.pem.sig"

static void write_file(const char *p, const void *data, size_t n) {
    FILE *f = fopen(p, "wb");
    CHECK(f != NULL);
    if (!f) return;
    if (n) fwrite(data, 1, n, f);
    fclose(f);
}

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

/* Candidates for the issuer of the fixture R12 certificate (ISRG Root X1): their count. */
static int isrg_candidates(void) {
    char path[512];
    snprintf(path, sizeof path, "%s/r12_intermediate.der", WTLS_TEST_FIXTURE_DIR);
    FILE *f = fopen(path, "rb");
    if (!f) return -1;
    uint8_t der[2048];
    size_t n = fread(der, 1, sizeof der, f);
    fclose(f);
    mbedtls_x509_crt child;
    mbedtls_x509_crt_init(&child);
    int count = -1;
    if (mbedtls_x509_crt_parse_der(&child, der, n) == 0) {
        mbedtls_x509_crt *c = (mbedtls_x509_crt *)1;
        if (wtls_castore_ca_cb(NULL, &child, &c) == 0) {
            count = 0;
            for (const mbedtls_x509_crt *p = c; p && p->raw.p; p = p->next) count++;
            if (c) {
                mbedtls_x509_crt_free(c);
                mbedtls_free(c);
            }
        }
    }
    mbedtls_x509_crt_free(&child);
    return count;
}

static void reset(void) { wtls_reset_trusted_cas(true); }

#if WTLS_EMBED_CA
static void test_castore_file_load_count(void) {
    reset();
    size_t n = 0;
    CHECK_EQ_INT(wtls_load_ca_bundle_file(WTLS_TEST_DATA_DIR "/cacert.pem", false, &n), WTLS_OK);
    CHECK_EQ_INT((long)n, (long)wtls_ca_bundle_count); /* the embedded bundle is generated from this file */
    reset();
}

static void test_castore_file_replace_builtin_uses_only_the_file(void) {
    reset();
    CHECK_EQ_INT(isrg_candidates(), 1); /* built-in */
    write_file(TMP_PEM, k_ca_file_pem, strlen(k_ca_file_pem)); /* a bundle with just R12: not the ISRG root */
    size_t n = 0;
    CHECK_EQ_INT(wtls_load_ca_bundle_file(TMP_PEM, true, &n), WTLS_OK);
    CHECK_EQ_INT((long)n, 1);
    CHECK_EQ_INT(isrg_candidates(), 0); /* built-in suppressed */
    CHECK_EQ_INT(wtls_load_ca_bundle_file(WTLS_TEST_DATA_DIR "/cacert.pem", true, &n), WTLS_OK);
    CHECK_EQ_INT(isrg_candidates(), 1); /* now from the file, which replaced the first one */
    reset();
    CHECK_EQ_INT(isrg_candidates(), 1);
    remove(TMP_PEM);
}
#endif

static void test_castore_file_skips_garbage_blocks(void) {
    reset();
    static const char junk[] =
        "Some header text\n=====\n"
        "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"
        "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n"
        "-----BEGIN CERTIFICATE-----\n!!not base64!!\n-----END CERTIFICATE-----\n";
    size_t pl = strlen(k_ca_file_pem), jl = strlen(junk);
    char *all = malloc(jl + pl + 1);
    memcpy(all, junk, jl);
    memcpy(all + jl, k_ca_file_pem, pl); /* the one good certificate comes last */
    write_file(TMP_PEM, all, jl + pl);
    free(all);
    size_t n = 99;
    CHECK_EQ_INT(wtls_load_ca_bundle_file(TMP_PEM, false, &n), WTLS_OK);
    CHECK_EQ_INT((long)n, 1);
    reset();
    remove(TMP_PEM);
}

static void test_castore_file_crlf_and_no_final_newline(void) {
    reset();
    size_t pl = strlen(k_ca_file_pem);
    char *crlf = malloc(pl * 2 + 1);
    size_t o = 0;
    for (size_t i = 0; i + 1 < pl; i++) { /* drop the final newline */
        if (k_ca_file_pem[i] == '\n') crlf[o++] = '\r';
        crlf[o++] = k_ca_file_pem[i];
    }
    write_file(TMP_PEM, crlf, o);
    free(crlf);
    size_t n = 0;
    CHECK_EQ_INT(wtls_load_ca_bundle_file(TMP_PEM, false, &n), WTLS_OK);
    CHECK_EQ_INT((long)n, 1);
    reset();
    remove(TMP_PEM);
}

static void test_castore_file_missing_file_error(void) {
    size_t n = 5;
    CHECK_EQ_INT(wtls_load_ca_bundle_file("wtls_no_such_file.pem", false, &n), WTLS_ERR_FILE);
    CHECK_EQ_INT((long)n, 0);
}

static void test_castore_file_no_usable_certificate(void) {
    write_file(TMP_PEM, "nothing to see here\n", 20);
    CHECK_EQ_INT(wtls_load_ca_bundle_file(TMP_PEM, true, NULL), WTLS_ERR_ARG);
    CHECK_EQ_INT(isrg_candidates() >= 0, 1); /* store still works (and, on error, is unchanged) */
#if WTLS_EMBED_CA
    CHECK_EQ_INT(isrg_candidates(), 1);
#endif
    remove(TMP_PEM);
}

static void test_castore_file_signed_ok(void) {
    reset();
    uint8_t pub[65], sig[80];
    CHECK_EQ_INT(unhex(pub, sizeof pub, k_sig_pub), 65);
    size_t sl = unhex(sig, sizeof sig, k_ca_file_sig_der);
    write_file(TMP_PEM, k_ca_file_pem, strlen(k_ca_file_pem));
    write_file(TMP_SIG, sig, sl);
    size_t n = 0;
    CHECK_EQ_INT(wtls_load_ca_bundle_file_signed(TMP_PEM, TMP_SIG, pub, 65, false, &n), WTLS_OK);
    CHECK_EQ_INT((long)n, 1);
    reset();
    remove(TMP_PEM);
    remove(TMP_SIG);
}

static void test_castore_file_signed_bad_keeps_old_store(void) {
    reset();
    uint8_t pub[65], sig[80];
    CHECK_EQ_INT(unhex(pub, sizeof pub, k_sig_pub), 65);
    size_t sl = unhex(sig, sizeof sig, k_ca_file_sig_der);
    char *tampered = strdup(k_ca_file_pem);
    tampered[100] = tampered[100] == 'A' ? 'B' : 'A'; /* a changed certificate byte */
    write_file(TMP_PEM, tampered, strlen(tampered));
    free(tampered);
    write_file(TMP_SIG, sig, sl);
    size_t n = 7;
    CHECK_EQ_INT(wtls_load_ca_bundle_file_signed(TMP_PEM, TMP_SIG, pub, 65, true, &n), WTLS_ERR_INTEGRITY);
    CHECK_EQ_INT((long)n, 0);
#if WTLS_EMBED_CA
    CHECK_EQ_INT(isrg_candidates(), 1); /* built-in bundle still active: nothing was replaced */
#endif
    CHECK_EQ_INT(wtls_load_ca_bundle_file_signed(TMP_PEM, "wtls_no_such.sig", pub, 65, true, &n), WTLS_ERR_FILE);
    CHECK_EQ_INT(wtls_load_ca_bundle_file_signed(TMP_PEM, NULL, pub, 65, true, &n), WTLS_ERR_ARG);
    reset();
    remove(TMP_PEM);
    remove(TMP_SIG);
}

int main(void) {
    if (wtls_init() != WTLS_OK) return 1;
#if WTLS_EMBED_CA
    RUN(test_castore_file_load_count);
    RUN(test_castore_file_replace_builtin_uses_only_the_file);
#endif
    RUN(test_castore_file_skips_garbage_blocks);
    RUN(test_castore_file_crlf_and_no_final_newline);
    RUN(test_castore_file_missing_file_error);
    RUN(test_castore_file_no_usable_certificate);
    RUN(test_castore_file_signed_ok);
    RUN(test_castore_file_signed_bad_keeps_old_store);
    wtls_shutdown();
    return CHECK_DONE();
}
