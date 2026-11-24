/* Crypto call profile of the benchmark (psa_prof.c, linker --wrap). */
#ifndef WTLS_PSA_PROF_H
#define WTLS_PSA_PROF_H

#include <stdbool.h>
#include <stdint.h>

/* Every wrapped function; bench/CMakeLists.txt and the root CMakeLists.txt
 * pass -Wl,--wrap=<name> for each (WTLS_BENCH_WRAP). */
#define WTLS_PP_LIST(X)                                                                            \
    X(psa_generate_key)                                                                            \
    X(psa_export_public_key)                                                                       \
    X(psa_raw_key_agreement)                                                                       \
    X(psa_generate_random)                                                                         \
    X(psa_import_key)                                                                              \
    X(psa_destroy_key)                                                                             \
    X(psa_verify_hash)                                                                             \
    X(psa_hash_compute)                                                                            \
    X(psa_hash_setup)                                                                              \
    X(psa_hash_update)                                                                             \
    X(psa_hash_finish)                                                                             \
    X(psa_hash_clone)                                                                              \
    X(psa_key_derivation_setup)                                                                    \
    X(psa_key_derivation_input_bytes)                                                              \
    X(psa_key_derivation_input_key)                                                                \
    X(psa_key_derivation_output_bytes)                                                             \
    X(psa_key_derivation_abort)                                                                    \
    X(psa_mac_compute)                                                                             \
    X(psa_mac_sign_setup)                                                                          \
    X(psa_mac_update)                                                                              \
    X(psa_mac_sign_finish)                                                                         \
    X(psa_aead_encrypt)                                                                            \
    X(psa_aead_decrypt)                                                                            \
    X(mbedtls_x509_crt_parse_der)                                                                  \
    X(mbedtls_x509_crt_verify_with_ca_cb)                                                          \
    X(mbedtls_pk_verify_ext)                                                                       \
    X(mbedtls_pk_parse_subpubkey)

enum {
#define X(name) WTLS_PP_##name,
    WTLS_PP_LIST(X)
#undef X
    WTLS_PP_COUNT
};

typedef struct {
    uint64_t us[WTLS_PP_COUNT];
    uint32_t n[WTLS_PP_COUNT];
} wtls_psa_prof;

extern wtls_psa_prof wtls_psa_prof_acc; /* accumulated while wtls_psa_prof_on */
extern bool wtls_psa_prof_on;
extern const char *const wtls_psa_prof_names[WTLS_PP_COUNT];

#endif
