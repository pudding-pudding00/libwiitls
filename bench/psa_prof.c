/* Per-function time of the crypto calls a handshake makes, for the benchmark.
 * The bench executables link with -Wl,--wrap=<fn> for every function below,
 * so each call from another object file (the TLS, X.509 and PK code of
 * Mbed TLS) goes through __wrap_<fn>, which times __real_<fn>.
 *
 * Times are inclusive: nested wrapped calls are counted in both (for example
 * psa_verify_hash inside mbedtls_pk_verify_ext inside
 * mbedtls_x509_crt_verify_with_ca_cb). Calls inside one object file (for
 * example within psa_crypto.c) are not seen. */
#include <string.h>

#include <mbedtls/pk.h>
#include <mbedtls/x509_crt.h>
#include <psa/crypto.h>

#include "plat/plat.h"
#include "psa_prof.h"

wtls_psa_prof wtls_psa_prof_acc;
bool wtls_psa_prof_on;

const char *const wtls_psa_prof_names[WTLS_PP_COUNT] = {
#define X(name) #name,
    WTLS_PP_LIST(X)
#undef X
};

static inline uint64_t pp_begin(void) { return wtls_psa_prof_on ? wtls_plat_now_us() : 0; }

static inline void pp_end(int idx, uint64_t t0) {
    if (!wtls_psa_prof_on) return;
    wtls_psa_prof_acc.us[idx] += wtls_plat_now_us() - t0;
    wtls_psa_prof_acc.n[idx]++;
}

/* WRAP(ret, name, (params), (args)): defines __wrap_name around __real_name.
 * Apple's ld64 does not support GNU ld's --wrap, so profiling wraps are skipped there. */
#if !defined(__APPLE__)
#define WRAP(ret, name, params, args)                                                              \
    ret __real_##name params;                                                                      \
    ret __wrap_##name params;                                                                      \
    ret __wrap_##name params {                                                                     \
        uint64_t t0 = pp_begin();                                                                  \
        ret r = __real_##name args;                                                                \
        pp_end(WTLS_PP_##name, t0);                                                                \
        return r;                                                                                  \
    }

WRAP(psa_status_t, psa_generate_key, (const psa_key_attributes_t *a, mbedtls_svc_key_id_t *k), (a, k))
WRAP(psa_status_t, psa_export_public_key, (mbedtls_svc_key_id_t k, uint8_t *d, size_t ds, size_t *dl),
     (k, d, ds, dl))
WRAP(psa_status_t, psa_raw_key_agreement,
     (psa_algorithm_t alg, mbedtls_svc_key_id_t k, const uint8_t *p, size_t pl, uint8_t *o, size_t os,
      size_t *ol),
     (alg, k, p, pl, o, os, ol))
WRAP(psa_status_t, psa_generate_random, (uint8_t *o, size_t n), (o, n))
WRAP(psa_status_t, psa_import_key,
     (const psa_key_attributes_t *a, const uint8_t *d, size_t dl, mbedtls_svc_key_id_t *k), (a, d, dl, k))
WRAP(psa_status_t, psa_destroy_key, (mbedtls_svc_key_id_t k), (k))
WRAP(psa_status_t, psa_verify_hash,
     (mbedtls_svc_key_id_t k, psa_algorithm_t alg, const uint8_t *h, size_t hl, const uint8_t *s, size_t sl),
     (k, alg, h, hl, s, sl))
WRAP(psa_status_t, psa_hash_compute,
     (psa_algorithm_t alg, const uint8_t *i, size_t il, uint8_t *h, size_t hs, size_t *hl),
     (alg, i, il, h, hs, hl))
WRAP(psa_status_t, psa_hash_setup, (psa_hash_operation_t *op, psa_algorithm_t alg), (op, alg))
WRAP(psa_status_t, psa_hash_update, (psa_hash_operation_t *op, const uint8_t *i, size_t il), (op, i, il))
WRAP(psa_status_t, psa_hash_finish, (psa_hash_operation_t *op, uint8_t *h, size_t hs, size_t *hl),
     (op, h, hs, hl))
WRAP(psa_status_t, psa_hash_clone, (const psa_hash_operation_t *s, psa_hash_operation_t *d), (s, d))
WRAP(psa_status_t, psa_key_derivation_setup, (psa_key_derivation_operation_t *op, psa_algorithm_t alg),
     (op, alg))
WRAP(psa_status_t, psa_key_derivation_input_bytes,
     (psa_key_derivation_operation_t *op, psa_key_derivation_step_t st, const uint8_t *d, size_t dl),
     (op, st, d, dl))
WRAP(psa_status_t, psa_key_derivation_input_key,
     (psa_key_derivation_operation_t *op, psa_key_derivation_step_t st, mbedtls_svc_key_id_t k), (op, st, k))
WRAP(psa_status_t, psa_key_derivation_output_bytes, (psa_key_derivation_operation_t *op, uint8_t *o, size_t ol),
     (op, o, ol))
WRAP(psa_status_t, psa_key_derivation_abort, (psa_key_derivation_operation_t *op), (op))
WRAP(psa_status_t, psa_mac_compute,
     (mbedtls_svc_key_id_t k, psa_algorithm_t alg, const uint8_t *i, size_t il, uint8_t *m, size_t ms,
      size_t *ml),
     (k, alg, i, il, m, ms, ml))
WRAP(psa_status_t, psa_mac_sign_setup, (psa_mac_operation_t *op, mbedtls_svc_key_id_t k, psa_algorithm_t alg),
     (op, k, alg))
WRAP(psa_status_t, psa_mac_update, (psa_mac_operation_t *op, const uint8_t *i, size_t il), (op, i, il))
WRAP(psa_status_t, psa_mac_sign_finish, (psa_mac_operation_t *op, uint8_t *m, size_t ms, size_t *ml),
     (op, m, ms, ml))
WRAP(psa_status_t, psa_aead_encrypt,
     (mbedtls_svc_key_id_t k, psa_algorithm_t alg, const uint8_t *n, size_t nl, const uint8_t *ad, size_t adl,
      const uint8_t *p, size_t pl, uint8_t *c, size_t cs, size_t *cl),
     (k, alg, n, nl, ad, adl, p, pl, c, cs, cl))
WRAP(psa_status_t, psa_aead_decrypt,
     (mbedtls_svc_key_id_t k, psa_algorithm_t alg, const uint8_t *n, size_t nl, const uint8_t *ad, size_t adl,
      const uint8_t *c, size_t cl, uint8_t *p, size_t ps, size_t *pl),
     (k, alg, n, nl, ad, adl, c, cl, p, ps, pl))
WRAP(int, mbedtls_x509_crt_parse_der, (mbedtls_x509_crt *c, const unsigned char *b, size_t bl), (c, b, bl))
WRAP(int, mbedtls_x509_crt_verify_with_ca_cb,
     (mbedtls_x509_crt *crt, mbedtls_x509_crt_ca_cb_t f_ca_cb, void *p_ca_cb,
      const mbedtls_x509_crt_profile *profile, const char *cn, uint32_t *flags,
      int (*f_vrfy)(void *, mbedtls_x509_crt *, int, uint32_t *), void *p_vrfy),
     (crt, f_ca_cb, p_ca_cb, profile, cn, flags, f_vrfy, p_vrfy))
WRAP(int, mbedtls_pk_verify_ext,
     (mbedtls_pk_sigalg_t type, mbedtls_pk_context *ctx, mbedtls_md_type_t md, const unsigned char *h,
      size_t hl, const unsigned char *s, size_t sl),
     (type, ctx, md, h, hl, s, sl))
WRAP(int, mbedtls_pk_parse_subpubkey, (unsigned char **p, const unsigned char *end, mbedtls_pk_context *pk),
     (p, end, pk))
#endif
