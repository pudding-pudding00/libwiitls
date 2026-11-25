#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <wiitls/wiitls.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    static bool init_done;
    if (!init_done) {
        if (wtls_init() != WTLS_OK) return 0;
        init_done = true;
    }
    if (size > 16384u) size = 16384u;

    size_t split = size / 2;
    const void *sep = memchr(data, '|', size);
    if (sep) split = (size_t)((const uint8_t *)sep - data);

    const uint8_t *cert = data;
    size_t cert_len = split;
    const uint8_t *key = split < size ? data + split + (sep ? 1u : 0u) : data;
    size_t key_len = split < size ? size - split - (sep ? 1u : 0u) : 0;

    /* Try raw (DER) and NUL-terminated (PEM) variants. */
    wtls_client_cred *cred = NULL;
    if (wtls_client_cred_load(&cred, cert, cert_len, key, key_len) == WTLS_OK) {
        wtls_client_cred_free(cred);
    }

    uint8_t *c_nul = malloc(cert_len + 1);
    uint8_t *k_nul = malloc(key_len + 1);
    if (c_nul && k_nul) {
        if (cert_len) memcpy(c_nul, cert, cert_len);
        c_nul[cert_len] = '\0';
        if (key_len) memcpy(k_nul, key, key_len);
        k_nul[key_len] = '\0';
        cred = NULL;
        if (wtls_client_cred_load(&cred, c_nul, cert_len + 1, k_nul, key_len + 1) == WTLS_OK) {
            wtls_client_cred_free(cred);
        }
    }
    free(c_nul);
    free(k_nul);
    return 0;
}
