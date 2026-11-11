/**
 * @file wiitls.h
 * @brief libwiitls - modern TLS (1.3, 1.2 fallback) client for Wii homebrew.
 *
 * Threading: every wtls_* function must be called from one single thread
 * (typically a dedicated network LWP thread of the application).
 */
#ifndef WIITLS_WIITLS_H
#define WIITLS_WIITLS_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    WTLS_OK            =   0,
    WTLS_WANT_READ     =  -1,  /**< non-blocking mode only */
    WTLS_WANT_WRITE    =  -2,  /**< non-blocking mode only; pass the same buffer again */
    WTLS_ERR_ARG       = -10,
    WTLS_ERR_STATE     = -11,
    WTLS_ERR_NOMEM     = -12,
    WTLS_ERR_ENTROPY   = -20,
    WTLS_ERR_CLOCK     = -21,
    WTLS_ERR_NET       = -30,  /**< network not initialised */
    WTLS_ERR_DNS       = -31,
    WTLS_ERR_CONNECT   = -32,
    WTLS_ERR_TIMEOUT   = -33,
    WTLS_ERR_IO        = -34,  /**< TCP reset or close without close_notify */
    WTLS_ERR_CLOSED    = -35,  /**< clean close_notify from the peer */
    WTLS_ERR_HANDSHAKE = -40,
    WTLS_ERR_CERT      = -41,
    WTLS_ERR_INTERNAL  = -99,
} wtls_status;

typedef struct wtls_conn wtls_conn;

typedef struct {
    uint32_t connect_timeout_ms;    /**< 0 => 5000  */
    uint32_t handshake_timeout_ms;  /**< 0 => 10000 */
    uint32_t io_timeout_ms;         /**< 0 => 15000, blocking read/write */
    const char *const *alpn;        /**< NULL-terminated list, e.g. {"http/1.1", NULL}; NULL = no ALPN */
    bool no_resumption;             /**< neither use nor store session tickets */
    bool insecure_skip_verify;      /**< TESTS ONLY: disables certificate verification */
} wtls_options;

typedef struct {
    const char *tls_version;   /**< "TLSv1.3" | "TLSv1.2" */
    const char *ciphersuite;   /**< Mbed TLS suite name */
    const char *alpn;          /**< NULL if not negotiated */
    bool        resumed;       /**< ticket offered AND no chain verification was needed */
    uint32_t    handshake_ms;  /**< TCP connected -> handshake done */
} wtls_conn_info;

/** Wii: net_init() must have succeeded before. */
wtls_status wtls_init(void);
void        wtls_shutdown(void);
/** DER, or PEM with the terminating NUL byte included in len. */
wtls_status wtls_add_trusted_ca(const uint8_t *buf, size_t len);
/** opt may be NULL for defaults. */
wtls_status wtls_connect(wtls_conn **out, const char *host, uint16_t port,
                         const wtls_options *opt);
/** Returns >0 bytes, otherwise a wtls_status; never 0. */
int         wtls_read(wtls_conn *c, void *buf, size_t len);
/** Blocking: returns len; otherwise bytes written or a status. */
int         wtls_write(wtls_conn *c, const void *buf, size_t len);
wtls_status wtls_set_nonblocking(wtls_conn *c, bool on);
/** Socket descriptor for the application's net_poll. */
int         wtls_get_fd(const wtls_conn *c);
/** Already decrypted, unread bytes. */
size_t      wtls_pending(const wtls_conn *c);
wtls_status wtls_get_info(const wtls_conn *c, wtls_conn_info *out);
/** MBEDTLS_X509_BADCERT_* flags of the last failed connect. */
uint32_t    wtls_last_verify_flags(void);
/** Sends close_notify (best effort) and frees; NULL is allowed. */
void        wtls_close(wtls_conn *c);
const char *wtls_strerror(int status);
/** server NULL = "pool.ntp.org". */
wtls_status wtls_time_sync_sntp(const char *server, uint32_t timeout_ms);

#ifdef __cplusplus
}
#endif

#endif /* WIITLS_WIITLS_H */
