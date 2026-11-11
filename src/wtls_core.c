#include "wtls_internal.h"

const char *wtls_strerror(int status) {
    switch (status) {
    case WTLS_OK:            return "ok";
    case WTLS_WANT_READ:     return "operation would block (read)";
    case WTLS_WANT_WRITE:    return "operation would block (write)";
    case WTLS_ERR_ARG:       return "invalid argument";
    case WTLS_ERR_STATE:     return "invalid state";
    case WTLS_ERR_NOMEM:     return "out of memory";
    case WTLS_ERR_ENTROPY:   return "entropy source failed";
    case WTLS_ERR_CLOCK:     return "system clock is not plausible (set the Wii clock or sync via SNTP)";
    case WTLS_ERR_NET:       return "network not initialised";
    case WTLS_ERR_DNS:       return "DNS resolution failed";
    case WTLS_ERR_CONNECT:   return "TCP connect failed";
    case WTLS_ERR_TIMEOUT:   return "timeout";
    case WTLS_ERR_IO:        return "connection reset or truncated";
    case WTLS_ERR_CLOSED:    return "connection closed by peer";
    case WTLS_ERR_HANDSHAKE: return "TLS handshake failed";
    case WTLS_ERR_CERT:      return "certificate verification failed";
    case WTLS_ERR_INTERNAL:  return "internal error";
    default:                 return "unknown error";
    }
}
