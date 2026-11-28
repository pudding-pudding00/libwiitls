/* ABI guard: the 1.0 layout of the public option/request/info structs must
 * never change (new fields are only ever appended), and the status codes added
 * in 1.1 must keep their values. Offsets were captured from v1.0.1.
 *
 * LP64 values were measured with a compiler. The ILP32 values (Wii/PowerPC)
 * follow from the natural alignment rules; they have not been verified by a
 * 32-bit build yet (wire this file into tests/hw to check them on the Wii). */
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <wiitls/http.h>
#include <wiitls/wiitls.h>

#include "check.h"

WTLS_CHECK_DEFINE_COUNTERS;

#define OFF(type, field, lp64, ilp32) \
    _Static_assert(offsetof(type, field) == (UINTPTR_MAX > 0xFFFFFFFFu ? (lp64) : (ilp32)), \
                   #type "." #field " moved: the 1.0 layout is frozen")

OFF(wtls_options, connect_timeout_ms,   0,   0);
OFF(wtls_options, handshake_timeout_ms, 4,   4);
OFF(wtls_options, io_timeout_ms,        8,   8);
OFF(wtls_options, alpn,                16,  12);
OFF(wtls_options, no_resumption,       24,  16);
OFF(wtls_options, insecure_skip_verify, 25, 17);
OFF(wtls_options, client_cred,         32,  20);
OFF(wtls_options, abort_cb,            40,  24);
OFF(wtls_options, abort_ctx,           48,  28);
OFF(wtls_options, spki_pins,           56,  32);
OFF(wtls_options, n_spki_pins,        120,  96);
/* 1.1 fields are appended after the 1.0 ones */
_Static_assert(offsetof(wtls_options, spki_pins_ext) > offsetof(wtls_options, n_spki_pins), "new fields go last");

OFF(wtls_http_request, method,            0,   0);
OFF(wtls_http_request, url,               8,   4);
OFF(wtls_http_request, headers,          16,   8);
OFF(wtls_http_request, n_headers,        24,  12);
OFF(wtls_http_request, body,             32,  16);
OFF(wtls_http_request, body_len,         40,  20);
OFF(wtls_http_request, max_redirects,    48,  24);
OFF(wtls_http_request, header_timeout_ms, 52, 28);
OFF(wtls_http_request, no_keepalive,     56,  32);
OFF(wtls_http_request, no_gzip,          57,  33);
OFF(wtls_http_request, tls,              64,  36);
OFF(wtls_http_request, body_cb,          72,  40);
OFF(wtls_http_request, body_ctx,         80,  44);
OFF(wtls_http_request, body_chunked,     88,  48);
OFF(wtls_http_request, progress_cb,      96,  52);
OFF(wtls_http_request, progress_ctx,    104,  56);
OFF(wtls_http_request, allow_upgrade,   112,  60);
OFF(wtls_http_request, expect_100_continue, 113, 61);
OFF(wtls_http_request, proxy_url,       120,  64);
OFF(wtls_http_request, no_h2,           128,  68);

_Static_assert(offsetof(wtls_http_request, cookie_jar) > offsetof(wtls_http_request, no_h2), "new fields go last");
_Static_assert(offsetof(wtls_http_request, total_timeout_ms) > offsetof(wtls_http_request, cookie_jar), "new fields go last");

OFF(wtls_http_info, url,               0,  0);
OFF(wtls_http_info, redirects,         8,  4);
OFF(wtls_http_info, reused_connection, 9,  5);
OFF(wtls_http_info, secure,           10,  6);
OFF(wtls_http_info, gzip,             11,  7);
OFF(wtls_http_info, tls,              16,  8);
OFF(wtls_http_info, deflate,          48, 28);
OFF(wtls_http_info, http2,            49, 29);

static void test_new_status_codes_values_and_text(void) {
    CHECK_EQ_INT(WTLS_ERR_UNSUPPORTED, -14);
    CHECK_EQ_INT(WTLS_ERR_WS, -53);
    CHECK_EQ_INT(WTLS_ERR_FILE, -60);
    CHECK_EQ_INT(WTLS_ERR_INTEGRITY, -61);
    CHECK(strcmp(wtls_strerror(WTLS_ERR_UNSUPPORTED), "feature not compiled in") == 0);
    CHECK(strcmp(wtls_strerror(WTLS_ERR_WS), "WebSocket protocol error") == 0);
    CHECK(strcmp(wtls_strerror(WTLS_ERR_FILE), "file I/O error") == 0);
    CHECK(strcmp(wtls_strerror(WTLS_ERR_INTEGRITY), "integrity check failed (digest or signature)") == 0);
}

static void test_old_status_codes_unchanged(void) {
    CHECK_EQ_INT(WTLS_ERR_ARG, -10);
    CHECK_EQ_INT(WTLS_ERR_CERT, -41);
    CHECK_EQ_INT(WTLS_ERR_HTTP_REDIRECT, -52);
    CHECK_EQ_INT(WTLS_ERR_INTERNAL, -99);
    CHECK(strcmp(wtls_strerror(12345), "unknown error") == 0);
}

int main(void) {
    RUN(test_new_status_codes_values_and_text);
    RUN(test_old_status_codes_unchanged);
    return CHECK_DONE();
}
