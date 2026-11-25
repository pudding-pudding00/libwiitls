# Changelog

## Unreleased

### Added

- P-256 ECDSA verify with 32-bit limbs (`WTLS_ACCEL_P256`, default ON,
  `src/accel/p256_verify.c`), hooked into the builtin driver's
  `mbedtls_psa_ecdsa_verify_hash` at configure time. Public inputs only, so
  it is variable time by design: Shamir's trick over interleaved wNAF
  (w = 6 against the generated affine fixed-base table `k_p256_g_odd`,
  w = 5 against eight odd multiples of the peer key, normalised with a
  single mod-p inversion), Jacobian arithmetic with a = -3 (3M + 5S doubling,
  8M + 3S mixed addition), Solinas field reduction over 8x32 limbs (the
  shifts are whole limbs) and a projective final comparison that covers the
  x_R = r + n wrap-around without a field inversion. Matches the builtin's
  psa_status_t mapping exactly; r/s range, point-on-curve, SEC 1 4.1.4
  hash truncation for 20/32/48/64-byte hashes and the wrap-around case are
  pinned by `tests/common/crypto_tests.c` (RFC 6979 A.2.5 vectors, a
  generated wrap-around vector, and differential tests against
  `mbedtls_ecdsa_verify` on random keys with bit-flip mutations, host and
  Wii). `tools/gen_p256.py` regenerates the curve constants and the
  fixed-base table (checked in as `src/accel/p256_curve.inc`).

## 0.2.0 (2026-11-25)

### Added

- HTTP/1.1 client, `<wiitls/http.h>`, with its own parser (RFC 9112 framing,
  no third-party HTTP code):
  - `wtls_http_open` / `wtls_http_read` / `wtls_http_close` stream a
    response; `wtls_http_fetch` reads a whole body into memory (1 MiB limit
    by default).
  - `https://` over libwiitls TLS and plain `http://`.
  - Content-Length, chunked and close-delimited bodies; trailers skipped;
    1xx interim responses skipped.
  - gzip Content-Encoding: offered by default and decoded while reading
    (zlib 1.3.1 inflate, compiled in; build option `WTLS_GZIP`, default ON).
  - Keep-alive pool (4 idle connections, 60 s) with a liveness check before
    reuse and one retry of idempotent requests on a stale connection.
  - Redirects (301, 302, 303, 307, 308; 5 by default); `Authorization`,
    `Proxy-Authorization` and `Cookie` are dropped when a redirect leaves
    the origin; `https` → `http` is refused.
  - `wtls_http_get_header`, `wtls_http_header_at`, `wtls_http_get_info`
    (effective URL, redirects, reuse, TLS facts), `wtls_http_pool_flush`.
- `WTLS_VERSION` macro in `<wiitls/wiitls.h>`.
- Error codes `WTLS_ERR_HTTP`, `WTLS_ERR_HTTP_LIMIT`, `WTLS_ERR_HTTP_REDIRECT`.
- Tests: host suites for URL, request, head parser, framing, chunked and gzip
  decoding, and an HTTP integration suite against a local test server; an
  ASan/UBSan CI job; the Wii runner gets an `http` suite, real-world HTTP
  tests and HTTP benchmarks.

### Changed

- The `https_get` example uses the HTTP client instead of raw TLS and
  hand-parsed headers; it accepts `http://` URLs and shows connection reuse.
- `wtls_shutdown` also closes the HTTP keep-alive pool.
- The release package contains `include/wiitls/http.h` and the zlib licence.

## 0.1.0 (2026-11-24)

First release: TLS 1.3 / 1.2 client for Wii homebrew on Mbed TLS 4.1.1 and
libogc, with certificate verification against the embedded Mozilla CA
bundle, session tickets, a DNS cache, blocking and non-blocking I/O, SNTP
clock sync and an IOS-jitter entropy source.
