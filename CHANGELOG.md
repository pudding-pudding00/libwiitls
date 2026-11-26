# Changelog

All notable changes to libwiitls are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project
follows [Semantic Versioning](https://semver.org/) from 1.0.0 on.

## [Unreleased]

### Changed

- Documentation reworked for the public release: rewritten README, usage
  guide fixes (error table, versioning section), condensed benchmark and
  security-review write-ups, `CONTRIBUTING.md`, issue and pull request
  templates. Internal planning notes were removed from the repository.
- Release packages are now built by a GitHub Actions workflow on every
  `v*` tag, with a `SHA256SUMS` file next to the zip.

## [1.0.0] - 2026-11-25

First stable release. From here on the public API follows SemVer: within 1.x,
functions, error codes and struct fields keep their meaning, and new struct
fields are only appended (their zero value keeps the old behaviour).

**Upgrading from 0.3.0:** source compatible, no code changes needed.
`wtls_options` and `wtls_http_request` gained fields, so rebuild everything
against the new headers; keep zero-initialising both structs.

### Added

- **Cancellation.** `abort_cb` / `abort_ctx` in `wtls_options` let your app
  cancel a connect, handshake, header wait, read or upload — for example when
  the user presses B. Blocking waits are sliced into ≤ 100 ms steps, so
  cancellation is prompt; the call returns the new `WTLS_ERR_CANCELLED`
  (-13). HTTP requests take the callback from `req.tls`; cancelled
  connections are closed, never pooled.
- **Download progress.** `progress_cb` / `progress_ctx` in
  `wtls_http_request` report `(received, total or -1)` during
  `wtls_http_fetch`.
- **Public-key pinning.** Up to two SHA-256 SPKI pins (`spki_pins`,
  `n_spki_pins` in `wtls_options`; primary + backup), matched against any
  certificate of the verified chain. Session tickets and pooled connections
  are never shared between different pin sets.
- **More robust networking.** DNS returns up to four IPv4 addresses and
  `wtls_connect` falls back to the next one if a connect fails; only the
  working address is cached. `wtls_net_reset()` flushes the DNS cache and
  pooled HTTP connections after a network change, and on the Wii a change of
  the console's IP address is detected automatically.
- **Thread-misuse check.** Debug builds (or `-DWTLS_THREAD_CHECK=ON`) abort
  when a `wtls_*` function is called from a thread other than the one that
  called `wtls_init()`.
- **Version API.** `WTLS_VERSION_MAJOR`, `WTLS_VERSION_MINOR`,
  `WTLS_VERSION_PATCH` and `wtls_version()`.
- **CMake package.** `cmake --install` produces a prefix usable with
  `find_package(wiitls 1.0 REQUIRED)` and the `wiitls::wiitls` target; the
  release package includes it. A toolchain file for native Windows Wii builds
  without MSYS2 (`cmake/wii-win-toolchain.cmake`).
- **Example** `examples/upload_mtls_abort`: streaming upload, mutual TLS,
  SPKI pinning, progress and cancellation with the Wiimote.
- **Testing and maintenance.** Six libFuzzer harnesses for the HTTP, URL,
  gzip and credential parsers (corpora replayed on every host test run), a
  soak suite (`suite=soak`), more real-world servers and CDNs in the
  `realworld` suite, a [security review](docs/security-review.md), a
  [security policy](SECURITY.md), and a monthly CI check for CA bundle and
  Mbed TLS 4.1 LTS updates.

### Changed

- Uploads on the Wii are sent in pieces of at most 2 KiB. Larger writes could
  stall for seconds against a slow peer, because IOS reports free send-buffer
  space it cannot actually accept
  ([details](docs/ios-socket-behaviour.md#stalled-peers-and-the-send-cap)).
- Less memory per request: the request head buffer starts at 512 bytes and
  grows on demand (was 16 KiB), and the 16 KiB streaming-upload buffer moved
  from the caller's thread stack to the heap.
- A response may contain at most 16 interim `1xx` heads
  (`WTLS_ERR_HTTP_LIMIT` above that).
- `cmake --install` installs only libwiitls, its bundled static archives,
  headers and the CMake package — not Mbed TLS's own install rules.

### Fixed

- HTTP requests cancelled through `abort_cb` no longer try to send a TLS
  `close_notify` on the way out.
- A zero-length streaming upload with a fixed `Content-Length` (`body_cb` set,
  `body_len == 0`) is sent correctly.
- `wtls_http_open()` rejects `headers == NULL` with `n_headers > 0` instead of
  dereferencing it.
- Plain `http://` connections are no longer split into separate keep-alive
  pools by TLS-only settings (pins, client certificate).
- `Content-Length` values close to `UINT64_MAX` are parsed exactly;
  `wtls_http_url_encode()` guards against `size_t` overflow.
- `wtls_write()` returns a stored transport error immediately.
- An empty or comment-only PEM client certificate is rejected with
  `WTLS_ERR_ARG`.

### Security

- Entropy buffers, session tickets and X25519 intermediates are wiped with
  `mbedtls_platform_zeroize()` / volatile stores, so the compiler cannot
  remove the wipe.
- Undefined behaviour (`NULL + 0` pointer arithmetic) removed from the gzip
  decoder and the HTTP parsers.
- The P-256 verify skips three redundant field operations per point addition
  (no change in results; slightly faster).

## [0.3.0] - 2026-11-25

### Added

- **Fast P-256 signature verification** (`WTLS_ACCEL_P256`, default ON):
  32-bit-limb ECDSA verify for the Broadway, plugged into Mbed TLS's PSA
  driver. On a Wii, a P-256 verify drops from 25.7 ms to 5.3 ms and a full
  TLS 1.3 handshake from 66 ms to 28 ms CPU. Verified against RFC 6979
  vectors, edge cases and differential tests against Mbed TLS on host and
  Wii.
- **Streaming uploads** (`wtls_http_body_cb`): a request body produced by a
  callback, sent with `Content-Length` (`body_len`) or as
  `Transfer-Encoding: chunked` (`body_chunked`). Redirects and retries that
  would need to rewind the stream are handled safely (303, and 301/302 after
  POST, drop the body; other redirects fail with `WTLS_ERR_HTTP_REDIRECT`).
- **Client certificates / mutual TLS** (`wtls_client_cred_load`,
  `wtls_client_cred_free`, `wtls_options.client_cred`): ECDSA and RSA keys in
  PEM or DER, reference-counted per connection, private key zeroised on the
  last release. Session tickets and pooled connections are keyed by the
  certificate, and the certificate is not sent after a redirect leaves the
  origin. Apps that don't use mTLS don't link the parsing code.
- **HTTP helpers:** `wtls_http_url_encode` (RFC 3986 percent-encoding) and
  `wtls_http_parse_content_range` (RFC 9110 `Content-Range`, for resumable
  `206` downloads).

### Fixed

- **Corrupted uploads on the Wii.** IOS queues part of a non-blocking
  `net_send` that exceeds the free socket buffer while still returning
  `-EAGAIN`, so the retry duplicated bytes and broke the TLS stream during
  larger uploads. `wtls_plat_send` now checks for space first and sends in
  blocking mode.

## [0.2.0] - 2026-11-25

### Added

- **HTTP/1.1 client**, `<wiitls/http.h>`, with its own parser:
  - `wtls_http_open` / `wtls_http_read` / `wtls_http_close` to stream a
    response, `wtls_http_fetch` to read a whole body (1 MiB limit by default);
  - `https://` and plain `http://`;
  - Content-Length, chunked and close-delimited bodies; 1xx responses and
    trailers skipped;
  - gzip decoding (zlib 1.3.1 inflate, built in; `WTLS_GZIP`, default ON);
  - keep-alive pool (4 idle connections, 60 s) with a liveness check and one
    retry of idempotent requests on a stale connection;
  - redirects (301, 302, 303, 307, 308; 5 by default) that drop
    `Authorization`, `Proxy-Authorization` and `Cookie` when leaving the
    origin and refuse `https` → `http`;
  - `wtls_http_get_header`, `wtls_http_header_at`, `wtls_http_get_info`,
    `wtls_http_pool_flush`.
- `WTLS_VERSION` macro.
- Error codes `WTLS_ERR_HTTP`, `WTLS_ERR_HTTP_LIMIT`, `WTLS_ERR_HTTP_REDIRECT`.

### Changed

- The `https_get` example uses the HTTP client and shows connection reuse.
- `wtls_shutdown` also closes the HTTP keep-alive pool.

## [0.1.0] - 2026-11-24

First release: TLS 1.3 / 1.2 client for Wii homebrew on Mbed TLS 4.1.1 and
libogc, with certificate verification against the embedded Mozilla CA
bundle, session tickets, a DNS cache, blocking and non-blocking I/O, SNTP
clock sync and an IOS-jitter entropy source.

[Unreleased]: https://github.com/pudding-pudding00/wii_tls/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/pudding-pudding00/wii_tls/compare/v0.3.0...v1.0.0
[0.3.0]: https://github.com/pudding-pudding00/wii_tls/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/pudding-pudding00/wii_tls/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/pudding-pudding00/wii_tls/releases/tag/v0.1.0
