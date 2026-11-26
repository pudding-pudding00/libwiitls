# Changelog

All notable changes to libwiitls are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project
follows [Semantic Versioning](https://semver.org/) from 1.0.0 on.

## [Unreleased]

### Changed

- Documentation reworked for the public 1.0.0 release, with `CONTRIBUTING.md`,
  issue and pull request templates, and an automated tag-based release
  workflow.

## [1.0.0] - 2026-11-25

Initial public release of **libwiitls** for Nintendo Wii homebrew
(devkitPPC / libogc), built on Mbed TLS 4.1.2 LTS (TF-PSA-Crypto) and
zlib 1.3.1.

### Added

- **TLS 1.3 & 1.2 client (`<wiitls/wiitls.h>`):**
  - ChaCha20-Poly1305 preferred (fast without AES hardware), AES-GCM
    fallback; X25519, P-256 and P-384 key exchange; ALPN support.
  - Always-on certificate chain and hostname verification (including IPv4
    literals via `iPAddress` SAN) against the embedded Mozilla CA bundle
    (118 roots in `.rodata`, parsed lazily), plus `wtls_add_trusted_ca()` for
    custom roots.
  - Optional SHA-256 SPKI public-key pinning (`spki_pins`, `n_spki_pins`,
    up to 2 pins) against any certificate in the verified chain.
  - Mutual TLS (`wtls_client_cred_load()`, `wtls_client_cred_free()`,
    `client_cred`) for ECDSA and RSA keys in PEM or DER, reference-counted
    and zeroised on release; isolated per identity in the session cache and
    HTTP pool.
  - TLS 1.3 session ticket cache (8 entries) and multi-IPv4 DNS cache
    (16 entries, connect fallback across up to 4 A-records).
  - Blocking I/O with per-stage timeouts and non-blocking mode
    (`wtls_set_nonblocking()`, `wtls_pending()`, `wtls_get_fd()`).
  - Cooperative cancellation (`abort_cb` / `abort_ctx`, `WTLS_ERR_CANCELLED`)
    checked before connect, across handshake steps, and in ≤ 100 ms poll
    slices.
- **HTTP/1.1 client (`<wiitls/http.h>`):**
  - `https://` and `http://` requests with `wtls_http_fetch()` (whole body,
    1 MiB default limit) or streaming `wtls_http_open()` /
    `wtls_http_read()` / `wtls_http_close()`.
  - Streaming uploads (`wtls_http_body_cb`) with `Content-Length` or
    `Transfer-Encoding: chunked`.
  - Built-in gzip decompression (`WTLS_GZIP`, default ON).
  - Keep-alive connection pool (4 idle connections, 60 s) with liveness
    checks and single retry of idempotent methods on stale connections.
  - Redirects (301, 302, 303, 307, 308) with cross-origin stripping of
    `Authorization`, `Proxy-Authorization`, `Cookie` and client
    certificates, and `https` → `http` downgrade refusal.
  - Progress callback (`progress_cb`) for `wtls_http_fetch()`.
  - `wtls_http_url_encode()` and `wtls_http_parse_content_range()` helpers.
- **Wii platform & performance:**
  - 32-bit-limb X25519 (`WTLS_ACCEL`, constant-time) and P-256 ECDSA
    verify (`WTLS_ACCEL_P256`) tuned for the Broadway CPU.
  - IOS IPC timing-jitter entropy source with SP 800-90B RCT/APT health
    tests and SHA-256 conditioning (fails closed with `WTLS_ERR_ENTROPY`).
  - SNTP clock sync (`wtls_time_sync_sntp()`), automatic Wii IP-change
    detection (`net_gethostip()`), `wtls_net_reset()`, and IOS socket
    workarounds (`wtls_plat_connect` polling, 2 KiB send cap).
- **Packaging, safety & tooling:**
  - `WTLS_VERSION_*` macros, `wtls_version()`, and zero-initialised
    append-only options/request structs under SemVer 1.x.
  - Debug single-thread affinity guard (`WTLS_THREAD_CHECK`).
  - CMake `cmake --install` + `find_package(wiitls 1.0 REQUIRED)` exporting
    `wiitls::wiitls`, native Windows Wii toolchain
    (`cmake/wii-win-toolchain.cmake`), and `tools/make_release.sh`.
  - Examples `examples/https_get` and `examples/upload_mtls_abort`.
  - Six Clang libFuzzer harnesses (`tests/fuzz/`), hardware test runner
    (`tests/hw/`), benchmark runner (`bench/`), [security
    review](docs/security-review.md), [security policy](SECURITY.md), and
    monthly CA bundle / Mbed TLS LTS check workflow.

[Unreleased]: https://github.com/pudding-pudding00/libwiitls/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/pudding-pudding00/libwiitls/releases/tag/v1.0.0
