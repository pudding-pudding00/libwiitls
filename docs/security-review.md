# Security review (1.0.0)

An internal code review done before the 1.0.0 release. It is **not** an
independent audit; independent review is welcome (see
[SECURITY.md](../SECURITY.md) for how to report issues).

## Scope

- Cryptographic accelerators: `src/accel/x25519_fe32.c`, `src/accel/p256_verify.c`
- Entropy: `src/wtls_jitter.c`, `src/wtls_entropy.c`
- Client credentials: `src/wtls_cred.c`
- TLS connection, session cache, CA store: `src/wtls_conn.c`, `src/wtls_scache.c`, `src/wtls_castore.c`
- HTTP client: everything under `src/http/`

Method: manual review, host builds with ASan/UBSan/LSan, six libFuzzer
harnesses over the parsers (`tests/fuzz/`), and the host and Wii test suites.

## Findings (all fixed in 1.0.0)

| # | Component | Severity | Finding | Fix |
|---|-----------|----------|---------|-----|
| 1 | `wtls_jitter.c` | Medium (hardening) | Conditioning wiped `digest[32]` and the raw sample buffer with `memset`, which compilers may elide right before return. | `mbedtls_platform_zeroize()` |
| 2 | `wtls_http_gzip.c` | Medium (UB) | `in + used` / `out + produced` computed on `NULL` pointers for empty buffers (`NULL + 0` is undefined in C11). | Argument guards and conditional pointer arithmetic |
| 3 | `wtls_http.c`, `wtls_http_req.c` | Medium | `headers == NULL` with `n_headers > 0` dereferenced before validation; HTTP-level `abort_cb` exits still attempted `close_notify`; 0-byte fixed-length streaming uploads mishandled; 16 KiB upload buffer on the caller's thread stack. | Early validation, aborted connections skip `close_notify`, 0-byte fast path, upload buffer on the heap |
| 4 | `wtls_scache.c` | Low (hardening) | Session tickets wiped with `memset`. | `mbedtls_platform_zeroize()` |
| 5 | `wtls_http.c` | Low (DoS) | A server could send `1xx` interim responses back to back until `header_timeout_ms` expired. | At most 16 interim responses per request (`WTLS_ERR_HTTP_LIMIT`) |
| 6 | `wtls_http_parse.c` | Low | `Content-Length` overflow check rejected the valid values `UINT64_MAX - 9 … UINT64_MAX`. | Exact digit-aware bound |
| 7 | `wtls_http_util.c` | Low | `wtls_http_url_encode()` lacked a `size_t` overflow guard. | Overflow guard |
| 8 | `wtls_http_chunked.c`, `wtls_http_parse.c` | Low | Internal entry points assumed non-NULL arguments. | Defensive guards |
| 9 | `wtls_cred.c` | Low | An empty or comment-only PEM chain was not rejected explicitly. | Fails with `WTLS_ERR_ARG` |
| 10 | `wtls_conn.c` | Low | `wtls_write()` after a sticky transport error still entered `mbedtls_ssl_write()`. | Returns the stored error immediately |
| 11 | `x25519_fe32.c` | Hardening | Some intermediates of `x25519_base()` were left on the stack. | Scrubbed before return |
| 12 | `p256_verify.c` | Informational | `pt_jadd()` repeated three field operations (correct result, wasted work). | Removed |

## Verified invariants

- **Constant-time X25519** (`x25519_fe32.c`): no secret-dependent branches or
  table lookups; `value_barrier()` keeps GCC `-O3` from turning masked swaps
  into branches. `tools/check_ct.cmake` checks the PPC32 object on every Wii
  build.
- **P-256 verify on public inputs only** (`p256_verify.c`): rejects
  `r`/`s` outside `[1, n-1]`, empty hashes, non-uncompressed keys, coordinates
  `≥ p`, off-curve points and `R = O`; handles the `x_R = r + n` wrap-around
  and SEC 1 hash truncation. Variable time by design (no secrets involved).
- **Entropy fails closed** (`wtls_jitter.c`, `wtls_entropy.c`): SP 800-90B
  repetition count test (cutoff 21) and adaptive proportion test (W = 512,
  cutoff 410) at a credit of 1 bit/sample, SHA-256 conditioning;
  `wtls_init()` returns `WTLS_ERR_ENTROPY` if a health test fails.
- **Identity isolation** (`wtls_scache.c`, `wtls_http_pool.c`): session
  tickets and keep-alive connections are keyed by scheme, host, port,
  verification mode, client certificate fingerprint and SPKI pin set;
  `no_resumption` and `insecure_skip_verify` connections never store or use
  tickets.
- **Redirects**: leaving the origin strips `Authorization`,
  `Proxy-Authorization`, `Cookie` and the client certificate; `https` →
  `http` is refused.
- **No pooling of broken connections**: cancelled, failed or partially read
  HTTP connections are closed, never returned to the pool.

## Known limitations

- No certificate revocation (OCSP/CRL); use SPKI pinning where needed.
- The IOS-jitter entropy source has been characterised on one retail Wii
  over Wi-Fi ([ios-socket-behaviour.md](ios-socket-behaviour.md)). Reports
  from other console revisions, vWii and USB Ethernet adapters are wanted.
- The embedded CA bundle is a snapshot; applications must ship updates.
