# Security & Code Review (v1.0.0 Audit)

Audit scope (per WP4 of the 1.0.0 roadmap):
- `src/accel/x25519_fe32.c`
- `src/accel/p256_verify.c`
- `src/wtls_jitter.c` and `src/wtls_entropy.c`
- `src/wtls_cred.c` and `src/wtls_cred.h`
- `src/wtls_conn.c`, `src/wtls_scache.c`, `src/wtls_castore.c`
- `src/http/*` (`wtls_http.c`, `wtls_http_parse.c`, `wtls_http_chunked.c`, `wtls_http_gzip.c`, `wtls_http_req.c`, `wtls_url.c`, `wtls_http_pool.c`, `wtls_http_util.c`)

## Summary of Findings and Fixes

1. **`src/wtls_jitter.c` — Compiler dead-store elimination on `digest` wipe (Medium / Hardening)**
   - *Finding:* `wtls_jitter_conditioned()` cleared the local stack buffer `digest[32]` and static `raw` with plain `memset(..., 0, ...)`, which optimising compilers may elide on stack locals right before return.
   - *Fix:* Replaced both `memset` calls with `mbedtls_platform_zeroize()`.

2. **`src/http/wtls_http.c` — Unbounded interim `1xx` response loop (Low / DoS)**
   - *Finding:* `read_head()` looped indefinitely when a server kept sending `100 Continue` / `1xx` interim heads back-to-back until `header_timeout_ms` expired.
   - *Fix:* Capped interim `1xx` responses per request hop to `16`, returning `WTLS_ERR_HTTP_LIMIT` above that.

3. **`src/http/wtls_http_gzip.c` — Null-pointer arithmetic / missing argument validation (Medium / UB)**
   - *Finding:* `wtls_gzip_inflate()` performed `in + *used` / `out + *produced` without checking for `NULL` pointers when `in_len == 0` / `out_cap == 0` or invalid `NULL` arguments. Under C11 / UBSan, `NULL + 0` is undefined behaviour.
   - *Fix:* Added explicit NULL/length argument guards returning `WTLS_ERR_ARG` and conditional pointer arithmetic (`in ? in + *used : NULL`). Added `NULL` guard to `wtls_gzip_finish()`.

4. **`src/http/wtls_http_chunked.c` & `src/http/wtls_http_parse.c` — Internal API defensive NULL guards & exact `uint64_t` overflow check (Low)**
   - *Finding:* `wtls_chunked_decode()`, `wtls_chunked_init()`, `wtls_http_head_end()`, and `wtls_http_parse_head()` assumed non-NULL pointers; `cl_elem()` checked `v > (UINT64_MAX - 9) / 10`, rejecting `UINT64_MAX - 9..UINT64_MAX`.
   - *Fix:* Added explicit NULL guards (`WTLS_ERR_ARG` / `0`) and exact digit-aware overflow bound `v > (UINT64_MAX - (uint64_t)(s[i] - '0')) / 10`.

5. **`src/wtls_cred.c` — Empty PEM chain guard (Low)**
   - *Finding:* `wtls_client_cred_load()` relied only on `mbedtls_x509_crt_parse() != 0` without asserting `!c->chain.raw.p`.
   - *Fix:* Added `|| !c->chain.raw.p` check so empty/comment-only PEM blobs fail cleanly with `WTLS_ERR_ARG`.

6. **`src/accel/p256_verify.c` — Duplicate field arithmetic in `pt_jadd()` (Informational)**
   - *Finding:* Lines 427–432 repeated `fe_sq(hh, h); fe_mul(hhh, hh, h); fe_mul(v, u1, hh);` twice consecutively.
   - *Fix:* Removed the redundant three lines, saving 21 field operations per P-256 verification.

7. **`src/accel/x25519_fe32.c` — Additional stack scrubbing in `x25519_base()` (Hardening)**
   - *Finding:* `x25519_base()` cleared `e`, `h`, `t`, `r`, and `k`, while intermediates `s`, `num`, and `den` remained on the stack.
   - *Fix:* Scrubbed `s`, `num`, and `den` via `volatile` pointers before returning.

8. **`src/wtls_conn.c` — Sticky transport error check in `wtls_write()` (Low)**
   - *Finding:* Calling `wtls_write()` again after `c->bio_err` was already set still entered `mbedtls_ssl_write()` before failing.
   - *Fix:* Return `c->bio_err` immediately at entry to `wtls_write()`.

9. **`src/http/wtls_http.c` & `src/http/wtls_http_req.c` — Pre-1.0 review hardening (Medium)**
   - *Findings:* `wtls_http_open()` called `wtls_http_headers_have()` before validating `(req->n_headers && !req->headers)`; `send_body_cb()` allocated a 16 KiB buffer on LWP stacks and mis-handled 0-byte fixed-length streaming uploads; HTTP-level `abort_cb` exits did not mark `tls->aborted = true` (still attempting `close_notify`); `wtls_scache` wiped tickets with `memset` instead of `mbedtls_platform_zeroize`; `wtls_http_url_encode()` lacked a `size_t` overflow guard.
   - *Fixes:* Added early NULL guards, moved the upload buffer to the heap with a 0-byte fast path, marked `tls->aborted` via `tr_mark_aborted()` on all HTTP cancellation exits, switched `wtls_scache` to `mbedtls_platform_zeroize()`, and added a `size_t` overflow guard to `wtls_http_url_encode()`.

## Verified Security Invariants

- **Constant-time X25519 (`src/accel/x25519_fe32.c`):** No secret-dependent branches or array lookups; `value_barrier()` prevents GCC `-O3` from turning masked swaps (`fe_cswap`/`fe_cmov`) into conditional branches (enforced by `tools/check_ct.cmake` on PPC32 object builds).
- **Public-input P-256 ECDSA verify (`src/accel/p256_verify.c`):** Rejects `r == 0`, `r >= n`, `s == 0`, `s >= n`, `hash_len == 0`, non-uncompressed keys, coordinates `>= p`, off-curve points, and `R = O`; handles `x_R = r + n < p` wrap-around and SEC1 hash truncation for arbitrary hash lengths.
- **Entropy fail-closed (`src/wtls_jitter.c`, `src/wtls_entropy.c`):** SP 800-90B RCT (`cutoff = 21`) and APT (`W = 512`, `cutoff = 410`) at `1 bit/sample` credit with 2x SHA-256 conditioning; returns `PSA_ERROR_INSUFFICIENT_ENTROPY` if any health test fails.
- **Identity & Verification Isolation (`src/wtls_scache.c`, `src/http/wtls_http_pool.c`, `src/http/wtls_http.c`):** Session tickets and keep-alive pool slots are keyed by `(scheme/secure, host, port, insecure_skip_verify, client_cred_fp, spki_pins_fp)`; `no_resumption` / `insecure_skip_verify` connections never store or consume tickets; cross-origin redirects strip `Authorization`, `Proxy-Authorization`, `Cookie`, and `client_cred`; `https -> http` downgrade redirects are refused.
- **Aborted/Incomplete Connections Never Pooled (`src/http/wtls_http.c`):** Cancelled (`WTLS_ERR_CANCELLED`), errored (`r->err`), or partially read connections are closed and never returned to the pool; `abort_cb`/`abort_ctx` pointers are cleared prior to pooling.
