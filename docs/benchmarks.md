# libwiitls benchmarks

How the numbers in [performance.md](performance.md) are measured, what every
build option does to them, and how the current defaults came about.

All Wii figures: retail Wii (Broadway, 729 MHz) over Wi-Fi, PC test server on
the same network, default build unless stated otherwise.

## How to run

```bash
cmake --build build-wii
python tools/hwtest.py --wii <wii-ip> --dol build-wii/bench/wtls_bench.dol --suite bench
```

`hwtest.py` starts the test server (`tests/host/tls_test_server.py`) with a
fresh test PKI, uploads the DOL and collects the log. The DOL prints one
`BENCH <name> <value> <unit>` line per value, one `GATE` line per performance
target, and the usual `WTLS-HWTEST DONE pass=P fail=F skip=S`.

On the host, `ctest -R test_bench` runs the same code against localhost. It
only proves that every benchmark works; the numbers are the PC's.

## What is measured

All values are medians of 20 runs (streams: 3 runs).

| Name | What | Unit |
|------|------|------|
| `sha256_16k` | `psa_hash_compute` SHA-256 over 16 KiB | MB/s |
| `chacha20_poly1305_enc_16k` | `psa_aead_encrypt` over 16 KiB | MB/s |
| `aes128_gcm_enc_16k` | `psa_aead_encrypt` over 16 KiB | MB/s |
| `x25519_keygen_agree` | ephemeral key generation + public key export + ECDH (one TLS 1.3 key exchange) | ms |
| `ecdsa_p256_verify` | `psa_verify_hash` with an imported public key (as in TLS) | ms |
| `ecdsa_p256_verify_p256m` | the same verify through p256-m's raw `p256_ecdsa_verify` (`bench/p256m_probe.c`, comparison only) | ms |
| `rsa2048_verify` | PKCS#1 v1.5 / SHA-256 `psa_verify_hash` (fixed vector, `bench/rsa_vector.h`) | ms |
| `handshake_full_wall` / `_cpu` | `wtls_connect` to port 4431 (TLS 1.3, ECDSA leaf), `no_resumption` | ms |
| `handshake_resumed_wall` / `_cpu` | `wtls_connect` with a session ticket (checked: `resumed == true`) | ms |
| `hs_<full\|resumed>_*` | per-step breakdown of the handshake, see [Handshake profile](#handshake-profile) | ms / calls |
| `PROF hs_<full\|resumed> <fn>` | mean time and calls per handshake of each PSA/X.509 function, via linker `--wrap` (bench builds only) | ms |
| `http_get_new_wall` / `http_get_pooled_wall` / `_cpu` | `GET /hello` (port 4438) on a new or a pooled connection, see [HTTP](#http) | ms |
| `net_recv_4m` | 4 MiB over raw TCP (`wtls_plat_recv`), first byte to last | MB/s |
| `wtls_read_4m` | 4 MiB through `wtls_read`, first byte to last | MB/s |
| `wtls_read_vs_raw` | `wtls_read_4m` / `net_recv_4m` | % |

**CPU time** = wall time − time blocked in `wtls_plat_poll`
(`wtls_plat_poll_wait_us`, including the polls of a pending TCP connect). It
still contains the CPU part of the TCP connect and the synchronous IOS IPC of
every send/recv, so it is an upper bound for the handshake's own CPU cost;
`hs_*_crypto_cpu` removes both.

## Targets

| Target | Value | Current (1.0.0) | |
|--------|-------|----------------:|---|
| Full TLS 1.3 handshake, CPU | ≤ 30 ms | 27.3 ms | met |
| Resumed handshake, CPU | ≤ 10 ms | 15.7 ms | missed |
| ChaCha20-Poly1305 | ≥ 20 MB/s | 24.1 MB/s | met |
| X25519 keygen + agreement | ≤ 5 ms | 4.60 ms | met |
| `wtls_read` throughput | ≥ 90 % of raw `net_recv` | 96.7 % | met |
| Pooled HTTP request CPU | < resumed handshake CPU | 3.0 ms | met |

The `GATE` lines are informational and never fail a run. The resumed target
is out of reach for crypto work: its crypto part is 5.9 ms, the rest is IOS
socket and connect IPC (about 0.45 ms per call, 12 calls per resumed
handshake). Keep-alive connections (`wtls_http`) avoid the handshake
altogether and are the practical answer.

## Current results (1.0.0)

Default build (`WTLS_EVEREST=ON`, `WTLS_OPT=O3`, `WTLS_ACCEL=ON`,
`WTLS_ACCEL_P256=ON`, `WTLS_BN_ASM=ON`), bench 10/10 pass:

```
BENCH sha256_16k 29.257 MB/s
BENCH chacha20_poly1305_enc_16k 24.094 MB/s
BENCH aes128_gcm_enc_16k 5.270 MB/s
BENCH x25519_keygen_agree 4.596 ms
BENCH ecdsa_p256_verify 5.405 ms
BENCH rsa2048_verify 8.608 ms
BENCH handshake_full_wall 36.844 ms
BENCH handshake_full_cpu 27.285 ms
BENCH hs_full_crypto_cpu 16.713 ms
BENCH handshake_resumed_wall 24.586 ms
BENCH handshake_resumed_cpu 15.662 ms
BENCH hs_resumed_crypto_cpu 5.886 ms
BENCH net_recv_4m 0.955 MB/s
BENCH wtls_read_4m 0.923 MB/s
BENCH wtls_read_vs_raw 96.657 %
BENCH http_get_new_wall 87.669 ms
BENCH http_get_pooled_wall 6.579 ms
BENCH http_get_pooled_cpu 3.046 ms
GATE handshake_full_cpu <= 30 ms        27.285 met
GATE handshake_resumed_cpu <= 10 ms     15.662 MISSED
GATE chacha20_poly1305 >= 20 MB/s       24.094 met
GATE x25519 <= 5 ms                     4.596 met
GATE wtls_read >= 90 % of net_recv      96.657 met
GATE http_get_pooled_cpu < handshake_resumed_cpu 3.046 met
```

Streams are link-bound: the Wi-Fi delivered about 1 MB/s, so
`wtls_read_vs_raw` shows that TLS adds no measurable cost at this link speed;
it is not a CPU measurement.

## How the handshake got from 5 s to 27 ms

| Step | Full handshake CPU | Resumed CPU | Full wall |
|------|-------------------:|------------:|----------:|
| First working build: connect waited out its whole timeout, because IOS does not signal a completed non-blocking connect | — | — | 5096 ms |
| TCP connect fix (`BN_ASM`, O2, builtin X25519) | 93.5 ms | 40.4 ms | 101 ms |
| `WTLS_EVEREST=ON`, `WTLS_OPT=O3` | 84.1 ms | 31.7 ms | 88 ms |
| Connect polls counted as wait; X25519 export through Everest | 70.4 ms | 18.0 ms | 87 ms |
| `WTLS_ACCEL`: X25519 with 32-bit limbs + fixed-base comb | 66.1 ms | 13.6 ms | 81 ms |
| `WTLS_ACCEL_P256`: P-256 verify with 32-bit limbs | 27.8 ms | 15.6 ms¹ | 37 ms |
| 1.0.0 (2 KiB send cap, `pt_jadd` cleanup) | **27.3 ms** | **15.7 ms** | **37 ms** |

¹ The resumed path verifies no signature; it rose by the socket IPC of the
`wtls_plat_send` workaround for IOS non-blocking `net_send` (about 1.5 ms,
see [ios-socket-behaviour.md](ios-socket-behaviour.md)).

### Build options

All options apply to libwiitls and the fetched Mbed TLS / TF-PSA-Crypto.

| CMake option | Effect | Default |
|--------------|--------|---------|
| `WTLS_BN_ASM` | `MBEDTLS_HAVE_ASM`: PPC32 inline assembly for bignum (RSA, ECC) | ON |
| `WTLS_EVEREST` | X25519 via Everest/HACL* (big-endian fix patched in at configure time) | ON |
| `WTLS_OPT` | `O2` or `O3` | `O3` |
| `WTLS_ACCEL` | X25519 with 32-bit limbs (`src/accel`), hooked into Everest; needs `WTLS_EVEREST` | ON |
| `WTLS_ACCEL_P256` | P-256 ECDSA verify with 32-bit limbs (`src/accel`), hooked into the builtin driver | ON |
| `WTLS_P256M` | p256-m driver for P-256 — does not build with TF-PSA-Crypto 4.1.1 (`#error "Unsupported partial support for ECC curves acceleration"`); CMake stops with an explanation | OFF |

Option matrix measured before the accelerators existed:

| BN_ASM | EVEREST | OPT | chacha MB/s | aes-gcm MB/s | sha256 MB/s | x25519 ms | p256 verify ms | rsa2048 verify ms | full hs CPU ms | resumed hs CPU ms |
|--------|---------|-----|------------:|-------------:|------------:|----------:|---------------:|------------------:|---------------:|------------------:|
| ON | OFF | O2 | 20.56 | 2.96 | 28.6 | 13.25 | 31.9 | 8.70 | 93.5 | 40.4 |
| OFF | OFF | O2 | 20.53 | 2.96 | 28.5 | 13.45 | 32.6 | 8.87 | 95.2 | 41.1 |
| ON | ON | O2 | 20.56 | 2.96 | 28.5 | 5.55 | 31.9 | 8.70 | 85.8 | 33.0 |
| **ON** | **ON** | **O3** | **24.02** | **5.28** | **29.3** | **4.49** | **31.6** | **8.61** | **84.1** | **31.7** |

`BN_ASM` moves P-256, RSA and the handshakes by only 1–2 %. (The P-256 verify
column used the key pair, which recomputes the public point on every call;
with a public key, as in TLS, the builtin verify takes 25.6 ms.)

### Configure-time patches to Mbed TLS

`CMakeLists.txt` patches the fetched Mbed TLS sources and stops with an error
if an anchor no longer matches, so a version bump cannot silently drop a fix:

- **Everest on big-endian.** In `kremlin/c_endianness.h`, the generic
  big-endian branch builds `htole64` from `htobe32`, a no-op on the Gekko.
  X25519 then computed wrong shared secrets and every TLS 1.3 handshake with
  X25519 failed. Patched to `htole32`; the `crypto` suite pins X25519 to the
  RFC 7748 §6.1 vectors on host and Wii.
- **`WTLS_OPT=O3` had no effect.** Mbed TLS adds `$<$<CONFIG:Release>:-O2>`
  to each of its targets, after the global `-O3`. The level is re-added per
  Mbed TLS target as `SHELL:-O3` (without `SHELL:`, CMake drops it as a
  duplicate).
- **X25519 public key export bypassed Everest.** TF-PSA-Crypto 4.1.1 uses
  Everest only for the key agreement; `psa_export_public_key` computed the
  public key with the generic `mbedtls_ecp_mul` (8.7 ms per handshake on the
  Wii). `mbedtls_psa_ecp_export_public_key` is patched to use
  `mbedtls_x25519_scalarmult(pub, priv, 9)`.
- **Accelerator hooks.** Everest's `mbedtls_x25519_scalarmult` calls
  `wtls_x25519`, and the builtin `mbedtls_psa_ecdsa_verify_hash` calls the
  P-256 verify in `src/accel/p256_verify.c` for the TLS shape (see below).

### Handshake profile

`wtls_connect` records a profile of every handshake (`src/wtls_prof.h`): TCP
connect (and its poll wait), setup, each `mbedtls_ssl_handshake_step` by
state, and the time inside `wtls_plat_send`/`recv`. The `tls` suite checks
that the parts add up. Profile before the accelerators (after the export fix):

| | Resumed ms | Full ms |
|---|---:|---:|
| wall | 29.3 | 86.9 |
| CPU (wall − poll wait) | 18.0 | 70.4 |
| TCP connect, CPU part (IOS IPC) | 2.6 | 2.4 |
| send/recv IPC | 5.2 (12 calls) | 6.3 (16 calls) |
| step `client_hello` (X25519 keygen + export) | 4.8 | 4.6 |
| step `server_hello` (X25519 agreement, key schedule) | 4.8 | 4.8 |
| step `server_certificate` (chain verify: 1 ECDSA P-256) | — | 25.9 |
| step `certificate_verify` (1 ECDSA P-256) | — | 25.7 |
| other steps | 0.6 | 0.6 |
| **crypto CPU (CPU − connect − IPC)** | **10.2** | **61.6** |

This showed where to spend effort: X25519 was nearly all of the resumed
handshake's crypto, and two P-256 verifies were 51 ms of the full one.
Hashing, HKDF, HMAC and AEAD together took about 1.2 ms; X.509 parsing 0.1 ms.
p256-m was no alternative: its raw verify takes 35.9 ms on the Wii, slower
than the builtin with `BN_ASM` (25.6 ms).

### X25519 with 32-bit limbs (`WTLS_ACCEL`)

Everest's HACL* code uses 51-bit limbs; without `__int128` on PPC32 every
64×64→128 product is emulated. `src/accel/x25519_fe32.c` uses ten limbs of
26/25 bits (the ref10 layout), so each product is one `mullw`/`mulhw` pair:

- **Key agreement:** Montgomery ladder per RFC 7748, constant time
  (`tools/check_ct.cmake` checks the PPC object for secret-dependent branches).
- **Public key** (point 9): fixed-base comb on the twisted Edwards form,
  signed radix-16 digits, 64 mixed additions from a 32×8 table and 4
  doublings, then u = (1+y)/(1−y).
- **Generated code:** `tools/gen_fe25519.py` writes the multiply/square
  (`fe25519_mul.inc`) and the base table (`ge25519_base.inc`).
- **Tests** (`crypto` suite): RFC 7748 §5.2 vectors, the iterated vector
  (1 and 1000 rounds), §6.1, edge points, and differential tests against
  Everest on random scalars and points (1000 on the host, 100 on the Wii).

| | Everest | 32-bit ladder | + fixed-base comb |
|---|---:|---:|---:|
| `x25519_keygen_agree` | 8.9 ms | 6.79 ms | **4.60 ms** |
| export in the handshake | 4.5 ms | 3.4 ms | 1.27 ms |
| agreement in the handshake | 4.5 ms | 3.4 ms | 3.45 ms |

ChaCha20-Poly1305 is not accelerated: at 24 MB/s it is far above what the
Wi-Fi delivers.

### P-256 verify with 32-bit limbs (`WTLS_ACCEL_P256`)

`src/accel/p256_verify.c` replaces the builtin driver's
`mbedtls_psa_ecdsa_verify_hash` for exactly the TLS shape: an uncompressed
65-byte P-256 public key and a raw 64-byte `r||s` signature. Verify inputs
are public, so it is variable time by design:

- 8×32-bit limbs; products accumulate into int64 columns, then one top-down
  Solinas pass folds with 2^256 = 2^224 − 2^192 − 2^96 + 1 (mod p), every
  shift a whole limb. No 64-bit multiplier is needed anywhere.
- Shamir's trick over interleaved wNAF: w = 6 for G against a generated
  affine table (16 odd multiples, 1 KiB `.rodata`, `tools/gen_p256.py`),
  w = 5 for Q against eight odd multiples normalised with a single mod-p
  inversion.
- Jacobian coordinates with a = −3: doubling 3M+5S, mixed addition 8M+3S.
- Projective final comparison X = r·Z² (mod p), with the x_R = r + n
  wrap-around as a second comparison: no field inversion for the result.
- Tests (`crypto` suite): RFC 6979 A.2.5 vectors, range and on-curve edge
  cases, constructed wrap-around and R = O vectors, and differential tests
  against the builtin on random keys with bit-flip mutations.

| | builtin | `WTLS_ACCEL_P256` |
|---|---:|---:|
| `ecdsa_p256_verify` | 25.6 ms | **5.30 ms** |
| `psa_verify_hash` in a full handshake (2 verifies) | 51.4 ms | **10.7 ms** |
| `handshake_full_cpu` | 66.4 ms | **27.8 ms** |
| `handshake_full_wall` | 81.0 ms | 37.3 ms |

## HTTP

Three lines from `bench_http_get` (median of 20, `GET /hello` on the test
server's keep-alive port 4438, body read to the end):

- `http_get_new_wall`: pool flushed before every request, session ticket
  allowed, so this is a resumed handshake plus one request/response.
- `http_get_pooled_wall`: the same request over the pooled connection.
- `http_get_pooled_cpu`: `http_get_pooled_wall` minus the time blocked in
  `wtls_plat_poll`, measured like the handshake CPU numbers.

On the Wii a pooled request costs 3.0 ms CPU (6.6 ms wall), against 15.7 ms
CPU (24.6 ms wall) for a resumed handshake.

## Host smoke run (PC, localhost; not the target)

Recorded once with the default options, only to show the output format:

```
BENCH sha256_16k 334.367 MB/s
BENCH chacha20_poly1305_enc_16k 420.103 MB/s
BENCH aes128_gcm_enc_16k 162.218 MB/s
BENCH x25519_keygen_agree 0.467 ms
BENCH ecdsa_p256_verify 1.025 ms
BENCH rsa2048_verify 0.101 ms
BENCH handshake_full_wall 3.227 ms
BENCH handshake_full_cpu 2.917 ms
BENCH handshake_resumed_wall 1.443 ms
BENCH handshake_resumed_cpu 1.206 ms
BENCH net_recv_4m 1867.455 MB/s
BENCH wtls_read_4m 136.841 MB/s
BENCH wtls_read_vs_raw 7.328 %
```

On loopback the raw path runs at memory speed while the TLS path is limited by
the Python test server's encryption, so the read ratio is meaningless here.
