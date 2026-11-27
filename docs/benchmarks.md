# libwiitls benchmarks

How the numbers in [performance.md](performance.md) are measured, what the
build options do, and how the PowerPC crypto accelerators work.

All Wii figures: retail Wii (Broadway, 729 MHz) over Wi-Fi, PC test server on
the same network, default build unless stated otherwise.

## How to run

```bash
cmake --build build-wii
python tools/hwtest.py --wii <wii-ip> --dol build-wii/bench/wtls_bench.dol --suite bench
```

`hwtest.py` starts the test server (`tests/host/tls_test_server.py`) with a
fresh test PKI, uploads the DOL and collects the log. The DOL prints one
`BENCH <name> <value> <unit>` line per measurement and the usual
`WTLS-HWTEST DONE pass=P fail=F skip=S`.

On the host, `ctest -R test_bench` runs the same code against localhost to
verify that every benchmark works; the numbers are the PC's.

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
| `hs_full_crypto_cpu` / `hs_resumed_crypto_cpu` | handshake CPU minus TCP connect and `send`/`recv` IOS IPC time | ms |
| `PROF hs_<full\|resumed> <fn>` | mean time and calls per handshake of each PSA/X.509 function, via linker `--wrap` (bench builds only) | ms |
| `http_get_new_wall` / `http_get_pooled_wall` / `_cpu` | `GET /hello` (port 4438) on a new connection (resumed handshake) or a pooled one | ms |
| `net_recv_4m` | 4 MiB over raw TCP (`wtls_plat_recv`), first byte to last | MB/s |
| `wtls_read_4m` | 4 MiB through `wtls_read`, first byte to last | MB/s |
| `wtls_read_vs_raw` | `wtls_read_4m` / `net_recv_4m` | % |

**CPU time** = wall time − time blocked in `wtls_plat_poll`
(`wtls_plat_poll_wait_us`, including the polls of a pending TCP connect). It
still contains the CPU part of the TCP connect and the synchronous IOS IPC of
every send/recv; `hs_*_crypto_cpu` removes both.

## Results (Wii, default build)

Measured with `WTLS_EVEREST=ON`, `WTLS_OPT=O3`, `WTLS_ACCEL=ON`,
`WTLS_ACCEL_P256=ON`, `WTLS_BN_ASM=ON` (bench 10/10 pass):

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
```

Streams are link-bound: the Wi-Fi delivered about 1 MB/s, so
`wtls_read_vs_raw` shows that TLS adds no measurable cost at this link speed.

### Read throughput against 1.0.1

`wtls_read_4m` of the 1.1.0 development branch against the `v1.0.1` tag,
same Wii and Wi-Fi, same build options. Seven pairs, each running 1.0.1
first and then the branch, so drift in the link hits both sides of a pair:

| Pair | 1.0.1 (MB/s) | branch (MB/s) | Δ |
|---|---|---|---|
| 1 | 1.017 | 1.028 | +1.1 % |
| 2 | 1.025 | 1.031 | +0.6 % |
| 3 | 1.025 | 1.032 | +0.7 % |
| 4 | 1.032 | 1.030 | −0.2 % |
| 5 | 1.030 | 1.030 | 0.0 % |
| 6 | 1.036 | 1.030 | −0.6 % |
| 7 | 1.030 | 1.025 | −0.5 % |

The median Δ is 0.0 % and all pairs fall within −0.6 to +1.1 %, against a
target of ±5 %. `net_recv_4m` was 0.997 to 1.014 MB/s in every run, so the
link stayed stable. Every run passed 10/0/0. At this link speed the
comparison can only show that the branch is not slower; differences in CPU
cost stay below what the Wi-Fi can resolve.

## Build options

All options apply to libwiitls and the fetched Mbed TLS / TF-PSA-Crypto.

| CMake option | Effect | Default |
|--------------|--------|---------|
| `WTLS_BN_ASM` | `MBEDTLS_HAVE_ASM`: PPC32 inline assembly for bignum (RSA, ECC) | ON |
| `WTLS_EVEREST` | X25519 via Everest/HACL* (big-endian fix patched in at configure time) | ON |
| `WTLS_OPT` | `O2` or `O3` | `O3` |
| `WTLS_ACCEL` | X25519 with 32-bit limbs (`src/accel`), hooked into Everest; needs `WTLS_EVEREST` | ON |
| `WTLS_ACCEL_P256` | P-256 ECDSA verify with 32-bit limbs (`src/accel`), hooked into the builtin driver | ON |
| `WTLS_P256M` | p256-m driver for P-256 — does not build with TF-PSA-Crypto 4.1.1 (`#error "Unsupported partial support for ECC curves acceleration"`); CMake stops with an explanation | OFF |

### Configure-time patches to Mbed TLS

`CMakeLists.txt` patches the fetched Mbed TLS sources and stops with an error
if an anchor no longer matches, so a version bump cannot silently drop a fix:

- **Everest on big-endian.** In `kremlin/c_endianness.h`, the generic
  big-endian branch builds `htole64` from `htobe32`, a no-op on the Gekko.
  Patched to `htole32`; the `crypto` suite pins X25519 to the RFC 7748 §6.1
  vectors on host and Wii.
- **`WTLS_OPT=O3`.** Mbed TLS adds `$<$<CONFIG:Release>:-O2>` per library
  after the global flags, so `-O3` is re-added per Mbed TLS library as
  `SHELL:-O3`.
- **X25519 public key export.** TF-PSA-Crypto 4.1.1 uses Everest only for
  key agreement; `mbedtls_psa_ecp_export_public_key` is patched to use
  `mbedtls_x25519_scalarmult(pub, priv, 9)`.
- **Accelerator hooks.** Everest's `mbedtls_x25519_scalarmult` calls
  `wtls_x25519`, and the builtin `mbedtls_psa_ecdsa_verify_hash` calls
  `wtls_p256_verify` for uncompressed P-256 keys.

## Accelerators

### X25519 with 32-bit limbs (`WTLS_ACCEL`)

Everest's HACL* code uses 51-bit limbs; without `__int128` on PPC32 every
64×64→128 product is emulated. `src/accel/x25519_fe32.c` uses ten limbs of
26/25 bits (the ref10 layout), so each product is one `mullw`/`mulhw` pair:

- **Key agreement:** Montgomery ladder per RFC 7748, constant time
  (`tools/check_ct.cmake` checks the PPC object for secret-dependent branches).
- **Public key** (point 9): fixed-base comb on the twisted Edwards form,
  signed radix-16 digits, 64 mixed additions from a 32×8 table and 4
  doublings, then u = (1+y)/(1−y).
- **Generated code:** `tools/gen_fe25519.py` writes `fe25519_mul.inc` and
  `ge25519_base.inc`.
- **Tests** (`crypto` suite): RFC 7748 §5.2 vectors, iterated vector (1 and
  1000 rounds), §6.1, edge points, and differential tests against Everest on
  random scalars and points.

On the Wii, `x25519_keygen_agree` takes **4.60 ms** (vs 8.9 ms in Everest).
ChaCha20-Poly1305 is not accelerated separately: at 24 MB/s it is far above
what the Wi-Fi delivers.

### P-256 verify with 32-bit limbs (`WTLS_ACCEL_P256`)

`src/accel/p256_verify.c` replaces the builtin driver's
`mbedtls_psa_ecdsa_verify_hash` for uncompressed 65-byte P-256 public keys
and raw 64-byte `r||s` signatures. Verify inputs are public, so it is
variable time by design:

- 8×32-bit limbs; products accumulate into int64 columns, then one top-down
  Solinas pass folds with 2^256 = 2^224 − 2^192 − 2^96 + 1 (mod p), every
  shift a whole limb.
- Shamir's trick over interleaved wNAF: w = 6 for G against a generated
  affine table (16 odd multiples, 1 KiB `.rodata`, `tools/gen_p256.py`),
  w = 5 for Q against eight odd multiples normalised with a single mod-p
  inversion.
- Jacobian coordinates with a = −3: doubling 3M+5S, mixed addition 8M+3S.
- Projective final comparison X = r·Z² (mod p), with the x_R = r + n
  wrap-around as a second comparison — no field inversion for the result.
- **Tests** (`crypto` suite): RFC 6979 A.2.5 vectors, range and on-curve
  edge cases, constructed wrap-around and R = O vectors, and differential
  tests against Mbed TLS on random keys with bit-flip mutations.

On the Wii, `ecdsa_p256_verify` takes **5.3–5.4 ms** (vs 25.6 ms builtin
and 35.9 ms p256-m).

## Host smoke run (PC, localhost)

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
