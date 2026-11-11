# libwiitls benchmarks

Status: **Wii measurements pending.** The benchmark code, the tuning options
and the host smoke run exist; the matrix below and the gate decision need a run
on real hardware (`tools/hwtest.py`, PC and Wii on the same network).

## How to run

```bash
cmake --build build-wii
python tools/hwtest.py --wii <wii-ip> --dol build-wii/bench/wtls_bench.dol --suite bench
```

`hwtest.py` starts the test server (`tests/host/tls_test_server.py`) with a
fresh test PKI, uploads the DOL and collects the log. The DOL prints one
`BENCH <name> <value> <unit>` line per value, the `GATE` lines and the usual
`WTLS-HWTEST DONE pass=P fail=F skip=S`.

On the host, `ctest -R test_bench` runs the same code against localhost: it
only proves that every benchmark works; the numbers are the PC's.

## What is measured

All values are medians of 20 runs (streams: 3 runs).

| Name | What | Unit |
|------|------|------|
| `sha256_16k` | `psa_hash_compute` SHA-256 over 16 KiB | MB/s |
| `chacha20_poly1305_enc_16k` | `psa_aead_encrypt` over 16 KiB | MB/s |
| `aes128_gcm_enc_16k` | `psa_aead_encrypt` over 16 KiB | MB/s |
| `x25519_keygen_agree` | ephemeral key generation + ECDH (one TLS 1.3 key exchange) | ms |
| `ecdsa_p256_verify` | `psa_verify_hash` | ms |
| `rsa2048_verify` | PKCS#1 v1.5 / SHA-256 `psa_verify_hash` (fixed vector, `bench/rsa_vector.h`) | ms |
| `handshake_full_wall` / `_cpu` | `wtls_connect` to port 4431 (TLS 1.3, ECDSA leaf), `no_resumption` | ms |
| `handshake_resumed_wall` / `_cpu` | `wtls_connect` with a session ticket (checked: `resumed == true`) | ms |
| `net_recv_4m` | 4 MiB over raw TCP (`wtls_plat_recv`), first byte to last | MB/s |
| `wtls_read_4m` | 4 MiB through `wtls_read`, first byte to last | MB/s |
| `wtls_read_vs_raw` | `wtls_read_4m` / `net_recv_4m` | % |

CPU time = wall time − time blocked in `wtls_plat_poll`
(`wtls_plat_poll_wait_us`). It includes the TCP connect, so it is an upper bound
for the handshake's own CPU cost.

## Tuning options

All options apply to libwiitls and the fetched Mbed TLS/TF-PSA-Crypto.

| CMake option | Effect | Default |
|--------------|--------|---------|
| `WTLS_BN_ASM` | `MBEDTLS_HAVE_ASM`: PPC32 inline assembly for bignum (RSA, ECC) | ON |
| `WTLS_P256M` | `MBEDTLS_PSA_P256M_DRIVER_ENABLED`: p256-m for P-256 (does not build, see below) | OFF |
| `WTLS_EVEREST` | `MBEDTLS_ECDH_VARIANT_EVEREST_ENABLED`: X25519 via Everest/HACL* | OFF |
| `WTLS_OPT` | `O2` or `O3` | `O2` |

### Option build check (Wii toolchain, devkitPPC)

| Variant | Builds |
|---------|--------|
| defaults (`BN_ASM=ON`, `OPT=O2`) | yes |
| `WTLS_BN_ASM=OFF` | yes |
| `WTLS_EVEREST=ON` | yes |
| `WTLS_OPT=O3` | yes |
| `WTLS_P256M=ON` | **no**: TF-PSA-Crypto 4.1.1 `#error "Unsupported partial support for ECC curves acceleration"`. p256-m covers only P-256, and PK needs P-384/X25519 from the builtin code, which this version rejects. CMake therefore stops at configure time with an explanation. |

So the matrix to measure is `WTLS_BN_ASM` × `WTLS_EVEREST` × `WTLS_OPT` (8 builds).

## Targets (gate for Task 12)

| Target | Value |
|--------|-------|
| Full TLS 1.3 handshake, CPU | ≤ 30 ms |
| Resumed handshake, CPU | ≤ 10 ms |
| ChaCha20-Poly1305 | ≥ 20 MB/s |
| X25519 keygen + agreement | ≤ 5 ms |
| `wtls_read` throughput | ≥ 90 % of raw `net_recv` |

Task 12 (PPC-optimised ChaCha20-Poly1305 and/or X25519 as a PSA accelerator
driver) is due only if, after tuning, ChaCha20-Poly1305 < 20 MB/s **or**
X25519 > 5 ms **or** any target above is missed.

## Results: Wii (pending)

Matrix to measure: `WTLS_BN_ASM` on/off × `WTLS_EVEREST` on/off × `WTLS_OPT`
O2/O3. After the run, set the defaults in `CMakeLists.txt` to the fastest
combination and re-run every host and hardware suite.

| BN_ASM | EVEREST | OPT | chacha MB/s | aes-gcm MB/s | sha256 MB/s | x25519 ms | p256 verify ms | rsa2048 verify ms | full hs CPU ms | resumed hs CPU ms | read vs raw % |
|--------|---------|-----|------------:|-------------:|------------:|----------:|---------------:|------------------:|---------------:|------------------:|--------------:|
| ON | OFF | O2 | – | – | – | – | – | – | – | – | – |

**Gate decision: pending** (no hardware run yet).

## Results: host smoke run (PC, localhost; not the target)

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
the Python test server's encryption, so the read ratio is meaningless here; on
the Wii the link (and IOS IPC) is the expected bottleneck.
