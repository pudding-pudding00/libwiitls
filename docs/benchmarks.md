# libwiitls benchmarks

Status: **measured on a Wii** (2026-11-24, Wi-Fi, PC test server on the same
network). Defaults are now `WTLS_EVEREST=ON`, `WTLS_OPT=O3`. Gate decision and
Task 12 ruling: see the end of the Wii results.

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
| `WTLS_EVEREST` | `MBEDTLS_ECDH_VARIANT_EVEREST_ENABLED`: X25519 via Everest/HACL* (big-endian fix patched in at configure time, see below) | ON |
| `WTLS_OPT` | `O2` or `O3` | `O3` |

### Option build check (Wii toolchain, devkitPPC)

| Variant | Builds |
|---------|--------|
| `BN_ASM=ON`, `EVEREST=OFF`, `OPT=O2` (old defaults) | yes |
| `WTLS_BN_ASM=OFF` | yes |
| `WTLS_EVEREST=ON` | yes |
| `WTLS_OPT=O3` | yes (defaults now: `EVEREST=ON`, `OPT=O3`) |
| `WTLS_P256M=ON` | **no**: TF-PSA-Crypto 4.1.1 `#error "Unsupported partial support for ECC curves acceleration"`. p256-m covers only P-256, and PK needs P-384/X25519 from the builtin code, which this version rejects. CMake therefore stops at configure time with an explanation. |

So the matrix to measure is `WTLS_BN_ASM` × `WTLS_EVEREST` × `WTLS_OPT` (8 builds).

### Two build fixes the Wii run turned up

- **Everest on big-endian.** In Everest's `kremlin/c_endianness.h`, the
  generic big-endian branch builds `htole64` from `htobe32`, a no-op on the
  Gekko. X25519 then computed wrong shared secrets, and every TLS 1.3
  handshake with X25519 failed. `CMakeLists.txt` patches that branch to
  `htole32` after fetching Mbed TLS and stops with an error if the header's
  layout changes. The `crypto` suite pins X25519 to the RFC 7748 §6.1
  vectors on host and Wii.
- **`WTLS_OPT=O3` had no effect.** Mbed TLS adds
  `$<$<CONFIG:Release>:-O2>` to each of its targets, after our global `-O3`.
  `CMakeLists.txt` now re-adds the level per Mbed TLS target as
  `SHELL:-O3`. The `SHELL:` prefix is needed because CMake otherwise drops
  the option as a duplicate of the global one.

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

## Results: Wii

Medians on a Wii (Gekko-class Broadway, 729 MHz) over Wi-Fi. All runs: bench
9/9 pass.

| BN_ASM | EVEREST | OPT | chacha MB/s | aes-gcm MB/s | sha256 MB/s | x25519 ms | p256 verify ms | rsa2048 verify ms | full hs CPU ms | resumed hs CPU ms | read vs raw % |
|--------|---------|-----|------------:|-------------:|------------:|----------:|---------------:|------------------:|---------------:|------------------:|--------------:|
| ON | OFF | O2 | 20.56 | 2.96 | 28.6 | 13.25 | 31.9 | 8.70 | 93.5 | 40.4 | 146 |
| OFF | OFF | O2 | 20.53 | 2.96 | 28.5 | 13.45 | 32.6 | 8.87 | 95.2 | 41.1 | 48 |
| ON | ON | O2 | 20.56 | 2.96 | 28.5 | 5.55 | 31.9 | 8.70 | 85.8 | 33.0 | 156 |
| **ON** | **ON** | **O3** | **24.02** | **5.28** | **29.3** | **4.49** | **31.6** | **8.61** | **84.1** | **31.7** | **103** |

Wall times of the new default (last row): full handshake 88.1 ms, resumed 35.6 ms.

The `BN_ASM=OFF` rows for `EVEREST=ON` and `OPT=O3` were not measured.
`BN_ASM` changes P-256, RSA and the handshakes by only 1–2 %, well inside what
the other two options move.

Notes:

- **Streams are link-bound.** `net_recv_4m` ran at 0.2–1.0 MB/s across the
  runs: Wi-Fi and the Python test server, not the CPU. The read ratio is
  therefore noise around 100 % (48–156 %). It shows that `wtls_read` adds no
  measurable cost at this link speed, but it is not a CPU measurement.
- **The TCP connect fix matters more than any option.** Before commit
  e89b9ee, `wtls_plat_connect` waited out its whole timeout because IOS
  `net_poll` does not signal a completed non-blocking connect (see
  `docs/ios-socket-behaviour.md`). The full handshake took 5096 ms wall;
  afterwards it took 101 ms.
- **What the handshake CPU is made of.** In the full handshake, two ECDSA P-256
  verifies (CertificateVerify plus the leaf signature) cost about 63 ms, and
  X25519 costs 4.5 ms. The resumed handshake has no signatures, and only
  about 4.5 ms of its 31.7 ms is X25519. The CPU figure also counts the TCP
  connect and any IOS IPC time outside `wtls_plat_poll`. Where the remaining
  ~27 ms goes is not yet profiled.

### Gate decision

| Target | Value | Result (default build) | |
|--------|-------|------------------------|---|
| ChaCha20-Poly1305 | ≥ 20 MB/s | 24.0 MB/s | met |
| X25519 keygen + agreement | ≤ 5 ms | 4.49 ms | met |
| `wtls_read` throughput | ≥ 90 % of raw | ≈ 100 % (link-bound) | met |
| Full TLS 1.3 handshake, CPU | ≤ 30 ms | 84.1 ms | **missed** |
| Resumed handshake, CPU | ≤ 10 ms | 31.7 ms | **missed** |

By the letter of the gate, Task 12 is due, because handshake targets are
missed. **Ruling: Task 12 is not carried out.** Task 12 accelerates
ChaCha20-Poly1305 and X25519, and both already meet their targets after tuning.
It cannot close the missed targets. Even an X25519 that took no time at all
would leave the full handshake at about 80 ms and the resumed one at about
27 ms. The full handshake is dominated by P-256 ECDSA verification, which p256-m
cannot take over in this Mbed TLS version (see above). The resumed handshake
has an unexplained ~27 ms. Both are recorded as follow-ups: profile the
resumed handshake, and look at a faster P-256 verify. If this ruling is wrong,
the cost is a missing driver that would save at most about 0.5 ms per
handshake at the current numbers.

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
