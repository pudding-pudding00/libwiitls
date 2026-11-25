# libwiitls benchmarks

Status: **measured on a Wii** (2026-11-24, Wi-Fi, PC test server on the same
network). Defaults are now `WTLS_EVEREST=ON`, `WTLS_OPT=O3`, `WTLS_ACCEL=ON`.
Gate decision, Task 12 ruling and the Task 12 result: see the end of the Wii
results.

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
| `x25519_keygen_agree` | ephemeral key generation + public key export + ECDH (one TLS 1.3 key exchange; the export was not timed before the breakdown below) | ms |
| `ecdsa_p256_verify` | `psa_verify_hash` with an imported public key (as in TLS; before the breakdown below it used the key pair, which recomputes the public point on every call) | ms |
| `ecdsa_p256_verify_p256m` | the same verify through p256-m's raw `p256_ecdsa_verify` (`bench/p256m_probe.c`, comparison only) | ms |
| `hs_<full\|resumed>_*` | breakdown of the handshake, see "Handshake breakdown" | ms / calls |
| `PROF hs_<full\|resumed> <fn>` | mean time and calls per handshake of each PSA/X.509 function, via linker `--wrap` (bench builds only) | ms |
| `rsa2048_verify` | PKCS#1 v1.5 / SHA-256 `psa_verify_hash` (fixed vector, `bench/rsa_vector.h`) | ms |
| `handshake_full_wall` / `_cpu` | `wtls_connect` to port 4431 (TLS 1.3, ECDSA leaf), `no_resumption` | ms |
| `handshake_resumed_wall` / `_cpu` | `wtls_connect` with a session ticket (checked: `resumed == true`) | ms |
| `http_get_new_wall` / `http_get_pooled_wall` / `_cpu` | `GET /hello` (port 4438) on a new connection (resumed handshake) or a pooled one, see "HTTP" | ms |
| `net_recv_4m` | 4 MiB over raw TCP (`wtls_plat_recv`), first byte to last | MB/s |
| `wtls_read_4m` | 4 MiB through `wtls_read`, first byte to last | MB/s |
| `wtls_read_vs_raw` | `wtls_read_4m` / `net_recv_4m` | % |

CPU time = wall time − time blocked in `wtls_plat_poll`
(`wtls_plat_poll_wait_us`). Since the breakdown below, the polls of a pending
TCP connect also count as wait. The CPU figure still includes the CPU part of
the TCP connect and the synchronous IOS IPC of every send/recv, so it is an
upper bound for the handshake's own CPU cost; `hs_*_crypto_cpu` removes both.

## Tuning options

All options apply to libwiitls and the fetched Mbed TLS/TF-PSA-Crypto.

| CMake option | Effect | Default |
|--------------|--------|---------|
| `WTLS_BN_ASM` | `MBEDTLS_HAVE_ASM`: PPC32 inline assembly for bignum (RSA, ECC) | ON |
| `WTLS_P256M` | `MBEDTLS_PSA_P256M_DRIVER_ENABLED`: p256-m for P-256 (does not build, see below) | OFF |
| `WTLS_EVEREST` | `MBEDTLS_ECDH_VARIANT_EVEREST_ENABLED`: X25519 via Everest/HACL* (big-endian fix patched in at configure time, see below) | ON |
| `WTLS_OPT` | `O2` or `O3` | `O3` |
| `WTLS_ACCEL` | X25519 with 32-bit limbs (`src/accel`), hooked into Everest's `mbedtls_x25519_scalarmult`; needs `WTLS_EVEREST` (see "Task 12 result") | ON |

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
- **X25519 public key export bypassed Everest.** With
  `MBEDTLS_ECDH_VARIANT_EVEREST_ENABLED`, TF-PSA-Crypto 4.1.1 uses Everest only
  for the key agreement. `psa_export_public_key` still computed the public key
  with the generic `mbedtls_ecp_mul`, which cost 8.7 ms per handshake on the
  Wii. `CMakeLists.txt` patches `mbedtls_psa_ecp_export_public_key` at
  configure time to compute X25519 public keys with
  `mbedtls_x25519_scalarmult(pub, priv, 9)`, and stops with an error if the
  anchor is gone. The RFC 7748 §6.1 vectors in the `crypto` suite pin the
  export, including clamping.

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
- **What the handshake CPU is made of.** See "Handshake breakdown" below; the
  table above predates it.

### Handshake breakdown

`wtls_connect` records a profile of every handshake (`src/wtls_prof.h`): TCP
connect (and its poll wait), setup, each `mbedtls_ssl_handshake_step` by
state, and the time inside `wtls_plat_send`/`recv`. The `tls` suite checks that
the parts add up. The bench prints medians, and its `PROF` lines time each
PSA/X.509 call. Default build, Wii over Wi-Fi, bench 9/9 pass.

"Before" is the build at commit 925aaa9 with only the accounting fixed (connect
polls counted as wait); "after" adds the X25519 export fix.

| Resumed handshake | before ms | after ms |
|-------------------|----------:|---------:|
| wall | 35.7 | 29.3 |
| CPU (wall − poll wait) | 26.5 | 18.0 |
| TCP connect, CPU part (IOS IPC) | 2.6 | 2.6 |
| send/recv IPC (12 calls: 3 send, 8 recv, 1 empty recv) | 5.6 | 5.2 |
| step `client_hello` (X25519 keygen + export) | 13.0 | 4.8 |
| step `server_hello` (X25519 agreement, key schedule) | 4.7 | 4.8 |
| steps `server_finished`, `client_finished`, rest | 0.5 | 0.6 |
| **crypto CPU (CPU − connect − IPC)** | **18.3** | **10.2** |

| Full handshake | before ms | after ms |
|----------------|----------:|---------:|
| wall | 91.7 | 86.9 |
| CPU (wall − poll wait) | 78.5 | 70.4 |
| TCP connect, CPU part | 2.4 | 2.4 |
| send/recv IPC (16 calls: 3 send, 12 recv, 1 empty) | 6.4 | 6.3 |
| step `client_hello` | 12.8 | 4.6 |
| step `server_hello` | 4.7 | 4.8 |
| step `server_certificate` (chain verify: 1 ECDSA P-256) | 25.8 | 25.9 |
| step `certificate_verify` (1 ECDSA P-256) | 25.7 | 25.7 |
| other steps and rest | 0.6 | 0.6 |
| **crypto CPU** | **69.6** | **61.6** |

What the numbers say:

- **The old CPU figure was not all crypto.** About 5 ms of the old 31.7 ms
  resumed CPU were connect polls, now counted as wait. Of what remains, the
  connect's IPC (2.6 ms) and the send/recv IPC (5.2 ms, about 0.45 ms per
  call; a send costs about 1 ms) are IOS round trips, not crypto.
- **Resumed handshake: X25519 is now nearly all of it.** Export 4.5 ms +
  agreement 4.5 ms of 10.2 ms crypto. Hashing, HKDF, HMAC and AEAD together
  take about 1.2 ms. The 10 ms target for the CPU figure cannot be met while
  it includes about 8 ms of IOS IPC; the crypto part is at 10.2 ms.
- **Full handshake: P-256 verify is 51 ms of 61.6 ms crypto.** Two verifies
  at 25.7 ms each (leaf signature in the chain, CertificateVerify).
  X.509 parsing costs 0.1 ms.
- **p256-m is slower on the Wii.** Raw `p256_ecdsa_verify` takes 35.9 ms vs
  25.6 ms for the builtin verify with `BN_ASM` (on the x86 host: 2.1 vs 1.0
  ms). p256-m's 32-bit C does not beat the PPC32 bignum assembly, so routing
  P-256 through it would make things worse. The builtin ECP options are
  already at their best: `MBEDTLS_ECP_FIXED_POINT_OPTIM` is on, and window
  size 4 is the maximum used for 256-bit curves.
- **Earlier ECDSA bench numbers were inflated.** `ecdsa_p256_verify` used the
  key pair, so the builtin driver recomputed the public point on every verify
  (31.6 ms). With a public key, as in TLS, it is 25.6 ms.

Remaining options, not done here:

- **Fewer IPCs.** A read-ahead buffer in the BIO could merge the
  header/body reads of TLS records (8–12 recv per handshake). It changes what
  `wtls_pending` and the fd's readiness mean, so it needs its own design.
- **Faster X25519 on PPC**: done, see "Task 12 result" below.
- **Cache verified certificate chains** across connections to the same host.
  This skips one P-256 verify (about 26 ms) per full handshake, but is a
  security policy decision (revocation, expiry, key pinning).
- **P-256 field arithmetic in PPC assembly**: beyond the existing `BN_ASM`,
  only a dedicated P-256 field multiplication could help; not investigated.
  → Done in 0.3.0 as portable C with `WTLS_ACCEL_P256`; see "P-256
  acceleration" below.

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

**Update after the handshake breakdown.** The profile showed that the X25519
key exchange in a handshake cost 13 ms, not 4.5 ms, because the public key
export bypassed Everest (fixed, see above). After the fix X25519 is about 9 ms
per handshake (export + agreement; `x25519_keygen_agree` now measures both,
8.9 ms), about half the resumed handshake's 18 ms CPU and nearly all of its
10.2 ms crypto. A faster X25519 is therefore the one lever left for the
resumed target; whether to do Task 12 is up for a new decision.

### Task 12 result: X25519 with 32-bit limbs

Decided: do the X25519 part of Task 12. Everest's HACL* code uses 51-bit limbs;
without `__int128` on PPC32 every 64×64→128 product is emulated.
`src/accel/x25519_fe32.c` uses ten limbs of 26/25 bits (the ref10 layout), so
each product is one `mullw`/`mulhw` pair:

- **Key agreement**: Montgomery ladder per RFC 7748, constant time.
- **Public key** (point 9): fixed-base comb on the twisted Edwards form,
  signed radix-16 digits, 64 mixed additions from a 32×8 table and 4 doublings,
  then u = (1+y)/(1−y). The ladder would cost as much as the agreement.
- **Generated code**: `tools/gen_fe25519.py` writes the multiply/square
  (`fe25519_mul.inc`, terms derived from the limb layout instead of
  hand-copied) and the base table (`ge25519_base.inc`, exact integer
  arithmetic).
- **Hook**: a configure-time patch makes Everest's `mbedtls_x25519_scalarmult`
  call `wtls_x25519`, so the PSA key exchange and the export (both through
  Everest, see above) use it.
- **Tests** (`crypto` suite): RFC 7748 §5.2 vectors, the iterated vector
  (1 and 1000 rounds), §6.1, and comparisons with Everest. There are 6 edge
  points, plus random scalar/point pairs and random base-point scalars
  including all-zero and all-one (1000 of each on the host, 100 on the Wii).

Wii, default build (`EVEREST=ON`, `OPT=O3`, `ACCEL=ON`):

| | Everest | 32-bit ladder | + fixed-base comb |
|---|---|---|---|
| `x25519_keygen_agree` (keygen + export + agreement) | 8.9 ms | 6.79 ms | **4.60 ms** |
| export in the handshake (`psa_export_public_key`) | 4.5 ms | 3.4 ms | 1.27 ms |
| agreement in the handshake (`psa_raw_key_agreement`) | 4.5 ms | 3.4 ms | 3.45 ms |
| full handshake CPU / wall | — | 68.5 / 80.1 ms | 66.1 / 81.0 ms |
| resumed handshake CPU / wall | 18 ms CPU | 16.3 / 27.0 ms | 13.6 / 24.7 ms |
| resumed handshake crypto | 10.2 ms | 8.0 ms | 5.9 ms |

Suites: `crypto` 8/8, `tls` 27/27, bench 9/9. X25519 gate met (4.60 ≤ 5 ms).
The handshake targets stay missed: the resumed one is now 13.6 ms CPU, of which
5.2 ms is socket I/O (IPC to IOS), not crypto. The full one is dominated by
P-256 verification (51 ms). **Ruling: ChaCha20-Poly1305 is not accelerated.**
At 24 MB/s it is above its target and far above what the Wi-Fi delivers.

## P-256 acceleration (WTLS_ACCEL_P256, 0.3.0)

`src/accel/p256_verify.c` replaces the builtin driver's
`mbedtls_psa_ecdsa_verify_hash` for exactly the TLS shape: an uncompressed
65-byte P-256 public key and a raw 64-byte `r||s` signature. Verify inputs
are public, so it is variable time by design:

- 8×32-bit limbs; the 64/36 schoolbook products accumulate into int64
  columns, then one top-down Solinas pass folds with
  2^256 = 2^224 − 2^192 − 2^96 + 1 (mod p) — every shift is a whole limb.
  GCC emits `mullw`/`mulhwu` pairs for the products (158 in the PPC
  object); no 64-bit multiplier is needed anywhere.
- Shamir's trick over interleaved wNAF: w = 6 for G against the generated
  affine table `k_p256_g_odd` (16 odd multiples, 1 KiB `.rodata`,
  `tools/gen_p256.py`), w = 5 for Q against eight odd multiples normalised
  with a single mod-p inversion (binary extended GCD, also used for
  s⁻¹ mod n).
- Jacobian coordinates with a = −3: doubling 3M+5S, mixed addition
  8M+3S.
- Projective final comparison X = r·Z² (mod p), with the x_R = r + n
  wrap-around as a second comparison — no field inversion for the result.

Wii, default build (`EVEREST=ON`, `OPT=O3`, `ACCEL=ON`, `BN_ASM=ON`,
`ACCEL_P256=ON`), 2026-11-26, Wi-Fi, PC test server on the same network
(including the `wtls_plat_send` `POLLOUT` + `O_NONBLOCK`-clear workaround for
IOS non-blocking `net_send`, which adds ~1.5 ms of socket IPC to a handshake):

| | builtin (0.2.0) | `WTLS_ACCEL_P256` |
|---|---:|---:|
| `ecdsa_p256_verify` | 25.6 ms | **5.30 ms** |
| `ecdsa_p256_verify_p256m` (reference) | 35.9 ms | 35.9 ms |
| `psa_verify_hash` in a full handshake (2 verifies) | 51.4 ms | **10.7 ms** |
| `handshake_full_cpu` | 66.4 ms | **27.8 ms** |
| `handshake_full_wall` | 81.0 ms | 37.3 ms |
| `handshake_resumed_cpu` (no verify in that path) | 14.0 ms | 15.6 ms |

```
BENCH ecdsa_p256_verify 5.300 ms
BENCH handshake_full_wall 37.328 ms
BENCH handshake_full_cpu 27.752 ms
BENCH hs_full_crypto_cpu 16.747 ms
GATE handshake_full_cpu <= 30 ms        27.752 met
GATE handshake_resumed_cpu <= 10 ms     15.594 MISSED
```

Gate status after 0.3.0: **the full-handshake target (≤ 30 ms CPU) is met
for the first time** (27.8 ms, with 2.2 ms headroom). The resumed target
stays missed (14.0 → 15.6 ms; the resumed path verifies no signature, and
about 9.7 ms of its CPU are IOS socket/connect IPCs — `connect_cpu` 2.6 ms
plus `io` 7.1 ms). A 5.3 ms verify sits at
the top of the 2–5 ms design window; the Phase-2 Broadway-FPU backend
(`double fmadd`) could go further but is not needed for any gate — it
stays an optional follow-up, to be judged against these numbers.

Suites on the same console: `crypto` 14/14 (the P-256 tests included:
RFC 6979 A.2.5, edge cases, a constructed x_R = r + n wrap-around vector,
a constructed R = O vector, differential against the builtin on random
keys), `tls` 34/34, `http` 76/76, `plat` 12/12, `time` 1/1, `realworld` 10/10,
bench 10/10.

### v1.0.0 verification (`OGC_SEND_MAX = 2048` + `pt_jadd` cleanup)

Re-measured on the same Wii over Wi-Fi on 2026-11-25 after reducing
`OGC_SEND_MAX` to 2048 B (`src/plat/plat_ogc.c`), removing duplicate field
ops in `pt_jadd()` (`src/accel/p256_verify.c`), and adding the 1.0.0
features (SPKI pinning, cooperative `abort_cb`, multi-IPv4 failover,
`wtls_net_reset`). Bench 10/10 pass (`WTLS-HWTEST DONE pass=10 fail=0 skip=0`):

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

All crypto and full-handshake gates remain met with improved headroom
(`handshake_full_cpu`: 27.8 → **27.3 ms**; `wtls_read_vs_raw`: **96.7 %**).

## HTTP

Three lines from `bench_http_get` (median of 20, `GET /hello` on the test
server's keep-alive port 4438, body read to the end):

- `http_get_new_wall`: pool flushed before every request, session ticket
  allowed, so this is a resumed handshake plus one request/response.
- `http_get_pooled_wall`: the same request over the pooled connection.
- `http_get_pooled_cpu`: `http_get_pooled_wall` minus the time spent blocked
  in `wtls_plat_poll`, measured like the handshake CPU numbers.

The informational gate `http_get_pooled_cpu < handshake_resumed_cpu` says
whether keeping the connection pays off; on the Wii the resumed handshake
costs 15.6 ms CPU.

Wii, default build (`WTLS_EVEREST=ON`, `WTLS_OPT=O3`, `WTLS_ACCEL=ON`, `WTLS_BN_ASM=ON`, `WTLS_ACCEL_P256=ON`), 2026-11-26 (Wi-Fi, PC test server on the same network):

```
BENCH http_get_new_wall 87.342 ms
BENCH http_get_pooled_wall 5.855 ms
BENCH http_get_pooled_cpu 2.969 ms
GATE http_get_pooled_cpu < handshake_resumed_cpu 2.969 met
```

In the same run, `handshake_resumed_wall` was 24.334 ms and `handshake_resumed_cpu` was 15.594 ms.

Host smoke run, 2026-11-25 (PC, localhost; not the target):

```
BENCH http_get_new_wall 11.379 ms
BENCH http_get_pooled_wall 0.058 ms
BENCH http_get_pooled_cpu 0.019 ms
GATE http_get_pooled_cpu < handshake_resumed_cpu 0.019 met
```

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
