# libwiitls performance

What to expect on a real Wii (Broadway, 729 MHz) with the default build
(`WTLS_EVEREST=ON`, `WTLS_OPT=O3`, `WTLS_ACCEL=ON`, `WTLS_BN_ASM=ON`).
Measured 2026-11-24 over Wi-Fi with the benchmark runner in `bench/`;
[benchmarks.md](benchmarks.md) has the method, every build variant and the
history of each number.

## In short

- **A new HTTPS connection costs about 80 ms**, a repeated one to the same
  server about 25 ms (Wi-Fi to a server on the same network; add your
  Internet round trips).
- **Downloads are limited by the Wii's Wi-Fi, not by TLS.** Decryption runs at
  24 MB/s; the Wi-Fi delivered 0.2–1 MB/s in our measurements, and
  `wtls_read` was as fast as plain TCP within the noise.
- **`wtls_init` takes about 400 ms** once at start-up (entropy collection).

## Connections

| | CPU | Wall clock (LAN, Wi-Fi) |
|---|---:|---:|
| Full TLS 1.3 handshake (DNS cached, ECDSA P-256 certificate chain) | 66 ms | 81 ms |
| Resumed handshake (session ticket, same host) | 14 ms | 25 ms |
| Resumed handshake against example.com over the Internet (Cloudflare, Frankfurt) | | 35 ms |
| Further HTTP request over a kept-alive connection (`wtls_http`, no handshake) | 2.4 ms | 5.3 ms |

Where the full handshake's CPU time goes: about 51 ms verifying two P-256
ECDSA signatures (server certificate chain and handshake signature), 4.6 ms for
the X25519 key exchange, the rest for hashing, key schedule and record
processing. The resumed handshake skips the certificate chain; what remains is
X25519 plus about 5 ms of socket calls to IOS.

Servers with RSA certificates are faster to verify (RSA-2048 verify: 8.6 ms).

The HTTP client keeps idle connections open (see the usage guide), so a
further request to the same server costs neither of the handshakes above,
only the request and response records. On the Wii the benchmark measures 2.4 ms CPU (5.3 ms wall) for such a request
against 14.0 ms CPU (23.0 ms wall) for a resumed handshake; see `http_get_*`
in [benchmarks.md](benchmarks.md#http).

## Primitives

| Operation | Speed |
|---|---:|
| ChaCha20-Poly1305 encrypt (16 KiB) | 24.0 MB/s |
| AES-128-GCM encrypt (16 KiB) | 5.3 MB/s |
| SHA-256 (16 KiB) | 29.3 MB/s |
| X25519 key exchange (key generation + public key + agreement) | 4.6 ms |
| ECDSA P-256 verify | 25.7 ms |
| RSA-2048 verify | 8.6 ms |

The Broadway has no AES instructions, so libwiitls offers ChaCha20-Poly1305
first; servers that insist on AES-GCM still work at about a fifth of the
speed, which is still well above Wi-Fi throughput.

## Size

| | |
|---|---:|
| `https_get.dol` (complete example program, HTTP client and gzip included) | 792 KB |
| Built-in Mozilla CA bundle (118 roots, parsed lazily) | in `.rodata` of `libwiitls.a` |
| Per connection | about 2 × 16 KiB record buffers plus Mbed TLS state, on the heap |

## Targets that are not met

The project set itself targets of ≤ 30 ms CPU for a full handshake and ≤ 10 ms
for a resumed one. Both are missed (66 ms and 14 ms). The full handshake is
dominated by P-256 signature verification in Mbed TLS's generic bignum code;
the resumed one is close, and about a third of it is IOS socket overhead.
In practice the network round trips cost more than either.
