# libwiitls performance

What to expect on a real Wii (Broadway, 729 MHz) with the default build
(`WTLS_EVEREST=ON`, `WTLS_OPT=O3`, `WTLS_ACCEL=ON`, `WTLS_ACCEL_P256=ON`,
`WTLS_BN_ASM=ON`). Measured with libwiitls 1.0.0 over Wi-Fi with the
benchmark runner in `bench/`; [benchmarks.md](benchmarks.md) has the
measurement details and build options.

## In short

- **A new HTTPS connection costs about 27 ms CPU / 37 ms wall**, a resumed
  one to the same server about 16 ms CPU / 25 ms wall (Wi-Fi to a server on
  the same network; add your Internet round trips).
- **A further request on a kept-alive connection costs about 3 ms CPU /
  6.6 ms wall**: the HTTP client's connection pool is the biggest win.
- **Downloads are limited by the Wii's Wi-Fi, not by TLS.** Decryption runs at
  24 MB/s; the Wi-Fi delivered 0.9–1.0 MB/s in our measurements, and
  `wtls_read` reached 96.7 % of plain TCP throughput.
- **`wtls_init()` takes about 400 ms** once at start-up (entropy collection).

## Connections

| | CPU | Wall clock (LAN, Wi-Fi) |
|---|---:|---:|
| Full TLS 1.3 handshake (DNS cached, ECDSA P-256 certificate chain) | 27 ms | 37 ms |
| Resumed handshake (session ticket, same host) | 16 ms | 25 ms |
| Resumed handshake against example.com over the Internet (Cloudflare, Frankfurt) | | 35 ms |
| Further HTTP request over a kept-alive connection (`wtls_http`, no handshake) | 3.0 ms | 6.6 ms |

Where the full handshake's CPU time goes: about 10.7 ms verifying two P-256
ECDSA signatures (server certificate chain and handshake signature), 4.7 ms
for the X25519 key exchange, and the rest for hashing, key schedule, record
processing and IOS socket calls. The resumed handshake skips the certificate
chain; what remains is X25519 plus IOS socket/connect IPC (~9 ms).

Servers with RSA certificates take a little longer to verify (RSA-2048
verify: 8.6 ms vs 5.3–5.4 ms for ECDSA P-256).

## Primitives

| Operation | Speed |
|---|---:|
| ChaCha20-Poly1305 encrypt (16 KiB) | 24.1 MB/s |
| AES-128-GCM encrypt (16 KiB) | 5.3 MB/s |
| SHA-256 (16 KiB) | 29.3 MB/s |
| X25519 key exchange (key generation + public key + agreement) | 4.6 ms |
| ECDSA P-256 verify (`WTLS_ACCEL_P256`) | 5.3–5.4 ms |
| RSA-2048 verify | 8.6 ms |

The Broadway has no AES instructions, so libwiitls offers ChaCha20-Poly1305
first; servers that insist on AES-GCM still work at about a fifth of the
speed, which is still well above Wi-Fi throughput.

## Size

| | |
|---|---:|
| `https_get.dol` (complete example program, HTTP client and gzip included) | 814 KiB |
| Built-in Mozilla CA bundle (118 roots, parsed lazily) | in `.rodata` of `libwiitls.a` |
| Per connection | about 2 × 16 KiB record buffers plus Mbed TLS state, on the heap |
