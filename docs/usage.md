# Using libwiitls

A guide for homebrew developers: setting up, the patterns that work on the
Wii, what each error means for your code, and what the library does not do.
The API reference is [include/wiitls/wiitls.h](../include/wiitls/wiitls.h);
performance numbers are in [performance.md](performance.md).

## 1. Add it to your project

**Release package** (prebuilt for devkitPPC/libogc, from the GitHub releases
page): unpack it and point your Makefile at it:

```make
WIITLS   := path/to/libwiitls-<version>-wii
CFLAGS   += -I$(WIITLS)/include \
            -DMBEDTLS_CONFIG_FILE='"wtls_mbedtls_config.h"' \
            -DTF_PSA_CRYPTO_CONFIG_FILE='"wtls_crypto_config.h"'
LIBPATHS += -L$(WIITLS)/lib
LIBS     := -lwiitls -lmbedtls -lmbedx509 -ltfpsacrypto -lwiitls -lwiiuse -lbte -logc -lm
```

The order matters: `-lwiitls` comes twice because TF-PSA-Crypto calls back
into libwiitls for entropy and the accelerated X25519. The two `-D` flags are
only needed when you include Mbed TLS headers yourself (e.g. `mbedtls/x509.h`
for the `MBEDTLS_X509_BADCERT_*` flags below); they must match the
configuration the archives were built with, which the package ships.
`example/Makefile` in the package builds the example this way.

**From source with CMake** (fetches Mbed TLS on the first configure):

```cmake
add_subdirectory(third_party/libwiitls)
target_link_libraries(my_app PRIVATE wiitls)
```

## 2. Start-up

```c
#include <network.h>
#include <wiitls/wiitls.h>

/* on your network thread (see 3.) */
if (net_init() < 0) { /* no network */ }
int r = wtls_init();               /* ~400 ms: seeds the random generator */
if (r != WTLS_OK) { /* WTLS_ERR_NET or WTLS_ERR_ENTROPY: no TLS possible */ }
wtls_time_sync_sntp(NULL, 3000);   /* recommended once; see "The clock" */
```

`wtls_init` measures timing jitter of IOS calls to seed the random generator.
It runs health tests on that data and fails with `WTLS_ERR_ENTROPY` rather
than run with weak randomness; treat that as fatal for networking.

**The clock.** Certificates can only be checked with a correct date, and the
Wii's clock is often wrong (dead clock battery, never set). Two strategies:

- Sync once at start-up with `wtls_time_sync_sntp(NULL, 3000)` (UDP 123 to
  `pool.ntp.org`, or pass your own server). Costs one round trip.
- Or sync only on demand: `wtls_connect` returns `WTLS_ERR_CLOCK` when the
  clock is clearly wrong (before the library was built, or 20 years after). A
  clock that is off by less shows up as `WTLS_ERR_CERT` with the
  `MBEDTLS_X509_BADCERT_EXPIRED` or `_FUTURE` flag. In both cases: sync, retry
  once.

## 3. One network thread

libwiitls has no locks. **Every `wtls_*` call must come from the same
thread.** Blocking calls (connect, read) take tens of milliseconds to seconds,
so do networking on its own LWP thread and keep the main thread drawing:

```c
static u8 net_stack[64 * 1024] __attribute__((aligned(32)));

static void *net_thread(void *arg) {
    net_init();
    wtls_init();
    /* ... all wtls_* calls here; hand results to the UI thread via a
     *     mutex-protected queue ... */
    return NULL;
}

lwp_t th;
LWP_CreateThread(&th, net_thread, NULL, net_stack, sizeof net_stack, 64);
```

64 KiB of stack is enough. [examples/https_get](../examples/https_get/main.c)
is a complete program with this structure.

## 4. A request

```c
static const char *const alpn[] = {"http/1.1", NULL};  /* must outlive the connection */
wtls_options opt = {0};          /* zero = defaults: 5 s connect, 10 s handshake, 15 s I/O */
opt.alpn = alpn;

wtls_conn *c;
int r = wtls_connect(&c, "example.com", 443, &opt);
if (r == WTLS_ERR_CLOCK ||
    (r == WTLS_ERR_CERT && (wtls_last_verify_flags() &
        (MBEDTLS_X509_BADCERT_EXPIRED | MBEDTLS_X509_BADCERT_FUTURE)))) {
    if (wtls_time_sync_sntp(NULL, 3000) == WTLS_OK)
        r = wtls_connect(&c, "example.com", 443, &opt);
}
if (r != WTLS_OK) { printf("connect: %s\n", wtls_strerror(r)); return; }

const char req[] = "GET /data.json HTTP/1.1\r\nHost: example.com\r\n"
                   "Connection: close\r\n\r\n";
if (wtls_write(c, req, sizeof req - 1) != (int)(sizeof req - 1)) { wtls_close(c); return; }

char buf[4096];
for (;;) {
    int n = wtls_read(c, buf, sizeof buf);
    if (n > 0) { consume(buf, n); continue; }
    if (n == WTLS_ERR_CLOSED) break;          /* clean end of the response */
    /* WTLS_ERR_IO: cut off without close_notify -> do NOT trust the data
     * WTLS_ERR_TIMEOUT: server silent for io_timeout_ms */
    report(n);
    break;
}
wtls_close(c);
```

Points that trip people up:

- **`wtls_read` never returns 0.** End of stream is `WTLS_ERR_CLOSED`. A
  stream that just stops (`WTLS_ERR_IO`) may be truncated by an attacker or a
  broken connection: discard the data, or check it against `Content-Length`.
- **libwiitls speaks TLS, not HTTP.** With `HTTP/1.1` most servers answer with
  `Transfer-Encoding: chunked` (hex chunk lengths between the data, as you see
  in the example's output); parse that yourself, or send `HTTP/1.0` to get a
  plain body.
- **The ALPN list is stored by pointer.** Keep it `static` or alive until
  `wtls_close`.
- **Host names:** DNS names are case-insensitive and a trailing dot is
  ignored. An IPv4 literal works too, but then the server's certificate must
  list that IP (most public certificates don't).

## 5. Faster second connections

The library keeps the last 8 TLS 1.3 session tickets and 16 DNS answers. A
later `wtls_connect` to the same host and port reuses both: no DNS lookup, no
certificate chain check, about 25 ms instead of 80 ms on Wi-Fi.
`wtls_get_info(c, &info)` tells you whether it happened (`info.resumed`).

The server sends its ticket after the handshake, so it is captured only while
you `wtls_read`/`wtls_write` on the connection. Reading the response as above
is enough. A connection closed right after `wtls_connect` stores nothing. To
opt out (e.g. for privacy between user accounts), set `opt.no_resumption`.

## 6. Non-blocking I/O for an event loop

`wtls_connect` always blocks. After it, `wtls_set_nonblocking(c, true)` makes
`wtls_read`/`wtls_write` return at once:

```c
wtls_set_nonblocking(c, true);
for (;;) {
    int n = wtls_read(c, buf, sizeof buf);
    if (n > 0) { consume(buf, n); continue; }      /* try again: more may be buffered */
    if (n == WTLS_WANT_READ || n == WTLS_WANT_WRITE) {
        /* nothing yet: do other work, then wait on wtls_get_fd(c) with
         * net_poll(); but check wtls_pending(c) first, decrypted bytes can be
         * waiting while the socket itself is not readable */
        break;
    }
    /* WTLS_ERR_CLOSED / errors as in blocking mode */
    break;
}
```

After `WTLS_WANT_WRITE` from `wtls_write`, call it again with **the same
buffer and length**.

## 7. Your own server / self-signed certificates

Add your CA (DER, or PEM including the terminating NUL in `len`) after
`wtls_init`:

```c
extern const unsigned char my_ca_pem[]; extern const size_t my_ca_pem_len;
wtls_add_trusted_ca(my_ca_pem, my_ca_pem_len);
```

It is trusted in addition to the built-in Mozilla roots until
`wtls_shutdown`. Do **not** use `insecure_skip_verify` for this. That option
turns off all certificate checks and exists for tests only.

## 8. What to do with each error

| Return | Typical cause | What your app should do |
|--------|---------------|-------------------------|
| `WTLS_ERR_NET` | `net_init` not done or failed | bring the network up first |
| `WTLS_ERR_ENTROPY` | random generator health test failed | no TLS; show an error |
| `WTLS_ERR_CLOCK` | Wii clock far off | `wtls_time_sync_sntp`, retry once |
| `WTLS_ERR_DNS` | no such host, no DNS | show "host not found" |
| `WTLS_ERR_CONNECT` | port closed, no route | retry later |
| `WTLS_ERR_TIMEOUT` | server or Wi-Fi too slow | retry; raise the timeouts in `wtls_options` if needed |
| `WTLS_ERR_HANDSHAKE` | server needs something unsupported (e.g. client certificates, TLS ≤ 1.1) | not fixable on the client |
| `WTLS_ERR_CERT` | untrusted, expired, wrong host name | `wtls_last_verify_flags()`; EXPIRED/FUTURE: sync the clock and retry once; otherwise refuse |
| `WTLS_ERR_IO` | connection reset or truncated | discard partial data; retry |
| `WTLS_ERR_CLOSED` | clean end of stream | done |
| `WTLS_ERR_NOMEM` | heap exhausted | close connections, free memory |

## 9. Shutting down

Close every connection, then `wtls_shutdown()`. It wipes the session tickets
(they contain secrets) and frees the CA store and caches. `wtls_init` can be
called again afterwards.

## 10. Limits and security notes

- **Client only.** No server mode, no client certificates.
- **TLS 1.3 preferred, TLS 1.2 minimum.** Ciphers: ChaCha20-Poly1305 first
  (fast without AES hardware), AES-GCM. Key exchange X25519, P-256, P-384.
- **No revocation checks** (OCSP/CRL), like most embedded TLS clients.
- **The CA bundle is a snapshot** of Mozilla's list, built into the library.
  Rebuild with a fresh `data/cacert.pem` now and then (see the README) and
  ship updates of your app, or add roots with `wtls_add_trusted_ca`.
- **Randomness comes from IOS timing jitter**, health-tested at start-up, and
  the library refuses to run when the tests fail. It has been measured on real
  hardware, but has not been evaluated independently. Keep this in mind
  before protecting high-value secrets.
- **Single thread**, see 3.
- **Memory:** each connection holds Mbed TLS's record buffers (two 16 KiB
  buffers plus overhead), allocated from the normal heap.
