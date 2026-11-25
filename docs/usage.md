# Using libwiitls

A guide for homebrew developers: setting up, the patterns that work on the
Wii, what each error means for your code, and what the library does not do.
The API reference is [include/wiitls/wiitls.h](../include/wiitls/wiitls.h)
and, for HTTP, [include/wiitls/http.h](../include/wiitls/http.h);
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
- **This is raw TLS: you speak the protocol yourself.** For HTTP, use the
  client in 5 instead: it handles chunked and gzip bodies, keep-alive and
  redirects. Speaking HTTP by hand means parsing `Transfer-Encoding: chunked`
  (hex chunk lengths between the data) yourself, or sending `HTTP/1.0` to get
  a plain body.
- **The ALPN list is stored by pointer.** Keep it `static` or alive until
  `wtls_close`.
- **Host names:** DNS names are case-insensitive and a trailing dot is
  ignored. An IPv4 literal works too, but then the server's certificate must
  list that IP (most public certificates don't).

## 5. HTTP requests

`<wiitls/http.h>` is an HTTP/1.1 client on top of the TLS layer: it builds
the request, parses the response head, decodes chunked and gzip bodies,
follows redirects and keeps connections alive for the next request. It needs
the same start-up (`net_init`, `wtls_init`) and the same single thread.

Streaming, for large bodies or when you want the headers first:

```c
#include <wiitls/http.h>

wtls_http_request req = {0};          /* zero = GET, defaults everywhere */
req.url = "https://example.com/data.json";

wtls_http_response *res;
int r = wtls_http_open(&res, &req);   /* connect (or reuse), send, read the head */
if (r != WTLS_OK) { printf("%s\n", wtls_strerror(r)); return; }

printf("status %d, type %s\n", wtls_http_status(res),
       wtls_http_get_header(res, "Content-Type"));   /* NULL if absent */
char buf[4096];
int n;
while ((n = wtls_http_read(res, buf, sizeof buf)) > 0) consume(buf, n);
if (n < 0) report(n);                 /* WTLS_ERR_IO: body cut short, discard it */
wtls_http_close(res);                 /* read to the end -> connection is pooled */
```

The whole body in one call, for small answers (JSON, text):

```c
wtls_http_request req = {0};
req.url = "https://example.com/api/version";
wtls_http_result res;
if (wtls_http_fetch(&req, 64 * 1024, &res) == WTLS_OK) {   /* 0 = 1 MiB limit */
    printf("%d: %s\n", res.status, res.body);             /* body is NUL-terminated */
    wtls_http_result_free(&res);
}
```

POST: set `req.method = "POST"`, `req.body`/`req.body_len` (sent with
`Content-Length`) and your headers, e.g.
`static const wtls_http_header h[] = {{"Content-Type", "application/json"}};`
with `req.headers = h; req.n_headers = 1;`. `Host`, `Content-Length`,
`Transfer-Encoding` and `Connection` are set by the library and refused in
`req.headers`.

Points that trip people up:

- **An HTTP status ≥ 400 is not an error.** `wtls_http_open` returns
  `WTLS_OK` for a 404 or 500; check `wtls_http_status`. Errors are things that
  went wrong on the way: network, TLS, a malformed response.
- **`wtls_http_read` returns 0 at the end of the body** (and again on every
  later call). This is the opposite of `wtls_read`, which never returns 0 and
  ends with `WTLS_ERR_CLOSED`: at the HTTP layer the end of a body is a normal
  event, a cut-off body (`WTLS_ERR_IO`) is not.
- **Keep-alive.** A response read to its end (`wtls_http_read` returned 0)
  goes back into a pool of 4 idle connections when you close it; idle
  connections are dropped after 60 s. The next request to the same scheme,
  host and port skips the connect and the handshake
  (`wtls_http_get_info` → `reused_connection`). A connection that died while
  idle is detected before use; if a reused connection still fails before any
  response byte arrives, GET, HEAD, PUT, DELETE, OPTIONS and TRACE are retried
  once on a new connection, POST and PATCH are not.
  `req.no_keepalive` or closing a response early opts out;
  `wtls_http_pool_flush` (and `wtls_shutdown`) closes the idle ones.
- **Redirects** (301, 302, 303, 307, 308) are followed, at most 5 by default
  (`req.max_redirects`; -1 hands the 3xx to you). 303, and 301/302 after a
  POST, become GET without a body; 307/308 keep method and body. When a
  redirect leaves the original scheme, host and port, `Authorization`,
  `Proxy-Authorization` and `Cookie` are dropped for the rest of the chain.
  `https` → `http` is refused (`WTLS_ERR_HTTP_REDIRECT`); `http` → `https` is
  followed. `wtls_http_get_info` has the final URL and the redirect count.
- **gzip.** Requests offer `Accept-Encoding: gzip` and gzip bodies are
  decompressed while you read; `wtls_http_content_length` is then -1 (the
  compressed length says nothing about the decoded size). `req.no_gzip`, or
  your own `Accept-Encoding` header, turns this off and hands you the bytes as
  sent. A corrupt gzip body is `WTLS_ERR_HTTP`, a cut one `WTLS_ERR_IO`.
- **`http://`** works too, without TLS: only for servers you trust on a
  network you trust. `wtls_http_get_info` → `secure` tells you which one a
  response came over.
- **Timeouts:** `req.tls` (a `wtls_options`) sets connect and I/O timeouts,
  `req.header_timeout_ms` (default 15 s) the time from sending the request to
  the complete response head.

Limits: URL 8 KiB; request and response head 16 KiB each; 100 response
header fields; 64 request headers; `wtls_http_fetch` body 1 MiB by default
(`WTLS_ERR_HTTP_LIMIT` above that, checked against the decoded size).

Not supported: HTTP/2 and HTTP/3, proxies, cookies (send your own `Cookie`
header), authentication schemes (send your own `Authorization`), request
bodies of unknown length (chunked uploads), `Expect: 100-continue`, ranges,
caching, and `deflate`/`br` encodings.

## 6. Faster second connections

The library keeps the last 8 TLS 1.3 session tickets and 16 DNS answers. A
later `wtls_connect` to the same host and port reuses both: no DNS lookup, no
certificate chain check, about 25 ms instead of 80 ms on Wi-Fi.
`wtls_get_info(c, &info)` tells you whether it happened (`info.resumed`).

The server sends its ticket after the handshake, so it is captured only while
you `wtls_read`/`wtls_write` on the connection. Reading the response as above
is enough. A connection closed right after `wtls_connect` stores nothing. To
opt out (e.g. for privacy between user accounts), set `opt.no_resumption`.

## 7. Non-blocking I/O for an event loop

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

## 8. Your own server / self-signed certificates

Add your CA (DER, or PEM including the terminating NUL in `len`) after
`wtls_init`:

```c
extern const unsigned char my_ca_pem[]; extern const size_t my_ca_pem_len;
wtls_add_trusted_ca(my_ca_pem, my_ca_pem_len);
```

It is trusted in addition to the built-in Mozilla roots until
`wtls_shutdown`. Do **not** use `insecure_skip_verify` for this. That option
turns off all certificate checks and exists for tests only.

## 9. What to do with each error

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
| `WTLS_ERR_HTTP` | malformed or unsupported HTTP response, corrupt gzip body | report; the server is broken or not HTTP/1.1 |
| `WTLS_ERR_HTTP_LIMIT` | response head over 16 KiB / 100 fields, or `wtls_http_fetch` body over its limit | stream with `wtls_http_read`, or raise `max_body` |
| `WTLS_ERR_HTTP_REDIRECT` | more than `max_redirects`, bad `Location`, or `https` → `http` | report; do not follow the downgrade yourself |

## 10. Shutting down

Close every connection, then `wtls_shutdown()`. It wipes the session tickets
(they contain secrets) and frees the CA store and caches. `wtls_init` can be
called again afterwards.

## 11. Limits and security notes

- **Client only.** No server mode, no client certificates.
- **HTTP:** HTTP/1.1 only, limits and non-goals in 5. `http://` has no
  encryption and no authentication of the server.
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
