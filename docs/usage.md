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

**As a subdirectory or installed package (`find_package`):**

```cmake
# Subdirectory (fetches Mbed TLS + zlib on the first configure):
add_subdirectory(third_party/libwiitls)
target_link_libraries(my_app PRIVATE wiitls::wiitls)

# Or from `cmake --install <build> --prefix <prefix>`:
find_package(wiitls 1.0 REQUIRED)
target_link_libraries(my_app PRIVATE wiitls::wiitls)
```

**devkitPro `dkp-pacman` (`PKGBUILD`):** `packaging/dkp-wii/PKGBUILD` (or
`tools/make_pkg.sh`) builds a `wii-libwiitls` package installing into
`$DEVKITPRO/portlibs/wii` with `powerpc-eabi-pkg-config wiitls` and
`find_package(wiitls)` support (with bundled Mbed TLS isolated under
`include/wiitls-deps` and `lib/wiitls` to avoid conflicts with `wii-mbedtls`).

**On native Windows without MSYS2:** configure Wii builds with Ninja using
[cmake/wii-win-toolchain.cmake](../cmake/wii-win-toolchain.cmake):

```sh
cmake -S . -B build-wii-win -G Ninja -DCMAKE_TOOLCHAIN_FILE=cmake/wii-win-toolchain.cmake
cmake --build build-wii-win
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
- Or remember the result: after a successful sync call
  `wtls_time_save("sd:/apps/myapp/clock.bin")`; at the next start
  `wtls_time_load(path, 7 * 86400)` applies it without network traffic. It is
  only a hint (rejected if the file is damaged, older than the age you pass, or
  the console clock went backwards); if a certificate still looks expired,
  sync once and retry as above.

**Network / Wi-Fi changes.** After `net_deinit()` / `net_init()` or switching
access points, `wtls_net_reset()` flushes the DNS cache and pooled HTTP
connections (on the Wii, interface IP changes via `net_gethostip()` are also
detected automatically before new connects).

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
shows a spinner UI thread + network LWP thread;
[examples/upload_mtls_abort](../examples/upload_mtls_abort/main.c) adds
streaming uploads, optional mTLS/SPKI pinning, progress reporting, and
Wiimote/GC cancellation.

In `Debug` builds (or with `-DWTLS_THREAD_CHECK=ON`), libwiitls checks on every
public entry point that the caller matches the thread bound by `wtls_init()` and
aborts immediately on misuse.

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

`<wiitls/http.h>` is an HTTP/2 (`h2` ALPN) and HTTP/1.1 client on top of the
TLS layer: it builds requests (HPACK or HTTP/1.1), parses headers, decodes
chunked, gzip and deflate bodies, follows redirects and pools connections for
the next request. It needs the same start-up (`net_init`, `wtls_init`) and
the same single thread.

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

Streaming uploads, when the body is generated on the fly or read
from SD without buffering it whole:

```c
/* int my_body_reader(void *ctx, void *buf, size_t len): fill buf with up to
 * len bytes, return the count, 0 at the end, or a negative value to abort. */

wtls_http_request req = {0};
req.method = "PUT";
req.url = "https://example.com/upload/savegame.bin";
req.body_cb = my_body_reader;      /* mutually exclusive with req.body */
req.body_ctx = &my_state;
req.body_len = file_size;          /* sent as Content-Length ... */
/* ... or req.body_chunked = true;  ... sent as Transfer-Encoding: chunked,
   the reader ends the body by returning 0 (no body_len needed). */
```

Rules the library enforces for you: a reader that stops early or fails
aborts the request with `WTLS_ERR_IO` and closes (never pools) the
connection; a stale pooled connection is only retried if the reader has not
been called yet and the method is idempotent; 303 (and 301/302 after POST)
turn into GET without calling the reader again; any other redirect with a
streaming body is refused with `WTLS_ERR_HTTP_REDIRECT`, because a stream
cannot be rewound - set `req.max_redirects = -1` if you can rewind it
yourself and follow the `Location` by hand.

Two small helpers in `<wiitls/http.h>`: `wtls_http_url_encode`
percent-encodes query values (RFC 3986, upper case hex), and
`wtls_http_parse_content_range` parses the `Content-Range` of a `206`
response for resumable downloads:

```c
/* https://example.com/d/app.zip?user=<encoded name> */
char q[300]; size_t qn;
wtls_http_url_encode(name, strlen(name), q, sizeof q, &qn);   /* out=NULL: size query */

/* Resume a download: Range: bytes=<have>- ... then check what arrived. */
wtls_http_content_range cr;
if (wtls_http_status(res) == 206 &&
    wtls_http_parse_content_range(wtls_http_get_header(res, "Content-Range"), &cr) == WTLS_OK) {
    /* cr.start, cr.end, cr.total (or -1 if "*"); cr.start == have means the
     * server resumed - otherwise the file changed and the data is useless. */
}
```

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
- **gzip and deflate.** Requests offer `Accept-Encoding: gzip, deflate` and
  compressed bodies are decompressed while you read (`info.gzip` /
  `info.deflate`); `wtls_http_content_length` is then -1 (the compressed
  length says nothing about the decoded size). `req.no_gzip`, or your own
  `Accept-Encoding` header, turns this off and hands you the bytes as sent. A
  corrupt compressed body is `WTLS_ERR_HTTP`, a cut one `WTLS_ERR_IO`.
- **`Expect: 100-continue`.** Set `req.expect_100_continue = true` on uploads
  (`body_cb` or `body`) to wait up to 1000 ms for `100 Continue` before
  transmitting the body; if the server immediately rejects with `401`/`413`,
  the upload is skipped without wasting bandwidth.
- **HTTP/2 (`h2` ALPN).** Enabled by default (`WTLS_HTTP2=ON`). Over `https://`,
  the client offers `h2` and `http/1.1` ALPN, handles HPACK (RFC 7541),
  flow-control `WINDOW_UPDATE`, `SETTINGS`, `PING`, `GOAWAY`, `RST_STREAM`, and
  reuses pooled HTTP/2 connections sequentially across streams (`info.http2`).
  Set `req.no_h2 = true` (or `req.allow_upgrade = true`) to force `http/1.1`.
- **HTTP `101 Switching Protocols` handoff.** Set `req.allow_upgrade = true`
  (with your `Upgrade` header) and call `wtls_http_detach()` on a `101`
  response to take over the underlying `wtls_conn *` (`wss://`) or socket fd
  (`ws://`), preserving any early bytes received with the `101` head.
- **Proxies.** Set `req.proxy_url`: `"http://host[:port]"` for `http://`
  forwarding and `https://` `CONNECT` tunneling, `"socks5h://host[:1080]"`
  (the proxy resolves names) or `"socks5://host[:1080]"` (resolved locally,
  IPv4). Add `user:pass@` (percent-encode special characters) for HTTP Basic
  proxy authentication or SOCKS5 username/password. Proxied requests bypass
  the keep-alive pool; `https://` is still verified against the target name.
- **`http://`** works too, without TLS: only for servers you trust on a
  network you trust. `wtls_http_get_info` → `secure` tells you which one a
  response came over.
- **Timeouts:** `req.tls` (a `wtls_options`) sets connect and I/O timeouts,
  `req.header_timeout_ms` (default 15 s) the time from sending the request to
  the complete response head.
- **Cancellation and progress:** set
  `opt.abort_cb` / `opt.abort_ctx` in `wtls_options` (shared via `req.tls` for
  both `https://` and `http://`). Polling sleeps in <= 100 ms slices, so
  pressing **B/HOME** cancels blocked connects, handshakes, header waits, or
  reads promptly with `WTLS_ERR_CANCELLED`. Set `req.progress_cb` to track
  `(done, total_or_minus_one)` bytes received in both `wtls_http_fetch()` and
  streaming `wtls_http_open()` / `wtls_http_read()`.

Additional helpers in `<wiitls/http.h>`: `wtls_http_form_encode()`
(`application/x-www-form-urlencoded`), `wtls_http_multipart_init()` /
`wtls_http_multipart_read()` (zero-buffer streaming `multipart/form-data`),
`wtls_http_format_range()` and `wtls_http_check_resume()`.

Limits: URL 8 KiB; request and response head 16 KiB each; 100 response
header fields; 64 request headers; `wtls_http_fetch` body 1 MiB by default
(`WTLS_ERR_HTTP_LIMIT` above that, checked against the decoded size).

Not supported: HTTP/3, concurrent HTTP/2 streams (multiplexing) and server
push, cookies (send your own `Cookie` header), authentication schemes (send
your own `Authorization`), caching, and `br` encoding.

### Deadlines and retries

```c
req.total_timeout_ms = 10000;   /* the whole call, redirects and body included */
req.max_retries = 2;            /* after DNS / connect / timeout / reset errors, idempotent requests only */
req.retry_backoff_ms = 500;     /* 0.5 s, 1 s, ... (+/-25 %) */
req.retry_on_503 = true;        /* also retry 429/503, honouring Retry-After (max 60 s) */
```

`total_timeout_ms` is the one number a UI wants: every stage timeout is cut down
to what is left, `wtls_http_read()` stops at the deadline with `WTLS_ERR_TIMEOUT`,
and waits between retries count against it. Host name resolution cannot be
interrupted (see the async DNS work on the roadmap). Retries cover the time up to
the response head; once body bytes are delivered nothing is repeated, and requests
with a streaming body (`body_cb`) or a method that is not idempotent (POST, PATCH)
are never retried.

### Cookies

```c
wtls_cookie_jar *jar = wtls_cookie_jar_new(0);       /* 0 => up to 64 cookies */
wtls_http_request req = {0};
req.cookie_jar = jar;                                /* reuse the same jar for every request */
req.url = "https://example.com/login";
/* ... fetch ...; later requests send the matching cookies automatically */
wtls_cookie_jar_free(jar);
```

The jar lives in memory only (persist what you need yourself). It follows
RFC 6265: `Domain` (host-only without it), `Path`, `Secure` (never sent in clear
and not accepted from plain http), `Expires` / `Max-Age` (deletion included),
and it decides per redirect hop, so cookies set by a redirect are sent to its
target. A `Cookie` header you pass yourself wins. Limits: there is no public
suffix list (a `Domain=co.uk` cookie is accepted; a bare `com` is not), no
`SameSite` handling (the library is not a browser), and cookies ignore ports as
in browsers.

### Authorization headers

```c
char auth[160];
wtls_http_basic_auth("user", "secret", auth, sizeof auth, NULL);   /* or wtls_http_bearer_auth(token, ...) */
wtls_http_header h[] = {{"Authorization", auth}};
req.headers = h;
req.n_headers = 1;
```

The helpers only build the header value (RFC 7617 / RFC 6750). `Authorization`
is dropped automatically when a redirect leaves the origin. Digest
authentication is not supported.

## 6. Faster second connections

The library keeps the last 8 TLS 1.3 session tickets and 16 DNS answers. A
later `wtls_connect` to the same host and port reuses both: no DNS lookup, no
certificate chain check, about 24 ms instead of 37 ms on Wi-Fi.
`wtls_get_info(c, &info)` tells you whether it happened (`info.resumed`).

The server sends its ticket after the handshake, so it is captured only while
you `wtls_read`/`wtls_write` on the connection. Reading the response as above
is enough. A connection closed right after `wtls_connect` stores nothing. To
opt out (e.g. for privacy between user accounts), set `opt.no_resumption`.

## 7. Non-blocking connect & I/O for an event loop

For an event loop or multiple concurrent connections, use
`wtls_connect_start()` + `wtls_connect_step()` (non-blocking TCP connect + TLS
handshake), then `wtls_set_nonblocking(c, true)` so `wtls_read`/`wtls_write`
return at once:

```c
wtls_conn *c = NULL;
wtls_status st = wtls_connect_start(&c, "example.com", 443, &opt);
while (st == WTLS_WANT_READ || st == WTLS_WANT_WRITE) {
    /* Wait on wtls_get_fd(c) with net_poll() (<= 5 ms slices during TCP
     * connect on the Wii: IOS net_poll does not wake on connect completion),
     * or do other work, then advance: */
    st = wtls_connect_step(c);
}
if (st != WTLS_OK) { wtls_close(c); return; }

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
`wtls_reset_trusted_cas()` or `wtls_shutdown()`. To replace the built-in
snapshot at runtime (e.g. from a fresh `cacert.pem` on SD card), call
`wtls_reset_trusted_cas(false)` first and then `wtls_add_trusted_ca()`. To
omit the ~200 KiB embedded bundle from the binary altogether, build with
`-DWTLS_EMBED_CA=OFF`. Do **not** use `insecure_skip_verify` for this. That
option turns off all certificate checks and exists for tests only.

### Client certificates (mutual TLS)

Servers that require the *client* to authenticate (your own API, a NAS, a
home server) get a client certificate from the TLS layer:

```c
extern const unsigned char my_cert_pem[]; extern const size_t my_cert_pem_len;
extern const unsigned char my_key_pem[];   extern const size_t my_key_pem_len;

wtls_client_cred *cred;
int r = wtls_client_cred_load(&cred, my_cert_pem, my_cert_pem_len,
                              my_key_pem, my_key_pem_len);
/* WTLS_OK; WTLS_ERR_ARG if unparsable or the key does not match the cert. */

wtls_options opt = {0};
opt.client_cred = cred;                       /* present it from now on */
wtls_conn *c;
r = wtls_connect(&c, "nas.local", 443, &opt); /* server must accept the cert */
...
wtls_close(c);
wtls_client_cred_free(cred);                   /* NULL is safe */
```

Both accept DER, or PEM with the terminating NUL byte included in `len`;
the certificate chain goes leaf-first. Keys: ECDSA (P-256, P-384) and RSA;
for password-protected PKCS#8 / PEM keys, use `wtls_client_cred_load_ex()`.
The match of key and leaf is checked at load.

The credential is reference-counted behind the scenes: every connection
(including idle keep-alive connections of the HTTP client, and pooled ones)
holds a reference, so `wtls_client_cred_free` may be called while
connections still use it - the private key is zeroized once the last
reference is gone. Session tickets and pooled HTTP connections are keyed by
the certificate's fingerprint: a connection with one identity never resumes
or reuses a connection of another. And like `Authorization` and `Cookie`,
the client certificate is stripped when a redirect leaves the origin.

### Public-key (SPKI) pinning

In addition to normal chain + date + hostname verification, you can pin up to
`WTLS_SPKI_MAX_PINS` (2: primary + backup; more in `spki_pins_ext`, below) SHA-256 digests of ASN.1 DER
`SubjectPublicKeyInfo`:

```c
static const uint8_t k_pin_primary[WTLS_SPKI_SHA256_LEN] = { /* 32 bytes */ };
static const uint8_t k_pin_backup[WTLS_SPKI_SHA256_LEN]  = { /* 32 bytes */ };

wtls_options opt = {0};
memcpy(opt.spki_pins[0], k_pin_primary, WTLS_SPKI_SHA256_LEN);
memcpy(opt.spki_pins[1], k_pin_backup,  WTLS_SPKI_SHA256_LEN);
opt.n_spki_pins = 2;
```

Matches if any verified chain certificate (leaf, intermediate, or trusted root)
matches a configured pin; mismatches fail with `WTLS_ERR_CERT`
(`MBEDTLS_X509_BADCERT_OTHER` set in `wtls_last_verify_flags()`). Pin sets are
isolated in both TLS session tickets and the HTTP keep-alive pool.

For key rotation with more backups, `spki_pins_ext` (added in 1.1; the 1.0 array
layout is unchanged) takes up to `WTLS_SPKI_MAX_PINS_EXT` (4) further digests,
so six pins are possible in total. Any match across both lists suffices:

```c
static const uint8_t k_more[3][WTLS_SPKI_SHA256_LEN] = { /* ... */ };
opt.spki_pins_ext = k_more;       /* copied at connect */
opt.n_spki_pins_ext = 3;
```

## 9. What to do with each error

| Return | Typical cause | What your app should do |
|--------|---------------|-------------------------|
| `WTLS_ERR_ARG` | invalid argument, `NULL` pointer, inconsistent counts | fix the call |
| `WTLS_ERR_STATE` | `wtls_init` not called (or failed) | call `wtls_init` first |
| `WTLS_ERR_CANCELLED` | your `abort_cb` returned `true` | clean up; do not retry |
| `WTLS_ERR_NET` | `net_init` not done or failed | bring the network up first |
| `WTLS_ERR_ENTROPY` | random generator health test failed | no TLS; show an error |
| `WTLS_ERR_CLOCK` | Wii clock far off | `wtls_time_sync_sntp`, retry once |
| `WTLS_ERR_DNS` | no such host, no DNS | show "host not found" |
| `WTLS_ERR_CONNECT` | port closed, no route | retry later |
| `WTLS_ERR_TIMEOUT` | server or Wi-Fi too slow | retry; raise the timeouts in `wtls_options` if needed |
| `WTLS_ERR_HANDSHAKE` | server needs something unsupported (e.g. TLS ≤ 1.1), or rejected our client certificate / did not send the required one | not fixable on the client as-is |
| `WTLS_ERR_CERT` | untrusted, expired, wrong host name | `wtls_last_verify_flags()`; EXPIRED/FUTURE: sync the clock and retry once; otherwise refuse |
| `WTLS_ERR_IO` | connection reset or truncated | discard partial data; retry |
| `WTLS_ERR_CLOSED` | clean end of stream | done |
| `WTLS_ERR_NOMEM` | heap exhausted | close connections, free memory |
| `WTLS_ERR_INTERNAL` | unexpected library error | report it as a bug |
| `WTLS_ERR_HTTP` | malformed or unsupported HTTP response, corrupt gzip/deflate body, or HTTP/2 protocol error | report; the server is broken or sent invalid framing |
| `WTLS_ERR_HTTP_LIMIT` | response head over 16 KiB / 100 fields, or `wtls_http_fetch` body over its limit | stream with `wtls_http_read`, or raise `max_body` |
| `WTLS_ERR_HTTP_REDIRECT` | more than `max_redirects`, bad `Location`, or `https` → `http` | report; do not follow the downgrade yourself |

## 9a. Logging and key log

Install a callback to see what the library does (handshakes, certificate
failures, redirects, connection reuse, network resets):

```c
static void on_log(void *ctx, wtls_log_level level, uint32_t category, const char *msg) {
    printf("[%d/%02x] %s\n", level, (unsigned)category, msg);
}
wtls_set_log_cb(on_log, NULL, WTLS_LOG_INFO, WTLS_LOG_CAT_ALL);
```

The callback runs on the thread that called the library function, and may be
installed before `wtls_init()`. Messages above the level or outside the
category mask are dropped before formatting. Request and response bodies,
header values, query strings and key material are never logged; request log
lines show only the method, host and port.

`wtls_set_keylog_cb()` delivers TLS secrets in the NSS `SSLKEYLOGFILE` format
(for Wireshark). It exists only when the library is built with
`-DWTLS_KEYLOG=ON`, the default for `Debug` builds; in release builds it
returns `WTLS_ERR_UNSUPPORTED` and the export code is not linked in. Never
ship an application that writes these lines anywhere.

## 9b. Custom allocator (e.g. MEM2)

By default the library uses the C library's `malloc`/`free`. To place its
memory elsewhere, install an allocator before `wtls_init()`; it also serves
Mbed TLS and zlib:

```c
static void *my_calloc(void *ctx, size_t n, size_t size) { return mem2_calloc(n, size); }
static void  my_free(void *ctx, void *p)                 { mem2_free(p); }

wtls_allocator a = { my_calloc, NULL, my_free, NULL };   /* realloc_fn is optional */
wtls_set_allocator(&a);
wtls_init();
```

`wtls_set_allocator()` returns `WTLS_ERR_STATE` while the library is
initialised. Close all connections and free all results before switching
allocators (after `wtls_shutdown()`). Each block carries a 16-byte header, so
return 16-byte aligned memory from `calloc_fn`.

## 9c. Verifying downloaded payloads

TLS protects the connection, not the file (a compromised mirror serves a valid
TLS session too). For updates, sign the payload offline and embed the public key:

```sh
python3 tools/sign_payload.py genkey update-key.pem          # once; keep it offline
python3 tools/sign_payload.py pubkey-c update-key.pem        # paste the C array into your app
python3 tools/sign_payload.py sign update-key.pem app.dol    # writes app.dol.sig (DER)
```

```c
if (wtls_sig_verify_p256(k_update_pubkey, 65, data, len, sig, sig_len, WTLS_SIG_DER) != WTLS_OK)
    /* WTLS_ERR_INTEGRITY: reject the file */;
```

For files too big for memory, hash while downloading (`wtls_sha256_init/update/finish`)
and call `wtls_sig_verify_p256_digest()`. ECDSA P-256 with SHA-256 only; the
signature format is passed explicitly (`WTLS_SIG_RAW` or canonical `WTLS_SIG_DER`).

## 9d. Downloading a file (with resume)

```c
wtls_http_request req = {0};
req.url = "https://example.com/app.bin";
wtls_http_download_opts opt = {0};
opt.sha256 = expected_digest;                 /* and/or a signature, see 9c */
wtls_http_download_result res;
wtls_status st = wtls_http_download(&req, "sd:/apps/app.bin", &opt, &res);
```

The data goes to `sd:/apps/app.bin.part` first; `.part.meta` records the URL and
the server's validator (strong `ETag` or `Last-Modified`). After a dropped
connection, a crash or a power loss, the same call resumes with `Range` /
`If-Range`; if the file changed or the server ignores ranges, it starts over.
The final file is replaced only after the digest and signature checks pass.
FAT cannot rename over an existing file, so the old file is moved to `.old`
first: call `wtls_http_download_recover(path)` at start-up (the download
function does it too) to repair a power loss in that moment.

## 9e. Refreshing the CA bundle from SD/USB

The embedded bundle is a snapshot. Ship a fresh `cacert.pem` next to your app
and load it at start-up:

```c
size_t n;
if (wtls_load_ca_bundle_file("sd:/apps/myapp/cacert.pem", true, &n) != WTLS_OK) {
    /* nothing changed: the embedded bundle stays in use */
}
```

`replace_builtin = true` trusts only the file; `false` adds it to the embedded
roots. To make sure nobody swapped the file, sign it and use
`wtls_load_ca_bundle_file_signed()` with a public key built into the app (see
9c). The file is streamed and kept as DER (about 150 KiB), parsed lazily.
Needs `wtls_init()`. Cached session tickets and idle connections are dropped.

## 9f. WebSockets

```c
#include <wiitls/websocket.h>

wtls_ws_options o = {0};
o.url = "wss://example.com/live";
wtls_ws *ws;
if (wtls_ws_connect(&ws, &o) == WTLS_OK) {
    wtls_ws_send(ws, WTLS_WS_TEXT, "hello", 5);
    char buf[1024];
    int type, n = wtls_ws_recv(ws, &type, buf, sizeof buf);   /* one complete message */
    wtls_ws_close(ws, 1000, "bye");
}
```

Messages arrive whole (fragments are reassembled), Ping is answered, and a
peer's Close ends `wtls_ws_recv()` with `WTLS_ERR_CLOSED` (code in
`wtls_ws_close_code()`). Protocol violations (masked server frames, bad UTF-8
in text, oversize messages) are answered with the proper Close code and
reported as `WTLS_ERR_WS`. For a game loop use `wtls_ws_set_nonblocking(ws, true)`
and poll `wtls_ws_get_fd()` (check `wtls_ws_pending()` first). `max_message`
(default 1 MiB) bounds memory; `ping_interval_ms` keeps idle links alive.
No extensions (no `permessage-deflate`). Build with `-DWTLS_WEBSOCKET=OFF` to
leave it out (the functions then return `WTLS_ERR_UNSUPPORTED`).

## 10. Shutting down

Close every connection, then `wtls_shutdown()`. It wipes the session tickets
(they contain secrets) and frees the CA store and caches. `wtls_init` can be
called again afterwards.

## 11. Limits and security notes

- **Client only.** No server mode. Client certificates for mutual TLS
  (including password-protected keys via `wtls_client_cred_load_ex()`) are
  supported (see 8).
- **HTTP:** HTTP/2 (`h2` ALPN over TLS, sequential single-stream per pooled
  connection) and HTTP/1.1; limits and non-goals in 5. `http://` has no
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
- **Memory:** each connection holds Mbed TLS's record buffers (a 16 KiB receive
  and a 16 KiB send buffer plus overhead), allocated from the normal heap (or
  your allocator, 9b). Build options `-DWTLS_SSL_OUT_CONTENT_LEN=<n>` and
  `-DWTLS_SSL_IN_CONTENT_LEN=<n>` (512..16384) shrink them. A smaller **send**
  buffer is always safe (the library just writes smaller records; the handshake
  needs about 2 KiB or more with long certificate chains): `4096` saves 12 KiB per
  connection. A smaller **receive** buffer works only if the server honours the
  `record_size_limit` (TLS 1.3, RFC 8449) or `max_fragment_length` (TLS 1.2, sizes
  512-4096) extension the client then sends; otherwise connections to that
  server fail with large records. Many servers (including OpenSSL-based ones)
  ignore them, so test your targets before shipping a small receive buffer.

## 12. Versioning and compatibility

libwiitls follows [Semantic Versioning](https://semver.org/) from 1.0.0 on:
within 1.x, existing functions, error codes and struct fields keep their
meaning, and new struct fields are only appended.

- `WTLS_VERSION_MAJOR`, `WTLS_VERSION_MINOR`, `WTLS_VERSION_PATCH` and
  `WTLS_VERSION` describe the headers you compiled against; `wtls_version()`
  returns the version of the library you linked.
- **Always zero-initialise option and request structs** (`wtls_options opt =
  {0};`, `wtls_http_request req = {0};`). A new field's zero value always
  keeps the previous behaviour, so zero-initialised code keeps working when
  you upgrade.
- Static archives are not ABI-stable across versions: rebuild your app
  against the headers of the archives you link.
