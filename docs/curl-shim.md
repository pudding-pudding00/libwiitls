# The `wiitls::curl` compatibility shim

A small subset of libcurl's easy and multi interfaces on top of libwiitls, so
that code written against libcurl can run with few changes. Enable with
`-DWTLS_BUILD_CURL_SHIM=ON` and link `wiitls::curl`. Everything not listed here
returns `CURLE_UNKNOWN_OPTION` (setopt/getinfo). Tests: `tests/host/test_curl_shim.c`.

## Easy interface

| Function | Notes |
|---|---|
| `curl_global_init`, `curl_global_cleanup` | call `wtls_init()` / `wtls_shutdown()` |
| `curl_easy_init`, `_cleanup`, `_perform`, `_getinfo`, `_strerror`, `curl_slist_*` | |

### `curl_easy_setopt` options

`CURLOPT_URL`, `PROXY` (`http://` proxies), `USERAGENT`, `USERPWD` (HTTP Basic),
`HTTPHEADER`, `CUSTOMREQUEST`, `POST`, `POSTFIELDS`, `POSTFIELDSIZE`,
`POSTFIELDSIZE_LARGE`, `HTTPGET`, `NOBODY`, `UPLOAD` (PUT), `INFILESIZE`,
`INFILESIZE_LARGE`, `READFUNCTION` / `READDATA` (streamed request bodies: with a
known size as `Content-Length`, otherwise chunked), `WRITEFUNCTION` / `WRITEDATA`
(default: `fwrite` to the `FILE *` or stdout), `HEADERFUNCTION` / `HEADERDATA`
(called once per header line after the response head, lower-case names),
`NOPROGRESS` + `XFERINFOFUNCTION` / `XFERINFODATA` (called after every received
chunk and every uploaded chunk; non-zero aborts with
`CURLE_ABORTED_BY_CALLBACK`), `FOLLOWLOCATION`, `MAXREDIRS`, `FAILONERROR`,
`SSL_VERIFYPEER` (0 disables verification: tests only), `SSL_VERIFYHOST` (accepted,
ignored: the host name is always checked), `CONNECTTIMEOUT_MS`, `TIMEOUT_MS`
(applied as the I/O and header timeout, not as a total deadline), `ACCEPT_ENCODING`
(empty string turns decompression off).

### `curl_easy_getinfo`

`RESPONSE_CODE`, `EFFECTIVE_URL`, `CONTENT_TYPE`, `REDIRECT_COUNT`,
`SIZE_DOWNLOAD_T`. String results stay valid until the next perform or cleanup.

## Multi interface

`curl_multi_init`, `add_handle`, `remove_handle`, `perform`, `wait`,
`info_read`, `cleanup`, `strerror`. **It is sequential:** the first
`curl_multi_perform()` runs every added handle to completion, one after the
other (blocking), and reports `running_handles = 0`; `curl_multi_wait()` returns
immediately with `numfds = 0`; `curl_multi_info_read()` hands out one
`CURLMSG_DONE` per handle. Code that loops "perform until running == 0" works
unchanged; code that relies on concurrent transfers gets none of the speed-up.

## Not supported

cookies, `CURLOPT_COOKIE*`, `CURLOPT_HTTPAUTH` (other than `USERPWD` = Basic),
`CURLOPT_CAINFO`/`CAPATH` (use `wtls_add_trusted_ca()`), `CURLOPT_SSLCERT` (use
client credentials of the native API), FTP and other protocols, `curl_easy_duphandle`,
`curl_easy_reset`, `curl_multi_socket_action`, `curl_share_*`, timing infos.
