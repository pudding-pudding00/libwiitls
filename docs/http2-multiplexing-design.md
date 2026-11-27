# Non-blocking HTTP/2 and stream multiplexing (WP3b, WP12)

## Decision

The blocking HTTP/2 engine (`src/http/wtls_http2.c`) stays as it is: one stream per connection, blocking
reads, fuzzed. The asynchronous API (`wtls_http_start`) gets its own engine, `src/http/wtls_h2s.c`: a
**session** over one TLS connection with a table of streams, driven by `h2s_pump()`, never waiting. The
two do not share connections: blocking requests use the keep-alive pool as before, asynchronous ones
use a small registry of live sessions. Sharing HPACK, framing constants and the request encoder keeps the
protocol code from forking.

Reason: turning the blocking engine into a multiplexer would touch every wait in it (`read_frame` is called
from seven places, each owning a loop) and risk the one path that is fuzzed and has run on hardware.

## Session

- Input: a frame assembler (9 byte header + up to 16384 payload bytes) fed by non-blocking reads; frames
  are processed as soon as they are complete, for any stream.
- Output: one queue of encoded frames, flushed with non-blocking writes. Control frames are always queued;
  DATA is accepted only while less than 64 KiB wait for the socket, which also bounds how much one upload
  can hog.
- Streams: odd ids from 1, at most `min(WTLS_H2_MAX_STREAMS, server SETTINGS_MAX_CONCURRENT_STREAMS)` open
  at once; a request that does not fit waits (`WTLS_WANT_READ`, the descriptor is the session's).
- Receive side: every stream has a buffer of `WTLS_H2_STREAM_WINDOW` bytes (default 32 KiB), which is also its
  advertised flow-control window. `WINDOW_UPDATE` goes out only for bytes the application has read
  (half a window at a time), so a stream nobody reads cannot grow without bound, and one stalled reader
  does not block the others (the connection window is credited by the same amounts and is sized for all
  streams together). Padding and data for cancelled streams are credited at once.
- Cancel: releasing an unfinished stream sends `RST_STREAM(CANCEL)` for that stream only; late frames for it
  are discarded (HEADERS are still HPACK-decoded: the table is shared by all streams).
- GOAWAY: no new streams; streams above `last_stream_id` fail with `WTLS_ERR_IO` flagged retryable, the
  request is repeated on a new connection if it is idempotent and nothing had been received.
  `REFUSED_STREAM` is retryable too. Streams up to `last_stream_id` finish normally.

## Registry

Live sessions are kept per (host, port, verification mode, client identity) like pooled connections; a
request takes a session that has a free stream slot, otherwise connects. While a first connection to a
host is still negotiating (ALPN unknown), further requests to it wait for the outcome instead of opening
parallel connections; if it turned out to be HTTP/1.1 they connect on their own. Idle sessions go away
after 60 s, `wtls_http_pool_flush()` closes the idle ones and retires the busy ones (closed with their last
stream).

## Memory

`WTLS_H2_MAX_STREAMS` (default 4) x `WTLS_H2_STREAM_WINDOW` (default 32 KiB) of receive buffers per
session, plus the TLS record buffers, a 16 KiB frame buffer and the output queue. Receive buffers are
allocated when the first data arrives.

## Tests

Unit tests drive the session with scripted server bytes (SETTINGS changes, GOAWAY, RST, padding,
CONTINUATION, trailers, flow control, cancelled streams); a concurrent test server
(`tests/host/tls_test_server.py`, ports 4449 and 4450) checks interleaving, fairness, cancel, the stream
limit and retry after GOAWAY end to end; a libFuzzer harness feeds the session arbitrary server bytes.
