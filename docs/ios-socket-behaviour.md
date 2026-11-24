# IOS socket and timebase behaviour

Measured on a real Wii (2026-11-24) with the `spike` and `jitterdump` suites of
the hardware test runner:

```sh
python tools/hwtest.py --wii <wii-ip> --dol build-wii/tests/hw/wtls_hwtest.dol --suite spike
python tools/hwtest.py --wii <wii-ip> --dol build-wii/tests/hw/wtls_hwtest.dol --suite jitterdump --timeout 300 > jd.log
python tools/jitter_assess.py jd.log
```

## Raw log (spike)

```
[1] non-blocking connect
    net_socket(SOCK_NONBLOCK) = 0
    net_connect = -119 after 1787 us
    net_poll(POLLOUT, 2000) = 1 revents=0x8 after 2002324 us
    second net_connect = -127
    echo poll=1 recv=6 'ok'
[2] TCP_NODELAY
    connect fd=0 setsockopt(TCP_NODELAY) = -109
[3] net_poll 100 ms on idle socket
    min=100277 median=100292 max=100421 us
[4] IPC roundtrip (net_poll timeout 0) x1000
    mean=135 us
[5] net_recv(65536) on a 64 KiB stream
    total=65536 calls=28 max_per_call=26116 time=423376 us (151 KiB/s)
[6] clock
    time(NULL)=1795548929 pctime=1795545327 diff=3602 s
[7] timebase jitter, 100000 samples per variant
    variant a: H_mcv=0.577 bits/sample, distinct low bytes=5
    variant b: H_mcv=0.879 bits/sample, distinct low bytes=7
    variant c: H_mcv=1.083 bits/sample, distinct low bytes=256
```

## Decisions

| Question | Measured | Decision |
|---|---|---|
| Non-blocking `net_connect` returns EINPROGRESS and `net_poll(POLLOUT)` signals completion? | partly. `-119` first. `net_poll` wakes at once on a refusal (RST), but **not** when the connect completes: POLLOUT shows up only when the poll times out, so a 5 s timeout meant a 5 s connect. A second `net_connect` returns `-120` (EALREADY) while the connect is running, `-127`/0 once connected, and `-119` again after a refusal, which is a new attempt | poll in 5 ms slices, each followed by a second `net_connect`: EALREADY = keep waiting, connected = done, anything else = fail. Connect now takes 8 ms, a refusal 6 ms (`plat` suite) |
| IOS error numbers | libogc returns **negated newlib errno values**: EINPROGRESS = 119, EISCONN = 127 (measured); EAGAIN = 11, EALREADY = 120 (same numbering) | `WTLS_IOS_*` in `src/plat/plat.h` |
| `TCP_NODELAY` accepted? | no: `-109` (ENOPROTOOPT) | not set on the Wii (saves one IPC per connection) |
| `net_sendto` address length | only 8 (IOS's own IPv4 sockaddr) works; `sizeof(struct sockaddr_in)` = 16 returns `-22` (EINVAL) | pass 8 in `wtls_plat_udp_exchange` |
| UDP loss (SNTP) | one of several syncs timed out over Wi-Fi | `wtls_sntp_query`: 3 attempts sharing the timeout |
| `net_poll` 100 ms timeout accuracy | min 100.28 / median 100.29 / max 100.42 ms | timeouts can rely on `net_poll` |
| IPC round trip (`net_poll`, timeout 0) | 135 µs | — |
| Max bytes per `net_recv(65536)` | 26116 | `WTLS_PLAT_MAX_CHUNK = 16384` stays |
| `time(NULL)` − PC time | +3602 s: the RTC holds **local time** (CET here), not UTC | SNTP sync where exact time matters; one hour does not break certificate checks |
| Jitter sampler and credited entropy | see below | **IOS IPC round trip** per sample, `WTLS_JITTER_BITS_PER_SAMPLE = 1` |

## Entropy source

The spike's MCV estimate alone (variants a–c above) overstates CPU-only timing.
`tools/jitter_assess.py` adds lag and order-k context predictors (best predictor
in hindsight, so more conservative than SP 800-90B's online predictors) and the
t-tuple estimate. Results on 100 000–300 000 samples per variant (min-entropy of
the timebase delta's low byte, bits/sample, worst estimator):

| Sampler | MCV | worst estimator | cost/sample |
|---|---:|---:|---:|
| stride walk over 256 KiB (the original variant b) | 0.94 | **0.22** (order-6 context) | 32 ns |
| stride walk over 4 MiB MEM2 | 0.15 | 0.09 | 85 ns |
| pointer chase over 8 MiB, 4 loads | 0.31 | 0.22 | 0.9 µs |
| IPC: `net_gethostip()` | 6.7 | 5.4 | 78 µs |
| **IPC: `IOS_Open` of a nonexistent path** (library) | 5.2–5.4 | 3.0–4.7 | 79 µs |

CPU-only timing on Broadway is close to deterministic: the walk fits the 256 KiB
L2, the deltas are 1–2 timebase ticks, and higher-order predictors keep
finding structure. Crediting 1 bit/sample for it would have seeded the DRBG
with roughly a quarter of the claimed entropy.

A round trip into IOS crosses to the Starlet, whose timing depends on
asynchronous events (Wi-Fi and timer interrupts, the IOS scheduler). The library
therefore samples the timebase across `IOS_Open("/dev/wtls/none")` (no side
effects, works before `net_init`). Its worst estimate, 3.0 bits/sample, comes
from an order-2 predictor with ~25 samples per context (biased low by
overfitting); order-1 gives 4.2. Crediting 1 bit/sample keeps a margin above 3x,
and the RCT/APT cutoffs in `src/wtls_jitter.h` are sized for that credit.

Cost on the Wii: `psa_crypto_init()` (inside `wtls_init`) takes about 400 ms,
once per process; 64 KiB of health-tested raw samples take 5.1 s.
