# IOS socket and timebase behaviour

Measured on real hardware with the `spike` suite of the hardware test runner:

```sh
python tools/hwtest.py --wii <wii-ip> --dol build-wii/tests/hw/wtls_hwtest.dol --suite spike
```

> **Status: pending hardware run.** The spike code exists (`tests/hw/spike_ios.c`),
> but it has not been run on a Wii yet. Until it has, the library uses the
> conservative defaults marked *provisional* below.

## Raw log

_(paste the `spike` output here)_

## Decisions

| Question | Measured | Decision |
|---|---|---|
| Non-blocking `net_connect` (`SOCK_NONBLOCK` / `F_SETFL`) returns EINPROGRESS and `net_poll(POLLOUT)` signals completion? | pending | *provisional:* try non-blocking; if IOS rejects it, connect blocking (timeout best effort) |
| `TCP_NODELAY` accepted? | pending | *provisional:* set it, ignore failure |
| `net_poll` 100 ms timeout accuracy (min/median/max) | pending | — |
| IPC round trip (`net_poll`, timeout 0) | pending | — |
| Max bytes per `net_recv(65536)` | pending | `WTLS_PLAT_MAX_CHUNK = 16384` (global constraint) |
| `time(NULL)` − PC time | pending | — |
| Jitter variant (a / b / c) and MCV min-entropy `H` of the low byte | pending | *provisional:* variant (b), `WTLS_JITTER_BITS_PER_SAMPLE = 1` |

`WTLS_JITTER_BITS_PER_SAMPLE` = floor(H/2), minimum 1. If `H < 2` for every
variant, the timebase is unusable as an entropy source and the design must be
revisited.

The spike computes the MCV estimate with the SP 800-90B upper confidence bound
(`p_u = p + 2.576·sqrt(p(1−p)/(n−1))`), which is slightly more conservative than
the plain `-log2(p_max)`.
