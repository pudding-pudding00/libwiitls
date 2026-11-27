# libwiitls in Dolphin

**Short version:** in Dolphin, libwiitls refuses to start: `wtls_init()` and
`wtls_init_step()` return `WTLS_ERR_ENTROPY`. The emulator's timing carries
no entropy, so any key generated there would be predictable. Up to 1.0.1 the
library did not notice this and ran with a predictable random generator.

## Why

On a real Wii the random generator is seeded from the PPC timebase measured
across an IOS round trip (`wtls_plat_jitter_sample()`). The Starlet runs
asynchronously (Wi-Fi and timer interrupts, the IOS scheduler), which gives
≥ 4.6 bits of min-entropy per sample under the worst estimator of
`tools/jitter_assess.py` (`docs/ios-socket-behaviour.md`). The library
credits 1 bit.

Dolphin emulates IOS in HLE and advances the timebase by a fixed amount per
emulated IPC call. The low byte of the delta therefore **alternates between
two values**. That sequence passes both SP 800-90B health tests: the RCT sees
no repeat, and the APT sees about 256 of 512 against a cutoff of 410. It still
carries nothing, because each sample predicts the next.

## Measurements

`tools/hwtest.py --dolphin <Dolphin.exe> --suite jitterdump`, then
`tools/jitter_assess.py` on the log. The `b` variant is the library's
sampler; `i` is a round trip through the network stack (`net_gethostip()`)
for comparison.

| Dolphin | CPU core | variant | samples | top values | MCV H | MIN H (worst estimator) |
|---|---|---|---|---|---|---|
| 2609b | JIT (default) | b | 200 000 | 23: 0.500, 24: 0.500 (11 distinct) | 0.992 | **0.000** (order-1 context) |
| 2609b | JIT (default) | i | 50 000 | 65: 0.542, 64: 0.458 | 0.870 | **0.005** (lag d=24) |
| 2609b | JIT, Sync GPU on | b | 200 000 | 23: 0.500, 24: 0.500 | – | **0.000** |
| 2609b | JIT, Sync GPU on | i | 50 000 | 65: 0.542, 64: 0.458 | – | **0.005** |
| 2609b | interpreter (`Core.CPUCore=0`) | b | 200 000 | 23: 0.749, 22: 0.250 (12 distinct) | – | **0.002** |
| 2609b | interpreter (`Core.CPUCore=0`) | i | 50 000 | 64: 0.792, 63: 0.208 | – | **0.000** |

After the fix (same Dolphin, JIT), the `entropy` suite shows the refusal: 2
pass, 2 skip. With `WTLS_DOLPHIN_DEV_ENTROPY=ON` the `tls` suite passes 49/0/5,
with the same skips as on the Wii. The same DOL on a real Wii still reports
`emulator: no` and 4/4.

Only one Dolphin version has been measured so far. The plan asks for two;
the second is still open.

For comparison, a real Wii (IOS 58) gives ≥ 4.6 bits per sample for `b`.

`entropy` suite in Dolphin 2609b (JIT), before the fix: `psa_crypto_init`
369 ms, 64 KiB of raw samples in 4.7 s, RCT max 3/21, **APT max 284/410**
(Wii: 19 to 32/410). The health tests pass, and `wtls_init()` returned
`WTLS_OK`.

## Decision (WP6, case C → fail closed)

The plan foresaw three cases: A (enough entropy), B (the health tests fail),
and C (they pass, but the entropy is lower than credited). Dolphin is
case C, at the extreme: the measured entropy is ~0, so no reduction factor of
the credit helps. The library therefore refuses the jitter source whenever it
detects the emulator (`IOS_Open("/dev/dolphin")` succeeds), as in case B:

- `wtls_init()` and `wtls_init_step()` return `WTLS_ERR_ENTROPY`, and
  `psa_crypto_init()` returns `PSA_ERROR_INSUFFICIENT_ENTROPY`.
- Host test `entropy_refused_in_emulator` (`tests/host/test_init_step.c`,
  test hook `wtls_plat_test_emulated`). The Wii `entropy` suite checks the
  refusal in Dolphin.
- Real consoles are unaffected: `/dev/dolphin` does not exist there.

## Testing in Dolphin anyway

For development only, build with `-DWTLS_DOLPHIN_DEV_ENTROPY=ON`. The library
then uses Dolphin's jitter and logs a warning (`WTLS_LOG_WARN`, category
platform). Keys are predictable in that mode; never ship it. Release builds
are checked by the link test `dolphin_dev_entropy_not_in_release`. The output
still differs between runs because the non-credited auxiliary input (timebase,
RTC) is mixed in, but that is no security.

Deviation from the plan: the option mixes in no host time from
`/dev/dolphin`. That would add no credited entropy either, and the auxiliary
input already makes runs differ.

## Running the hardware suites in Dolphin

```
python tools/hwtest.py --dolphin <path>/Dolphin.exe --dol build-wii/tests/hw/wtls_hwtest.dol --suite entropy
python tools/hwtest.py --dolphin ... --suite jitterdump > dump.log; python tools/jitter_assess.py dump.log
python tools/hwtest.py --dolphin ... --dol build-wii-devent/tests/hw/wtls_hwtest.dol --suite tls
python tools/hwtest.py --dolphin ... --dolphin-config Core.CPUCore=0      # interpreter
```

Dolphin boots the DOL without the `meta.xml` arguments. When the runner sees
no `logip=` in Dolphin, it connects to `127.0.0.1:4405` (Dolphin's sockets are
host sockets) and reads its arguments from the first line `hwtest.py` sends
(`ARGS ...`). Keep the default `--logport` for Dolphin runs.
