# Configure-time patches to Mbed TLS / TF-PSA-Crypto

libwiitls builds Mbed TLS 4.1.x LTS from source and edits four spots in the
fetched sources at configure time (`CMakeLists.txt`). Every edit is
idempotent (a marker comment stops a second application) and **fails the
configure step** if its anchor text is not found, so an LTS bump can never
silently build an unpatched library. This page lists what each one does and
what it takes to drop it. Each LTS bump must re-check the anchors and re-run
`tests/common/crypto_tests.c` (host and Wii).

| # | File patched | What | Why | Test that pins it | Can go when |
|---|---|---|---|---|---|
| 1 | `drivers/everest/include/.../kremlin/c_endianness.h` | In the generic big-endian branch, `htole64` uses `htole32` for both halves instead of `htobe32` | Everest's generic `htole64` is wrong on big-endian CPUs: X25519 returned wrong shared secrets on the Wii | RFC 7748 vectors in `crypto_tests.c` (`test_x25519_rfc7748_*`), run on the Wii | Upstream release with the fix |
| 2 | `drivers/builtin/src/psa_crypto_ecp.c`, `mbedtls_psa_ecp_export_public_key` | X25519 public key export goes through Everest (`mbedtls_x25519_scalarmult` with base point 9) | The generic ECP code costs more than keygen and agreement together on the Wii (`docs/benchmarks.md`) | `test_x25519_rfc7748_alice/bob` | Upstream routes Montgomery export through the Everest driver, or a PSA driver interface (see below) |
| 3 | `drivers/everest/library/x25519.c`, `mbedtls_x25519_scalarmult` | With `WTLS_ACCEL_X25519` the single Everest entry point calls `wtls_x25519()` (`src/accel/x25519_fe32.c`) instead of HACL* | HACL*'s 51-bit limbs need emulated 128-bit products on PPC32 | `test_x25519_fast_*`, Wycheproof X25519, `fuzz_x25519_diff` | A PSA accelerator driver can host the code |
| 4 | `drivers/builtin/src/psa_crypto_ecp.c`, `mbedtls_psa_ecdsa_verify_hash` | With `WTLS_ACCEL_P256` the function first tries `wtls_p256_verify()` (`src/accel/p256_verify.c`) for uncompressed P-256 keys and raw 64-byte signatures; everything else falls through to the builtin code | The builtin verify is slow on the Broadway CPU | `test_p256_*`, Wycheproof ECDSA P-256, `fuzz_p256_verify_diff` | A PSA accelerator driver can host the code |

Patches 1-2 are workarounds for upstream behaviour; 3-4 are hooks for the
hand-written accelerators. The accelerators are the only custom cryptography in
the library, and the roadmap lists no further ones.

## Getting rid of them

- **1 (endianness):** report upstream with a minimal reproducer: Everest's
  `Hacl_Curve25519_crypto_scalarmult` on a big-endian target (QEMU
  `qemu-ppc-static` is enough, no Wii needed). Remove the patch once an LTS
  release contains the fix; keep the RFC 7748 vectors as the guard.
- **2 (public key export):** report as a performance issue. If TF-PSA-Crypto
  gets a driver entry for key-pair public export, move this into patch 3's
  driver.
- **3 and 4 (accelerators):** the clean solution is a PSA *accelerator driver*:
  TF-PSA-Crypto's driver interface lets an application provide
  `PSA_ALG_ECDH` (Montgomery 255) and `PSA_ALG_ECDSA` verify implementations
  via `psa_crypto_driver_wrappers` without touching library sources. Whether
  the 4.1 LTS exposes enough entry points for these two operations (public-key
  export, key agreement, verify of an uncompressed key) has to be checked
  against the driver-wrapper headers of the LTS in use; this was not done for
  1.1.0. When it works, the accelerator files move unchanged behind a driver
  table, patches 2-4 disappear, and `tools/check_ct.cmake` keeps guarding the
  constant-time property of the X25519 code.

## When an anchor no longer matches

The configure step stops with `unexpected layout of <file>`. Do not loosen the
anchor blindly: read the new function, re-apply the intent of the patch by
hand, re-run the vectors above (including the big-endian run on the Wii), and
only then update the anchor.
