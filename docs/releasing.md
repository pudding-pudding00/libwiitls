# Releasing libwiitls

The checklist for maintainers is in [CONTRIBUTING.md](../CONTRIBUTING.md#releasing-maintainers);
this page explains what the release machinery does so that it does not depend on one person's memory.

## Steps

1. **Version:** `project(libwiitls VERSION x.y.z)` in `CMakeLists.txt` and `WTLS_VERSION*` in
   `include/wiitls/wiitls.h` (the configure step compares them).
2. **Changelog:** move `[Unreleased]` to `[x.y.z] - <date>`, update the compare links.
3. **Dependencies:** `maintenance.yml` opens pull requests for new Mbed TLS / zlib / CA bundle releases
   (`tools/update_dep.py`). A new Mbed TLS LTS release needs the patch check in
   [mbedtls-patches.md](mbedtls-patches.md) and a hardware run. A CA bundle bump regenerates
   `src/gen/ca_bundle.c` and `data/cacert.pem.sha256` with `tools/gen_ca_bundle.py`.
4. **Hardware:** `tools/hwtest.py --suite all` and the benchmark on a Wii (see
   [CONTRIBUTING.md](../CONTRIBUTING.md#hardware-reports)), results into the release notes.
5. **Tag** `vx.y.z` on main and push it. `release.yml` first runs `tools/release_gate.sh`: the commit must be on
   main, and the CI that its push to main started must have passed (the gate waits up to 90 minutes for it). It
   then runs CI again, builds the package with `tools/make_release.sh` (devkitPro container), and publishes the
   GitHub release only if every job passed.

## What the release contains

- `libwiitls-<v>-wii.zip`: headers, libraries, CMake package, examples, licenses.
- `libwiitls-<v>-wii.sbom.spdx.json`: an SPDX 2.3 SBOM from `tools/gen_sbom.py` (Mbed TLS, zlib and the
  CA bundle with their hashes, read from `CMakeLists.txt` and `data/cacert.pem.sha256`).
- `SHA256SUMS` for both.
- A GitHub **build provenance attestation** for the zip and the SBOM. Verify a download with
  `gh attestation verify libwiitls-<v>-wii.zip --repo pudding-pudding00/libwiitls`.

## Reproducible builds

`-DWTLS_REPRODUCIBLE=ON` (used by `make_release.sh`) maps source and build paths out of the objects and
writes archives without timestamps; the build time comes from `SOURCE_DATE_EPOCH` (the release script
uses the commit time). The `reproducible` CI job builds the host libraries twice in different directories
and compares the archives byte for byte. The release zip is made by `tools/deterministic_zip.sh`
(sorted entries, fixed times). To check a release yourself, rebuild the tag with the same devkitPro
container image and compare `sha256sum` of the libraries inside the zip; two builds with the same
toolchain are expected to match, builds with different compiler versions are not.

The Wii (`powerpc-eabi`) build itself is only exercised by the release job; whether it is byte-identical
across machines has not been measured, so the claim above is verified for the host toolchain only.
