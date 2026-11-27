#!/usr/bin/env python3
"""The SBOM generator: parses the repository, is deterministic, names every dependency with its hash."""
import json
import os
import subprocess
import sys
import tempfile

ROOT = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
TOOL = os.path.join(ROOT, "tools", "gen_sbom.py")


def run(out, epoch):
    env = dict(os.environ, SOURCE_DATE_EPOCH=epoch)
    subprocess.run([sys.executable, "-I", TOOL, "--out", out], check=True, env=env, capture_output=True)
    with open(out, "rb") as f:
        return f.read()


def main():
    with tempfile.TemporaryDirectory() as d:
        a = run(os.path.join(d, "a.json"), "1790000000")
        b = run(os.path.join(d, "b.json"), "1790000000")
        assert a == b, "SBOM is not deterministic"
        c = run(os.path.join(d, "c.json"), "1790000001")
        assert a != c, "creation time must follow SOURCE_DATE_EPOCH"
        doc = json.loads(a)
    names = {p["name"]: p for p in doc["packages"]}
    assert set(names) == {"libwiitls", "mbedtls", "zlib", "mozilla-ca-bundle"}, names.keys()
    for n in ("mbedtls", "zlib", "mozilla-ca-bundle"):
        sums = names[n]["checksums"]
        assert len(sums) == 1 and len(sums[0]["checksumValue"]) == 64
    assert names["mbedtls"]["versionInfo"].startswith("4.1"), names["mbedtls"]["versionInfo"]
    assert names["zlib"]["versionInfo"] != "unknown"
    with open(os.path.join(ROOT, "CMakeLists.txt")) as f:
        assert ("VERSION " + names["libwiitls"]["versionInfo"]) in f.read()
    rel = {(r["relationshipType"], r["relatedSpdxElement"]) for r in doc["relationships"]}
    assert ("DEPENDS_ON", "SPDXRef-mbedtls") in rel and ("DEPENDS_ON", "SPDXRef-zlib") in rel
    print("gen_sbom tests passed")


if __name__ == "__main__":
    main()
