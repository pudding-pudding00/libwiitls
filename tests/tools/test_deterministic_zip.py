#!/usr/bin/env python3
"""tools/deterministic_zip.sh: same bytes whatever the file times, a different archive when content changes."""
import hashlib
import os
import shutil
import subprocess
import sys
import tempfile
import time

ROOT = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
TOOL = os.path.join(ROOT, "tools", "deterministic_zip.sh")


def pack(src, out):
    env = dict(os.environ, SOURCE_DATE_EPOCH="1790000000")
    subprocess.run(["bash", TOOL, src, out], check=True, env=env, capture_output=True)
    with open(out, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


def main():
    if shutil.which("zip") is None:
        print("zip not installed: skipped")
        return
    with tempfile.TemporaryDirectory() as d:
        src = os.path.join(d, "pkg")
        os.makedirs(os.path.join(src, "sub"))
        for name, data in (("b.txt", "bee"), ("a.txt", "ay"), ("sub/c.txt", "see")):
            with open(os.path.join(src, name), "w") as f:
                f.write(data)
        h1 = pack(src, os.path.join(d, "1.zip"))
        time.sleep(2)
        for root, _, files in os.walk(src):  # new mtimes
            for n in files:
                os.utime(os.path.join(root, n), None)
        h2 = pack(src, os.path.join(d, "2.zip"))
        assert h1 == h2, "zip depends on file times"
        with open(os.path.join(src, "a.txt"), "w") as f:
            f.write("changed")
        assert pack(src, os.path.join(d, "3.zip")) != h1, "content change not reflected"
    print("deterministic_zip tests passed")


if __name__ == "__main__":
    main()
