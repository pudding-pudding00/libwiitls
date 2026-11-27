#!/usr/bin/env python3
"""Tests for tools/update_dep.py, run against copies of the real project files."""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
SCRIPT = os.path.join(ROOT, "tools", "update_dep.py")
SHA = "ab" * 32
# Newer than anything the project pins, inside each dependency's allowed range.
NEWER = {"mbedtls": "4.1.999", "zlib": "999.0"}


def releases(*tags, **flags):
    return [{"tag_name": t, "draft": False, "prerelease": False, **flags} for t in tags]


class UpdateDepTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp)
        for name in ("CMakeLists.txt", "README.md"):
            shutil.copy(os.path.join(ROOT, name), self.tmp)

    def run_tool(self, *args, stdin=None):
        return subprocess.run(
            [sys.executable, SCRIPT, "--root", self.tmp, *args],
            input=stdin, capture_output=True, text=True)

    def ok(self, *args, stdin=None):
        r = self.run_tool(*args, stdin=stdin)
        self.assertEqual(r.returncode, 0, r.stderr)
        return r.stdout.strip()

    def read(self, name):
        with open(os.path.join(self.tmp, name), "rb") as f:
            return f.read()

    def changed_lines(self, name, before):
        old, new = before.split(b"\n"), self.read(name).split(b"\n")
        self.assertEqual(len(old), len(new))
        return [n.decode() for o, n in zip(old, new) if o != n]

    def test_url_for_pinned_version_is_the_one_in_cmakelists(self):
        for dep in NEWER:
            url = self.ok("url", dep, self.ok("current", dep))
            self.assertIn(url.encode(), self.read("CMakeLists.txt"), dep)

    def test_check_prints_highest_stable_release(self):
        data = (releases("v999.1", "v999.3", "v999.2")
                + releases("v999.9", prerelease=True)
                + releases("v999.8", draft=True))
        self.assertEqual(self.ok("check", "zlib", stdin=json.dumps(data)), "999.3")

    def test_check_stays_on_mbedtls_4_1_branch(self):
        data = releases("mbedtls-5.0.0", "mbedtls-4.2.0", "mbedtls-4.1.999",
                        "v4.1.998", "mbedtls-3.6.9", "mbedtls-4.1.1000-rc1")
        self.assertEqual(self.ok("check", "mbedtls", stdin=json.dumps(data)), "4.1.999")

    def test_check_prints_nothing_when_up_to_date_or_older(self):
        for dep in NEWER:
            current = self.ok("current", dep)
            data = releases("v" + current, "v0.1")
            self.assertEqual(self.ok("check", dep, stdin=json.dumps(data)), "", dep)

    def test_check_fails_on_api_error_object(self):
        r = self.run_tool("check", "zlib", stdin='{"message": "API rate limit exceeded"}')
        self.assertEqual(r.returncode, 1, r.stderr)

    def test_apply_mbedtls_changes_comment_url_and_hash_only(self):
        before = self.read("CMakeLists.txt")
        readme = self.read("README.md")
        self.ok("apply", "mbedtls", "4.1.999", "--sha256", SHA)
        lines = self.changed_lines("CMakeLists.txt", before)
        self.assertEqual(len(lines), 3, lines)
        self.assertIn("# Mbed TLS 4.1.999 LTS", lines[0])
        self.assertIn("mbedtls-4.1.999/mbedtls-4.1.999.tar.bz2", lines[1])
        self.assertIn("URL_HASH SHA256=" + SHA, lines[2])
        self.assertEqual(self.read("README.md"), readme)
        self.assertEqual(self.ok("current", "mbedtls"), "4.1.999")

    def test_apply_zlib_changes_url_hash_and_readme_only(self):
        before = self.read("CMakeLists.txt")
        readme = self.read("README.md")
        self.ok("apply", "zlib", "999.0", "--sha256", SHA)
        lines = self.changed_lines("CMakeLists.txt", before)
        self.assertEqual(len(lines), 2, lines)
        self.assertIn("v999.0/zlib-999.0.tar.gz", lines[0])
        self.assertIn("URL_HASH SHA256=" + SHA, lines[1])
        lines = self.changed_lines("README.md", readme)
        self.assertEqual(len(lines), 1, lines)
        self.assertIn("[zlib](https://zlib.net/) 999.0 inflate", lines[0])

    def assert_rejected(self, *args):
        before = self.read("CMakeLists.txt"), self.read("README.md")
        r = self.run_tool(*args)
        self.assertEqual(r.returncode, 1, r.stderr)  # 1: refused by the tool itself
        self.assertEqual((self.read("CMakeLists.txt"), self.read("README.md")), before)
        return r.stderr

    def test_apply_rejects_unsafe_input(self):
        self.assert_rejected("apply", "zlib", "999.0;id", "--sha256", SHA)
        self.assert_rejected("apply", "zlib", "999.0\n", "--sha256", SHA)
        self.assert_rejected("apply", "zlib", "999.0", "--sha256", "abc123")
        self.assert_rejected("apply", "mbedtls", "4.2.0", "--sha256", SHA)

    def test_apply_rejects_downgrade_and_same_version(self):
        for dep in NEWER:
            self.assert_rejected("apply", dep, self.ok("current", dep), "--sha256", SHA)
        self.assert_rejected("apply", "zlib", "0.1", "--sha256", SHA)

    def test_apply_writes_nothing_when_a_file_lost_its_anchor(self):
        path = os.path.join(self.tmp, "README.md")
        with open(path, "wb") as f:
            f.write(b"# no version here\n")
        err = self.assert_rejected("apply", "zlib", "999.0", "--sha256", SHA)
        self.assertIn("README.md", err)


if __name__ == "__main__":
    unittest.main()
