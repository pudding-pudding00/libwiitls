#!/usr/bin/env python3
"""Run a libwiitls hardware test suite on a real Wii or in Dolphin.

Starts a TCP log listener and tests/host/tls_test_server.py (bound to 0.0.0.0),
sends the DOL with wiiload (or boots it in Dolphin, arguments via meta.xml)
and prints the log. Exit code 0 only if the runner reports
"WTLS-HWTEST DONE pass=P fail=0".

  python tools/hwtest.py --wii <wii-ip> --dol build-wii/tests/hw/wtls_hwtest.dol --suite selftest
  python tools/hwtest.py --dolphin <path>/Dolphin.exe --dol ... --suite entropy \
      [--dolphin-config Core.CPUCore=0 ...]
"""
import argparse
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from xml.sax.saxutils import escape

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DONE_RE = re.compile(r"WTLS-HWTEST DONE pass=(\d+) fail=(\d+)")


def local_ip_towards(ip):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect((ip, 9))
        return s.getsockname()[0]
    finally:
        s.close()


def find_wiiload():
    candidates = []
    for base in (os.environ.get("DEVKITPRO"), "C:/devkitPro", "/opt/devkitpro"):
        if base:
            candidates += [os.path.join(base, "tools", "bin", n) for n in ("wiiload.exe", "wiiload")]
    for c in candidates:
        if os.path.isfile(c):
            return c
    found = shutil.which("wiiload")
    if found:
        return found
    sys.exit("wiiload not found (install devkitPro tools)")


def start_dolphin(dolphin, dol, runner_args, config, work):
    """Boots dol in Dolphin. The meta.xml carries runner_args as the Homebrew
    Channel would; Dolphin builds that ignore it boot without arguments, and
    the runner then fetches them over the log connection (see main())."""
    app = os.path.join(work, "wtls_hwtest")
    os.makedirs(app)
    shutil.copy(dol, os.path.join(app, "boot.dol"))
    args_xml = "".join(f"<arg>{escape(a)}</arg>" for a in runner_args)
    with open(os.path.join(app, "meta.xml"), "w", encoding="utf-8") as f:
        f.write('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
                f"<app version=\"1\"><name>wtls_hwtest</name><arguments>{args_xml}</arguments></app>\n")
    cmd = [dolphin, "-b"]
    for c in config:
        cmd += ["-C", c if c.split("=", 1)[0].count(".") >= 2 else "Dolphin." + c]
    cmd += ["-e", os.path.join(app, "boot.dol")]
    print("hwtest: " + " ".join(cmd), file=sys.stderr)
    return subprocess.Popen(cmd)


def main():
    ap = argparse.ArgumentParser()
    target = ap.add_mutually_exclusive_group(required=True)
    target.add_argument("--wii", help="IP address of the Wii (Homebrew Channel running)")
    target.add_argument("--dolphin", help="path to Dolphin.exe / dolphin-emu: run in the emulator instead")
    ap.add_argument("--dolphin-config", nargs="*", default=[],
                    help="Dolphin config overrides, e.g. Core.CPUCore=0 (interpreter) Core.SyncGPU=True")
    ap.add_argument("--dol", required=True)
    ap.add_argument("--suite", required=True)
    ap.add_argument("--timeout", type=int, default=120)
    ap.add_argument("--logport", type=int, default=4405)
    ap.add_argument("--extra", nargs="*", default=[], help="extra key=value runner args")
    args = ap.parse_args()

    # Dolphin's emulated sockets are host sockets: the PC is reachable as itself.
    my_ip = local_ip_towards(args.wii) if args.wii else local_ip_towards("192.0.2.1")
    ls = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    ls.bind(("0.0.0.0", args.logport))
    ls.listen(1)
    # Dolphin needs a while to boot (and much longer with the interpreter).
    ls.settimeout(args.timeout if args.wii else max(args.timeout, 300))

    # Test PKI whose leaf certificates also carry this PC's IP as iPAddress SAN.
    work = tempfile.mkdtemp(prefix="wtls-hw-")
    cert_dir = os.path.join(work, "certs")
    subprocess.run([sys.executable, os.path.join(ROOT, "tests", "host", "make_certs.py"),
                    "--out", cert_dir, "--extra-ip", my_ip], check=True)
    server = subprocess.Popen(
        [sys.executable, os.path.join(ROOT, "tests", "host", "tls_test_server.py"), "--bind", "0.0.0.0",
         "--certs", cert_dir],
        stdout=subprocess.PIPE, text=True)
    emu = None
    try:
        if server.stdout.readline().strip() != "READY":
            sys.exit("test server failed to start")
        runner_args = [f"logip={my_ip}", f"logport={args.logport}", f"suite={args.suite}",
                       f"server={my_ip}", f"pctime={int(time.time())}"] + args.extra
        if args.wii:
            env = dict(os.environ, WIILOAD=f"tcp:{args.wii}")
            subprocess.run([find_wiiload(), args.dol] + runner_args, env=env, check=True)
        else:
            emu = start_dolphin(args.dolphin, args.dol, runner_args, args.dolphin_config, work)

        conn, _ = ls.accept()
        conn.settimeout(args.timeout)
        if emu:
            # Dolphin boots the DOL without arguments: the runner then connects to
            # 127.0.0.1:4405 and reads them from this first line (tests/hw/main.c).
            conn.sendall(("ARGS " + " ".join(runner_args) + "\n").encode())
        deadline = time.time() + args.timeout
        log = b""
        result = None
        while time.time() < deadline:
            try:
                data = conn.recv(4096)
            except socket.timeout:
                break
            if not data:
                break
            # --timeout is how long the runner may stay silent, not the whole
            # run: --suite all takes longer than the default 120 s.
            deadline = time.time() + args.timeout
            sys.stdout.write(data.decode("utf-8", "replace"))
            sys.stdout.flush()
            log += data
            result = DONE_RE.search(log.decode("utf-8", "replace"))
            if result:
                break
        conn.close()
        if not result:
            print("\nhwtest: no DONE line (timeout or crash)", file=sys.stderr)
            return 2
        return 0 if int(result.group(2)) == 0 else 1
    finally:
        if emu:
            emu.terminate()
            try:
                emu.wait(10)
            except subprocess.TimeoutExpired:
                emu.kill()
        server.terminate()
        ls.close()
        shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
