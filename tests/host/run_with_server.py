#!/usr/bin/env python3
"""CTest wrapper: start tls_test_server.py, run the test, stop the server.

  python run_with_server.py <test-exe> [args...]

Exit code is the test's exit code (1 if the server does not start).
"""
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))


def main():
    if len(sys.argv) < 2:
        sys.exit("usage: run_with_server.py <test-exe> [args...]")
    server = subprocess.Popen([sys.executable, os.path.join(HERE, "tls_test_server.py")],
                              stdout=subprocess.PIPE, text=True)
    try:
        line = server.stdout.readline().strip()
        if line != "READY":
            print(f"run_with_server: server did not start ({line!r})", flush=True)
            return 1
        return subprocess.call(sys.argv[1:])
    finally:
        server.terminate()
        try:
            server.wait(timeout=5)
        except subprocess.TimeoutExpired:
            server.kill()


if __name__ == "__main__":
    sys.exit(main())
