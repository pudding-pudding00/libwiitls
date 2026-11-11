#!/usr/bin/env python3
"""Test server for libwiitls host and hardware tests (stdlib only).

Port 4430: plain-text line protocol.
Commands (one per line):
  SILENT   stop answering; keep the connection open
  BYE      close the connection (clean TCP FIN)
  BIG n    send n pattern bytes: byte i = i % 251
  other    echoed back unchanged (including the newline)

Prints "READY" on stdout once every listener is bound.
"""
import argparse
import socket
import sys
import threading

PLAIN_PORT = 4430


def pattern(n, offset=0):
    return bytes((offset + i) % 251 for i in range(n))


def send_big(write, n):
    chunk = 16384
    sent = 0
    while sent < n:
        k = min(chunk, n - sent)
        write(pattern(k, sent))
        sent += k


class LineConn:
    """Line-oriented wrapper around a socket-like object (plain or TLS)."""

    def __init__(self, sock):
        self.sock = sock
        self.buf = b""

    def readline(self):
        while b"\n" not in self.buf:
            data = self.sock.recv(65536)
            if not data:
                return None
            self.buf += data
        line, self.buf = self.buf.split(b"\n", 1)
        return line + b"\n"


def handle_plain(sock):
    conn = LineConn(sock)
    try:
        while True:
            line = conn.readline()
            if line is None:
                return
            cmd = line.strip()
            if cmd == b"SILENT":
                while sock.recv(65536):
                    pass
                return
            if cmd == b"BYE":
                return
            if cmd.startswith(b"BIG "):
                send_big(sock.sendall, int(cmd[4:]))
                continue
            sock.sendall(line)
    except OSError:
        pass
    finally:
        try:
            sock.close()
        except OSError:
            pass


def serve(bind, port, handler):
    ls = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    ls.bind((bind, port))
    ls.listen(16)

    def loop():
        while True:
            try:
                s, _ = ls.accept()
            except OSError:
                return
            s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            threading.Thread(target=handler, args=(s,), daemon=True).start()

    threading.Thread(target=loop, daemon=True).start()
    return ls


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--bind", default="127.0.0.1")
    args = ap.parse_args()
    listeners = [serve(args.bind, PLAIN_PORT, handle_plain)]
    print("READY", flush=True)
    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        pass
    for ls in listeners:
        ls.close()


if __name__ == "__main__":
    sys.exit(main())
