#!/usr/bin/env python3
"""Test server for libwiitls host and hardware tests (stdlib only).

Port 4430: plain-text line protocol.
Commands (one per line):
  SILENT   stop answering; keep the connection open
  BYE      close the connection (clean TCP FIN)
  BIG n    send n pattern bytes: byte i = i % 251
  CA       "<len>
" followed by the test CA in DER (needs --certs)
  other    echoed back unchanged (including the newline)

TLS ports (only with --certs DIR, the output of make_certs.py; default: the
WTLS_TEST_CERT_DIR environment variable):
  4431 TLS 1.3 only, ECDSA leaf, ALPN http/1.1, session tickets
  4432 TLS 1.3 only, RSA leaf
  4433 TLS 1.2 only, ECDHE-ECDSA-CHACHA20-POLY1305
  4434 expired certificate        4435 untrusted CA
  4436 certificate for other.test
  4437 certificate without the serverAuth extended key usage
TLS commands: PING, SNI (received SNI or "-"), BIG n (byte i = i & 0xFF),
CLOSE (close_notify), TRUNC (TCP close without close_notify), SILENT,
CONNS (TCP connections accepted on this port so far).

Prints "READY" on stdout once every listener is bound.
"""
import argparse
import os
import socket
import ssl
import sys
import threading

PLAIN_PORT = 4430
CERT_DIR = None


def pattern(n, offset=0):
    return bytes((offset + i) % 251 for i in range(n))


def send_big(write, n):
    # Built up front (like the TLS BIG) so the benchmark compares links, not
    # Python generator speed.
    data = pattern(n)
    for k in range(0, n, 16384):
        write(data[k:k + 16384])


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
            if cmd == b"CA":
                der = open(os.path.join(CERT_DIR, "test-ca.der"), "rb").read() if CERT_DIR else b""
                sock.sendall(b"%d\n" % len(der) + der)
                continue
            sock.sendall(line)
    except OSError:
        pass
    finally:
        try:
            sock.close()
        except OSError:
            pass


class Counter:
    def __init__(self):
        self.n = 0
        self.lock = threading.Lock()

    def inc(self):
        with self.lock:
            self.n += 1


def tls_context(leaf, tls13_only=False, tls12_only=False, alpn=None, ciphers=None):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    # CPython sets OP_CIPHER_SERVER_PREFERENCE by default: clear it so the
    # client's suite order decides.
    ctx.options &= ~ssl.OP_CIPHER_SERVER_PREFERENCE
    ctx.load_cert_chain(os.path.join(CERT_DIR, leaf + ".pem"), os.path.join(CERT_DIR, leaf + ".key"))
    if tls13_only:
        ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    if tls12_only:
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.maximum_version = ssl.TLSVersion.TLSv1_2
    if ciphers:
        ctx.set_ciphers(ciphers)
    if alpn:
        ctx.set_alpn_protocols(alpn)

    def on_sni(sslobj, name, _ctx):
        sslobj.wtls_sni = name

    ctx.sni_callback = on_sni
    return ctx


def tls_handler(ctx, counter):
    def handle(raw):
        counter.inc()
        try:
            sock = ctx.wrap_socket(raw, server_side=True)
        except (OSError, ssl.SSLError):
            raw.close()
            return
        conn = LineConn(sock)
        try:
            while True:
                line = conn.readline()
                if line is None:
                    return
                cmd = line.strip()
                if cmd == b"PING":
                    sock.sendall(b"PING\n")
                elif cmd == b"SNI":
                    sni = getattr(sock, "wtls_sni", None)
                    sock.sendall((sni.encode() if sni else b"-") + b"\n")
                elif cmd.startswith(b"BIG "):
                    n = int(cmd[4:])
                    data = bytes(i & 0xFF for i in range(n))
                    for k in range(0, n, 16384):
                        sock.sendall(data[k:k + 16384])
                elif cmd == b"CLOSE":
                    sock.unwrap().close()
                    return
                elif cmd == b"TRUNC":
                    sock.shutdown(socket.SHUT_RDWR)  # TCP FIN/RST, no close_notify
                    return
                elif cmd == b"SILENT":
                    while sock.recv(65536):
                        pass
                    return
                elif cmd == b"CONNS":
                    sock.sendall(b"%d\n" % counter.n)
                else:
                    sock.sendall(line)
        except (OSError, ssl.SSLError, ValueError):
            pass
        finally:
            try:
                sock.close()
            except OSError:
                pass

    return handle


def tls_listeners(bind):
    specs = [
        (4431, dict(leaf="ecdsa", tls13_only=True, alpn=["http/1.1"])),
        (4432, dict(leaf="rsa", tls13_only=True)),
        (4433, dict(leaf="ecdsa", tls12_only=True, ciphers="ECDHE-ECDSA-CHACHA20-POLY1305")),
        (4434, dict(leaf="expired")),
        (4435, dict(leaf="untrusted")),
        (4436, dict(leaf="wronghost")),
        (4437, dict(leaf="clientonly")),
    ]
    return [serve(bind, port, tls_handler(tls_context(**kw), Counter())) for port, kw in specs]


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
    ap.add_argument("--certs", default=os.environ.get("WTLS_TEST_CERT_DIR"))
    args = ap.parse_args()
    global CERT_DIR
    CERT_DIR = args.certs
    listeners = [serve(args.bind, PLAIN_PORT, handle_plain)]
    if CERT_DIR:
        listeners += tls_listeners(args.bind)
    print("READY", flush=True)
    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        pass
    for ls in listeners:
        ls.close()


if __name__ == "__main__":
    sys.exit(main())
