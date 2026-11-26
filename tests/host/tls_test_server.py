#!/usr/bin/env python3
"""Test server for libwiitls host and hardware tests (stdlib only).

Port 4430: plain-text line protocol.
Commands (one per line):
  SILENT   stop answering; keep the connection open
  BYE      close the connection (clean TCP FIN)
  BIG n    send n pattern bytes: byte i = i % 251
  CA       "<len>
" followed by the test CA in DER (needs --certs)
  CLIENTCERT <name> "<len>
" + the client certificate <name> in DER (client-ec, client-rsa,
           client-untrusted; needs --certs)
  CLIENTKEY <name> "<len>
" + the private key <name> in PEM (unencrypted test keys, plain TCP)
  other    echoed back unchanged (including the newline)

TLS ports (only with --certs DIR, the output of make_certs.py; default: the
WTLS_TEST_CERT_DIR environment variable):
  4431 TLS 1.3 only, ECDSA leaf, ALPN http/1.1, session tickets
  4432 TLS 1.3 only, RSA leaf
  4433 TLS 1.2 only, ECDHE-ECDSA-CHACHA20-POLY1305
  4434 expired certificate        4435 untrusted CA
  4436 certificate for other.test
  4437 certificate without the serverAuth extended key usage
  4441 mutual TLS: a client certificate from the test CA is REQUIRED
TLS commands: PING, SNI (received SNI or "-"), BIG n (byte i = i & 0xFF),
CLOSE (close_notify), TRUNC (TCP close without close_notify), SILENT,
CONNS (TCP connections accepted on this port so far).

HTTP/1.1 ports (with --certs; TLS 1.2+1.3, ECDSA leaf, ALPN http/1.1): 4438 and
4439; the same endpoints over plain TCP on 4440; port 4442 asks for a client
certificate (optional) and answers /who with the client CN. Keep-alive until
the request says "Connection: close" or an endpoint
closes. Pattern bytes: i % 251. Unknown query parameters (e.g. id=...) are
ignored, so a test can tag its requests and count them with /count.
  GET /hello                      200, text/plain, "hello"
  GET|HEAD /len?n=N               200, Content-Length N, N pattern bytes
  GET /chunked?n=N&size=S[&cut=1] chunked in S-byte chunks, first chunk with
                                  ";ext=1", trailer "X-T: 1"; cut=1: TCP close
                                  without close_notify before the last chunk
  GET /close?n=N[&notify=0]       no CL/TE, "Connection: close", N bytes, then
                                  close_notify (notify=0: TCP close without)
  GET /trunc?n=N&cut=K            CL N, TCP close without close_notify after K
  GET /trickle                    CL 13 "hello trickle", one TLS record per byte
  GET /slowbody?ms=M              head (CL 2) at once, body "ok" after M ms
  GET /bighead?n=N                head of exactly N bytes (padded X-Big field)
  GET /status?code=C              status C; 204/304 without body, else CL 0
  GET /continue                   "100 Continue", then 200 "ok"
  GET /slowhead                   status line only, then silence
  POST /echo                      body = request body
  * /method                       "<METHOD> <body_len>"
  GET /headers                    body = request head as received
  GET /conn                       "<conn_id> <req_no>" (per port / per connection)
  GET /drop-next                  200 "ok"; the next request on this connection
                                  is read and answered by a TCP close
  GET /idle-close?ms=M[&notify=0] 200 "ok"; after M ms idle close_notify + close
                                  (notify=0: TCP close without)
  GET /redirect?code=C&to=URL     status C, Location: URL (percent-decoded)
  GET /redirect-chain?n=K         K > 0: 302 to n=K-1; K = 0: 200 "done"
  GET /count?id=K                 requests received so far (all ports, dropped
                                  ones too) whose query has id=K; /count itself
                                  is not counted
  GET /gzip?n=N[&chunked=1][&bad=1][&cut=1][&members=2][&enc=E]
                                  N pattern bytes gzip'd (mtime 0), Content-
                                  Encoding E (default gzip), CL or chunked;
                                  bad=1: CRC flipped; cut=1: only the first
                                  half of the gzip stream (framing complete);
                                  members=2: two gzip members back to back
  GET /encoding?name=E            Content-Encoding E, CL 3, body "raw"

Prints "READY" on stdout once every listener is bound.
"""
import argparse
import gzip
import os
import socket
import ssl
import sys
import threading
import time
import urllib.parse
import zlib

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

    def recv(self, n):
        if self.buf:
            out, self.buf = self.buf[:n], self.buf[n:]
            return out
        return self.sock.recv(n)


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
            if cmd == b"STALL":
                try:
                    sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
                except OSError:
                    pass
                time.sleep(3.0)
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
            if cmd.startswith(b"CLIENTCERT "):
                name = cmd[len(b"CLIENTCERT "):].decode()
                path = os.path.join(CERT_DIR, name + ".der") if CERT_DIR else None
                der = open(path, "rb").read() if path and os.path.isfile(path) else b""
                sock.sendall(b"%d\n" % len(der) + der)
                continue
            if cmd.startswith(b"CLIENTKEY "):
                name = cmd[len(b"CLIENTKEY "):].decode()
                path = os.path.join(CERT_DIR, name + ".key") if CERT_DIR else None
                pem = open(path, "rb").read() if path and os.path.isfile(path) else b""
                sock.sendall(b"%d\n" % len(pem) + pem)
                continue
            if cmd.startswith(b"SPKI "):
                name = cmd[len(b"SPKI "):].decode()
                path = os.path.join(CERT_DIR, name + ".spki") if CERT_DIR else None
                pin = open(path, "rb").read() if path and os.path.isfile(path) else b""
                sock.sendall(b"%d\n" % len(pin) + pin)
                continue
            if cmd.startswith(b"SENDFUZZ "):
                """Send-truthfulness probe: read exactly <total> pattern bytes
                (byte i = i % 251) and report the first mismatch or a short read."""
                total = int(cmd[9:])
                got = 0
                bad = None
                while got < total and bad is None:
                    data = conn.recv(min(65536, total - got))
                    if not data:
                        break
                    for i, b in enumerate(data):
                        if b != (got + i) % 251:
                            bad = (got + i, b)
                            break
                    got += len(data)
                if bad is None and got == total:
                    sock.sendall(b"FUZZOK %d\n" % total)
                else:
                    off, g = bad if bad else (got, 0)
                    sock.sendall(b"FUZZBAD off=%d got=%d want=%d total=%d\n" %
                                 (off, g, off % 251, total))
                continue
            if cmd.startswith(b"SENDFUZZDUP "):
                """Bidirectional-pressure probe: while reading the <total> pattern
                bytes (like SENDFUZZ), a thread pushes junk back, the way a TLS
                server's post-handshake records arrive during a big upload."""
                total = int(cmd[12:])

                def push_junk(sock=sock, n=256 * 1024):
                    try:
                        junk = b"J" * 4096
                        for _ in range(n // len(junk)):
                            sock.sendall(junk)
                    except OSError:
                        pass

                import threading as _t
                pusher = _t.Thread(target=push_junk, daemon=True)
                pusher.start()
                got = 0
                bad = None
                while got < total and bad is None:
                    data = conn.recv(min(65536, total - got))
                    if not data:
                        break
                    for i, b in enumerate(data):
                        if b != (got + i) % 251:
                            bad = (got + i, b)
                            break
                    got += len(data)
                pusher.join(5)
                if bad is None and got == total:
                    sock.sendall(b"FUZZOK %d\n" % total)
                else:
                    off, g = bad if bad else (got, 0)
                    sock.sendall(b"FUZZBAD off=%d got=%d want=%d total=%d\n" %
                                 (off, g, off % 251, total))
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


def mtls_context(leaf, required):
    """TLS context that verifies client certificates against the test CA
    (mutual TLS). required: handshake fails without a client cert."""
    ctx = tls_context(leaf)
    ctx.verify_mode = ssl.CERT_REQUIRED if required else ssl.CERT_OPTIONAL
    ctx.load_verify_locations(os.path.join(CERT_DIR, "test-ca.pem"))
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
    listeners = [serve(bind, port, tls_handler(tls_context(**kw), Counter())) for port, kw in specs]
    # mutual TLS: the handshake fails unless the client presents a
    # certificate signed by the test CA
    listeners.append(serve(bind, 4441, tls_handler(mtls_context("ecdsa", required=True), Counter())))
    # the same, TLS 1.2 only
    mtls12 = mtls_context("ecdsa", required=True)
    mtls12.minimum_version = ssl.TLSVersion.TLSv1_2
    mtls12.maximum_version = ssl.TLSVersion.TLSv1_2
    listeners.append(serve(bind, 4443, tls_handler(mtls12, Counter())))
    return listeners


# ---- HTTP/1.1 -------------------------------------------------------------

HTTP_LOG = []  # query dicts of every request received (for /count)
HTTP_LOG_LOCK = threading.Lock()


class HttpReader:
    def __init__(self, sock):
        self.sock = sock
        self.buf = b""

    def fill(self):
        data = self.sock.recv(65536)
        if not data:
            return False
        self.buf += data
        return True

    def head(self):
        """Raw request head (up to and including the empty line) or None at EOF."""
        while True:
            for sep in (b"\r\n\r\n", b"\n\n"):
                i = self.buf.find(sep)
                if i >= 0:
                    head, self.buf = self.buf[:i + len(sep)], self.buf[i + len(sep):]
                    return head
            if not self.fill():
                return None

    def line(self):
        """One CRLF (or LF) terminated line, without its terminator."""
        while True:
            for sep in (b"\r\n", b"\n"):
                i = self.buf.find(sep)
                if i >= 0:
                    line, self.buf = self.buf[:i], self.buf[i + len(sep):]
                    return line
            if not self.fill():
                return None

    def body(self, n):
        while len(self.buf) < n:
            if not self.fill():
                return None
        body, self.buf = self.buf[:n], self.buf[n:]
        return body

    def chunked_body(self, max_len=2 * 1024 * 1024):
        """Decodes a chunked request body; None when malformed or over max_len."""
        out = b""
        while True:
            size_line = self.line()
            if size_line is None:
                return None
            size_line = size_line.split(b";", 1)[0].strip()
            try:
                size = int(size_line, 16)
            except ValueError:
                return None
            if size == 0:
                while True:  # trailers until the empty line
                    t = self.line()
                    if t is None:
                        return None
                    if t == b"":
                        return out
            data = self.body(size)
            if data is None:
                return None
            out += data
            if len(out) > max_len:
                return None
            if self.body(2) != b"\r\n":
                return None  # the CRLF that ends every chunk


def http_response(status, headers=(), body=b"", reason=b"X"):
    out = b"HTTP/1.1 %d %s\r\n" % (status, reason)
    for k, v in headers:
        out += k.encode() + b": " + (v if isinstance(v, bytes) else str(v).encode()) + b"\r\n"
    return out + b"\r\n" + body


def tcp_abort(sock):
    """TCP close without close_notify."""
    try:
        sock.shutdown(socket.SHUT_RDWR)
    except OSError:
        pass


def clean_close(sock, secure):
    """close_notify (TLS) or FIN (plain), not waiting long for the peer."""
    if not secure:
        tcp_abort(sock)
        return
    try:
        sock.settimeout(2)
        sock.unwrap()
    except (OSError, ssl.SSLError, ValueError):
        pass


def http_respond(sock, secure, method, path, query, head, body, state):
    """Answers one request. Returns False when the connection is finished."""
    send = sock.sendall
    n = int(query.get("n", "0"))
    if path == "/hello":
        send(http_response(200, [("Content-Type", "text/plain"), ("Content-Length", 5)], b"hello", b"OK"))
    elif path == "/len":
        send(http_response(200, [("Content-Length", n)]))
        if method != "HEAD":
            send_big(send, n)
    elif path == "/chunked":
        size = max(1, int(query.get("size", "1000")))
        send(http_response(200, [("Transfer-Encoding", "chunked")]))
        data = pattern(n)
        for k in range(0, n, size):
            piece = data[k:k + size]
            ext = b";ext=1" if k == 0 else b""
            send(b"%x%s\r\n" % (len(piece), ext) + piece + b"\r\n")
        if query.get("cut") == "1":
            tcp_abort(sock)
            return False
        send(b"0\r\nX-T: 1\r\n\r\n")
    elif path == "/close":
        send(http_response(200, [("Connection", "close")]) + pattern(n))
        if query.get("notify") == "0":
            tcp_abort(sock)
        else:
            clean_close(sock, secure)
        return False
    elif path == "/trunc":
        cut = int(query.get("cut", "0"))
        send(http_response(200, [("Content-Length", n)]) + pattern(n)[:cut])
        tcp_abort(sock)
        return False
    elif path == "/trickle":
        for b in http_response(200, [("Content-Length", 13)], b"hello trickle", b"OK"):
            send(bytes([b]))
    elif path == "/slowbody":
        send(http_response(200, [("Content-Length", 2)]))
        time.sleep(int(query.get("ms", "0")) / 1000.0)
        send(b"ok")
    elif path == "/bighead":
        pre = b"HTTP/1.1 200 X\r\nContent-Length: 0\r\nX-Big: "
        send(pre + b"a" * max(0, n - len(pre) - 4) + b"\r\n\r\n")
    elif path == "/status":
        code = int(query.get("code", "200"))
        send(http_response(code) if code in (204, 304) else http_response(code, [("Content-Length", 0)]))
    elif path == "/continue":
        send(b"HTTP/1.1 100 Continue\r\n\r\n")
        send(http_response(200, [("Content-Length", 2)], b"ok"))
    elif path == "/upgrade":
        early = b"EARLY!" if query.get("early") == "1" else b""
        resp = http_response(101, [("Upgrade", "echo"), ("Connection", "Upgrade")], early, b"Switching Protocols")
        send(resp)
        try:
            while True:
                data = sock.recv(4096)
                if not data:
                    break
                send(data)
        except (OSError, ssl.SSLError):
            pass
        return False
    elif path == "/slowhead":
        send(b"HTTP/1.1 200 OK\r\n")
        while sock.recv(65536):
            pass
        return False
    elif path == "/echo":
        send(http_response(200, [("Content-Length", len(body))], body))
    elif path == "/method":
        out = b"%s %d" % (method.encode(), len(body))
        send(http_response(200, [("Content-Length", len(out))], b"" if method == "HEAD" else out))
    elif path == "/headers":
        send(http_response(200, [("Content-Length", len(head))], head))
    elif path == "/conn":
        out = b"%d %d" % (state["conn_id"], state["req_no"])
        send(http_response(200, [("Content-Length", len(out))], out))
    elif path == "/drop-next":
        send(http_response(200, [("Content-Length", 2)], b"ok"))
        state["drop_next"] = True
    elif path == "/idle-close":
        send(http_response(200, [("Content-Length", 2)], b"ok"))
        state["idle"] = (int(query.get("ms", "1000")), query.get("notify") != "0")
    elif path == "/redirect":
        code = int(query.get("code", "302"))
        send(http_response(code, [("Location", query.get("to", "/hello")), ("Content-Length", 0)]))
    elif path == "/redirect-chain":
        if n > 0:
            send(http_response(302, [("Location", "/redirect-chain?n=%d" % (n - 1)), ("Content-Length", 0)]))
        else:
            send(http_response(200, [("Content-Length", 4)], b"done"))
    elif path == "/gzip":
        data = pattern(n)
        enc_name = query.get("enc", "gzip")
        if enc_name.lower() == "deflate":
            z = zlib.compress(data)
        elif query.get("members") == "2":
            z = gzip.compress(data[:n // 2], mtime=0) + gzip.compress(data[n // 2:], mtime=0)
        else:
            z = gzip.compress(data, mtime=0)
        if query.get("bad") == "1":
            z = z[:-8] + bytes([z[-8] ^ 1]) + z[-7:]
        if query.get("cut") == "1":
            z = z[:len(z) // 2]
        enc = ("Content-Encoding", enc_name)
        if query.get("chunked") == "1":
            send(http_response(200, [enc, ("Transfer-Encoding", "chunked")]))
            for k in range(0, len(z), 100):
                piece = z[k:k + 100]
                send(b"%x\r\n" % len(piece) + piece + b"\r\n")
            send(b"0\r\n\r\n")
        else:
            send(http_response(200, [enc, ("Content-Length", len(z))], z))
    elif path == "/encoding":
        send(http_response(200, [("Content-Encoding", query.get("name", "br")), ("Content-Length", 3)], b"raw"))
    elif path == "/who":
        """Mutual TLS made visible: the CN of the client certificate, or none."""
        cn = "none"
        try:
            peercert = sock.getpeercert()
            if peercert:
                for rdn in peercert.get("subject", ()):
                    for key, value in rdn:
                        if key == "commonName":
                            cn = value
        except (AttributeError, ValueError):
            pass  # plain socket or no certificate
        out = cn.encode()
        send(http_response(200, [("Content-Length", len(out))], out))
    elif path == "/count":
        with HTTP_LOG_LOCK:
            c = sum(1 for q in HTTP_LOG if q.get("id") == query.get("id"))
        out = b"%d" % c
        send(http_response(200, [("Content-Length", len(out))], out))
    else:
        send(http_response(404, [("Content-Length", 0)]))
    return True


def _serve_http1(sock, secure, state):
    rd = HttpReader(sock)
    try:
        while True:
            idle = state["idle"]
            if idle:
                sock.settimeout(idle[0] / 1000.0)
                try:
                    head = rd.head()
                except (socket.timeout, TimeoutError):
                    if idle[1]:
                        clean_close(sock, secure)
                    else:
                        tcp_abort(sock)
                    return
                sock.settimeout(None)
                state["idle"] = None
            else:
                head = rd.head()
            if head is None:
                return
            lines = head.replace(b"\r\n", b"\n").split(b"\n")
            method, target, _ = lines[0].decode().split(" ", 2)
            fields = {}
            for line in lines[1:]:
                if b":" in line:
                    k, v = line.split(b":", 1)
                    fields[k.strip().lower().decode()] = v.strip().decode()
            url = urllib.parse.urlsplit(target)
            query = dict(urllib.parse.parse_qsl(url.query))
            if fields.get("expect", "").lower() == "100-continue":
                if url.path == "/expect-reject":
                    sock.sendall(http_response(413, [("Connection", "close"), ("Content-Length", 6)], b"toobig"))
                    clean_close(sock, secure)
                    return
                if url.path == "/expect-accept":
                    sock.sendall(b"HTTP/1.1 100 Continue\r\n\r\n")
            if fields.get("transfer-encoding", "").lower() == "chunked":
                body = rd.chunked_body()
            else:
                body = rd.body(int(fields.get("content-length", "0")))
            if body is None:
                return
            if url.path != "/count":
                with HTTP_LOG_LOCK:
                    HTTP_LOG.append(query)
            state["req_no"] += 1
            if state["drop_next"]:
                tcp_abort(sock)
                return
            if url.path in ("/expect-accept", "/expect-silent"):
                sock.sendall(http_response(200, [("Content-Length", len(body))], body))
            elif not http_respond(sock, secure, method, url.path, query, head, body, state):
                return
            if "close" in fields.get("connection", "").lower():
                clean_close(sock, secure)
                return
    except (OSError, ssl.SSLError, ValueError):
        pass
    finally:
        try:
            sock.close()
        except OSError:
            pass


def http_handler(ctx, counter):
    """HTTP/1.1 over TLS (ctx) or plain TCP (ctx None)."""
    secure = ctx is not None

    def handle(raw):
        counter.inc()
        state = {"conn_id": counter.n, "req_no": 0, "drop_next": False, "idle": None}
        if secure:
            try:
                sock = ctx.wrap_socket(raw, server_side=True)
            except (OSError, ssl.SSLError):
                raw.close()
                return
        else:
            sock = raw
        _serve_http1(sock, secure, state)

    return handle


def proxy_handler(raw):
    """Minimal HTTP/1.1 forward + CONNECT tunnel proxy on port 4444."""
    rd = HttpReader(raw)
    up = None
    try:
        head = rd.head()
        if head is None:
            return
        lines = head.replace(b"\r\n", b"\n").split(b"\n")
        method, target, ver = lines[0].decode().split(" ", 2)
        if method == "CONNECT":
            host, port_s = target.rsplit(":", 1)
            port = int(port_s)
            if port not in (4438, 4439, 4442, 4445):
                raw.sendall(http_response(403, [("Content-Length", 0)]))
                return
            up = socket.create_connection((host, port), timeout=5)
            up.settimeout(None)
            raw.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            if rd.buf:
                up.sendall(rd.buf)

            def pipe(src, dst):
                try:
                    while True:
                        d = src.recv(16384)
                        if not d:
                            break
                        dst.sendall(d)
                except OSError:
                    pass
                try:
                    dst.shutdown(socket.SHUT_WR)
                except OSError:
                    pass

            t1 = threading.Thread(target=pipe, args=(raw, up), daemon=True)
            t2 = threading.Thread(target=pipe, args=(up, raw), daemon=True)
            t1.start()
            t2.start()
            t1.join()
            t2.join()
            return

        # Plain HTTP forward proxy: GET http://host:port/path
        u = urllib.parse.urlsplit(target)
        host = u.hostname
        port = u.port or 80
        path = (u.path or "/") + (("?" + u.query) if u.query else "")
        up = socket.create_connection((host, port), timeout=5)
        up.settimeout(None)
        req = ("%s %s %s\r\n" % (method, path, ver)).encode() + b"\r\n".join(lines[1:])
        up.sendall(req)
        if rd.buf:
            up.sendall(rd.buf)
        up.shutdown(socket.SHUT_WR)
        while True:
            d = up.recv(16384)
            if not d:
                break
            raw.sendall(d)
    except OSError:
        pass
    finally:
        for s in (up, raw):
            if s:
                try:
                    s.close()
                except OSError:
                    pass


# RFC 7541 static table entries needed by the minimal HTTP/2 test server
H2_STATIC = [
    (":authority", ""), (":method", "GET"), (":method", "POST"), (":path", "/"),
    (":path", "/index.html"), (":scheme", "http"), (":scheme", "https"),
    (":status", "200"), (":status", "204"), (":status", "206"), (":status", "304"),
    (":status", "400"), (":status", "404"), (":status", "500"),
    ("accept-charset", ""), ("accept-encoding", "gzip, deflate"),
    ("accept-language", ""), ("accept-ranges", ""), ("accept", ""),
    ("access-control-allow-origin", ""), ("age", ""), ("allow", ""),
    ("authorization", ""), ("cache-control", ""), ("content-disposition", ""),
    ("content-encoding", ""), ("content-language", ""), ("content-length", ""),
    ("content-location", ""), ("content-range", ""), ("content-type", ""),
    ("cookie", ""), ("date", ""), ("etag", ""), ("expect", ""), ("expires", ""),
    ("from", ""), ("host", ""), ("if-match", ""), ("if-modified-since", ""),
    ("if-none-match", ""), ("if-range", ""), ("if-unmodified-since", ""),
    ("last-modified", ""), ("link", ""), ("location", ""), ("max-forwards", ""),
    ("proxy-authenticate", ""), ("proxy-authorization", ""), ("range", ""),
    ("referer", ""), ("refresh", ""), ("retry-after", ""), ("server", ""),
    ("set-cookie", ""), ("strict-transport-security", ""), ("transfer-encoding", ""),
    ("user-agent", ""), ("vary", ""), ("via", ""), ("www-authenticate", ""),
]


def _hpack_dec_int(buf, pos, prefix_bits):
    mask = (1 << prefix_bits) - 1
    val = buf[pos] & mask
    pos += 1
    if val < mask:
        return val, pos
    m = 0
    while True:
        b = buf[pos]
        pos += 1
        val += (b & 0x7f) << m
        m += 7
        if not (b & 0x80):
            return val, pos


def _hpack_dec_str(buf, pos):
    if buf[pos] & 0x80:
        raise ValueError("huffman decode not implemented in test server")
    slen, pos = _hpack_dec_int(buf, pos, 7)
    return buf[pos:pos + slen].decode("latin1"), pos + slen


def _hpack_dec_block(buf, dyn):
    pos = 0
    out = []
    def lookup(idx):
        if idx <= len(H2_STATIC):
            return H2_STATIC[idx - 1]
        return dyn[idx - len(H2_STATIC) - 1]
    while pos < len(buf):
        b = buf[pos]
        if (b & 0xe0) == 0x20:
            _, pos = _hpack_dec_int(buf, pos, 5)
            continue
        if b & 0x80:
            idx, pos = _hpack_dec_int(buf, pos, 7)
            out.append(lookup(idx))
        else:
            inc = bool(b & 0x40)
            idx, pos = _hpack_dec_int(buf, pos, 6 if inc else 4)
            if idx:
                name = lookup(idx)[0]
            else:
                name, pos = _hpack_dec_str(buf, pos)
            val, pos = _hpack_dec_str(buf, pos)
            out.append((name, val))
            if inc:
                dyn.insert(0, (name, val))
    return out


def _hpack_enc_int(prefix_mask, prefix_bits, val):
    max_p = (1 << prefix_bits) - 1
    if val < max_p:
        return bytes([prefix_mask | val])
    out = bytearray([prefix_mask | max_p])
    val -= max_p
    while val >= 128:
        out.append((val & 0x7f) | 0x80)
        val >>= 7
    out.append(val)
    return bytes(out)


def _hpack_enc_str(s):
    b = s.encode("latin1")
    return _hpack_enc_int(0x00, 7, len(b)) + b


def _hpack_enc_headers(status, hdrs, inc_dyn=False):
    out = bytearray()
    st_s = str(status)
    idx_st = {v: i + 1 for i, (k, v) in enumerate(H2_STATIC) if k == ":status"}.get(st_s)
    if idx_st:
        out += _hpack_enc_int(0x80, 7, idx_st)
    else:
        out += _hpack_enc_int(0x00, 4, 8) + _hpack_enc_str(st_s)
    for k, v in hdrs:
        kl = k.lower()
        vs = str(v)
        mask = 0x40 if inc_dyn else 0x00
        bits = 6 if inc_dyn else 4
        out += _hpack_enc_int(mask, bits, 0) + _hpack_enc_str(kl) + _hpack_enc_str(vs)
    return bytes(out)


def _h2_frame(ftype, flags, stream, payload=b""):
    return (
        len(payload).to_bytes(3, "big")
        + bytes([ftype, flags])
        + (stream & 0x7fffffff).to_bytes(4, "big")
        + payload
    )


def _h2_recv_exact(sock, n):
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return None
        buf += chunk
    return bytes(buf)


def h2_session(sock, state):
    preface = _h2_recv_exact(sock, 24)
    if preface != b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n":
        return
    # Send server SETTINGS (ENABLE_PUSH=0, INITIAL_WINDOW_SIZE=65535, MAX_FRAME_SIZE=16384)
    sock.sendall(_h2_frame(4, 0, 0, b"\x00\x02\x00\x00\x00\x00\x00\x03\x00\x00\x00\x10"))

    dyn = []
    client_init_win = 65535
    conn_send_win = 65535
    client_max_frame = 16384
    streams = {}  # stream_id -> {"hdr_blk": bytearray, "hdr_done": bool, "headers": [], "body": bytearray}
    pending_frames = []

    def read_frame_raw():
        if pending_frames:
            return pending_frames.pop(0)
        hdr = _h2_recv_exact(sock, 9)
        if hdr is None:
            return None
        flen = int.from_bytes(hdr[:3], "big")
        ftype, flags = hdr[3], hdr[4]
        sid = int.from_bytes(hdr[5:9], "big") & 0x7fffffff
        pay = _h2_recv_exact(sock, flen) if flen else b""
        if pay is None:
            return None
        return flen, ftype, flags, sid, pay

    def handle_ctrl(ftype, flags, sid, pay):
        nonlocal client_init_win, conn_send_win, client_max_frame
        if ftype == 4:  # SETTINGS
            if not (flags & 1):
                for off in range(0, len(pay), 6):
                    pid = int.from_bytes(pay[off:off + 2], "big")
                    pval = int.from_bytes(pay[off + 2:off + 6], "big")
                    if pid == 4:
                        client_init_win = pval
                    elif pid == 5:
                        client_max_frame = max(16384, min(pval, 16384))
                sock.sendall(_h2_frame(4, 1, 0))
        elif ftype == 6:  # PING
            if not (flags & 1):
                sock.sendall(_h2_frame(6, 1, 0, pay))
        elif ftype == 8:  # WINDOW_UPDATE
            inc = int.from_bytes(pay, "big") & 0x7fffffff
            if sid == 0:
                conn_send_win += inc
            elif sid in streams:
                streams[sid]["send_win"] += inc
        elif ftype == 3:  # RST_STREAM
            streams.pop(sid, None)

    def send_data_flow(sid, data):
        nonlocal conn_send_win
        off = 0
        if not data:
            sock.sendall(_h2_frame(0, 1, sid, b""))
            return
        while off < len(data):
            while conn_send_win <= 0 or streams[sid]["send_win"] <= 0:
                fr = read_frame_raw()
                if fr is None:
                    raise OSError("eof waiting window")
                _, ft, fl, fs, fp = fr
                if ft in (4, 6, 8, 3):
                    handle_ctrl(ft, fl, fs, fp)
                else:
                    pending_frames.append(fr)
            chunk = min(len(data) - off, client_max_frame, conn_send_win, streams[sid]["send_win"])
            end = 1 if (off + chunk == len(data)) else 0
            sock.sendall(_h2_frame(0, end, sid, data[off:off + chunk]))
            conn_send_win -= chunk
            streams[sid]["send_win"] -= chunk
            off += chunk

    def finish_stream(sid):
        st = streams[sid]
        hdrs = st["headers"]
        body = bytes(st["body"])
        hmap = {}
        for k, v in hdrs:
            hmap.setdefault(k, []).append(v)
        method = hmap.get(":method", ["GET"])[0]
        raw_path = hmap.get(":path", ["/"])[0]
        parsed = urllib.parse.urlsplit(raw_path)
        path = parsed.path
        query = dict(urllib.parse.parse_qsl(parsed.query))
        state["req_no"] += 1
        n = int(query.get("n", "0"))

        def send_resp(status, r_hdrs, r_body=b"", end_on_hdrs=False, cont=False, inc_dyn=False):
            blk = _hpack_enc_headers(status, r_hdrs, inc_dyn=inc_dyn)
            if cont and len(blk) > 4:
                sock.sendall(_h2_frame(1, 0, sid, blk[:4]))
                sock.sendall(_h2_frame(9, 4 | (1 if end_on_hdrs else 0), sid, blk[4:]))
            else:
                sock.sendall(_h2_frame(1, 4 | (1 if end_on_hdrs else 0), sid, blk))
            if not end_on_hdrs:
                send_data_flow(sid, r_body)

        if path == "/hello":
            hdr_list = [("content-type", "text/plain")]
            if query.get("no_cl") != "1":
                hdr_list.append(("content-length", 5))
            send_resp(200, hdr_list, b"hello")
        elif path == "/len":
            send_resp(200, [("content-length", n)], b"" if method == "HEAD" else pattern(n), end_on_hdrs=(method == "HEAD"))
        elif path == "/echo":
            send_resp(200, [("content-length", len(body))], body)
        elif path == "/method":
            out = b"%s %d" % (method.encode(), len(body))
            send_resp(200, [("content-length", len(out))], b"" if method == "HEAD" else out, end_on_hdrs=(method == "HEAD"))
        elif path == "/headers":
            lines = "".join("%s: %s\n" % (k, v) for k, v in hdrs).encode()
            send_resp(200, [("content-length", len(lines))], lines)
        elif path == "/status":
            code = int(query.get("code", "200"))
            if code in (204, 304):
                send_resp(code, [], b"", end_on_hdrs=True)
            else:
                send_resp(code, [("content-length", 0)], b"", end_on_hdrs=True)
        elif path == "/redirect":
            code = int(query.get("code", "302"))
            send_resp(code, [("location", query.get("to", "/hello")), ("content-length", 0)], b"", end_on_hdrs=True)
        elif path == "/gzip":
            data = pattern(n)
            enc = query.get("enc", "gzip")
            z = zlib.compress(data) if enc.lower() == "deflate" else gzip.compress(data, mtime=0)
            send_resp(200, [("content-encoding", enc), ("content-length", len(z))], z)
        elif path == "/conn":
            out = b"%d %d" % (state["conn_id"], sid)
            send_resp(200, [("content-length", len(out))], out)
        elif path == "/goaway":
            send_resp(200, [("content-length", 3)], b"bye")
            sock.sendall(_h2_frame(7, 0, 0, sid.to_bytes(4, "big") + (0).to_bytes(4, "big")))
        elif path == "/cont":
            blk = _hpack_enc_headers(200, [("x-custom", "hpack-dyn"), ("content-length", 4)], inc_dyn=True)
            sock.sendall(_h2_frame(1, 0, sid, blk[:5]))
            sock.sendall(_h2_frame(9, 4, sid, blk[5:]))
            send_data_flow(sid, b"cont")
        else:
            send_resp(404, [("content-length", 0)], b"", end_on_hdrs=True)

    while True:
        fr = read_frame_raw()
        if fr is None:
            return
        flen, ftype, flags, sid, pay = fr
        if ftype in (4, 6, 8, 3):
            handle_ctrl(ftype, flags, sid, pay)
            continue
        if ftype == 1:  # HEADERS
            off = 0
            pad = 0
            if flags & 0x08:
                pad = pay[0]
                off += 1
            if flags & 0x20:
                off += 5
            frag = pay[off:len(pay) - pad]
            st = streams.setdefault(sid, {
                "hdr_blk": bytearray(), "hdr_done": False, "headers": [],
                "body": bytearray(), "send_win": client_init_win, "end_recv": False
            })
            st["hdr_blk"] += frag
            if flags & 0x01:
                st["end_recv"] = True
            if flags & 0x04:
                st["headers"] = _hpack_dec_block(bytes(st["hdr_blk"]), dyn)
                st["hdr_done"] = True
                hmap = dict(st["headers"])
                if st["end_recv"]:
                    finish_stream(sid)
                    streams.pop(sid, None)
                elif hmap.get("expect") == "100-continue":
                    parsed_p = urllib.parse.urlsplit(hmap.get(":path", "/"))
                    if parsed_p.path == "/expect-reject":
                        blk = _hpack_enc_headers(417, [("content-length", 6)])
                        sock.sendall(_h2_frame(1, 4, sid, blk))
                        send_data_flow(sid, b"reject")
                        streams.pop(sid, None)
                    else:
                        sock.sendall(_h2_frame(1, 4, sid, _hpack_enc_headers(100, [])))
        elif ftype == 9 and sid in streams:  # CONTINUATION
            st = streams[sid]
            st["hdr_blk"] += pay
            if flags & 0x04:
                st["headers"] = _hpack_dec_block(bytes(st["hdr_blk"]), dyn)
                st["hdr_done"] = True
                if st["end_recv"]:
                    finish_stream(sid)
                    streams.pop(sid, None)
        elif ftype == 0 and sid in streams:  # DATA
            st = streams[sid]
            off = 0
            pad = 0
            if flags & 0x08:
                pad = pay[0]
                off += 1
            data = pay[off:len(pay) - pad]
            st["body"] += data
            if flen > 0:
                upd = flen.to_bytes(4, "big")
                sock.sendall(_h2_frame(8, 0, 0, upd) + _h2_frame(8, 0, sid, upd))
            if flags & 0x01:
                finish_stream(sid)
                streams.pop(sid, None)


def h2_or_h1_handler(ctx, counter):
    """TLS with h2/http1.1 ALPN: runs h2_session when 'h2' was negotiated, else HTTP/1.1."""
    def handle(raw):
        counter.inc()
        state = {"conn_id": counter.n, "req_no": 0, "drop_next": False, "idle": None}
        try:
            sock = ctx.wrap_socket(raw, server_side=True)
        except (OSError, ssl.SSLError):
            raw.close()
            return
        if sock.selected_alpn_protocol() == "h2":
            try:
                h2_session(sock, state)
            except (OSError, ssl.SSLError, ValueError):
                pass
            finally:
                try:
                    sock.close()
                except OSError:
                    pass
            return
        _serve_http1(sock, True, state)
    return handle


def http_listeners(bind):
    ctx = tls_context("ecdsa", alpn=["http/1.1"])
    ctx_h2 = tls_context("ecdsa", alpn=["h2", "http/1.1"])
    tls = [serve(bind, port, http_handler(ctx, Counter())) for port in (4438, 4439)]
    # mutual TLS, client certificate optional: /who shows who connected
    mtls = serve(bind, 4442, http_handler(mtls_context("ecdsa", required=False), Counter()))
    h2 = serve(bind, 4445, h2_or_h1_handler(ctx_h2, Counter()))
    return tls + [mtls, h2, serve(bind, 4440, http_handler(None, Counter())), serve(bind, 4444, proxy_handler)]


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
        listeners += http_listeners(args.bind)
    print("READY", flush=True)
    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        pass
    for ls in listeners:
        ls.close()


if __name__ == "__main__":
    sys.exit(main())
