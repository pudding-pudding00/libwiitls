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
        if query.get("members") == "2":
            z = gzip.compress(data[:n // 2], mtime=0) + gzip.compress(data[n // 2:], mtime=0)
        else:
            z = gzip.compress(data, mtime=0)
        if query.get("bad") == "1":
            z = z[:-8] + bytes([z[-8] ^ 1]) + z[-7:]
        if query.get("cut") == "1":
            z = z[:len(z) // 2]
        enc = ("Content-Encoding", query.get("enc", "gzip"))
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
                if fields.get("transfer-encoding", "").lower() == "chunked":
                    body = rd.chunked_body()
                else:
                    body = rd.body(int(fields.get("content-length", "0")))
                if body is None:
                    return
                url = urllib.parse.urlsplit(target)
                query = dict(urllib.parse.parse_qsl(url.query))
                if url.path != "/count":
                    with HTTP_LOG_LOCK:
                        HTTP_LOG.append(query)
                state["req_no"] += 1
                if state["drop_next"]:
                    tcp_abort(sock)
                    return
                if not http_respond(sock, secure, method, url.path, query, head, body, state):
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

    return handle


def http_listeners(bind):
    ctx = tls_context("ecdsa", alpn=["http/1.1"])
    tls = [serve(bind, port, http_handler(ctx, Counter())) for port in (4438, 4439)]
    # mutual TLS, client certificate optional: /who shows who connected
    mtls = serve(bind, 4442, http_handler(mtls_context("ecdsa", required=False), Counter()))
    return tls + [mtls, serve(bind, 4440, http_handler(None, Counter()))]


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
