#!/usr/bin/env python3
"""Create the libwiitls test PKI with the OpenSSL CLI.

  python make_certs.py --out DIR [--extra-ip A.B.C.D] [--openssl PATH]

Writes into DIR (each cert as .pem and .der, each key as .key):
  test-ca       ECDSA P-256 root, trusted by the tests
  untrusted-ca  ECDSA P-256 root, never trusted
  ecdsa         leaf, P-256, SAN DNS:localhost, IP:127.0.0.1 (+ --extra-ip)
  rsa           leaf, RSA-2048, same SANs
  expired       leaf, P-256, notAfter 2021-01-01
  wronghost     leaf, P-256, SAN DNS:other.test
  untrusted     leaf, P-256, signed by untrusted-ca
  clientonly    leaf, P-256, same SANs, extendedKeyUsage clientAuth only
  client-ec     client leaf, P-256, signed by test-ca, extendedKeyUsage clientAuth
  client-rsa    client leaf, RSA-2048, signed by test-ca, clientAuth
  client-untrusted client leaf, P-256, signed by untrusted-ca, clientAuth
"""
import argparse
import base64
import hashlib
import os
import re
import shutil
import subprocess
import sys
import tempfile

CA_CNF = """\
[ ca ]
default_ca = test_ca
[ test_ca ]
dir = {db}
database = {db}/index.txt
serial = {db}/serial
new_certs_dir = {db}
default_md = sha256
policy = policy_any
unique_subject = no
copy_extensions = none
[ policy_any ]
commonName = supplied
[ v3_leaf ]
basicConstraints = critical, CA:FALSE
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = {eku}
subjectAltName = {san}
"""


def run(openssl, *args):
    subprocess.run([openssl, *args], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)


def keygen(openssl, path, kind):
    if kind == "rsa":
        run(openssl, "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048", "-out", path)
    else:
        run(openssl, "genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256", "-out", path)


def to_der(openssl, pem, der):
    run(openssl, "x509", "-in", pem, "-outform", "DER", "-out", der)


def write_spki_sha256(openssl, pem, spki_path):
    res = subprocess.run([openssl, "x509", "-in", pem, "-pubkey", "-noout"],
                         check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    m = re.search(rb"-----BEGIN PUBLIC KEY-----\s*(.*?)\s*-----END PUBLIC KEY-----", res.stdout, re.S)
    if not m:
        raise RuntimeError(f"cannot extract SPKI from {pem}")
    spki_der = base64.b64decode(b"".join(m.group(1).split()))
    with open(spki_path, "wb") as f:
        f.write(hashlib.sha256(spki_der).digest())


def make_ca(openssl, out, name, cn):
    key = os.path.join(out, name + ".key")
    pem = os.path.join(out, name + ".pem")
    keygen(openssl, key, "ec")
    run(openssl, "req", "-x509", "-new", "-key", key, "-out", pem, "-days", "7300", "-sha256",
        "-subj", "/CN=" + cn,
        "-addext", "basicConstraints=critical,CA:TRUE",
        "-addext", "keyUsage=critical,keyCertSign,cRLSign")
    to_der(openssl, pem, os.path.join(out, name + ".der"))
    write_spki_sha256(openssl, pem, os.path.join(out, name + ".spki"))


def make_leaf(openssl, out, name, ca, kind, san, start=None, end=None, eku="serverAuth"):
    key = os.path.join(out, name + ".key")
    pem = os.path.join(out, name + ".pem")
    keygen(openssl, key, kind)
    with tempfile.TemporaryDirectory() as db:
        dbp = db.replace("\\", "/")
        open(os.path.join(db, "index.txt"), "w").close()
        with open(os.path.join(db, "serial"), "w") as f:
            f.write(os.urandom(8).hex() + "\n")
        cnf = os.path.join(db, "ca.cnf")
        with open(cnf, "w") as f:
            f.write(CA_CNF.format(db=dbp, san=san, eku=eku))
        csr = os.path.join(db, "leaf.csr")
        run(openssl, "req", "-new", "-key", key, "-out", csr, "-subj", "/CN=" + name + ".test")
        dates = ["-startdate", start, "-enddate", end] if start else ["-days", "3650"]
        run(openssl, "ca", "-batch", "-notext", "-config", cnf, "-extensions", "v3_leaf",
            "-cert", os.path.join(out, ca + ".pem"), "-keyfile", os.path.join(out, ca + ".key"),
            "-in", csr, "-out", pem, *dates)
    to_der(openssl, pem, os.path.join(out, name + ".der"))
    write_spki_sha256(openssl, pem, os.path.join(out, name + ".spki"))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    ap.add_argument("--extra-ip", action="append", default=[])
    ap.add_argument("--openssl", default=shutil.which("openssl") or "openssl")
    args = ap.parse_args()
    out = args.out
    os.makedirs(out, exist_ok=True)
    o = args.openssl
    san = ",".join(["DNS:localhost", "IP:127.0.0.1"] + ["IP:" + ip for ip in args.extra_ip])
    try:
        make_ca(o, out, "test-ca", "libwiitls Test CA")
        make_ca(o, out, "untrusted-ca", "libwiitls Untrusted CA")
        make_leaf(o, out, "ecdsa", "test-ca", "ec", san)
        make_leaf(o, out, "rsa", "test-ca", "rsa", san)
        make_leaf(o, out, "expired", "test-ca", "ec", san, "200101000000Z", "210101000000Z")
        make_leaf(o, out, "wronghost", "test-ca", "ec", "DNS:other.test")
        make_leaf(o, out, "untrusted", "untrusted-ca", "ec", san)
        make_leaf(o, out, "clientonly", "test-ca", "ec", san, eku="clientAuth")
        make_leaf(o, out, "client-ec", "test-ca", "ec", san, eku="clientAuth")
        run(o, "pkcs8", "-topk8", "-v2", "aes-256-cbc", "-v2prf", "hmacWithSHA256",
            "-in", os.path.join(out, "client-ec.key"),
            "-out", os.path.join(out, "client-ec-enc.key"),
            "-passout", "pass:wiitls-pw")
        make_leaf(o, out, "client-rsa", "test-ca", "rsa", san, eku="clientAuth")
        make_leaf(o, out, "client-untrusted", "untrusted-ca", "ec", san, eku="clientAuth")
    except subprocess.CalledProcessError as e:
        sys.stderr.write(e.stderr.decode(errors="replace"))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
