#!/usr/bin/env python3
"""Generate test fixtures for ca-key-audit.

Everything stays local in fixtures/. Deliberately weak material:
  good.pem / good.crt     - normal 2048-bit RSA, SHA256 self-signed cert
  small.pem               - 1024-bit RSA key
  shared1.pem/shared2.pem - two RSA keys sharing one prime (batch-GCD case)
  roca.pem                - synthetic ROCA-structured key (fingerprint case)
  weakec.pem              - secp192r1 EC key
  sha1.crt                - SHA1-signed certificate
"""

import os
import subprocess
import sys
from functools import reduce

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

HERE = os.path.dirname(os.path.abspath(__file__))
FIX = os.path.join(HERE, "fixtures")
os.makedirs(FIX, exist_ok=True)


def run(cmd):
    subprocess.run(cmd, check=True, capture_output=True)


def openssl(args):
    run(["openssl"] + args)


# --- good key + cert -------------------------------------------------------
good = os.path.join(FIX, "good.pem")
openssl(["genrsa", "-out", good, "2048"])
openssl(["req", "-x509", "-new", "-key", good, "-sha256", "-days", "30",
         "-subj", "/CN=good.lab.example", "-out", os.path.join(FIX, "good.crt")])

# --- small key --------------------------------------------------------------
openssl(["genrsa", "-out", os.path.join(FIX, "small.pem"), "1024"])

# --- weak EC key ------------------------------------------------------------
openssl(["ecparam", "-name", "secp192r1", "-genkey", "-noout",
         "-out", os.path.join(FIX, "weakec.pem")])

# --- SHA1-signed cert -------------------------------------------------------
openssl(["req", "-x509", "-new", "-key", good, "-sha1", "-days", "30",
         "-subj", "/CN=sha1.lab.example", "-out", os.path.join(FIX, "sha1.crt")])

# --- shared-prime pair ------------------------------------------------------
# Build two 1024-bit keys whose moduli share one 512-bit prime.
from cryptography.hazmat.primitives.asymmetric.rsa import (
    RSAPrivateNumbers, RSAPublicNumbers,
)


def genprime(bits: int) -> int:
    while True:
        c = int.from_bytes(os.urandom(bits // 8), "big") | (1 << (bits - 1)) | 1
        if is_probable_prime(c):
            return c


def is_probable_prime(x: int) -> bool:
    if x < 2:
        return False
    for p in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
        if x == p:
            return True
        if x % p == 0:
            return False
    d, s = x - 1, 0
    while d % 2 == 0:
        s += 1
        d //= 2
    for _ in range(30):
        a = int.from_bytes(os.urandom(16), "big") % (x - 3) + 2
        y = pow(a, d, x)
        if y in (1, x - 1):
            continue
        for _ in range(s - 1):
            y = y * y % x
            if y == x - 1:
                break
        else:
            return False
    return True


def build_key(p: int, q: int, path: str):
    assert p != q
    e = 65537
    n = p * q
    d = pow(e, -1, (p - 1) * (q - 1) // __import__("math").gcd(p - 1, q - 1))
    dmp1 = d % (p - 1)
    dmq1 = d % (q - 1)
    iqmp = pow(q, -1, p)
    pub = RSAPublicNumbers(e, n)
    priv = RSAPrivateNumbers(p, q, d, dmp1, dmq1, iqmp, pub)
    key = priv.private_key()
    pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    )
    with open(path, "wb") as fh:
        fh.write(pem)


shared_p = genprime(512)
build_key(shared_p, genprime(512), os.path.join(FIX, "shared1.pem"))
build_key(shared_p, genprime(512), os.path.join(FIX, "shared2.pem"))

# --- synthetic ROCA-structured key ------------------------------------------
# p = k*M + (65537^a mod M), M = product of the first 71 primes (matches the
# published parameter for 992-1952-bit moduli). Synthetic — only the
# structural fingerprint is reproduced, for detector testing.


def first_primes(count: int):
    ps, x = [], 2
    while len(ps) < count:
        if all(x % p for p in ps if p * p <= x):
            ps.append(x)
        x += 1
    return ps


M = reduce(lambda a, b: a * b, first_primes(71))


def roca_prime(a_offset: int = 0) -> int:
    for a in range(a_offset, a_offset + 4096):
        r = pow(65537, a, M)
        # k chosen so p lands around 512 bits
        k0 = (1 << 511) // M
        for k in range(k0, k0 + 64):
            p = k * M + r
            if p.bit_length() == 512 and is_probable_prime(p):
                return p
    raise RuntimeError("no ROCA-style prime found")


used = set()
offset = 0


def roca_prime_unique(used: set) -> int:
    global offset
    while True:
        x = roca_prime(offset)
        offset += 4096
        if x not in used:
            used.add(x)
            return x


p = roca_prime_unique(used)
q = roca_prime_unique(used)
assert p != q
build_key(p, q, os.path.join(FIX, "roca.pem"))

# --- tiny-scalar EC key (CTF-style weak keygen: scalar = 0x73 on P-384) ------
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization as ser

weak = ec.derive_private_key(0x73, ec.SECP384R1())
with open(os.path.join(FIX, "weakscalar.pem"), "wb") as fh:
    fh.write(weak.private_bytes(
        ser.Encoding.PEM, ser.PrivateFormat.PKCS8, ser.NoEncryption()))
with open(os.path.join(FIX, "weakscalar.pub"), "wb") as fh:
    fh.write(weak.public_key().public_bytes(
        ser.Encoding.PEM, ser.PublicFormat.SubjectPublicKeyInfo))
# a second tiny-scalar key, public only (scalar 4, P-384 — the G3C case)
weak2 = ec.derive_private_key(4, ec.SECP384R1())
with open(os.path.join(FIX, "weakscalar2.pub"), "wb") as fh:
    fh.write(weak2.public_key().public_bytes(
        ser.Encoding.PEM, ser.PublicFormat.SubjectPublicKeyInfo))

print("fixtures written to", FIX)
for f in sorted(os.listdir(FIX)):
    print("  -", f)
