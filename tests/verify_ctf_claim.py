#!/usr/bin/env python3
"""Verify the CTF claim: is the published public point equal to 0x73 * G on P-384?

Pure arithmetic on the values supplied in the challenge write-up.
"""

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
import binascii

# pub bytes exactly as printed by `openssl ec -text -noout`
lines = [
    "04:25:db:a8:5a:64:d3:97:da:0b:10:52:e9:ea:54",
    "6e:48:7b:ef:ea:9c:9d:9d:68:a0:c5:ea:dc:fe:ef",
    "75:a6:9b:b5:d6:fc:01:f4:2b:fb:ca:6e:b4:0b:cd",
    "64:c0:76:7e:36:ff:d0:5d:97:a8:13:c5:aa:0c:6c",
    "95:30:e7:9c:f5:f0:86:64:68:f1:38:06:42:0a:a5",
    "c8:51:84:0b:1e:25:25:40:e7:90:e4:b6:54:c3:85",
    "2e:d6:4a:f1:e8:65:7d",
]
data = binascii.unhexlify("".join(l.replace(":", "") for l in lines))
print(f"pub length: {len(data)} bytes (expect 1 + 2*48)")
assert data[0] == 0x04 and len(data) == 97

x = int.from_bytes(data[1:49], "big")
y = int.from_bytes(data[49:97], "big")

# Claimed private scalar: 0x73
claimed = 0x73
derived = ec.derive_private_key(claimed, ec.SECP384R1())
dpub = derived.public_key().public_numbers()

print(f"claimed  d = {claimed} ({claimed:#x})")
print(f"claimed  X = {x:096x}")
print(f"derived  X = {dpub.x:096x}")
print(f"claimed  Y = {y:096x}")
print(f"derived  Y = {dpub.y:096x}")

if (dpub.x, dpub.y) == (x, y):
    print("\nMATCH: pub == 0x73 * G on P-384 — the recovered scalar is correct.")
else:
    print("\nNO MATCH: 0x73 * G does not reproduce the published point.")

pem = derived.private_bytes(
    serialization.Encoding.PEM,
    serialization.PrivateFormat.PKCS8,
    serialization.NoEncryption(),
).decode()
print("\nReconstructed PKCS8 key (from the trivially-recovered scalar):")
print(pem)
