"""Archive encryption. Standard library only.

No dependencies, deliberately. I am asking people to download this and run it.
"pip install" before you can even start loses half of them and breaks the
environment of the other half.

scrypt for the derivation -- memory-hard, and in hashlib since 3.6 -- then an
HMAC-SHA256 keystream in counter mode and an HMAC tag. Ordinary construction,
without AES, which the standard library does not expose.
"""

import hashlib
import hmac
import struct

SALT = b"aldercrest.atlas.core.v1"
# OpenSSL refuses scrypt above 32 MB by default and raises an opaque error
# ("memory limit exceeded"). Stay under it AND pass maxmem explicitly: without
# that it works here and breaks on a machine with a stricter build. The
# strength does not come from these numbers anyway.
N, R, P = 2 ** 14, 8, 1
MAXMEM = 64 * 1024 * 1024


def derive(*parts):
    """Credentials -> 64 byte key (32 for the cipher, 32 for the tag)."""
    material = "\x1f".join(p.strip().upper() for p in parts).encode("utf-8")
    return hashlib.scrypt(material, salt=SALT, n=N, r=R, p=P,
                          maxmem=MAXMEM, dklen=64)


# Separate salt: the account table and the archive must not be able to teach
# each other anything. The name and the password are hashed separately, so the
# service can answer "no such account" without anyone being able to read out of
# this file which account does exist.
ACCOUNT_SALT = b"aldercrest.atlas.core.accounts"


def account_hash(*parts):
    """Account identifier -> hex digest. One way."""
    material = "\x1f".join(p.strip().upper() for p in parts).encode("utf-8")
    return hashlib.scrypt(material, salt=ACCOUNT_SALT, n=N, r=R, p=P,
                          maxmem=MAXMEM, dklen=32).hex()


def _stream(key, n):
    out = bytearray()
    ctr = 0
    while len(out) < n:
        out += hmac.new(key, struct.pack(">Q", ctr), hashlib.sha256).digest()
        ctr += 1
    return bytes(out[:n])


def seal(plaintext, key):
    ek, ak = key[:32], key[32:]
    ct = bytes(a ^ b for a, b in zip(plaintext, _stream(ek, len(plaintext))))
    return hmac.new(ak, ct, hashlib.sha256).digest() + ct


def unseal(blob, key):
    """Renvoie le clair, ou leve ValueError. Aucun demi-succes possible."""
    ek, ak = key[:32], key[32:]
    tag, ct = blob[:32], blob[32:]
    if not hmac.compare_digest(tag, hmac.new(ak, ct, hashlib.sha256).digest()):
        raise ValueError("archive: authentication failed")
    return bytes(a ^ b for a, b in zip(ct, _stream(ek, len(ct))))
