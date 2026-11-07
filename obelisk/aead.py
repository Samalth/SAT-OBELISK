from __future__ import annotations

import os

from .permutation import permute, A_ROUNDS, B_ROUNDS
from .sponge import RATE, lanes, rate_bytes, xor_rate, set_rate, pad, absorb

KEY_BYTES = 16
NONCE_BYTES = 16
TAG_BYTES = 16

_IV = bytes([0x4F, 0x42, 0x4C, 0x4B, A_ROUNDS, B_ROUNDS, RATE, KEY_BYTES]) + b"\x00" * 8


class TagMismatch(Exception):
    pass


def _init(key, nonce):
    k0, k1 = lanes(key)
    n0, n1 = lanes(nonce)
    iv0, iv1 = lanes(_IV)
    s = [iv0, iv1, k0, k1, n0, n1]
    s = permute(s, A_ROUNDS)
    s[4] ^= k0
    s[5] ^= k1
    return s


def _absorb_ad(s, ad):
    if ad:
        absorb(s, ad, B_ROUNDS)
    s[5] ^= 1


def _finalize(s, key):
    k0, k1 = lanes(key)
    s[2] ^= k0
    s[3] ^= k1
    s = permute(s, A_ROUNDS)
    return (s[4] ^ k0).to_bytes(8, "little") + (s[5] ^ k1).to_bytes(8, "little")


def encrypt(key, nonce, plaintext, associated_data=b""):
    if len(key) != KEY_BYTES or len(nonce) != NONCE_BYTES:
        raise ValueError("key and nonce must be 16 bytes")
    s = _init(key, nonce)
    _absorb_ad(s, associated_data)

    out = bytearray()
    full = len(plaintext) // RATE
    for i in range(full):
        xor_rate(s, plaintext[i * RATE:(i + 1) * RATE])
        out += rate_bytes(s)
        s = permute(s, B_ROUNDS)
    rem = plaintext[full * RATE:]
    xor_rate(s, pad(rem))
    out += rate_bytes(s)[:len(rem)]

    tag = _finalize(s, key)
    return bytes(out), tag


def decrypt(key, nonce, ciphertext, tag, associated_data=b""):
    if len(key) != KEY_BYTES or len(nonce) != NONCE_BYTES:
        raise ValueError("key and nonce must be 16 bytes")
    if len(tag) != TAG_BYTES:
        raise ValueError("tag must be 16 bytes")
    s = _init(key, nonce)
    _absorb_ad(s, associated_data)

    out = bytearray()
    full = len(ciphertext) // RATE
    for i in range(full):
        c = ciphertext[i * RATE:(i + 1) * RATE]
        r = rate_bytes(s)
        out += bytes(a ^ b for a, b in zip(r, c))
        set_rate(s, c)
        s = permute(s, B_ROUNDS)
    rem = ciphertext[full * RATE:]
    r = rate_bytes(s)
    out += bytes(a ^ b for a, b in zip(r[:len(rem)], rem))
    block = bytearray(r)
    block[:len(rem)] = rem
    block[len(rem)] ^= 0x01
    set_rate(s, bytes(block))

    expected = _finalize(s, key)
    if not _ct_eq(expected, tag):
        raise TagMismatch("authentication failed: ciphertext or AD was tampered with")
    return bytes(out)


def _ct_eq(a, b):
    if len(a) != len(b):
        return False
    diff = 0
    for x, y in zip(a, b):
        diff |= x ^ y
    return diff == 0


def seal(key, plaintext, associated_data=b""):
    nonce = os.urandom(NONCE_BYTES)
    ct, tag = encrypt(key, nonce, plaintext, associated_data)
    return nonce + ct + tag


def unseal(key, sealed, associated_data=b""):
    if len(sealed) < NONCE_BYTES + TAG_BYTES:
        raise ValueError("sealed message too short")
    nonce = sealed[:NONCE_BYTES]
    tag = sealed[-TAG_BYTES:]
    ct = sealed[NONCE_BYTES:-TAG_BYTES]
    return decrypt(key, nonce, ct, tag, associated_data)
