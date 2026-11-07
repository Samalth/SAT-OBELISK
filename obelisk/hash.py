from __future__ import annotations

from .permutation import permute, A_ROUNDS
from .sponge import RATE, lanes, rate_bytes, absorb

_IV_HASH = bytes([0x4F, 0x42, 0x4C, 0x4B, 0x48, A_ROUNDS, RATE, 0x20]) + b"\x00" * 8


def _init():
    iv0, iv1 = lanes(_IV_HASH)
    return permute([iv0, iv1, 0, 0, 0, 0], A_ROUNDS)


def _squeeze(s, length):
    out = bytearray()
    while len(out) < length:
        out += rate_bytes(s)
        if len(out) < length:
            s = permute(s, A_ROUNDS)
    return bytes(out[:length])


def hash(data, length=32):
    s = _init()
    absorb(s, data, A_ROUNDS)
    return _squeeze(s, length)


def xof(data, length):
    return hash(data, length)


def kdf(key_material, length, salt=b"", info=b""):
    s = _init()
    absorb(s, len(salt).to_bytes(4, "little") + salt +
           len(key_material).to_bytes(4, "little") + key_material +
           len(info).to_bytes(4, "little") + info, A_ROUNDS)
    return _squeeze(s, length)
