from __future__ import annotations

from .permutation import permute, A_ROUNDS

RATE = 16
_IV_HASH = bytes([0x4F, 0x42, 0x4C, 0x4B, 0x48, A_ROUNDS, RATE, 0x20]) + b"\x00" * 8


def _init():
    iv0 = int.from_bytes(_IV_HASH[:8], "little")
    iv1 = int.from_bytes(_IV_HASH[8:16], "little")
    s = [iv0, iv1, 0, 0, 0, 0]
    return permute(s, A_ROUNDS)


def _absorb(s, data):
    full = len(data) // RATE
    for i in range(full):
        blk = data[i * RATE:(i + 1) * RATE]
        s[0] ^= int.from_bytes(blk[:8], "little")
        s[1] ^= int.from_bytes(blk[8:16], "little")
        s = permute(s, A_ROUNDS)
    rem = data[full * RATE:]
    blk = rem + b"\x01" + b"\x00" * (RATE - len(rem) - 1)
    s[0] ^= int.from_bytes(blk[:8], "little")
    s[1] ^= int.from_bytes(blk[8:16], "little")
    return permute(s, A_ROUNDS)


def _squeeze(s, length):
    out = bytearray()
    while len(out) < length:
        out += s[0].to_bytes(8, "little") + s[1].to_bytes(8, "little")
        if len(out) < length:
            s = permute(s, A_ROUNDS)
    return bytes(out[:length])


def hash(data, length=32):
    s = _init()
    s = _absorb(s, data)
    return _squeeze(s, length)


def xof(data, length):
    return hash(data, length)


def kdf(key_material, length, salt=b"", info=b""):
    s = _init()
    s = _absorb(s, len(salt).to_bytes(4, "little") + salt +
                len(key_material).to_bytes(4, "little") + key_material +
                len(info).to_bytes(4, "little") + info)
    return _squeeze(s, length)
