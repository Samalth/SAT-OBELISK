from __future__ import annotations

from .permutation import permute

RATE = 16


def lanes(b16):
    return int.from_bytes(b16[:8], "little"), int.from_bytes(b16[8:16], "little")


def rate_bytes(s):
    return s[0].to_bytes(8, "little") + s[1].to_bytes(8, "little")


def xor_rate(s, b16):
    a, b = lanes(b16)
    s[0] ^= a
    s[1] ^= b


def set_rate(s, b16):
    s[0], s[1] = lanes(b16)


def pad(tail):
    return tail + b"\x01" + b"\x00" * (RATE - len(tail) - 1)


def absorb(s, data, rounds):
    full = len(data) // RATE
    for i in range(full):
        xor_rate(s, data[i * RATE:(i + 1) * RATE])
        s[:] = permute(s, rounds)
    xor_rate(s, pad(data[full * RATE:]))
    s[:] = permute(s, rounds)
