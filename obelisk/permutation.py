from __future__ import annotations

MASK64 = (1 << 64) - 1
NLANES = 6
A_ROUNDS = 16
B_ROUNDS = 10


def rol(x: int, n: int) -> int:
    n &= 63
    return ((x << n) | (x >> (64 - n))) & MASK64


def ror(x: int, n: int) -> int:
    n &= 63
    return ((x >> n) | (x << (64 - n))) & MASK64


_PI_WORDS = [
    0x243F6A8885A308D3, 0x13198A2E03707344, 0xA4093822299F31D0,
    0x082EFA98EC4E6C89, 0x452821E638D01377, 0xBE5466CF34E90C6C,
    0xC0AC29B7C97C50DD, 0x3F84D5B5B5470917, 0x9216D5D98979FB1B,
    0xD1310BA698DFB5AC, 0x2FFD72DBD01ADFB7, 0xB8E1AFED6A267E96,
    0xBA7C9045F12C7F99, 0x24A19947B3916CF7, 0x0801F2E2858EFC16,
    0x636920D871574E69, 0xA458FEA3F4933D7E, 0x0D95748F728EB658,
    0x718BCD5882154AEE, 0x7B54A41DC25A59B5,
]


def round_constant(i: int) -> int:
    return _PI_WORDS[i % len(_PI_WORDS)] ^ ((0x9E3779B97F4A7C15 * (i + 1)) & MASK64)


def arxbox(a: int, b: int, k: int) -> tuple[int, int]:
    a = (ror(a, 8) + b) & MASK64
    a ^= k
    b = rol(b, 3) ^ a
    a = (ror(a, 8) + b) & MASK64
    b = rol(b, 3) ^ a
    return a, b


def arxbox_inv(a: int, b: int, k: int) -> tuple[int, int]:
    b = rol(b ^ a, 61)
    a = (a - b) & MASK64
    a = rol(a, 8)
    b = rol(b ^ a, 61)
    a ^= k
    a = (a - b) & MASK64
    a = rol(a, 8)
    return a, b


_FWD = (19, 28, 41, 7, 53, 38)
_BWD = (11, 47, 23, 61, 31, 5)


def linear(s: list[int]) -> list[int]:
    x0, x1, x2, x3, x4, x5 = s
    a, b, c, d, e, f = _FWD
    x1 ^= rol(x0, a); x2 ^= rol(x1, b); x3 ^= rol(x2, c)
    x4 ^= rol(x3, d); x5 ^= rol(x4, e); x0 ^= rol(x5, f)
    g, h, i, j, k, l = _BWD
    x4 ^= rol(x5, g); x3 ^= rol(x4, h); x2 ^= rol(x3, i)
    x1 ^= rol(x2, j); x0 ^= rol(x1, k); x5 ^= rol(x0, l)
    return [x5, x0, x1, x2, x3, x4]


def linear_inv(s: list[int]) -> list[int]:
    x5, x0, x1, x2, x3, x4 = s
    g, h, i, j, k, l = _BWD
    x5 ^= rol(x0, l); x0 ^= rol(x1, k); x1 ^= rol(x2, j)
    x2 ^= rol(x3, i); x3 ^= rol(x4, h); x4 ^= rol(x5, g)
    a, b, c, d, e, f = _FWD
    x0 ^= rol(x5, f); x5 ^= rol(x4, e); x4 ^= rol(x3, d)
    x3 ^= rol(x2, c); x2 ^= rol(x1, b); x1 ^= rol(x0, a)
    return [x0, x1, x2, x3, x4, x5]


def _round(s: list[int], i: int) -> list[int]:
    s = s[:]
    rc = round_constant(i)
    s[0] ^= rc
    s[0], s[1] = arxbox(s[0], s[1], rc)
    s[2], s[3] = arxbox(s[2], s[3], ror(rc, 21))
    s[4], s[5] = arxbox(s[4], s[5], ror(rc, 42))
    return linear(s)


def _round_inv(s: list[int], i: int) -> list[int]:
    s = linear_inv(s)
    rc = round_constant(i)
    s[4], s[5] = arxbox_inv(s[4], s[5], ror(rc, 42))
    s[2], s[3] = arxbox_inv(s[2], s[3], ror(rc, 21))
    s[0], s[1] = arxbox_inv(s[0], s[1], rc)
    s[0] ^= rc
    return s


def permute(state: list[int], rounds: int) -> list[int]:
    s = state
    for i in range(rounds):
        s = _round(s, i)
    return s


def permute_inv(state: list[int], rounds: int) -> list[int]:
    s = state
    for i in reversed(range(rounds)):
        s = _round_inv(s, i)
    return s


def bytes_to_state(b: bytes) -> list[int]:
    if len(b) != 48:
        raise ValueError("state must be 48 bytes")
    return [int.from_bytes(b[8 * i:8 * i + 8], "little") for i in range(NLANES)]


def state_to_bytes(s: list[int]) -> bytes:
    return b"".join(int(w & MASK64).to_bytes(8, "little") for w in s)
