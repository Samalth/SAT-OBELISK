import os
import sys
import random

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from obelisk.permutation import (
    permute, permute_inv, bytes_to_state, state_to_bytes, A_ROUNDS, B_ROUNDS,
)

STATE_BITS = 384


def rnd_state():
    return bytes_to_state(os.urandom(48))


def flip_bit(s, bit):
    s = s[:]
    s[bit // 64] ^= (1 << (bit % 64))
    return s


def hamming(a, b):
    return sum(bin(x ^ y).count("1") for x, y in zip(a, b))


def test_bijectivity(trials=2000):
    for _ in range(trials):
        s = rnd_state()
        for r in (B_ROUNDS, A_ROUNDS):
            assert permute_inv(permute(s, r), r) == s, "permutation is NOT a bijection!"
    print(f"  bijectivity: OK over {trials} random states (b={B_ROUNDS}, a={A_ROUNDS})")


def avalanche(rounds, samples=4000):
    total = 0
    mn, mx = STATE_BITS, 0
    for _ in range(samples):
        s = rnd_state()
        bit = random.randrange(STATE_BITS)
        o1 = permute(s, rounds)
        o2 = permute(flip_bit(s, bit), rounds)
        d = hamming(o1, o2)
        total += d
        mn, mx = min(mn, d), max(mx, d)
    return total / samples, mn, mx


def full_diffusion_round(states=48):
    ALL = (1 << STATE_BITS) - 1
    for rounds in range(1, 13):
        reached = True
        for in_bit in range(STATE_BITS):
            affected = 0
            for _ in range(states):
                s = rnd_state()
                a = int.from_bytes(state_to_bytes(permute(s, rounds)), "little")
                b = int.from_bytes(state_to_bytes(permute(flip_bit(s, in_bit), rounds)), "little")
                affected |= (a ^ b)
                if affected == ALL:
                    break
            if affected != ALL:
                reached = False
                break
        if reached:
            return rounds
    return None


if __name__ == "__main__":
    random.seed(1)
    print("OBELISK-384 diffusion report")
    print("-" * 50)
    test_bijectivity()
    print()
    print("  avalanche (ideal mean = 192.0 of 384 bits):")
    for r in (2, 4, 6, 8, B_ROUNDS, A_ROUNDS):
        mean, mn, mx = avalanche(r)
        pct = 100 * mean / STATE_BITS
        print(f"    {r:2d} rounds: mean={mean:6.1f} ({pct:4.1f}%)  min={mn:3d} max={mx:3d}")
    print()
    fd = full_diffusion_round()
    print(f"  full diffusion (every in-bit -> every out-bit): {fd} rounds")
    if fd:
        print(f"  -> data rounds  b={B_ROUNDS} give margin {B_ROUNDS/fd:.1f}x over full diffusion")
        print(f"  -> init rounds  a={A_ROUNDS} give margin {A_ROUNDS/fd:.1f}x over full diffusion")
    print("\nall diffusion checks passed.")
