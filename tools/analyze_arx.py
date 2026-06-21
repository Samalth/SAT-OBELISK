import os
import sys
import math
import random

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from obelisk.permutation import (
    arxbox, permute, bytes_to_state, state_to_bytes, A_ROUNDS, B_ROUNDS, MASK64,
)

STATE_BITS = 384


def rnd64():
    return random.getrandbits(64)


def box_best_diff(da, db, samples):
    counts = {}
    for _ in range(samples):
        a, b = rnd64(), rnd64()
        o1 = arxbox(a, b, 0)
        o2 = arxbox(a ^ da, b ^ db, 0)
        d = (o1[0] ^ o2[0], o1[1] ^ o2[1])
        counts[d] = counts.get(d, 0) + 1
    best = max(counts.values())
    return best / samples


def arxbox_differential(samples=40000):
    print("A. ARX-box differential probability (empirical, key-independent)")
    print("   best output-difference probability per input difference; lower = stronger")
    best_overall = 0.0
    best_desc = ""
    diffs = []
    for bit in range(64):
        diffs.append(((1 << bit, 0), f"a:bit{bit}"))
        diffs.append((0, 1 << bit) if False else ((0, 1 << bit), f"b:bit{bit}"))
    for _ in range(40):
        diffs.append(((rnd64() & rnd64(), rnd64() & rnd64()), "random-lowweight"))
    sampled = random.sample(diffs, 48)
    for (da, db), desc in sampled:
        if da == 0 and db == 0:
            continue
        p = box_best_diff(da, db, samples)
        if p > best_overall:
            best_overall, best_desc = p, desc
    w = -math.log2(best_overall) if best_overall > 0 else float("inf")
    print(f"   best found: p={best_overall:.5f}  (weight {w:.1f} bits)  via {best_desc}")
    print(f"   note: sampling finds a LOWER bound on the true max differential probability.\n")
    return best_overall


def bit_bias(rounds, in_bit, samples):
    flip = [0] * STATE_BITS
    for _ in range(samples):
        s = bytes_to_state(os.urandom(48))
        s2 = s[:]
        s2[in_bit // 64] ^= (1 << (in_bit % 64))
        o1 = int.from_bytes(state_to_bytes(permute(s, rounds)), "little")
        o2 = int.from_bytes(state_to_bytes(permute(s2, rounds)), "little")
        d = o1 ^ o2
        for j in range(STATE_BITS):
            flip[j] += (d >> j) & 1
    return max(abs(c / samples - 0.5) for c in flip)


def differential_bias_decay(samples=8000):
    print("B. Single-bit differential: max per-output-bit bias |P(flip)-0.5|")
    noise = 3.0 / math.sqrt(samples)
    print(f"   sampling noise floor ~ {noise:.4f} ({samples} samples). Ideal = 0.\n")
    in_bits = random.sample(range(STATE_BITS), 6)
    for r in (1, 2, 3, 4, 6, 8, B_ROUNDS, A_ROUNDS):
        worst = max(bit_bias(r, b, samples) for b in in_bits)
        flag = "  <-- above noise" if worst > 2 * noise else ""
        print(f"   {r:2d} rounds: max bias = {worst:.4f}{flag}")
    print()


def linear_corr(rounds, samples, trials):
    best = 0.0
    for _ in range(trials):
        im = random.getrandbits(STATE_BITS)
        om = random.getrandbits(STATE_BITS)
        if im == 0 or om == 0:
            continue
        acc = 0
        for _ in range(samples):
            s = bytes_to_state(os.urandom(48))
            o = int.from_bytes(state_to_bytes(permute(s, rounds)), "little")
            si = int.from_bytes(state_to_bytes(s), "little")
            par = bin(si & im).count("1") + bin(o & om).count("1")
            acc += (par & 1)
        corr = abs(acc / samples - 0.5)
        best = max(best, corr)
    return best


def linear_sampling(samples=4000, trials=200):
    print("C. Linear correlation of RANDOM masks (sampling, weak estimate)")
    noise = 3.0 / math.sqrt(samples)
    for r in (2, 4, B_ROUNDS):
        c = linear_corr(r, samples, trials)
        print(f"   {r:2d} rounds: best random-mask correlation = {c:.4f} (noise ~ {noise:.4f})")
    print("   note: random masks almost never hit the best linear approximation;")
    print("   this only rules out gross linearity, it is NOT a hull/correlation bound.\n")


if __name__ == "__main__":
    random.seed(20260621)
    print("=" * 64)
    print("OBELISK-384 ARX cryptanalysis (empirical, NOT a proof)")
    print("=" * 64 + "\n")
    arxbox_differential()
    differential_bias_decay()
    linear_sampling()
    print("Interpretation: see CRYPTANALYSIS.md. Empirical absence of bias is")
    print("evidence against trivial distinguishers, never a security proof.")
