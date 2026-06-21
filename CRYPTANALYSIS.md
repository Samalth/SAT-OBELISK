# OBELISK-384 — Cryptanalysis Notes (empirical, critical)

**Date:** 2026-06-21 · **Tool:** [tools/analyze_arx.py](tools/analyze_arx.py)
**Status:** self-analysis. This is *evidence*, never a *proof*. Read §4 before trusting anything.

These are the **actual measured numbers** from a single run (seed fixed for reproducibility).
I am being deliberately critical: a finding that looks good is reported as "no problem
*detected*", not "secure".

---

## 1. ARX-box differential probability (the nonlinear layer of one round)

The ARX-box is two Speck128-style rounds on a 64-bit lane pair. Measured (key-independent,
40k samples per input difference, single-bit + random low-weight differences):

```
best found: p ≈ 0.246  (weight ≈ 2.0 bits)  via a difference in b, bit 63 (MSB)
```

**🔴 Concrete weakness found.** A single-bit difference in the **most significant bit**
propagates through the box with probability ~¼ (only ~2 bits of differential weight). This is
a *known, expected* ARX property: the carry out of the MSB of a modular addition is discarded,
so MSB differences behave almost linearly and are "cheap". On its own the ARX-box is therefore
**weak** — which is normal for only two Speck rounds (Speck needs ~20+ rounds for strength).

**Implication:** all of OBELISK's differential resistance must come from *accumulation* — the
linear layer + lane permutation forcing more active ARX-boxes each round, over 10–16 rounds.
**I have not bounded that accumulation.** See §3.

---

## 2. Single-bit differential bias over rounds (does diffusion kill simple trails?)

For a single-bit input difference, the max per-output-bit bias `|P(flip) − 0.5|` over 6 random
input positions (8k samples; sampling noise floor ≈ 0.0335):

| rounds | max bias | reading |
|-------:|---------:|---------|
| 1 | 0.500 | fully deterministic (no diffusion yet) |
| 2 | 0.500 | still deterministic |
| 3 | 0.023 | **at noise floor** — no bias detectable |
| 4 | 0.018 | at noise floor |
| 6 | 0.020 | at noise floor |
| 8 | 0.021 | at noise floor |
| 10 (B) | 0.019 | at noise floor |
| 16 (A) | 0.020 | at noise floor |

**Reading:** from **round 3** onward, no single output bit shows bias above sampling noise.
This matches the avalanche/full-diffusion result (3 rounds). With B=10 and A=16 there is a large
empirical margin over the point where *simple single-bit differentials* vanish. Good — but this
only tests the weakest possible distinguisher (one input bit), not constructed multi-bit trails.

## 3. Linear correlation (random masks)

Best correlation found over random input/output masks stays at/below the noise floor (≈0.047)
at 2, 4 and 10 rounds. **This is a weak test:** random masks almost never coincide with the best
linear approximation, so it only rules out *gross* linearity. It is **not** a linear-hull bound.

---

## 4. Honest conclusion (what this does and does not say)

**What the evidence supports:**
- The diffusion layer quickly destroys trivial single-bit differentials (≤3 rounds), with a
  comfortable round-count margin.
- No gross linear or differential distinguisher was detected by sampling.

**What it does NOT support — and the real gaps:**
1. **The ARX-box has a low-weight (~2-bit) MSB differential.** Security relies entirely on this
   being amplified by many rounds; that amplification is **unbounded here**.
2. **Sampling cannot find rare high-probability trails.** An adversary constructs the *best*
   trail; random sampling almost never sees it. Absence of detected bias ≠ absence of a trail.
3. **The correct analysis was not done.** A real security margin needs an **MILP- or SAT-based
   optimal-trail search** (Mouha et al., *Differential and Linear Cryptanalysis using MILP*;
   tools like CryptoSMT) to bound the *minimum number of active ARX operations* over r rounds,
   plus independent expert review. That is future work and needs a solver.

**Verdict:** these numbers are consistent with a non-broken design, but they are **not** a
security argument, and the MSB observation is a concrete reason for caution. **Do not rely on the
`obelisk` cipher for real data.** Use the vetted backends (`chacha20`, `aes256gcm`). The round
counts (A=16/B=10) look generously chosen relative to where simple distinguishers die, but
"looks generous" is not a proven margin.

### Suggested follow-up (if OBELISK is ever to be taken seriously)
- Run a SAT/MILP optimal differential & linear trail search; report min active boxes per round.
- Reconsider the ARX-box (extra round, or break MSB-linearity with rotation/constant injection).
- External cryptanalysis. Until then: research artifact only.
