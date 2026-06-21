# OBELISK-384 — Reviewer Checklist & Questionnaire

**For:** an independent cryptographer / tester evaluating OBELISK.
**Date created:** 2026-06-21 · **Target version:** see [`obelisk/__init__.py`](obelisk/__init__.py) (`__version__`).

This is a structured walk-through for someone reviewing the design. It is deliberately
adversarial: the goal is to **find problems**, not to confirm that it works. A "pass" on a
question means *"no problem detected by this check"* — never *"proven secure"*.

> **Scope note.** The custom part of OBELISK is the **permutation** and the way the modes are
> wired together. The modes themselves (Ascon-style duplex AEAD, sponge hash/XOF, X25519 for
> key exchange) are reused from peer-reviewed designs. Spend your effort on the permutation and
> the wiring, not on re-deriving the sponge security proof.

---

## How to use this document

1. Work top to bottom. Each item has a **claim**, **how to check**, and a **verdict box**.
2. Fill in each verdict: `PASS` / `FAIL` / `UNCLEAR` / `OUT-OF-SCOPE`, plus a note.
3. Anything `FAIL` or `UNCLEAR` → record it in the [Findings log](#findings-log) at the bottom.
4. Reproduce the author's numbers before trusting them (item 0).

Reference documents you will need:
- Design rationale: [`DESIGN.md`](DESIGN.md)
- Author's self-cryptanalysis: [`CRYPTANALYSIS.md`](CRYPTANALYSIS.md)
- Threat model: [`THREAT_MODEL.md`](THREAT_MODEL.md)
- Permutation: [`obelisk/permutation.py`](obelisk/permutation.py) · AEAD: [`obelisk/aead.py`](obelisk/aead.py)
- Tools: [`tools/analyze_arx.py`](tools/analyze_arx.py) · [`tests/test_diffusion.py`](tests/test_diffusion.py)

---

## 0. Reproducibility (do this first)

| # | Claim | How to check |
|---|-------|--------------|
| 0.1 | The test suite passes on a clean checkout. | `python -m pytest -q` (or run the files in `tests/`). |
| 0.2 | The diffusion/bijectivity numbers reproduce. | `python tests/test_diffusion.py` — confirm bijectivity OK, avalanche ≈ 50%, full diffusion = 3 rounds. |
| 0.3 | The ARX/differential/linear numbers reproduce. | `python tools/analyze_arx.py` (seed is fixed). Confirm the ~¼ MSB differential is reported. |
| 0.4 | Test vectors (KATs) match across a re-implementation. | Re-implement `permute` from the spec in another language; check it against `tests/`. **Are there published KATs to check against?** |

> ☐ Verdict 0: __________________________________________________

---

## 1. The permutation — structure

| # | Claim | How to check |
|---|-------|--------------|
| 1.1 | `permute` is a bijection for all round counts used. | `permute_inv(permute(s,r),r) == s`. Covered by `test_bijectivity` — extend to r ∈ {1..16}. |
| 1.2 | The linear layer is invertible by construction (unit-triangular over GF(2)). | Inspect `linear` / `linear_inv` in [`permutation.py`](obelisk/permutation.py). Confirm each is the other's inverse independent of constants. |
| 1.3 | The ARX-box is invertible. | `arxbox_inv(arxbox(a,b,k),k) == (a,b)` for random a,b,k. |
| 1.4 | The lane permutation actually moves box boundaries each round (no 3 lanes stay isolated). | Trace which lane-pairs feed each ARX-box over consecutive rounds. A fixed pairing would be fatal. |
| 1.5 | Round constants are distinct, non-zero, and "nothing-up-my-sleeve". | Inspect `round_constant` (π words ⊕ golden-ratio multiple). Confirm no collisions / zeros over the rounds used; confirm the derivation is reproducible from stated constants. |
| 1.6 | No fixed points / symmetries the constants fail to break. | Check `permute(all-zero, r) ≠ all-zero`; look for rotational or slide symmetry the constant schedule should destroy. |

> ☐ Verdict 1: __________________________________________________

---

## 2. The permutation — diffusion & statistical behaviour

| # | Claim | How to check |
|---|-------|--------------|
| 2.1 | Full diffusion (every input bit reaches every output bit) within a few rounds. | `full_diffusion_round()` in `test_diffusion.py` reports **3**. Verify independently. |
| 2.2 | Avalanche ≈ 50% with reasonable spread by the data-round count. | `avalanche()` → mean ≈ 192/384. Check the **min/max** spread, not just the mean. |
| 2.3 | Round-count margin over full diffusion is honestly stated. | Author claims ~3.3× (b=10) / ~5.3× (a=16) over full diffusion (3 rounds). Is "margin over full diffusion" a *meaningful* security margin, or a weak proxy? (It is a weak proxy — see §4.) |
| 2.4 | No single-bit differential bias survives past a few rounds. | `differential_bias_decay()` in `analyze_arx.py`. Note this only tests the **weakest** distinguisher. |

> ☐ Verdict 2: __________________________________________________

---

## 3. The permutation — the analysis that actually matters

This is where a real review earns its keep. The author explicitly states this work was **not** done.

| # | Question | What a real answer requires |
|---|----------|------------------------------|
| 3.1 | What is the **minimum number of active ARX-boxes** over *r* rounds? | MILP/SAT optimal-trail search (Mouha et al.; CryptoSMT / a SAT model of the ARX-box + linear layer). |
| 3.2 | What is the best **differential trail** probability over b=10 and a=16 rounds? | Bound it; compare to 2⁻¹²⁸. The ~¼ MSB box differential (CRYPTANALYSIS §1) must be shown to *not* chain cheaply. |
| 3.3 | What is the best **linear trail** correlation / linear-hull estimate? | Same machinery for linear masks. Sampling (analyze_arx §C) is explicitly *not* a hull bound. |
| 3.4 | Any **rotational, slide, invariant-subspace, or integral/division-property** distinguisher? | Dedicated structural cryptanalysis of the round function. |
| 3.5 | Any **algebraic** weakness (low degree growth, cube/AIDA)? | Degree-estimation over rounds. |
| 3.6 | Is the round count chosen with a **proven** margin, or just "looks generous"? | Compare min-active-boxes × box-weight to the 128-bit target, with a stated margin factor. |

> ☐ Verdict 3 (the decisive one): __________________________________________________

---

## 4. The modes (reused designs — verify the *wiring*, not the proofs)

| # | Claim | How to check |
|---|-------|--------------|
| 4.1 | The AEAD matches the Ascon-style duplex it claims to reuse (init, AD, PT, finalize, domain separation). | Compare `aead.py` against `DESIGN.md §3` and the Ascon mode. Look for off-by-one in padding (`10*`), domain-separation bit, rate/capacity split. |
| 4.2 | Rate/capacity are r=128 / c=256, giving a **128-bit** security target — and this is stated, not implied as 256. | Confirm `RATE`, key/nonce/tag sizes; confirm hash collision resistance is claimed as 128-bit (capacity/2), see `DESIGN §7b`. |
| 4.3 | Tag comparison is constant-time. | Inspect `_ct_eq` in `aead.py`. |
| 4.4 | Nonce-reuse is documented as catastrophic and the file format avoids it (per-file salt → subkey). | `DESIGN §3` + `§7c`; check `filecrypt.py` derives a per-file subkey so nonces don't repeat under one master key. |
| 4.5 | Decryption rejects on tag mismatch **before** releasing plaintext where it matters; padding/format errors don't leak via distinguishable behaviour. | Trace `decrypt` / `unseal` error paths. |
| 4.6 | The header is authenticated as associated data (no downgrade/tamper). | `DESIGN §7c`; verify the header bytes are fed as AD. |
| 4.7 | X25519 is used for the DH (not home-rolled), with only transcript-binding/KDF via the sponge. | `DESIGN §6`; confirm the `cryptography` X25519 is the DH and the sponge only does KDF/transcript. |

> ☐ Verdict 4: __________________________________________________

---

## 5. Implementation & operational

| # | Claim | How to check |
|---|-------|--------------|
| 5.1 | No secret-dependent table lookups or branches (ARX is the point). | Inspect hot paths; note the author does **not** claim full side-channel freedom in Python (`DESIGN §7`). |
| 5.2 | Key material handling limitations are disclosed (no secure wipe in Python). | `DESIGN §7b`. Confirm it's stated, not hidden. |
| 5.3 | Output is atomic (no partial file on failure). | `filecrypt.py` temp-file + `os.replace()`. |
| 5.4 | Password KDF is memory-hard (Argon2id) when available, with a flagged fallback. | `DESIGN §7c`; confirm the fallback is marked in the header so decryption picks the right KDF. |
| 5.5 | The "research-grade / not for production" warning is prominent and not contradicted elsewhere. | `README.md`, `DESIGN §0`. |

> ☐ Verdict 5: __________________________________________________

---

## 6. Documentation honesty

| # | Question |
|---|----------|
| 6.1 | Does any document claim or imply security that the analysis does not support? |
| 6.2 | Are all "we measured X" claims backed by a runnable, seeded tool? |
| 6.3 | Is the gap between "no distinguisher *detected*" and "secure" stated clearly? |
| 6.4 | Are the reused vs. original parts clearly separated (so a reviewer knows where to look)? |

> ☐ Verdict 6: __________________________________________________

---

## Findings log

| ID | Item | Severity (info/low/med/high/critical) | Description | Reproduction |
|----|------|----------------------------------------|-------------|--------------|
|    |      |                                        |             |              |

---

## Reviewer sign-off

- Reviewer: ____________________  Affiliation: ____________________  Date: __________
- Time spent: __________  Tooling used (MILP/SAT solver, etc.): ____________________
- **Overall verdict:** ☐ no blocking issues found by this review  ☐ issues found (see log)
- **Explicit statement of limits:** this review covered ______________________________ and did
  **not** cover ______________________________. It is not a security guarantee.

---

### A note to whoever fills this in

If you only have time for one section, do **§3**. Everything else is hygiene; §3 is the
question that decides whether OBELISK has a real security margin or just an absence of obvious
bugs. The author agrees this is the open gap — see `CRYPTANALYSIS.md §4`.
