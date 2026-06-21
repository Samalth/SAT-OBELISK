# OBELISK — Threat Model

**Version:** file format v3 · **Date:** 2026-06-21
**Status:** research / educational. Read [DESIGN.md](DESIGN.md) §0 first.

This document states *who* OBELISK defends against, *what* it protects, and — just as
important — *what it explicitly does not protect*. A security claim without a threat model
is meaningless, so this is deliberately precise and conservative.

---

## 1. Assets (what we protect)

| Asset | Protection goal |
|-------|-----------------|
| File / folder contents | Confidentiality + integrity at rest |
| File metadata bound in the header (cipher id, flags, salt) | Integrity (authenticated) |
| Keys (raw key, keyfile, derived key) | Confidentiality |

**Not an asset here:** the *existence*, *size*, *name*, and *modification time* of an encrypted
file. These leak by design (see §4).

---

## 2. Attacker model (who we defend against)

We assume a **realistic offline adversary**:

- **A1 — Storage attacker.** Can read, copy, modify, reorder, truncate, or delete the encrypted
  `.obl` file(s) on disk, in backups, or in transit. Does **not** have the key.
- **A2 — Tamper/forgery attacker.** Tries to make a modified ciphertext decrypt to attacker-chosen
  or attacker-useful plaintext, or to pass authentication.
- **A3 — Offline brute-force attacker.** Has the `.obl` file and tries to guess the password,
  including reimplementing the KDF on GPU/ASIC.
- **A4 — Downgrade attacker.** Tries to force a weaker cipher/KDF than the one chosen at encryption.

We do **not** defend against the adversaries in §5.

---

## 3. Guarantees (what holds, and why)

| # | Guarantee | Mechanism | Holds against |
|---|-----------|-----------|---------------|
| G1 | Confidentiality of contents | AEAD encryption per chunk | A1 |
| G2 | Integrity / tamper-evidence | AEAD tag per chunk; decryption refuses on mismatch | A1, A2 |
| G3 | No reordering of chunks | chunk counter is the AEAD nonce **and** in the AD | A1, A2 |
| G4 | No truncation | authenticated final-chunk flag; missing final chunk → error | A1, A2 |
| G5 | No header tamper / downgrade | full header (incl. cipher id + flags) is AD of chunk 0 | A2, A4 |
| G6 | No cross-file nonce reuse | per-file 128-bit random salt → per-file subkey | A1 (key-recovery via two-time pad) |
| G7 | Password stretching | Argon2id (memory-hard) when available | A3 (partially — see §5) |
| G8 | No release of unverified plaintext | each chunk is verified *before* it is written | A2 |
| G9 | Failed operation leaves no partial output | atomic temp-file + `os.replace()` | operational integrity |
| G10 | Constant-time tag comparison | `_ct_eq` for OBELISK; vetted libs for ChaCha/AES | timing side-channel on the tag |

**Cipher choice.** With `--cipher chacha20` or `--cipher aes256gcm`, G1–G2 rest on
**vetted, standardized** primitives (the `cryptography` library). With the default
`--cipher obelisk`, they rest on an **unanalyzed** primitive — see §5.

---

## 4. Accepted leakage (by design)

- **File size** leaks (ciphertext length ≈ plaintext length + per-chunk overhead). No length hiding.
- **Folder structure size** leaks via the tar size; individual filenames inside are hidden (the whole
  tar is encrypted) but the *total* size is visible.
- **Existence and timing** of encryption operations are not hidden.
- **Which cipher/KDF** was used is stored in the cleartext header (authenticated, but visible).

If hiding size/existence matters, that is out of scope and needs padding/traffic-analysis defenses
this tool does not provide.

---

## 5. Out of scope / explicit non-goals

- **NG1 — Cryptanalysis of the OBELISK permutation.** The default cipher has **not** undergone
  independent cryptanalysis. Round counts (A=16, B=10) are justified only by statistical diffusion,
  which is necessary but **not sufficient**. Do not rely on the `obelisk` cipher for real data;
  use `chacha20`/`aes256gcm`, or AES-GCM/Ascon outside this tool.
- **NG2 — Strong password security in pure Python.** Without `argon2-cffi`, the fallback KDF is a
  fast iterated sponge (~1500 iters) and is **weak** against GPU/ASIC brute force. Even with Argon2id,
  a low-entropy password is guessable. Prefer a random keyfile.
- **NG3 — Memory secrets / secure wipe.** Python `bytes`/`str` are immutable; keys and passwords may
  linger in memory and swap. Not defended.
- **NG4 — Endpoint compromise.** Malware, keyloggers, or a compromised OS/clipboard defeat any file
  encryptor. Out of scope.
- **NG5 — Side channels beyond the tag compare.** Cache/timing/power analysis of the pure-Python
  OBELISK permutation is not addressed (ARX is table-free, which helps, but Python gives no guarantee).
- **NG6 — Key management lifecycle.** Key escrow, rotation, revocation, and secure backup of keyfiles
  are the user's responsibility. Losing a keyfile = losing the data.
- **NG7 — Multi-user / access control.** No per-user keys, no authorization model.

---

## 6. Operational guidance

1. **For anything real, select a vetted cipher** (`chacha20` or `aes256gcm`) — or don't use this tool.
2. **Prefer keyfiles over passwords.** Back them up securely; their loss is unrecoverable.
3. **Never reuse a raw key + nonce manually** via the low-level API; the file format handles this
   correctly, the low-level `encrypt()` does not.
4. **Treat the `.obl` header as public.** It authenticates but does not hide metadata.
