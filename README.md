# OBELISK

A small sponge-based cryptosystem built on one 384-bit permutation: authenticated
encryption, hashing, key derivation, key-wrapping and file encryption.

It's a research and teaching project. The custom `obelisk` cipher has never been
independently reviewed, so don't trust it with real secrets. For real data pick one
of the vetted backends, `chacha20` or `aes256gcm`, which run on the audited
pyca/cryptography library. Even then, the file format, key derivation and nonce
handling around the cipher are still home-grown code, so treat the whole tool as
experimental, not just the permutation.

## Usage

### Command line

```
python -m obelisk genkey --out my.key --label "laptop"   # create a keyfile
python -m obelisk fingerprint --keyfile my.key           # show key fingerprint
python -m obelisk encrypt in.dat out.obl --keyfile my.key
python -m obelisk decrypt out.obl back.dat --keyfile my.key
```

Other key sources:

```
python -m obelisk genkey                                 # print a random key (hex)
python -m obelisk encrypt in.dat out.obl --key <32-hex>
python -m obelisk encrypt in.dat out.obl --password "pw"   # convenience-grade only
```

Password mode isn't memory-hard, so prefer a keyfile for anything serious. And back
up your keyfile: lose it and the data is gone.

### Graphical app

```
python app.py                                  # run the GUI
powershell -ExecutionPolicy Bypass -File build_exe.ps1   # build dist\Obelisk.exe (portable)
```

### Library

```python
import os
from obelisk import encrypt, decrypt, hash, kdf, wrap, unwrap
from obelisk import encrypt_file, decrypt_file, KEY_BYTES, NONCE_BYTES

key, nonce = os.urandom(KEY_BYTES), os.urandom(NONCE_BYTES)
ct, tag = encrypt(key, nonce, b"secret", associated_data=b"header")
pt = decrypt(key, nonce, ct, tag, associated_data=b"header")   # raises TagMismatch if tampered

encrypt_file("in.dat", "out.obl", key=key)
decrypt_file("out.obl", "back.dat", key=key)

digest = hash(b"data")
subkey = kdf(b"master", 32, salt=b"s", info=b"app")
```

Never reuse a nonce under the same key. Like AES-GCM, reuse breaks everything.

### Tests

```
python tests/test_obelisk.py
python tests/test_filecrypt.py
python tests/test_diffusion.py
```

## How it's documented

If you want to dig in or review it:

- [DESIGN.md](DESIGN.md) — why each piece is built the way it is.
- [CRYPTANALYSIS.md](CRYPTANALYSIS.md) — the author's own measurements, including the weak spots.
- [THREAT_MODEL.md](THREAT_MODEL.md) — what it does and doesn't protect against.
- [REVIEW-CHECKLIST.md](REVIEW-CHECKLIST.md) — a walk-through for an independent reviewer.

## Challenge: try to break it

I'd rather someone breaks the `obelisk` cipher now than have it quietly fail later.
"Nobody broke it" isn't proof of anything, but a real attack, or the absence of one
under serious effort, tells me far more than my own tests do.

Targets, easiest to hardest:

- Distinguish the permutation from random with less than 2^128 work.
- Forge a valid tag, or recover plaintext, without the key.
- Recover the key.

Round-reduced results count too: break some of the 10/16 rounds and say how far you got.
The permutation is exposed as `permute(state, rounds)`, so you can attack reduced-round
versions directly. A break is any of the above below the 128-bit claim, with a writeup I
can reproduce.

Want to review instead of attack? [REVIEW-CHECKLIST.md](REVIEW-CHECKLIST.md) is a
structured walk-through. Either way, start a thread in
[GitHub Discussions](https://github.com/Samalth/SAT-Obelisk/discussions).

## Author

S.A. Thiers. Questions and contact go through
[GitHub Discussions](https://github.com/Samalth/SAT-Obelisk/discussions).

## License

Apache License 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
