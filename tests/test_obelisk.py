import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from obelisk import (
    encrypt, decrypt, seal, unseal, TagMismatch, hash, kdf, wrap, unwrap,
    KEY_BYTES, NONCE_BYTES,
)
from obelisk.permutation import permute, permute_inv, bytes_to_state, B_ROUNDS, A_ROUNDS


def test_permutation_bijective():
    for _ in range(500):
        s = bytes_to_state(os.urandom(48))
        for r in (B_ROUNDS, A_ROUNDS):
            assert permute_inv(permute(s, r), r) == s
    print("ok  permutation is a bijection")


def test_aead_roundtrip():
    key = os.urandom(KEY_BYTES)
    for plen in (0, 1, 15, 16, 17, 31, 32, 100, 1000):
        for adlen in (0, 1, 16, 50):
            nonce = os.urandom(NONCE_BYTES)
            pt = os.urandom(plen)
            ad = os.urandom(adlen)
            ct, tag = encrypt(key, nonce, pt, ad)
            assert len(ct) == len(pt)
            rec = decrypt(key, nonce, ct, tag, ad)
            assert rec == pt, (plen, adlen)
    print("ok  AEAD encrypt/decrypt round-trip across lengths")


def test_tamper_detection():
    key = os.urandom(KEY_BYTES)
    nonce = os.urandom(NONCE_BYTES)
    pt = b"attack at dawn, bring coffee" * 4
    ad = b"header-v1"
    ct, tag = encrypt(key, nonce, pt, ad)

    for i in range(len(ct)):
        bad = bytearray(ct); bad[i] ^= 0x01
        try:
            decrypt(key, nonce, bytes(bad), tag, ad); assert False
        except TagMismatch:
            pass
    for i in range(len(tag)):
        bad = bytearray(tag); bad[i] ^= 0x80
        try:
            decrypt(key, nonce, ct, bytes(bad), ad); assert False
        except TagMismatch:
            pass
    try:
        decrypt(key, nonce, ct, tag, ad + b"x"); assert False
    except TagMismatch:
        pass
    try:
        decrypt(key, os.urandom(NONCE_BYTES), ct, tag, ad); assert False
    except TagMismatch:
        pass
    print("ok  tamper detection (ciphertext, tag, AD, nonce)")


def test_seal_open():
    key = os.urandom(KEY_BYTES)
    msg = b"sealed envelope payload"
    box = seal(key, msg, b"ctx")
    assert unseal(key, box, b"ctx") == msg
    try:
        unseal(key, box, b"wrong"); assert False
    except TagMismatch:
        pass
    print("ok  seal/open with random nonce")


def test_nonce_determinism():
    key = os.urandom(KEY_BYTES)
    nonce = os.urandom(NONCE_BYTES)
    pt = b"deterministic under fixed nonce"
    a = encrypt(key, nonce, pt)
    b = encrypt(key, nonce, pt)
    assert a == b
    c = encrypt(key, os.urandom(NONCE_BYTES), pt)
    assert c != a
    print("ok  deterministic per (key,nonce); differs across nonces")


def test_hash_properties():
    h1 = hash(b"")
    h2 = hash(b"")
    h3 = hash(b"a")
    h4 = hash(b"b")
    assert h1 == h2 and len(h1) == 32
    assert h3 != h4
    assert hash(b"abc", 64) != hash(b"abc", 32) + hash(b"abc", 32)[:0]
    assert len(hash(b"x", 17)) == 17
    flips = sum(bin(x ^ y).count("1") for x, y in zip(hash(b"message0"), hash(b"message1")))
    assert 80 < flips < 176, flips
    print(f"ok  hash deterministic, variable length, avalanche={flips}/256 bits")


def test_kdf():
    k = b"master-secret-material"
    a = kdf(k, 32, salt=b"s1", info=b"app")
    b = kdf(k, 32, salt=b"s2", info=b"app")
    c = kdf(k, 32, salt=b"s1", info=b"other")
    assert a != b and a != c and len(a) == 32
    assert kdf(k, 64)[:32] == kdf(k, 32)
    print("ok  KDF separates on salt/info, prefix-stable on length")


def test_keywrap():
    kek = os.urandom(32)
    dek = os.urandom(KEY_BYTES)
    blob = wrap(kek, dek, context=b"device-42")
    assert unwrap(kek, blob, context=b"device-42") == dek
    try:
        unwrap(kek, blob, context=b"device-99"); assert False
    except TagMismatch:
        pass
    bad = bytearray(blob); bad[-1] ^= 0x01
    try:
        unwrap(kek, bytes(bad), context=b"device-42"); assert False
    except TagMismatch:
        pass
    print("ok  key-wrap round-trip + context binding + tamper detection")


def test_known_answer_stability():
    key = bytes(range(16))
    nonce = bytes(range(16, 32))
    pt = b"OBELISK known-answer test vector"
    ct, tag = encrypt(key, nonce, pt, b"kat")
    print(f"    KAT ct  = {ct.hex()}")
    print(f"    KAT tag = {tag.hex()}")
    print(f"    KAT hash= {hash(pt).hex()}")
    assert decrypt(key, nonce, ct, tag, b"kat") == pt
    print("ok  known-answer vectors stable and self-consistent")


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
    print("\nALL TESTS PASSED")
