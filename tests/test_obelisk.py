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


AEAD_VECTORS = [
    (b"OBELISK known-answer test vector", b"kat",
     "3b554cb8c54bcb2b1d091e248736481305ce979343fe1c0ff265dbbc53228e69",
     "418cf211625e39be97c5328168e04c02"),
    (b"", b"", "", "d85b901bfad8c19211068b2e3070ffa0"),
    (bytes(range(37)), bytes(range(100, 140)),
     "05c269ded55010a58786f4a7fdf56aefbba3d9dbb394b98aaae08d6cfa27e25957280d8d80",
     "08ad1225742e32118a0de0c2835eb4c7"),
]
HASH_VECTORS = [
    (b"", "1e4143092bfddbc8d8448bc90980da8b9f841de947834f69a55f8932496d2018"
          "74efc2a50a4647db1b5a7c3293c55001e75e"),
    (b"OBELISK known-answer test vector",
     "ec580fd956820892d2fee0cb4a024494dec353cd05371368ca04b0abeb69e026"
     "b2c151952fe67a0b5c1414ea8c78f43fca58"),
    (bytes(range(100)), "86ff79ab89ea06b7e2137f7b747208bf76a4335da2aa3deec4857e7eca2ba350"
                        "3c7dc5042de164abd2b7bccebfed0e2b78b8"),
]
KDF_VECTOR = "11c04eb3481afd08ed223c8ad6bf10118a98791ae51f59fbccf6c26bebd729211af8f2482cf08955"
WRAP_VECTOR = ("c4eb44d1503a6c6e10bdb838d391faa5f8b3f3f915bb5d2a"
               "da11614065072ec65bed36600953da267729084efe952efb")


def test_known_answer_vectors():
    key = bytes(range(16))
    nonce = bytes(range(16, 32))
    for pt, ad, ct_hex, tag_hex in AEAD_VECTORS:
        ct, tag = encrypt(key, nonce, pt, ad)
        assert (ct.hex(), tag.hex()) == (ct_hex, tag_hex), (pt, ad)
        assert decrypt(key, nonce, ct, tag, ad) == pt
    for data, digest_hex in HASH_VECTORS:
        assert hash(data, 50).hex() == digest_hex, data
        assert hash(data).hex() == digest_hex[:64], data
    assert kdf(b"master-secret", 40, salt=b"salt", info=b"info").hex() == KDF_VECTOR
    assert unwrap(bytes(range(32)), bytes.fromhex(WRAP_VECTOR),
                  context=b"device-42") == bytes(range(200, 216))
    print("ok  pinned known-answer vectors: AEAD (incl. multi-block AD/empty), hash, KDF, key-wrap")


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
    print("\nALL TESTS PASSED")
