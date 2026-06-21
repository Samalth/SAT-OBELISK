import os
import sys
import shutil
import filecmp
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from obelisk import (
    encrypt_file, decrypt_file, encrypt_folder, is_folder_archive,
    TagMismatch, FileFormatError, KEY_BYTES,
)
from obelisk.filecrypt import CHUNK


def _tmp():
    fd, path = tempfile.mkstemp()
    os.close(fd)
    return path


def roundtrip(data, **kw):
    src, enc, dec = _tmp(), _tmp(), _tmp()
    try:
        with open(src, "wb") as f:
            f.write(data)
        encrypt_file(src, enc, **kw)
        decrypt_file(enc, dec, **kw)
        with open(dec, "rb") as f:
            return f.read(), enc
    finally:
        for p in (src, dec):
            os.path.exists(p) and os.remove(p)


def test_key_roundtrip_sizes():
    key = os.urandom(KEY_BYTES)
    for size in (0, 1, 100, CHUNK - 1, CHUNK, CHUNK + 1, 3 * CHUNK + 123):
        data = os.urandom(size)
        out, enc = roundtrip(data, key=key)
        os.remove(enc)
        assert out == data, size
    print("ok  file round-trip with raw key across sizes (incl. multi-chunk)")


def test_password_roundtrip():
    data = b"password protected payload " * 1000
    out, enc = roundtrip(data, password="correct horse battery staple")
    os.remove(enc)
    assert out == data
    print("ok  file round-trip with password")


def test_wrong_key_fails():
    data = b"sensitive"
    src, enc, dec = _tmp(), _tmp(), _tmp()
    with open(src, "wb") as f:
        f.write(data)
    encrypt_file(src, enc, key=os.urandom(KEY_BYTES))
    try:
        decrypt_file(enc, dec, key=os.urandom(KEY_BYTES))
        assert False
    except TagMismatch:
        print("ok  wrong key is rejected")
    finally:
        for p in (src, enc, dec):
            os.path.exists(p) and os.remove(p)


def test_tamper_fails():
    data = b"x" * (CHUNK + 500)
    src, enc, dec = _tmp(), _tmp(), _tmp()
    key = os.urandom(KEY_BYTES)
    with open(src, "wb") as f:
        f.write(data)
    encrypt_file(src, enc, key=key)
    blob = bytearray(open(enc, "rb").read())
    blob[len(blob) // 2] ^= 0x01
    with open(enc, "wb") as f:
        f.write(blob)
    try:
        decrypt_file(enc, dec, key=key)
        assert False
    except TagMismatch:
        print("ok  tampered file is rejected")
    finally:
        for p in (src, enc, dec):
            os.path.exists(p) and os.remove(p)


def test_truncation_fails():
    data = b"y" * (2 * CHUNK + 10)
    src, enc, dec = _tmp(), _tmp(), _tmp()
    key = os.urandom(KEY_BYTES)
    with open(src, "wb") as f:
        f.write(data)
    encrypt_file(src, enc, key=key)
    blob = open(enc, "rb").read()
    with open(enc, "wb") as f:
        f.write(blob[:len(blob) // 2])
    try:
        decrypt_file(enc, dec, key=key)
        assert False
    except (TagMismatch, FileFormatError):
        print("ok  truncated file is rejected")
    finally:
        for p in (src, enc, dec):
            os.path.exists(p) and os.remove(p)


def _dirs_equal(a, b):
    cmp = filecmp.dircmp(a, b)
    if cmp.left_only or cmp.right_only or cmp.diff_files or cmp.funny_files:
        return False
    return all(_dirs_equal(os.path.join(a, d), os.path.join(b, d)) for d in cmp.common_dirs)


def test_folder_roundtrip():
    work = tempfile.mkdtemp()
    try:
        src = os.path.join(work, "data")
        os.makedirs(os.path.join(src, "sub"))
        with open(os.path.join(src, "a.txt"), "w") as f:
            f.write("alpha")
        with open(os.path.join(src, "sub", "b.bin"), "wb") as f:
            f.write(os.urandom(CHUNK + 7))
        enc = os.path.join(work, "data.obl")
        out = os.path.join(work, "restored")
        key = os.urandom(KEY_BYTES)
        encrypt_folder(src, enc, key=key)
        assert is_folder_archive(enc)
        decrypt_file(enc, out, key=key)
        assert _dirs_equal(src, os.path.join(out, "data"))
        print("ok  folder encrypt/decrypt preserves structure and content")
    finally:
        shutil.rmtree(work, ignore_errors=True)


def test_folder_tamper():
    work = tempfile.mkdtemp()
    try:
        src = os.path.join(work, "d")
        os.makedirs(src)
        with open(os.path.join(src, "f.txt"), "w") as f:
            f.write("secret payload")
        enc = os.path.join(work, "d.obl")
        out = os.path.join(work, "r")
        key = os.urandom(KEY_BYTES)
        encrypt_folder(src, enc, key=key)
        blob = bytearray(open(enc, "rb").read())
        blob[-20] ^= 0x01
        with open(enc, "wb") as f:
            f.write(blob)
        try:
            decrypt_file(enc, out, key=key)
            assert False
        except (TagMismatch, FileFormatError):
            print("ok  tampered folder archive is rejected")
    finally:
        shutil.rmtree(work, ignore_errors=True)


def test_header_tamper():
    work = tempfile.mkdtemp()
    try:
        src, enc, out = (os.path.join(work, n) for n in ("s", "s.obl", "o"))
        with open(src, "wb") as f:
            f.write(b"payload")
        key = os.urandom(KEY_BYTES)
        encrypt_file(src, enc, key=key)
        blob = bytearray(open(enc, "rb").read())
        blob[9] ^= 0x02
        with open(enc, "wb") as f:
            f.write(blob)
        try:
            decrypt_file(enc, out, key=key)
            assert False
        except (TagMismatch, FileFormatError):
            print("ok  authenticated header: flag tamper rejected")
    finally:
        shutil.rmtree(work, ignore_errors=True)


def test_subkey_uniqueness():
    work = tempfile.mkdtemp()
    try:
        src, e1, e2 = (os.path.join(work, n) for n in ("s", "a.obl", "b.obl"))
        with open(src, "wb") as f:
            f.write(b"same plaintext, same key")
        key = os.urandom(KEY_BYTES)
        encrypt_file(src, e1, key=key)
        encrypt_file(src, e2, key=key)
        c1 = open(e1, "rb").read()[30:]
        c2 = open(e2, "rb").read()[30:]
        assert c1 != c2, "per-file subkey must randomize ciphertext"
        print("ok  per-file subkey: same key+plaintext -> different ciphertext")
    finally:
        shutil.rmtree(work, ignore_errors=True)


def test_no_partial_output_on_failure():
    work = tempfile.mkdtemp()
    try:
        src, enc, out = (os.path.join(work, n) for n in ("s", "s.obl", "o"))
        with open(src, "wb") as f:
            f.write(os.urandom(CHUNK * 2))
        key = os.urandom(KEY_BYTES)
        encrypt_file(src, enc, key=key)
        try:
            decrypt_file(enc, out, key=os.urandom(KEY_BYTES))
            assert False
        except TagMismatch:
            pass
        assert not os.path.exists(out), "failed decrypt must not leave a partial file"
        print("ok  atomic output: failed decrypt leaves no partial file")
    finally:
        shutil.rmtree(work, ignore_errors=True)


def test_password_argon2_roundtrip():
    from obelisk.filecrypt import argon2_available, inspect
    work = tempfile.mkdtemp()
    try:
        src, enc, out = (os.path.join(work, n) for n in ("s", "s.obl", "o"))
        with open(src, "wb") as f:
            f.write(b"argon protected")
        encrypt_file(src, enc, password="pwé\U0001f510")
        assert inspect(enc)["argon2"] == argon2_available()
        decrypt_file(enc, out, password="pwé\U0001f510")
        assert open(out, "rb").read() == b"argon protected"
        print(f"ok  password roundtrip (argon2={argon2_available()}, unicode pw)")
    finally:
        shutil.rmtree(work, ignore_errors=True)


def test_ciphers_and_downgrade():
    from obelisk import ciphers, inspect
    work = tempfile.mkdtemp()
    try:
        data = os.urandom(CHUNK + 50)
        src = os.path.join(work, "s")
        with open(src, "wb") as f:
            f.write(data)
        key = os.urandom(KEY_BYTES)
        for name in ciphers.names():
            enc, out = os.path.join(work, name), os.path.join(work, name + ".out")
            encrypt_file(src, enc, key=key, cipher=name)
            assert inspect(enc)["cipher"] == name
            decrypt_file(enc, out, key=key)
            assert open(out, "rb").read() == data, name
        enc = os.path.join(work, "chacha20")
        blob = bytearray(open(enc, "rb").read())
        blob[10] = 1
        with open(enc, "wb") as f:
            f.write(blob)
        try:
            decrypt_file(enc, os.path.join(work, "x"), key=key)
            assert False
        except (TagMismatch, FileFormatError):
            pass
        print(f"ok  ciphers {ciphers.names()} roundtrip + cipher-downgrade rejected")
    finally:
        shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
    print("\nALL FILE TESTS PASSED")
