from __future__ import annotations

import contextlib
import os
import struct
import tarfile
import tempfile

from . import aead
from . import ciphers
from .hash import kdf

MAGIC = b"OBLKFILE"
VERSION = 3
CHUNK = 65536
SALT_BYTES = 16
DEFAULT_PW_ITERS = 1500

FLAG_PASSWORD = 0x01
FLAG_FOLDER = 0x02
FLAG_ARGON2 = 0x04

ARGON2_TIME = 3
ARGON2_MEM = 65536
ARGON2_PAR = 4

_HEADER = struct.Struct("<8sBBBI16s")


class FileFormatError(Exception):
    pass


def argon2_available():
    try:
        import argon2.low_level  # noqa: F401
        return True
    except ModuleNotFoundError:
        return False


def _argon2_key(material, salt):
    from argon2.low_level import hash_secret_raw, Type
    return hash_secret_raw(material, salt, time_cost=ARGON2_TIME, memory_cost=ARGON2_MEM,
                           parallelism=ARGON2_PAR, hash_len=aead.KEY_BYTES, type=Type.ID)


def _sponge_key(material, salt, iters):
    out = kdf(material, 32, salt=salt, info=b"OBELISK-file-pw")
    for _ in range(iters):
        out = kdf(out, 32, salt=salt, info=b"OBELISK-file-pw-iter")
    return out[:aead.KEY_BYTES]


def derive_password_key(password, salt, iters=DEFAULT_PW_ITERS, use_argon2=None):
    material = password.encode("utf-8") if isinstance(password, str) else password
    if use_argon2 is None:
        use_argon2 = argon2_available()
    if use_argon2:
        return _argon2_key(material, salt), True
    return _sponge_key(material, salt, iters), False


def _derive_subkey(master, file_salt, key_bytes):
    return kdf(master, key_bytes, salt=file_salt, info=b"OBELISK-file-subkey-v3")


def _master_for_encrypt(key, password, file_salt, iters):
    if (key is None) == (password is None):
        raise ValueError("provide exactly one of key= or password=")
    if key is not None:
        if len(key) != aead.KEY_BYTES:
            raise ValueError(f"key must be {aead.KEY_BYTES} bytes")
        return key, 0
    master, used_argon2 = derive_password_key(password, file_salt, iters)
    flags = FLAG_PASSWORD | (FLAG_ARGON2 if used_argon2 else 0)
    return master, flags


def _master_for_decrypt(flags, key, password, file_salt, iters):
    if flags & FLAG_PASSWORD:
        if password is None:
            raise ValueError("file is password-protected; pass password=")
        if flags & FLAG_ARGON2 and not argon2_available():
            raise FileFormatError("this file needs Argon2 to decrypt: pip install argon2-cffi")
        master, _ = derive_password_key(password, file_salt, iters,
                                        use_argon2=bool(flags & FLAG_ARGON2))
        return master
    if key is None or len(key) != aead.KEY_BYTES:
        raise ValueError(f"file needs a {aead.KEY_BYTES}-byte key=")
    return key


@contextlib.contextmanager
def _atomic_write(path):
    folder = os.path.dirname(os.path.abspath(path))
    fd, tmp = tempfile.mkstemp(dir=folder, suffix=".tmp")
    os.close(fd)
    try:
        f = open(tmp, "wb")
        try:
            yield f
        finally:
            f.close()
        os.replace(tmp, path)
    except BaseException:
        os.path.exists(tmp) and os.remove(tmp)
        raise


def _write_encrypted(fin, fout, cipher, subkey, header, progress=None, total=0):
    fout.write(header)
    counter = 0
    done = 0
    cur = fin.read(CHUNK)
    while True:
        nxt = fin.read(CHUNK)
        is_last = len(nxt) == 0
        flag = b"\x01" if is_last else b"\x00"
        ad = counter.to_bytes(8, "little") + flag + (header if counter == 0 else b"")
        nonce = counter.to_bytes(cipher.nonce_bytes, "little")
        blob = cipher.seal(subkey, nonce, cur, ad)
        fout.write(flag + struct.pack("<I", len(blob)) + blob)
        counter += 1
        done += len(cur)
        if progress:
            progress(done, total)
        if is_last:
            break
        cur = nxt


def _decrypt_to(fin, fout, cipher, subkey, header, progress=None, total=0):
    counter = 0
    done = len(header)
    while True:
        flag = fin.read(1)
        if len(flag) == 0:
            raise FileFormatError("truncated file: no final chunk")
        lenbuf = fin.read(4)
        if len(lenbuf) != 4:
            raise FileFormatError("truncated file: chunk header")
        blen = struct.unpack("<I", lenbuf)[0]
        blob = fin.read(blen)
        if len(blob) != blen:
            raise FileFormatError("truncated file: chunk body")
        ad = counter.to_bytes(8, "little") + flag + (header if counter == 0 else b"")
        nonce = counter.to_bytes(cipher.nonce_bytes, "little")
        fout.write(cipher.open(subkey, nonce, blob, ad))
        counter += 1
        done += 1 + 4 + blen
        if progress:
            progress(done, total)
        if flag == b"\x01":
            break


def _read_header(fin):
    head = fin.read(_HEADER.size)
    if len(head) != _HEADER.size:
        raise FileFormatError("file too short / not an OBELISK file")
    magic, version, flags, cipher_id, iters, file_salt = _HEADER.unpack(head)
    if magic != MAGIC:
        raise FileFormatError("bad magic / not an OBELISK file")
    if version != VERSION:
        raise FileFormatError(f"unsupported version {version}")
    try:
        cipher = ciphers.get_by_id(cipher_id)
    except ValueError as e:
        raise FileFormatError(str(e))
    return head, flags, cipher, iters, file_salt


def encrypt_file(infile, outfile, key=None, password=None, iters=DEFAULT_PW_ITERS,
                 cipher=ciphers.DEFAULT, progress=None):
    c = ciphers.get_by_name(cipher) if isinstance(cipher, str) else cipher
    file_salt = os.urandom(SALT_BYTES)
    master, flags = _master_for_encrypt(key, password, file_salt, iters)
    subkey = _derive_subkey(master, file_salt, c.key_bytes)
    header = _HEADER.pack(MAGIC, VERSION, flags, c.id, iters, file_salt)
    total = os.path.getsize(infile)
    with open(infile, "rb") as fin, _atomic_write(outfile) as fout:
        _write_encrypted(fin, fout, c, subkey, header, progress, total)


def encrypt_folder(infolder, outfile, key=None, password=None, iters=DEFAULT_PW_ITERS,
                   cipher=ciphers.DEFAULT, progress=None):
    if not os.path.isdir(infolder):
        raise ValueError("not a folder")
    c = ciphers.get_by_name(cipher) if isinstance(cipher, str) else cipher
    file_salt = os.urandom(SALT_BYTES)
    master, flags = _master_for_encrypt(key, password, file_salt, iters)
    flags |= FLAG_FOLDER
    subkey = _derive_subkey(master, file_salt, c.key_bytes)
    header = _HEADER.pack(MAGIC, VERSION, flags, c.id, iters, file_salt)
    arcname = os.path.basename(os.path.normpath(infolder)) or "folder"
    fd, tmp = tempfile.mkstemp(suffix=".tar")
    os.close(fd)
    try:
        with tarfile.open(tmp, "w") as tar:
            tar.add(infolder, arcname=arcname)
        total = os.path.getsize(tmp)
        with open(tmp, "rb") as fin, _atomic_write(outfile) as fout:
            _write_encrypted(fin, fout, c, subkey, header, progress, total)
    finally:
        os.path.exists(tmp) and os.remove(tmp)


def encrypt_path(src, dst, key=None, password=None, iters=DEFAULT_PW_ITERS,
                 cipher=ciphers.DEFAULT, progress=None):
    if os.path.isdir(src):
        encrypt_folder(src, dst, key=key, password=password, iters=iters,
                       cipher=cipher, progress=progress)
    else:
        encrypt_file(src, dst, key=key, password=password, iters=iters,
                     cipher=cipher, progress=progress)


def is_folder_archive(infile):
    with open(infile, "rb") as fin:
        _, flags, _, _, _ = _read_header(fin)
    return bool(flags & FLAG_FOLDER)


def inspect(infile):
    with open(infile, "rb") as fin:
        _, flags, cipher, iters, _ = _read_header(fin)
    return {
        "cipher": cipher.name,
        "password": bool(flags & FLAG_PASSWORD),
        "argon2": bool(flags & FLAG_ARGON2),
        "folder": bool(flags & FLAG_FOLDER),
    }


def decrypt_file(infile, outfile, key=None, password=None, progress=None):
    total = os.path.getsize(infile)
    with open(infile, "rb") as fin:
        header, flags, cipher, iters, file_salt = _read_header(fin)
        master = _master_for_decrypt(flags, key, password, file_salt, iters)
        subkey = _derive_subkey(master, file_salt, cipher.key_bytes)
        if flags & FLAG_FOLDER:
            fd, tmp = tempfile.mkstemp(suffix=".tar")
            os.close(fd)
            try:
                with open(tmp, "wb") as fout:
                    _decrypt_to(fin, fout, cipher, subkey, header, progress, total)
                os.makedirs(outfile, exist_ok=True)
                with tarfile.open(tmp, "r") as tar:
                    tar.extractall(outfile, filter="data")
            finally:
                os.path.exists(tmp) and os.remove(tmp)
        else:
            with _atomic_write(outfile) as fout:
                _decrypt_to(fin, fout, cipher, subkey, header, progress, total)
