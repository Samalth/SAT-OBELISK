from __future__ import annotations

import os

from . import ciphers
from .filecrypt import derive_password_key, argon2_available, DEFAULT_PW_ITERS, SALT_BYTES
from .keywrap import seal_derived, open_derived

_KEK_INFO = b"OBELISK-pwseal-kek-v1"


class SealError(Exception):
    pass


def _associated_data(context, fields):
    parts = [fields["cipher"], fields["kdf"], fields["iters"], fields["salt"]]
    return context + b"\n" + "\n".join(parts).encode("utf-8")


def _password_secret(password, fields):
    secret, _ = derive_password_key(password, bytes.fromhex(fields["salt"]), int(fields["iters"]),
                                    use_argon2=fields["kdf"] == "argon2id")
    return secret


def seal(password, plaintext, context):
    if not password:
        raise SealError("a password is required")
    cipher = ciphers.get_by_name(ciphers.DEFAULT)
    if not cipher.available():
        cipher = ciphers.get_by_name("obelisk")
    fields = {
        "cipher": cipher.name,
        "kdf": "argon2id" if argon2_available() else "sponge",
        "iters": str(DEFAULT_PW_ITERS),
        "salt": os.urandom(SALT_BYTES).hex(),
    }
    nonce, sealed = seal_derived(_password_secret(password, fields), plaintext,
                                 bytes.fromhex(fields["salt"]), _KEK_INFO,
                                 _associated_data(context, fields), cipher)
    fields["nonce"] = nonce.hex()
    fields["ciphertext"] = sealed.hex()
    return fields


def unseal(password, fields, context):
    if fields.get("kdf") == "argon2id" and not argon2_available():
        raise SealError("needs Argon2: pip install argon2-cffi")
    try:
        cipher = ciphers.get_by_name(fields["cipher"])
        nonce = bytes.fromhex(fields["nonce"])
        sealed = bytes.fromhex(fields["ciphertext"])
        return open_derived(_password_secret(password, fields), nonce, sealed,
                            bytes.fromhex(fields["salt"]), _KEK_INFO,
                            _associated_data(context, fields), cipher)
    except (KeyError, ValueError, TypeError, AttributeError):
        raise SealError("data is corrupt")
    except ciphers.CipherUnavailable as e:
        raise SealError(str(e))
