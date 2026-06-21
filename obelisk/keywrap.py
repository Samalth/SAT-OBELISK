from __future__ import annotations

import os

from . import aead
from .hash import kdf

_WRAP_CONTEXT = b"OBELISK-keywrap-v1"


def wrap(kek, key_material, context=b""):
    if len(kek) < 16:
        raise ValueError("kek must be at least 16 bytes")
    dek = kdf(kek, aead.KEY_BYTES, salt=context, info=_WRAP_CONTEXT)
    nonce = os.urandom(aead.NONCE_BYTES)
    ct, tag = aead.encrypt(dek, nonce, key_material, _WRAP_CONTEXT + context)
    return nonce + tag + ct


def unwrap(kek, wrapped, context=b""):
    if len(wrapped) < aead.NONCE_BYTES + aead.TAG_BYTES:
        raise ValueError("wrapped blob too short")
    dek = kdf(kek, aead.KEY_BYTES, salt=context, info=_WRAP_CONTEXT)
    nonce = wrapped[:aead.NONCE_BYTES]
    tag = wrapped[aead.NONCE_BYTES:aead.NONCE_BYTES + aead.TAG_BYTES]
    ct = wrapped[aead.NONCE_BYTES + aead.TAG_BYTES:]
    return aead.decrypt(dek, nonce, ct, tag, _WRAP_CONTEXT + context)
