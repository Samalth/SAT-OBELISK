from __future__ import annotations

import os

from . import aead
from . import ciphers
from .hash import kdf

_WRAP_CONTEXT = b"OBELISK-keywrap-v1"


def seal_derived(secret, plaintext, salt, info, associated_data, cipher):
    key = kdf(secret, cipher.key_bytes, salt=salt, info=info)
    nonce = os.urandom(cipher.nonce_bytes)
    return nonce, cipher.seal(key, nonce, plaintext, associated_data)


def open_derived(secret, nonce, sealed, salt, info, associated_data, cipher):
    key = kdf(secret, cipher.key_bytes, salt=salt, info=info)
    return cipher.open(key, nonce, sealed, associated_data)


def wrap(kek, key_material, context=b""):
    if len(kek) < 16:
        raise ValueError("kek must be at least 16 bytes")
    nonce, sealed = seal_derived(kek, key_material, context, _WRAP_CONTEXT,
                                 _WRAP_CONTEXT + context, ciphers.get_by_name("obelisk"))
    return nonce + sealed[-aead.TAG_BYTES:] + sealed[:-aead.TAG_BYTES]


def unwrap(kek, wrapped, context=b""):
    if len(wrapped) < aead.NONCE_BYTES + aead.TAG_BYTES:
        raise ValueError("wrapped blob too short")
    nonce = wrapped[:aead.NONCE_BYTES]
    tag = wrapped[aead.NONCE_BYTES:aead.NONCE_BYTES + aead.TAG_BYTES]
    ct = wrapped[aead.NONCE_BYTES + aead.TAG_BYTES:]
    return open_derived(kek, nonce, ct + tag, context, _WRAP_CONTEXT, _WRAP_CONTEXT + context,
                        ciphers.get_by_name("obelisk"))
