from __future__ import annotations

from .hash import kdf
from . import aead

_KEX_INFO = b"OBELISK-X25519-hybrid-v1"


def _require_x25519():
    try:
        from cryptography.hazmat.primitives.asymmetric.x25519 import (
            X25519PrivateKey, X25519PublicKey,
        )
        from cryptography.hazmat.primitives import serialization
        return X25519PrivateKey, X25519PublicKey, serialization
    except ModuleNotFoundError as exc:
        raise RuntimeError(
            "The FIREFLY-style key agreement needs vetted X25519. "
            "Install it with:  pip install cryptography"
        ) from exc


def generate_keypair():
    X25519PrivateKey, _, serialization = _require_x25519()
    sk = X25519PrivateKey.generate()
    pub = sk.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    priv = sk.private_bytes(
        serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
        serialization.NoEncryption())
    return priv, pub


def derive_shared_key(my_private, their_public, transcript=b"", length=32):
    X25519PrivateKey, X25519PublicKey, _ = _require_x25519()
    sk = X25519PrivateKey.from_private_bytes(my_private)
    pk = X25519PublicKey.from_public_bytes(their_public)
    dh = sk.exchange(pk)
    return kdf(dh, length, salt=transcript, info=_KEX_INFO)


def establish_channel_keys(my_private, their_public, my_public):
    a, b = sorted([my_public, their_public])
    transcript = a + b
    shared = derive_shared_key(my_private, their_public, transcript, length=aead.KEY_BYTES * 2)
    return shared[:aead.KEY_BYTES], shared[aead.KEY_BYTES:]
