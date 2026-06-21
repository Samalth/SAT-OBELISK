from __future__ import annotations

from . import aead


class CipherUnavailable(Exception):
    pass


class Cipher:
    id = 0
    name = ""
    key_bytes = 0
    nonce_bytes = 0
    vetted = False

    def available(self):
        return True

    def seal(self, key, nonce, pt, ad):
        raise NotImplementedError

    def open(self, key, nonce, blob, ad):
        raise NotImplementedError


class ObeliskCipher(Cipher):
    id = 1
    name = "obelisk"
    key_bytes = aead.KEY_BYTES
    nonce_bytes = aead.NONCE_BYTES
    vetted = False

    def seal(self, key, nonce, pt, ad):
        ct, tag = aead.encrypt(key, nonce, pt, ad)
        return ct + tag

    def open(self, key, nonce, blob, ad):
        if len(blob) < aead.TAG_BYTES:
            raise aead.TagMismatch("authentication failed")
        return aead.decrypt(key, nonce, blob[:-aead.TAG_BYTES], blob[-aead.TAG_BYTES:], ad)


class _LibAEAD(Cipher):
    vetted = True

    def available(self):
        try:
            import cryptography.hazmat.primitives.ciphers.aead  # noqa: F401
            return True
        except ModuleNotFoundError:
            return False

    def _algo(self, key):
        raise NotImplementedError

    def seal(self, key, nonce, pt, ad):
        if not self.available():
            raise CipherUnavailable(f"cipher '{self.name}' needs: pip install cryptography")
        return self._algo(key).encrypt(nonce, pt, ad)

    def open(self, key, nonce, blob, ad):
        if not self.available():
            raise CipherUnavailable(f"cipher '{self.name}' needs: pip install cryptography")
        from cryptography.exceptions import InvalidTag
        try:
            return self._algo(key).decrypt(nonce, blob, ad)
        except InvalidTag:
            raise aead.TagMismatch("authentication failed")


class ChaCha20Cipher(_LibAEAD):
    id = 2
    name = "chacha20"
    key_bytes = 32
    nonce_bytes = 12

    def _algo(self, key):
        from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
        return ChaCha20Poly1305(key)


class AESGCMCipher(_LibAEAD):
    id = 3
    name = "aes256gcm"
    key_bytes = 32
    nonce_bytes = 12

    def _algo(self, key):
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        return AESGCM(key)


_CIPHERS = [ObeliskCipher(), ChaCha20Cipher(), AESGCMCipher()]
_BY_ID = {c.id: c for c in _CIPHERS}
_BY_NAME = {c.name: c for c in _CIPHERS}

# Default to a vetted, peer-reviewed AEAD. The experimental "obelisk" cipher
# stays available but must be selected explicitly.
DEFAULT = "chacha20"


def get_by_name(name):
    if name not in _BY_NAME:
        raise ValueError(f"unknown cipher '{name}'; choose from {', '.join(_BY_NAME)}")
    return _BY_NAME[name]


def get_by_id(cid):
    if cid not in _BY_ID:
        raise ValueError(f"unknown cipher id {cid}")
    return _BY_ID[cid]


def names():
    return list(_BY_NAME)


def available_names():
    return [c.name for c in _CIPHERS if c.available()]
