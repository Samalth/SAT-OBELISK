from __future__ import annotations

import os
import datetime
import subprocess

from . import aead
from .hash import hash as _hash

MAGIC = "OBELISK-KEYFILE"
VERSION = 1
FP_BYTES = 8


class KeyfileError(Exception):
    pass


def new_key():
    return os.urandom(aead.KEY_BYTES)


def fingerprint(key):
    return _hash(b"OBELISK-keyid\x00" + key, FP_BYTES).hex()


def _restrict_permissions(path):
    try:
        if os.name == "posix":
            os.chmod(path, 0o600)
        elif os.name == "nt":
            user = os.environ.get("USERNAME")
            if user:
                kw = dict(capture_output=True, check=False)
                subprocess.run(["icacls", path, "/inheritance:r"], **kw)
                subprocess.run(["icacls", path, "/grant:r", f"{user}:F"], **kw)
    except Exception:
        pass


def save_keyfile(path, key, label=""):
    if len(key) != aead.KEY_BYTES:
        raise KeyfileError(f"key must be {aead.KEY_BYTES} bytes")
    created = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    lines = [
        f"{MAGIC} v{VERSION}",
        f"label={label}",
        f"created={created}",
        f"key={key.hex()}",
        f"fingerprint={fingerprint(key)}",
        "",
    ]
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    _restrict_permissions(path)
    return fingerprint(key)


def load_keyfile(path):
    fields = {}
    with open(path, "r", encoding="utf-8") as f:
        first = f.readline().strip()
        if not first.startswith(MAGIC):
            raise KeyfileError("not an OBELISK keyfile")
        for line in f:
            if "=" in line:
                k, v = line.strip().split("=", 1)
                fields[k] = v
    if "key" not in fields:
        raise KeyfileError("keyfile has no key")
    try:
        key = bytes.fromhex(fields["key"])
    except ValueError:
        raise KeyfileError("keyfile key is not valid hex")
    if len(key) != aead.KEY_BYTES:
        raise KeyfileError("keyfile key has wrong length")
    fp = fields.get("fingerprint")
    if fp is not None and fp != fingerprint(key):
        raise KeyfileError("keyfile is corrupt: fingerprint does not match key")
    return key


def generate_keyfile(path, label=""):
    key = new_key()
    fp = save_keyfile(path, key, label=label)
    return key, fp
