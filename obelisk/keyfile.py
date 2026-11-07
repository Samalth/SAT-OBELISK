from __future__ import annotations

import os
import datetime
import subprocess

from . import aead
from . import pwseal
from .filecrypt import atomic_write
from .hash import hash as _hash

MAGIC = "OBELISK-KEYFILE"
VERSION = 2
FP_BYTES = 8


class KeyfileError(Exception):
    pass


class KeyfilePasswordRequired(KeyfileError):
    pass


def new_key():
    return os.urandom(aead.KEY_BYTES)


def parse_hex_key(text):
    try:
        key = bytes.fromhex(text.strip())
    except ValueError:
        raise ValueError("key must be hex")
    if len(key) != aead.KEY_BYTES:
        raise ValueError(f"key must be {aead.KEY_BYTES} bytes ({aead.KEY_BYTES * 2} hex chars)")
    return key


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


def utc_timestamp():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _seal_context(fp):
    return f"{MAGIC} v{VERSION}\n{fp}".encode("utf-8")


def write_keyfile_text(path, text):
    with atomic_write(path) as f:
        f.write(text.encode("utf-8"))
    _restrict_permissions(path)


def save_keyfile(path, key, password, label="", created=None):
    if len(key) != aead.KEY_BYTES:
        raise KeyfileError(f"key must be {aead.KEY_BYTES} bytes")
    if not password:
        raise KeyfileError("a password is required to protect the keyfile")
    fp = fingerprint(key)
    fields = {
        "label": label,
        "created": created or utc_timestamp(),
        "fingerprint": fp,
    }
    fields.update(pwseal.seal(password, key, _seal_context(fp)))
    lines = [f"{MAGIC} v{VERSION}"]
    for k, v in fields.items():
        lines.append(f"{k}={v}")
    lines.append("")
    write_keyfile_text(path, "\n".join(lines))
    return fp


def _read_fields(path):
    fields = {}
    try:
        with open(path, "r", encoding="utf-8") as f:
            first = f.readline().strip()
            if not first.startswith(MAGIC):
                raise KeyfileError("not an OBELISK keyfile")
            for line in f:
                if "=" in line:
                    k, v = line.strip().split("=", 1)
                    fields[k] = v
    except UnicodeDecodeError:
        raise KeyfileError("not an OBELISK keyfile")
    return first[len(MAGIC):].strip(), fields


def read_keyfile_info(path):
    version, fields = _read_fields(path)
    fp = fields.get("fingerprint", "")
    if not fp and version == "v1":
        fp = fingerprint(load_keyfile(path))
    return {
        "label": fields.get("label", ""),
        "created": fields.get("created", ""),
        "fingerprint": fp,
        "protected": version != "v1",
    }


def load_keyfile(path, password=None):
    version, fields = _read_fields(path)
    if version == "v1":
        if "key" not in fields:
            raise KeyfileError("keyfile has no key")
        try:
            key = bytes.fromhex(fields["key"])
        except ValueError:
            raise KeyfileError("keyfile key is not valid hex")
    elif version == f"v{VERSION}":
        if not password:
            raise KeyfilePasswordRequired("keyfile is password-protected")
        try:
            key = pwseal.unseal(password, fields, _seal_context(fields.get("fingerprint", "")))
        except pwseal.SealError as e:
            raise KeyfileError(f"keyfile: {e}")
        except aead.TagMismatch:
            raise KeyfileError("wrong password, or the keyfile was tampered with")
    else:
        raise KeyfileError(f"unsupported keyfile version '{version}'")
    if len(key) != aead.KEY_BYTES:
        raise KeyfileError("keyfile key has wrong length")
    fp = fields.get("fingerprint")
    if fp is not None and fp != fingerprint(key):
        raise KeyfileError("keyfile is corrupt: fingerprint does not match key")
    return key


def change_keyfile_password(path, old_password, new_password):
    info = read_keyfile_info(path)
    key = load_keyfile(path, old_password)
    return save_keyfile(path, key, new_password, label=info["label"], created=info["created"])


def protect_keyfile(path, password):
    if read_keyfile_info(path)["protected"]:
        raise KeyfileError("keyfile is already password-protected")
    return change_keyfile_password(path, None, password)


def generate_keyfile(path, password, label=""):
    key = new_key()
    fp = save_keyfile(path, key, password, label=label)
    return key, fp
