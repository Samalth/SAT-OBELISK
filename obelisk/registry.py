from __future__ import annotations

import contextlib
import getpass
import json
import os
import socket
import time

from . import aead
from . import pwseal
from .filecrypt import atomic_write
from .keyfile import read_keyfile_info, write_keyfile_text, utc_timestamp, KeyfileError

MAGIC = "OBELISK-DB"
VERSION = 1
EXTENSION = ".obldb"
LOCK_SUFFIX = ".lock"
LOCK_STALE_SECONDS = 30
LOCK_WAIT_SECONDS = 10
LOCK_POLL_SECONDS = 0.2
_SEAL_CONTEXT = f"{MAGIC} v{VERSION}".encode("utf-8")


class RegistryError(Exception):
    pass


class WrongPassword(RegistryError):
    def __init__(self, path):
        super().__init__(f"wrong password for {os.path.basename(path)}, "
                         "or the database was tampered with")
        self.path = path


class DatabaseBusy(RegistryError):
    def __init__(self, path, status):
        super().__init__(f"{os.path.basename(path)} is in use by {status['owner']} "
                         f"since {status['since_text']}")
        self.path = path
        self.status = status


class LockReleased(RegistryError):
    def __init__(self, path):
        super().__init__(f"the lock on {os.path.basename(path)} was released by someone else; "
                         "nothing was written")
        self.path = path


def with_extension(path):
    return path if path.lower().endswith(EXTENSION) else path + EXTENSION


def lock_status(path):
    lock = path + LOCK_SUFFIX
    try:
        with open(lock, encoding="utf-8") as f:
            raw = f.read()
        since = os.path.getmtime(lock)
    except FileNotFoundError:
        return None
    try:
        info = json.loads(raw)
    except ValueError:
        info = {}
    if not isinstance(info, dict):
        info = {}
    return {
        "owner": str(info.get("owner", "?")),
        "token": str(info.get("token", "")),
        "since": since,
        "since_text": time.strftime("%H:%M:%S", time.localtime(since)),
        "stale": time.time() - since > LOCK_STALE_SECONDS,
    }


def release_lock(path, token=None):
    if token is not None:
        status = lock_status(path)
        if status is None or status["token"] != token:
            return False
    try:
        os.remove(path + LOCK_SUFFIX)
    except FileNotFoundError:
        return False
    return True


def _lock_owner():
    try:
        user = getpass.getuser()
    except (OSError, KeyError, ImportError):
        user = "unknown"
    return f"{user}@{socket.gethostname()}"


def _acquire_lock(path):
    token = os.urandom(8).hex()
    deadline = time.monotonic() + LOCK_WAIT_SECONDS
    while True:
        try:
            fd = os.open(path + LOCK_SUFFIX, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
        except FileExistsError:
            status = lock_status(path)
            if status is not None and status["stale"]:
                release_lock(path, status["token"])
                continue
            if status is not None and time.monotonic() >= deadline:
                raise DatabaseBusy(path, status)
            time.sleep(LOCK_POLL_SECONDS)
            continue
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump({"owner": _lock_owner(), "token": token}, f)
        return token


@contextlib.contextmanager
def _locked(path):
    token = _acquire_lock(path)
    try:
        yield token
    finally:
        release_lock(path, token)


def load(path, password):
    try:
        with open(path, encoding="utf-8") as f:
            outer = json.load(f)
    except (ValueError, UnicodeDecodeError):
        raise RegistryError(f"not an OBELISK database: {path}")
    if not isinstance(outer, dict) or outer.get("format") != MAGIC:
        raise RegistryError(f"not an OBELISK database: {path}")
    if outer.get("version") != VERSION:
        raise RegistryError(f"unsupported database version: {path}")
    if not password:
        raise WrongPassword(path)
    try:
        data = json.loads(pwseal.unseal(password, outer, _SEAL_CONTEXT))
    except aead.TagMismatch:
        raise WrongPassword(path)
    except pwseal.SealError as e:
        raise RegistryError(f"database: {e}")
    except ValueError:
        raise RegistryError(f"database content is corrupt: {path}")
    if (not isinstance(data, dict) or not isinstance(data.get("keys"), dict)
            or not isinstance(data.get("files"), dict)):
        raise RegistryError(f"database has an unexpected layout: {path}")
    return data


def _save(path, password, data, token):
    outer = {"format": MAGIC, "version": VERSION}
    outer.update(pwseal.seal(password, json.dumps(data, sort_keys=True).encode("utf-8"),
                             _SEAL_CONTEXT))
    with atomic_write(path) as f:
        f.write(json.dumps(outer, indent=2).encode("utf-8"))
        status = lock_status(path)
        if status is None or status["token"] != token:
            raise LockReleased(path)


def create(path, password):
    if not password:
        raise RegistryError("a password is required to protect the database")
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with _locked(path) as token:
        if os.path.exists(path):
            raise RegistryError(f"file already exists: {path}")
        _save(path, password, {"keys": {}, "files": {}}, token)


def add_keyfile(path, password, keyfile_path):
    info = read_keyfile_info(keyfile_path)
    stored = None
    if info["protected"]:
        with open(keyfile_path, encoding="utf-8") as f:
            stored = f.read()
    with _locked(path) as token:
        data = load(path, password)
        data["keys"][info["fingerprint"]] = {
            "label": info["label"],
            "path": os.path.abspath(keyfile_path),
            "created": info["created"],
            "keyfile": stored,
        }
        _save(path, password, data, token)
    return info["fingerprint"]


def add_file(path, password, file_id, fp, file_path, cipher):
    with _locked(path) as token:
        data = load(path, password)
        data["files"][file_id] = {
            "fingerprint": fp,
            "path": os.path.abspath(file_path),
            "cipher": cipher,
            "encrypted": utc_timestamp(),
        }
        _save(path, password, data, token)


def keyfile_for(path, password, file_id):
    data = load(path, password)
    entry = data["files"].get(file_id)
    if entry is None:
        return None
    key = data["keys"].get(entry.get("fingerprint"))
    return key["path"] if key else None


def change_password(path, old_password, new_password):
    if not new_password:
        raise RegistryError("a password is required to protect the database")
    with _locked(path) as token:
        try:
            data = load(path, old_password)
        except WrongPassword:
            raise RegistryError(f"the current password for {os.path.basename(path)} is wrong")
        _save(path, new_password, data, token)


def remove_key(path, password, fp):
    with _locked(path) as token:
        data = load(path, password)
        if fp not in data["keys"]:
            raise RegistryError(f"no key with fingerprint {fp}")
        del data["keys"][fp]
        orphaned = []
        for fid, entry in data["files"].items():
            if entry.get("fingerprint") == fp:
                orphaned.append(fid)
        for fid in orphaned:
            del data["files"][fid]
        _save(path, password, data, token)
    return len(orphaned)


def remove_file(path, password, file_id):
    with _locked(path) as token:
        data = load(path, password)
        if file_id not in data["files"]:
            raise RegistryError(f"no file with id {file_id}")
        del data["files"][file_id]
        _save(path, password, data, token)


def find_keyfile(unlocked, file_id):
    for path, password in unlocked.items():
        try:
            keyfile = keyfile_for(path, password, file_id)
        except (RegistryError, OSError):
            continue
        if keyfile:
            return keyfile
    return None


def known_keyfiles(unlocked):
    paths = []
    for path, password in unlocked.items():
        try:
            keys = load(path, password)["keys"]
        except (RegistryError, OSError):
            continue
        for entry in keys.values():
            if entry.get("path") and entry["path"] not in paths:
                paths.append(entry["path"])
    return sorted(paths)


def _databases_with_key(unlocked, fp):
    found = []
    for path, password in unlocked.items():
        if fp in load(path, password)["keys"]:
            found.append(path)
    return found


def record_keyfile(unlocked, active, keyfile_path):
    fp = read_keyfile_info(keyfile_path)["fingerprint"]
    if active not in unlocked or _databases_with_key(unlocked, fp):
        return None
    add_keyfile(active, unlocked[active], keyfile_path)
    return active


def update_stored_keyfile(unlocked, keyfile_path):
    fp = read_keyfile_info(keyfile_path)["fingerprint"]
    updated = _databases_with_key(unlocked, fp)
    for path in updated:
        add_keyfile(path, unlocked[path], keyfile_path)
    return updated


def record_file(unlocked, active, file_id, fp, file_path, cipher):
    targets = _databases_with_key(unlocked, fp)
    if not targets and active in unlocked:
        targets = [active]
    for path in targets:
        add_file(path, unlocked[path], file_id, fp, file_path, cipher)
    return targets


def restore_keyfile(path, password, fp, out_path):
    with _locked(path) as token:
        data = load(path, password)
        entry = data["keys"].get(fp)
        if not entry or not entry.get("keyfile"):
            raise RegistryError(f"no stored keyfile for fingerprint {fp}")
        write_keyfile_text(out_path, entry["keyfile"])
        try:
            restored_fp = read_keyfile_info(out_path)["fingerprint"]
        except KeyfileError as e:
            raise RegistryError(f"restored keyfile is invalid: {e}")
        if restored_fp != fp:
            raise RegistryError("restored keyfile does not match the fingerprint")
        entry["path"] = os.path.abspath(out_path)
        _save(path, password, data, token)
