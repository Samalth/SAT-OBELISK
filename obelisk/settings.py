from __future__ import annotations

import base64
import json
import os
import sys

from . import credentials
from . import registry
from .filecrypt import atomic_write

APP_DIR_NAME = "SAT-Obelisk"
CONFIG_FILE = "config.json"


def _config_dir():
    if sys.platform == "win32":
        base = os.environ.get("APPDATA") or os.path.expanduser("~")
    else:
        base = os.environ.get("XDG_CONFIG_HOME") or os.path.join(
            os.path.expanduser("~"), ".config")
    return os.path.join(base, APP_DIR_NAME)


def _config_path():
    return os.path.join(_config_dir(), CONFIG_FILE)


def load_prefs():
    try:
        with open(_config_path(), encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def get_pref(key, default=None):
    return load_prefs().get(key, default)


def set_pref(key, value):
    """Persist a single preference. Best-effort: never raises, so a read-only
    or unavailable config location can't break the app."""
    prefs = load_prefs()
    prefs[key] = value
    try:
        os.makedirs(_config_dir(), exist_ok=True)
        with atomic_write(_config_path()) as f:
            f.write(json.dumps(prefs, indent=2).encode("utf-8"))
    except OSError:
        pass


def _path_key(path):
    return os.path.normcase(os.path.abspath(path))


def databases():
    stored = get_pref("databases", [])
    paths = []
    for path in stored if isinstance(stored, list) else []:
        if isinstance(path, str):
            paths.append(path)
    return paths


def linked_path(path):
    for linked in databases():
        if _path_key(linked) == _path_key(path):
            return linked
    return None


def link_database(path):
    linked = linked_path(path)
    if linked is None:
        linked = path
        set_pref("databases", databases() + [linked])
    if active_database() is None:
        set_pref("active_database", linked)
    return linked


def unlink_database(path):
    remaining = []
    for linked in databases():
        if _path_key(linked) != _path_key(path):
            remaining.append(linked)
    set_pref("databases", remaining)
    forget_login(path)
    if active_database() is None:
        set_pref("active_database", remaining[0] if remaining else None)


def active_database():
    active = get_pref("active_database")
    return linked_path(active) if isinstance(active, str) else None


def set_active_database(path):
    linked = linked_path(path)
    if linked is not None:
        set_pref("active_database", linked)
    return linked


def _logins():
    logins = get_pref("database_logins", {})
    return logins if isinstance(logins, dict) else {}


def remember_login(path, password):
    logins = _logins()
    blob = credentials.protect(password.encode("utf-8"))
    logins[_path_key(path)] = base64.b64encode(blob).decode("ascii")
    set_pref("database_logins", logins)


def remembered_login(path):
    blob = _logins().get(_path_key(path))
    if not isinstance(blob, str):
        return None
    try:
        return credentials.unprotect(base64.b64decode(blob)).decode("utf-8")
    except (OSError, ValueError):
        return None


def scan_databases(paths):
    states = {}
    unlocked = {}
    locks = {}
    for path in paths:
        if not os.path.exists(path):
            states[path] = "missing"
            continue
        locks[path] = registry.lock_status(path)
        password = remembered_login(path)
        if password is not None:
            try:
                registry.load(path, password)
                unlocked[path] = password
                states[path] = "unlocked"
                continue
            except (registry.RegistryError, OSError):
                pass
        states[path] = "locked"
    return states, unlocked, locks


def forget_login(path):
    logins = _logins()
    if logins.pop(_path_key(path), None) is not None:
        set_pref("database_logins", logins)
