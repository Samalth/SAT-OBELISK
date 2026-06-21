from __future__ import annotations

import json
import os
import sys

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
        tmp = _config_path() + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(prefs, f, indent=2)
        os.replace(tmp, _config_path())
    except OSError:
        pass
