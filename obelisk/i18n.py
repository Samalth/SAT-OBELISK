from __future__ import annotations

import json
import os
import sys

LANG_NAMES = {
    "en": "English",
    "nl": "Nederlands",
    "es": "Español",
    "zh": "中文",
    "ro": "Română",
    "fr": "Français",
    "de": "Deutsch",
    "it": "Italiano",
    "pt": "Português",
}


def _locales_dir():
    base = getattr(sys, "_MEIPASS", None)
    if base:
        return os.path.join(base, "locales")
    return os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "locales")


def _load(lang):
    path = os.path.join(_locales_dir(), lang + ".json")
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except OSError:
        return {}


REGISTRY_KEY = r"Software\SAT-Obelisk"
REGISTRY_VALUE = "Language"


def _registry_language():
    """Return the language the installer recorded, or None if unavailable."""
    if sys.platform != "win32":
        return None
    try:
        import winreg
    except ImportError:
        return None
    for root in (winreg.HKEY_CURRENT_USER, winreg.HKEY_LOCAL_MACHINE):
        try:
            with winreg.OpenKey(root, REGISTRY_KEY) as k:
                val, _ = winreg.QueryValueEx(k, REGISTRY_VALUE)
                if val:
                    return str(val)
        except OSError:
            continue
    return None


def detect_language(default="en"):
    """Pick the startup language: installer choice if a matching locale exists,
    otherwise the given default."""
    lang = _registry_language()
    if lang and os.path.exists(os.path.join(_locales_dir(), lang + ".json")):
        return lang
    return default


class Translator:
    def __init__(self, lang="en"):
        self._cache = {"en": _load("en")}
        self.set(lang)

    def available(self):
        d = _locales_dir()
        langs = []
        if os.path.isdir(d):
            langs = sorted(f[:-5] for f in os.listdir(d) if f.endswith(".json"))
        return langs or ["en"]

    def set(self, lang):
        if lang not in self._cache:
            self._cache[lang] = _load(lang)
        self.lang = lang
        self._strings = self._cache[lang]

    def t(self, key, **kw):
        s = self._strings.get(key) or self._cache["en"].get(key) or key
        if kw:
            try:
                return s.format(**kw)
            except (KeyError, IndexError, ValueError):
                return s
        return s
