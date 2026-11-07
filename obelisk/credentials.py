from __future__ import annotations

import ctypes
import sys

_ENTROPY = b"OBELISK-database-login-v1"
_CRYPTPROTECT_UI_FORBIDDEN = 0x01


class _Blob(ctypes.Structure):
    _fields_ = [("cbData", ctypes.c_uint32), ("pbData", ctypes.POINTER(ctypes.c_char))]


def available():
    return sys.platform == "win32"


def _call(function_name, data):
    if not available():
        raise OSError("remembering a login is only supported on Windows")
    function = getattr(ctypes.windll.crypt32, function_name)
    data_buffer = ctypes.create_string_buffer(data, len(data))
    entropy_buffer = ctypes.create_string_buffer(_ENTROPY, len(_ENTROPY))
    data_in = _Blob(len(data), ctypes.cast(data_buffer, ctypes.POINTER(ctypes.c_char)))
    entropy = _Blob(len(_ENTROPY), ctypes.cast(entropy_buffer, ctypes.POINTER(ctypes.c_char)))
    data_out = _Blob()
    if not function(ctypes.byref(data_in), None, ctypes.byref(entropy), None, None,
                    _CRYPTPROTECT_UI_FORBIDDEN, ctypes.byref(data_out)):
        raise ctypes.WinError()
    try:
        return ctypes.string_at(data_out.pbData, data_out.cbData)
    finally:
        ctypes.windll.kernel32.LocalFree(data_out.pbData)


def protect(data):
    return _call("CryptProtectData", data)


def unprotect(blob):
    return _call("CryptUnprotectData", blob)
