from __future__ import annotations

import tkinter as tk
from tkinter import ttk

from . import credentials

ERROR_COLOR = "#c0392b"
TEXT_WIDTH = 340


def _open(app, title):
    win = tk.Toplevel(app)
    win.title(title)
    win.transient(app)
    win.resizable(False, False)
    win.geometry(f"+{app.winfo_rootx() + 80}+{app.winfo_rooty() + 140}")
    body = ttk.Frame(win, padding=12)
    body.pack(fill="both", expand=True)
    return win, body


def _run(app, win, body, confirm_text, on_confirm, focus):
    buttons = ttk.Frame(body)
    buttons.pack(fill="x", pady=(6, 0))
    ttk.Button(buttons, text=app.t("cancel_btn"), command=win.destroy).pack(side="right")
    ttk.Button(buttons, text=confirm_text, command=on_confirm).pack(side="right", padx=(0, 6))
    win.bind("<Return>", on_confirm)
    win.bind("<Escape>", lambda _event: win.destroy())
    focus.focus_set()
    win.grab_set()
    app.wait_window(win)


def ask_password(app, title, prompt, confirm=False, remember=False, error=""):
    win, body = _open(app, title)
    password = tk.StringVar()
    repeated = tk.StringVar()
    remember_var = tk.BooleanVar(value=False)
    result = []

    error_label = ttk.Label(body, text=error, foreground=ERROR_COLOR, wraplength=TEXT_WIDTH)
    if error:
        error_label.pack(anchor="w", pady=(0, 6))
    prompt_label = ttk.Label(body, text=prompt, wraplength=TEXT_WIDTH)
    prompt_label.pack(anchor="w")
    entry = ttk.Entry(body, textvariable=password, show="*", width=44)
    entry.pack(fill="x", pady=(2, 6))
    if confirm:
        ttk.Label(body, text=app.t("pw_confirm")).pack(anchor="w")
        ttk.Entry(body, textvariable=repeated, show="*", width=44).pack(fill="x", pady=(2, 6))
    if remember and credentials.available():
        ttk.Checkbutton(body, text=app.t("remember_login"), variable=remember_var).pack(
            anchor="w", pady=(0, 6))

    def ok(_event=None):
        if not password.get():
            return
        if confirm and password.get() != repeated.get():
            error_label.configure(text=app.t("pw_mismatch"))
            error_label.pack(anchor="w", pady=(0, 6), before=prompt_label)
            return
        result.append((password.get(), remember_var.get()))
        win.destroy()

    _run(app, win, body, app.t("ok_btn"), ok, entry)
    return result[0] if result else None


def ask_choice(app, title, message, confirm_text):
    win, body = _open(app, title)
    result = []
    ttk.Label(body, text=message, wraplength=TEXT_WIDTH).pack(anchor="w", pady=(0, 6))

    def ok(_event=None):
        result.append(True)
        win.destroy()

    _run(app, win, body, confirm_text, ok, win)
    return bool(result)
