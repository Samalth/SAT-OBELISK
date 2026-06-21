from __future__ import annotations

import os
import sys
import threading
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

from . import aead
from . import ciphers
from . import settings
from . import __version__
from .filecrypt import encrypt_path, decrypt_file, FileFormatError
from .keyfile import (
    generate_keyfile, load_keyfile, new_key, fingerprint, KeyfileError,
)
from .i18n import Translator, detect_language

PAD = 8
COLORS = {"info": "#444", "success": "#1a7f37", "error": "#c0392b", "working": "#b8860b"}
DEFAULT_GEOMETRY = "620x600"
DETAILS_GEOMETRY = "620x760"
DEFAULT_LANG = "nl"


def _resource(name, sub):
    base = getattr(sys, "_MEIPASS", None)
    if base:
        return os.path.join(base, sub, name)
    return os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), sub, name)


class ObeliskApp(tk.Tk):
    def __init__(self, initial_path=None):
        super().__init__()
        self.tr = Translator(detect_language(DEFAULT_LANG))
        self.title("OBELISK")
        self.geometry(DEFAULT_GEOMETRY)
        self.minsize(580, 560)
        self._set_icon()
        self.mode = tk.StringVar(value="encrypt")
        self.keysrc = tk.StringVar(value="keyfile")
        saved_cipher = settings.get_pref("cipher", ciphers.DEFAULT)
        if saved_cipher not in ciphers.names():
            saved_cipher = ciphers.DEFAULT
        self.cipher = tk.StringVar(value=saved_cipher)
        self.infile = tk.StringVar()
        self.outfile = tk.StringVar()
        self.keyfile_path = tk.StringVar()
        self.hexkey = tk.StringVar()
        self.password = tk.StringVar()
        self.show_pw = tk.BooleanVar(value=False)
        self.status_var = tk.StringVar()
        self.progress_var = tk.DoubleVar(value=0)
        self._status_kind = "info"
        self._loglines = []
        self.details_open = False
        self._prog = {"done": 0, "total": 0}
        self._running = False
        self._build()
        if initial_path:
            self._prefill(initial_path)
        else:
            self._status(self.tr.t("ready"), "info")

    def _set_icon(self):
        for setter, name in ((self.iconbitmap, "icon.ico"), (None, "icon.png")):
            try:
                path = _resource(name, "assets")
                if not os.path.exists(path):
                    continue
                if name.endswith(".ico"):
                    self.iconbitmap(path)
                else:
                    self._icon_img = tk.PhotoImage(file=path)
                    self.iconphoto(True, self._icon_img)
            except Exception:
                pass

    def t(self, key, **kw):
        return self.tr.t(key, **kw)

    def _build(self):
        self.root_frame = ttk.Frame(self, padding=PAD)
        self.root_frame.pack(fill="both", expand=True)
        root = self.root_frame

        head = ttk.Frame(root); head.pack(fill="x", anchor="w")
        ttk.Label(head, text="OBELISK", font=("Segoe UI", 18, "bold")).pack(anchor="w")
        ttk.Label(head, text=self.t("subtitle"), foreground="#666").pack(anchor="w")

        mode = ttk.LabelFrame(root, text=self.t("operation"), padding=PAD)
        mode.pack(fill="x", pady=(PAD, 0))
        ttk.Radiobutton(mode, text=self.t("encrypt"), value="encrypt", variable=self.mode,
                        command=self._suggest_out).pack(side="left", padx=PAD)
        ttk.Radiobutton(mode, text=self.t("decrypt"), value="decrypt", variable=self.mode,
                        command=self._suggest_out).pack(side="left", padx=PAD)

        files = ttk.LabelFrame(root, text=self.t("files"), padding=PAD)
        files.pack(fill="x", pady=PAD)
        r = ttk.Frame(files); r.pack(fill="x", pady=2)
        ttk.Label(r, text=self.t("input"), width=8).pack(side="left")
        ttk.Entry(r, textvariable=self.infile).pack(side="left", fill="x", expand=True, padx=PAD)
        ttk.Button(r, text=self.t("file_btn"), command=self._pick_in).pack(side="left")
        ttk.Button(r, text=self.t("folder_btn"), command=self._pick_in_dir).pack(side="left", padx=(4, 0))
        r2 = ttk.Frame(files); r2.pack(fill="x", pady=2)
        ttk.Label(r2, text=self.t("output"), width=8).pack(side="left")
        ttk.Entry(r2, textvariable=self.outfile).pack(side="left", fill="x", expand=True, padx=PAD)
        ttk.Button(r2, text=self.t("browse"), command=self._pick_out).pack(side="left")

        cf = ttk.LabelFrame(root, text=self.t("cipher"), padding=PAD)
        cf.pack(fill="x", pady=(0, PAD))
        cc = ttk.Combobox(cf, values=ciphers.names(), textvariable=self.cipher,
                          state="readonly", width=14)
        cc.bind("<<ComboboxSelected>>", self._on_cipher)
        cc.pack(side="left")
        ttk.Label(cf, text=self.t("cipher_hint"), foreground="#666").pack(side="left", padx=PAD)

        key = ttk.LabelFrame(root, text=self.t("key"), padding=PAD)
        key.pack(fill="x", pady=(0, PAD))
        row = ttk.Frame(key); row.pack(fill="x")
        for label, val in (("keyfile", "keyfile"), ("hexkey", "hex"), ("password", "password")):
            ttk.Radiobutton(row, text=self.t(label), value=val, variable=self.keysrc,
                            command=self._refresh_key).pack(side="left", padx=PAD)
        self.key_area = ttk.Frame(key)
        self.key_area.pack(fill="x", pady=(PAD, 0))

        run = ttk.Frame(root); run.pack(fill="x", pady=PAD)
        self.run_btn = ttk.Button(run, text=self.t("run"), command=self._run)
        self.run_btn.pack(side="right")
        self.progress = ttk.Progressbar(run, variable=self.progress_var, maximum=100)
        self.progress.pack(side="left", fill="x", expand=True, padx=(0, PAD))

        bar = ttk.Frame(root); bar.pack(fill="x", pady=(PAD, 0))
        self.status_lbl = ttk.Label(bar, textvariable=self.status_var,
                                    foreground=COLORS[self._status_kind], wraplength=430)
        self.status_lbl.pack(side="left", fill="x", expand=True)
        self.toggle_btn = ttk.Button(
            bar, text=self.t("hide_details" if self.details_open else "show_details"),
            width=18, command=self._toggle_details)
        self.toggle_btn.pack(side="right")

        self.logframe = ttk.LabelFrame(root, text=self.t("details"), padding=PAD)
        self.log = tk.Text(self.logframe, height=8, wrap="word", state="disabled",
                           bg="#111", fg="#0f0", insertbackground="#0f0")
        self.log.pack(fill="both", expand=True)
        if self.details_open:
            self.logframe.pack(fill="both", expand=True, pady=(PAD, 0))

        self.footer = ttk.Label(
            root, text=f"v{__version__}  ·  © S.A. Thiers",
            foreground="#999", font=("Segoe UI", 8), anchor="center")
        self.footer.pack(side="bottom", fill="x", pady=(PAD, 0))

        self._render_log()
        self._refresh_key()

    def _toggle_details(self):
        if self.details_open:
            self.logframe.pack_forget()
            self.toggle_btn.configure(text=self.t("show_details"))
            self.geometry(DEFAULT_GEOMETRY)
        else:
            self.logframe.pack(fill="both", expand=True, pady=(PAD, 0))
            self.toggle_btn.configure(text=self.t("hide_details"))
            self.geometry(DETAILS_GEOMETRY)
        self.details_open = not self.details_open

    def _refresh_key(self):
        for w in self.key_area.winfo_children():
            w.destroy()
        src = self.keysrc.get()
        if src == "keyfile":
            r = ttk.Frame(self.key_area); r.pack(fill="x")
            ttk.Entry(r, textvariable=self.keyfile_path).pack(
                side="left", fill="x", expand=True, padx=(0, PAD))
            ttk.Button(r, text=self.t("browse"), command=self._pick_keyfile).pack(side="left")
            ttk.Button(r, text=self.t("new_btn"), command=self._new_keyfile).pack(side="left", padx=(PAD, 0))
        elif src == "hex":
            r = ttk.Frame(self.key_area); r.pack(fill="x")
            ttk.Entry(r, textvariable=self.hexkey).pack(
                side="left", fill="x", expand=True, padx=(0, PAD))
            ttk.Button(r, text=self.t("generate"), command=self._gen_hex).pack(side="left")
            ttk.Button(r, text=self.t("fingerprint_btn"), command=self._show_fp).pack(side="left", padx=(PAD, 0))
        else:
            r = ttk.Frame(self.key_area); r.pack(fill="x")
            self.pw_entry = ttk.Entry(r, textvariable=self.password, show="*")
            self.pw_entry.pack(side="left", fill="x", expand=True, padx=(0, PAD))
            ttk.Checkbutton(r, text=self.t("show"), variable=self.show_pw,
                            command=self._toggle_pw).pack(side="left")
            ttk.Label(self.key_area, foreground="#a60", wraplength=520,
                      text=self.t("pw_warning")).pack(anchor="w", pady=(4, 0))

    def _toggle_pw(self):
        self.pw_entry.configure(show="" if self.show_pw.get() else "*")

    def _on_cipher(self, _evt=None):
        settings.set_pref("cipher", self.cipher.get())

    def _pick_in(self):
        path = filedialog.askopenfilename(title=self.t("dlg_select_input_file"))
        if path:
            self.infile.set(path); self._suggest_out()

    def _pick_in_dir(self):
        path = filedialog.askdirectory(title=self.t("dlg_select_input_folder"))
        if path:
            self.infile.set(path); self._suggest_out()

    def _pick_out(self):
        if self.mode.get() == "decrypt":
            path = filedialog.asksaveasfilename(title=self.t("dlg_select_output"))
        else:
            path = filedialog.asksaveasfilename(title=self.t("dlg_select_output_file"),
                                                defaultextension=".obl")
        if path:
            self.outfile.set(path)

    def _suggest_out(self):
        src = self.infile.get()
        if not src:
            return
        if self.mode.get() == "encrypt":
            self.outfile.set(os.path.normpath(src) + ".obl")
        else:
            self.outfile.set(src[:-4] if src.endswith(".obl") else src + ".out")

    def _prefill(self, path):
        self.infile.set(path)
        self.mode.set("decrypt" if path.lower().endswith(".obl") else "encrypt")
        self._suggest_out()
        self._status(self.t("ready"), "info")

    def _pick_keyfile(self):
        path = filedialog.askopenfilename(
            title=self.t("dlg_select_keyfile"),
            filetypes=[("OBELISK keyfile", "*.key"), ("All", "*.*")])
        if path:
            self.keyfile_path.set(path)
            try:
                k = load_keyfile(path)
                self._log(self.t("loaded_keyfile", fp=fingerprint(k)))
            except (KeyfileError, OSError) as e:
                self._status(self.t("keyfile_error", err=e), "error")

    def _new_keyfile(self):
        path = filedialog.asksaveasfilename(title=self.t("dlg_create_keyfile"),
                                            defaultextension=".key",
                                            filetypes=[("OBELISK keyfile", "*.key")])
        if not path:
            return
        try:
            _, fp = generate_keyfile(path, label=os.path.basename(path))
        except OSError as e:
            self._status(self.t("failed", err=e), "error")
            return
        self.keyfile_path.set(path)
        self._status(self.t("created_keyfile", fp=fp), "success")
        messagebox.showinfo(self.t("keyfile_saved_title"),
                            self.t("keyfile_saved_msg", path=path, fp=fp))

    def _gen_hex(self):
        k = new_key()
        self.hexkey.set(k.hex())
        self._log(self.t("generated_key", fp=fingerprint(k)))

    def _show_fp(self):
        try:
            k = bytes.fromhex(self.hexkey.get().strip())
            if len(k) != aead.KEY_BYTES:
                raise ValueError
        except ValueError:
            self._status(self.t("enter_valid_key"), "error")
            return
        self._log(self.t("fp_line", fp=fingerprint(k)))

    def _resolve_key(self):
        src = self.keysrc.get()
        if src == "keyfile":
            p = self.keyfile_path.get().strip()
            if not p:
                raise ValueError(self.t("choose_keyfile"))
            return load_keyfile(p), None
        if src == "hex":
            k = bytes.fromhex(self.hexkey.get().strip())
            if len(k) != aead.KEY_BYTES:
                raise ValueError(self.t("key_len_err", n=aead.KEY_BYTES * 2))
            return k, None
        pw = self.password.get()
        if not pw:
            raise ValueError(self.t("enter_password"))
        return None, pw

    def _run(self):
        infile = self.infile.get().strip()
        outfile = self.outfile.get().strip()
        if not infile or not outfile:
            self._status(self.t("set_io"), "error"); return
        if not os.path.exists(infile):
            self._status(self.t("input_not_found", path=infile), "error"); return
        if os.path.abspath(infile) == os.path.abspath(outfile):
            self._status(self.t("io_differ"), "error"); return
        try:
            key, password = self._resolve_key()
        except (ValueError, KeyfileError, OSError) as e:
            self._status(self.t("key_error", err=e), "error"); return
        self.run_btn.configure(state="disabled")
        op = self.mode.get()
        self._status(self.t("encrypting" if op == "encrypt" else "decrypting"), "working")
        self._prog = {"done": 0, "total": 0}
        self.progress_var.set(0)
        self._running = True
        self.after(80, self._poll_progress)
        threading.Thread(target=self._work,
                         args=(op, infile, outfile, key, password, self.cipher.get()),
                         daemon=True).start()

    def _set_prog(self, done, total):
        self._prog = {"done": done, "total": total}

    def _poll_progress(self):
        total = self._prog["total"]
        if total > 0:
            self.progress_var.set(min(100.0, 100.0 * self._prog["done"] / total))
        if self._running:
            self.after(80, self._poll_progress)

    def _work(self, op, infile, outfile, key, password, cipher):
        try:
            if op == "encrypt":
                encrypt_path(infile, outfile, key=key, password=password,
                             cipher=cipher, progress=self._set_prog)
                tkey = "encrypted_folder" if os.path.isdir(infile) else "encrypted_file"
                msg = self.t(tkey, cipher=cipher, path=outfile)
                if key is not None:
                    self.after(0, lambda: self._log(self.t("key_fp", fp=fingerprint(key))))
            else:
                decrypt_file(infile, outfile, key=key, password=password, progress=self._set_prog)
                msg = self.t("decrypted", path=outfile)
            self.after(0, lambda: self._done(msg, "success"))
        except ciphers.CipherUnavailable as e:
            self.after(0, lambda e=e: self._done(self.t("failed", err=e), "error"))
        except aead.TagMismatch:
            self.after(0, lambda: self._done(self.t("auth_failed"), "error"))
        except (FileFormatError, OSError, ValueError) as e:
            self.after(0, lambda e=e: self._done(self.t("failed", err=e), "error"))

    def _done(self, msg, kind):
        self._running = False
        self.progress_var.set(100 if kind == "success" else 0)
        self._status(msg, kind)
        self.run_btn.configure(state="normal")

    def _render_log(self):
        self.log.configure(state="normal")
        self.log.delete("1.0", "end")
        for line in self._loglines:
            self.log.insert("end", line + "\n")
        self.log.see("end")
        self.log.configure(state="disabled")

    def _log(self, text):
        self._loglines.append(text)
        self.log.configure(state="normal")
        self.log.insert("end", text + "\n")
        self.log.see("end")
        self.log.configure(state="disabled")

    def _status(self, text, kind="info"):
        self._status_kind = kind
        self.status_var.set(text)
        self.status_lbl.configure(foreground=COLORS.get(kind, COLORS["info"]))
        self._log(text)


def main():
    initial = sys.argv[1] if len(sys.argv) > 1 else None
    if initial and not os.path.exists(initial):
        initial = None
    ObeliskApp(initial_path=initial).mainloop()


if __name__ == "__main__":
    main()
