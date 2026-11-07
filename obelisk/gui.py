from __future__ import annotations

import os
import sys
import threading
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

from . import aead
from . import ciphers
from . import gui_dialogs
from . import registry
from . import settings
from . import __version__
from .filecrypt import encrypt_path, decrypt_file, file_id, FileFormatError
from .gui_database import DatabaseTab, load_contents
from .keyfile import (
    generate_keyfile, load_keyfile, protect_keyfile, change_keyfile_password, read_keyfile_info,
    parse_hex_key, new_key, fingerprint, KeyfileError, KeyfilePasswordRequired,
)
from .i18n import Translator, detect_language
from .resources import resource_path

PAD = 8
COLORS = {"info": "#444", "success": "#1a7f37", "error": "#c0392b", "working": "#b8860b"}
DEFAULT_GEOMETRY = "620x600"
DETAILS_GEOMETRY = "620x760"
DEFAULT_LANG = "nl"
MAX_LISTED_DATABASES = 8


def _find_keyfile(unlocked, src):
    try:
        return registry.find_keyfile(unlocked, file_id(src))
    except (FileFormatError, OSError):
        return None


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
        self.unlocked = {}
        self.db_state = {}
        self.db_locks = {}
        self.known_keyfiles = []
        self.db_lock = threading.Lock()
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
        self.after(200, self._unlock_databases)

    def _set_icon(self):
        for setter, name in ((self.iconbitmap, "icon.ico"), (None, "icon.png")):
            try:
                path = resource_path("assets", name)
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

        self.tabs = ttk.Notebook(root)
        self.tabs.pack(fill="x", pady=(PAD, 0))
        main = ttk.Frame(self.tabs, padding=PAD)
        self.db_tab = DatabaseTab(self.tabs, self, PAD)
        self.tabs.add(main, text=self.t("tab_crypt"))
        self.tabs.add(self.db_tab, text=self.t("tab_database"))

        mode = ttk.LabelFrame(main, text=self.t("operation"), padding=PAD)
        mode.pack(fill="x")
        ttk.Radiobutton(mode, text=self.t("encrypt"), value="encrypt", variable=self.mode,
                        command=self._suggest_out).pack(side="left", padx=PAD)
        ttk.Radiobutton(mode, text=self.t("decrypt"), value="decrypt", variable=self.mode,
                        command=self._suggest_out).pack(side="left", padx=PAD)

        files = ttk.LabelFrame(main, text=self.t("files"), padding=PAD)
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

        cf = ttk.LabelFrame(main, text=self.t("cipher"), padding=PAD)
        cf.pack(fill="x", pady=(0, PAD))
        cc = ttk.Combobox(cf, values=ciphers.names(), textvariable=self.cipher,
                          state="readonly", width=14)
        cc.bind("<<ComboboxSelected>>", self._on_cipher)
        cc.pack(side="left")
        ttk.Label(cf, text=self.t("cipher_hint"), foreground="#666").pack(side="left", padx=PAD)

        key = ttk.LabelFrame(main, text=self.t("key"), padding=PAD)
        key.pack(fill="x", pady=(0, PAD))
        row = ttk.Frame(key); row.pack(fill="x")
        for label, val in (("keyfile", "keyfile"), ("hexkey", "hex"), ("password", "password")):
            ttk.Radiobutton(row, text=self.t(label), value=val, variable=self.keysrc,
                            command=self._refresh_key).pack(side="left", padx=PAD)
        self.key_area = ttk.Frame(key)
        self.key_area.pack(fill="x", pady=(PAD, 0))

        run = ttk.Frame(main); run.pack(fill="x", pady=(PAD, 0))
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
            known = ttk.Combobox(r, textvariable=self.keyfile_path)
            known.configure(postcommand=lambda: known.configure(values=self.known_keyfiles))
            known.pack(side="left", fill="x", expand=True, padx=(0, PAD))
            ttk.Button(r, text=self.t("browse"), command=self._pick_keyfile).pack(side="left")
            ttk.Button(r, text=self.t("new_btn"), command=self._new_keyfile).pack(side="left", padx=(PAD, 0))
            ttk.Button(r, text=self.t("password_btn"),
                       command=self._change_keyfile_password).pack(side="left", padx=(PAD, 0))
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
            self._suggest_key(src)

    def run_in_background(self, work, done):
        def runner():
            result = work()
            self.after(0, lambda: done(result))
        threading.Thread(target=runner, daemon=True).start()

    def write_databases(self, work, done):
        unlocked = dict(self.unlocked)
        active = settings.active_database()

        def locked_work():
            with self.db_lock:
                try:
                    return work(unlocked, active), None
                except (registry.RegistryError, KeyfileError, FileFormatError, OSError) as e:
                    return None, e
        self.run_in_background(locked_work,
                               lambda outcome: self._write_finished(outcome, work, done))

    def _write_finished(self, outcome, work, done):
        error = outcome[1]
        if isinstance(error, registry.LockReleased):
            if gui_dialogs.ask_choice(
                    self, self.t("lock_released_title"),
                    self.t("lock_released_msg", name=os.path.basename(error.path)),
                    self.t("merge_btn")):
                self.write_databases(work, done)
                return
        elif isinstance(error, registry.DatabaseBusy):
            if gui_dialogs.ask_choice(
                    self, self.t("db_busy_title"),
                    self.t("db_busy_msg", name=os.path.basename(error.path),
                           owner=error.status["owner"], since=error.status["since_text"]),
                    self.t("release_lock_btn")):
                registry.release_lock(error.path)
                self.write_databases(work, done)
                return
        elif isinstance(error, registry.WrongPassword):
            self._log(self.t("registry_warning", err=error))
            self.unlocked.pop(error.path, None)
            self.db_state[error.path] = "locked"
            self.login_database(error.path, str(error),
                                then=lambda: self.write_databases(work, done))
            return
        done(outcome)

    def _suggest_key(self, src):
        if not self.unlocked:
            return
        unlocked = dict(self.unlocked)
        self.run_in_background(lambda: _find_keyfile(unlocked, src),
                               lambda keyfile: self._key_suggested(src, keyfile))

    def _key_suggested(self, src, keyfile):
        if not keyfile or src != self.infile.get() or keyfile == self.keyfile_path.get():
            return
        self.keysrc.set("keyfile")
        self.keyfile_path.set(keyfile)
        self._refresh_key()
        self._log(self.t("registry_key_found", path=keyfile))

    def _register_keyfile(self, path):
        self.write_databases(
            lambda unlocked, active: registry.record_keyfile(unlocked, active, path),
            self._databases_written)

    def _record_use(self, op, outfile, cipher, keyfile, fp):
        if not self.unlocked:
            return

        def work(unlocked, active):
            if keyfile:
                registry.record_keyfile(unlocked, active, keyfile)
            if op == "encrypt":
                registry.record_file(unlocked, active, file_id(outfile), fp, outfile, cipher)
            return True
        self.write_databases(work, self._databases_written)

    def _databases_written(self, outcome):
        written, error = outcome
        if error is not None:
            self._log(self.t("registry_warning", err=error))
        elif written:
            self.databases_changed()

    def _unlock_databases(self):
        self.scan_databases(settings.databases(), ask_login=True)

    def scan_databases(self, paths, ask_login):
        for path in paths:
            if path not in self.unlocked:
                self.db_state[path] = "checking"
        self.db_tab.refresh()
        if paths:
            self.run_in_background(lambda: settings.scan_databases(paths),
                                   lambda result: self._databases_scanned(result, ask_login))

    def _databases_scanned(self, result, ask_login):
        states, unlocked, locks = result
        self.unlocked.update(unlocked)
        self.db_locks.update(locks)
        locked = []
        for path, state in states.items():
            if path in self.unlocked:
                state = "unlocked"
            self.db_state[path] = state
            if state == "locked":
                locked.append(path)
        self.databases_changed()
        if not ask_login:
            return
        if len(locked) == 1:
            self.login_database(locked[0])
        elif locked:
            names = []
            for path in locked[:MAX_LISTED_DATABASES]:
                names.append(os.path.basename(path))
            if len(locked) > MAX_LISTED_DATABASES:
                names.append(self.t("db_and_more", n=len(locked) - MAX_LISTED_DATABASES))
            if messagebox.askyesno(self.t("db_locked_title"),
                                   self.t("db_locked_many", names="\n".join(names))):
                self.tabs.select(self.db_tab)

    def login_database(self, path, error="", then=None):
        name = os.path.basename(path)
        answer = gui_dialogs.ask_password(self, self.t("db_login_title"),
                                          self.t("pw_for", name=name),
                                          remember=True, error=error)
        if answer is None:
            return
        password, remember = answer
        self._status(self.t("db_checking", name=name), "working")
        self.run_in_background(
            lambda: load_contents(path, password)[1],
            lambda error: self._login_checked(path, password, remember, error, then))

    def _login_checked(self, path, password, remember, error, then):
        if isinstance(error, registry.RegistryError):
            self.login_database(path, str(error), then)
            return
        if error is not None:
            self._status(self.t("registry_error", err=error), "error")
            return
        self.unlocked[path] = password
        self.db_state[path] = "unlocked"
        if remember:
            settings.remember_login(path, password)
        self._status(self.t("db_logged_in", name=os.path.basename(path)), "success")
        self.databases_changed()
        if then is not None:
            then()

    def databases_changed(self):
        self.db_tab.refresh()
        unlocked = dict(self.unlocked)
        self.run_in_background(lambda: registry.known_keyfiles(unlocked),
                               lambda paths: setattr(self, "known_keyfiles", paths))
        if self.mode.get() == "decrypt" and self.infile.get():
            self._suggest_key(self.infile.get())

    def ask_new_password(self, title, prompt):
        answer = gui_dialogs.ask_password(self, title, prompt, confirm=True)
        return answer[0] if answer else None

    def _prefill(self, path):
        self.infile.set(path)
        self.mode.set("decrypt" if path.lower().endswith(".obl") else "encrypt")
        self._suggest_out()
        self._status(self.t("ready"), "info")

    def _pick_keyfile(self):
        path = filedialog.askopenfilename(
            title=self.t("dlg_select_keyfile"),
            filetypes=[("OBELISK keyfile", "*.key"), ("All", "*.*")])
        if not path:
            return
        path = os.path.normpath(path)
        self.keyfile_path.set(path)
        try:
            info = read_keyfile_info(path)
        except (KeyfileError, OSError) as e:
            self._status(self.t("keyfile_error", err=e), "error")
            return
        self._log(self.t("loaded_keyfile", fp=info["fingerprint"]))
        if not info["protected"] and messagebox.askyesno(self.t("unprotected_title"),
                                                         self.t("unprotected_msg")):
            password = self.ask_new_password(self.t("keyfile_pw_title"), self.t("keyfile_pw_new"))
            if password:
                try:
                    protect_keyfile(path, password)
                except (KeyfileError, OSError) as e:
                    self._status(self.t("keyfile_error", err=e), "error")
                    return
                self._status(self.t("protected_keyfile", fp=info["fingerprint"]), "success")
        self._register_keyfile(path)

    def _new_keyfile(self):
        path = filedialog.asksaveasfilename(title=self.t("dlg_create_keyfile"),
                                            defaultextension=".key",
                                            filetypes=[("OBELISK keyfile", "*.key")])
        if not path:
            return
        path = os.path.normpath(path)
        password = self.ask_new_password(self.t("keyfile_pw_title"), self.t("keyfile_pw_new"))
        if not password:
            return
        try:
            _, fp = generate_keyfile(path, password, label=os.path.basename(path))
        except (KeyfileError, OSError) as e:
            self._status(self.t("failed", err=e), "error")
            return
        self._register_keyfile(path)
        self.keyfile_path.set(path)
        self._status(self.t("created_keyfile", fp=fp), "success")
        messagebox.showinfo(self.t("keyfile_saved_title"),
                            self.t("keyfile_saved_msg", path=path, fp=fp))

    def _change_keyfile_password(self):
        path = self.keyfile_path.get().strip()
        if not path:
            self._status(self.t("choose_keyfile"), "error")
            return
        try:
            protected = read_keyfile_info(path)["protected"]
        except (KeyfileError, OSError) as e:
            self._status(self.t("keyfile_error", err=e), "error")
            return
        old_password = None
        if protected:
            answer = gui_dialogs.ask_password(
                self, self.t("keyfile_pw_title"),
                self.t("pw_current_for", name=os.path.basename(path)))
            if answer is None:
                return
            old_password = answer[0]
        new_password = self.ask_new_password(self.t("keyfile_pw_title"), self.t("keyfile_pw_new"))
        if not new_password:
            return
        try:
            fp = change_keyfile_password(path, old_password, new_password)
        except (KeyfileError, OSError) as e:
            self._status(self.t("keyfile_error", err=e), "error")
            return
        self._status(self.t("keyfile_pw_changed", fp=fp), "success")
        self.write_databases(
            lambda unlocked, active: registry.update_stored_keyfile(unlocked, path),
            self._databases_written)

    def _gen_hex(self):
        k = new_key()
        self.hexkey.set(k.hex())
        self._log(self.t("generated_key", fp=fingerprint(k)))

    def _show_fp(self):
        try:
            k = parse_hex_key(self.hexkey.get())
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
            try:
                key = load_keyfile(p)
            except KeyfilePasswordRequired:
                answer = gui_dialogs.ask_password(
                    self, self.t("keyfile_pw_title"),
                    self.t("pw_for", name=os.path.basename(p)))
                if answer is None:
                    raise ValueError(self.t("keyfile_pw_cancelled"))
                key = load_keyfile(p, answer[0])
            return key, None
        if src == "hex":
            try:
                return parse_hex_key(self.hexkey.get()), None
            except ValueError:
                raise ValueError(self.t("key_len_err", n=aead.KEY_BYTES * 2))
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
        keyfile = self.keyfile_path.get().strip() if self.keysrc.get() == "keyfile" else None
        self.run_btn.configure(state="disabled")
        op = self.mode.get()
        self._status(self.t("encrypting" if op == "encrypt" else "decrypting"), "working")
        self._prog = {"done": 0, "total": 0}
        self.progress_var.set(0)
        self._running = True
        self.after(80, self._poll_progress)
        threading.Thread(target=self._work,
                         args=(op, infile, outfile, key, password, self.cipher.get(), keyfile),
                         daemon=True).start()

    def _set_prog(self, done, total):
        self._prog = {"done": done, "total": total}

    def _poll_progress(self):
        total = self._prog["total"]
        if total > 0:
            self.progress_var.set(min(100.0, 100.0 * self._prog["done"] / total))
        if self._running:
            self.after(80, self._poll_progress)

    def _work(self, op, infile, outfile, key, password, cipher, keyfile):
        try:
            if op == "encrypt":
                encrypt_path(infile, outfile, key=key, password=password,
                             cipher=cipher, progress=self._set_prog)
                tkey = "encrypted_folder" if os.path.isdir(infile) else "encrypted_file"
                msg = self.t(tkey, cipher=cipher, path=outfile)
                if key is not None:
                    fp = fingerprint(key)
                    self.after(0, lambda: self._log(self.t("key_fp", fp=fp)))
            else:
                decrypt_file(infile, outfile, key=key, password=password, progress=self._set_prog)
                msg = self.t("decrypted", path=outfile)
            self.after(0, lambda: self._done(msg, "success"))
            if key is not None:
                self.after(0, lambda: self._record_use(op, outfile, cipher, keyfile,
                                                       fingerprint(key)))
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
