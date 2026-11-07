from __future__ import annotations

import os
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

from . import gui_dialogs
from . import registry
from . import settings

DATABASE_COLUMN_WIDTHS = {"name": 120, "status": 90, "active": 50, "remembered": 80,
                          "location": 160}
KEY_COLUMN_WIDTHS = {"label": 110, "fingerprint": 130, "created": 140, "files": 45, "path": 200}
FILE_COLUMN_WIDTHS = {"file": 140, "key": 110, "encrypted": 140, "location": 200}


def _tree(parent, columns, height, t):
    names = tuple(columns)
    tree = ttk.Treeview(parent, columns=names, show="headings", height=height,
                        selectmode="browse")
    for col, width in columns.items():
        tree.heading(col, text=t("col_" + col), anchor="w")
        tree.column(col, width=width, stretch=col == names[-1], anchor="w")
    return tree


def load_contents(path, password):
    try:
        return registry.load(path, password), None
    except (registry.RegistryError, OSError) as e:
        return None, e


class DatabaseTab(ttk.Frame):
    def __init__(self, parent, app, pad):
        super().__init__(parent, padding=pad)
        self.app = app
        self.contents_title = tk.StringVar()
        self.contents = None
        self._request = 0
        t = app.t

        top = ttk.Frame(self)
        top.pack(fill="x")
        buttons = ttk.Frame(top)
        buttons.pack(side="right", fill="y", padx=(pad, 0))
        for text, command in ((t("open_btn"), self._open), (t("new_btn"), self._new),
                              (t("login_btn"), self._login), (t("logout_btn"), self._logout),
                              (t("set_active_btn"), self._set_active),
                              (t("password_btn"), self._change_password),
                              (t("release_lock_btn"), self._release_lock),
                              (t("unlink_btn"), self._unlink)):
            ttk.Button(buttons, text=text, command=command).pack(fill="x", pady=(0, 2))
        self.db_tree = _tree(top, DATABASE_COLUMN_WIDTHS, 7, t)
        self.db_tree.pack(side="left", fill="both", expand=True)
        self.db_tree.bind("<<TreeviewSelect>>", lambda _event: self._show_contents())

        ttk.Label(self, textvariable=self.contents_title).pack(anchor="w", pady=(pad, 4))
        self.views = ttk.Notebook(self)
        self.views.pack(fill="both", expand=True)
        self.key_tree = _tree(self.views, KEY_COLUMN_WIDTHS, 4, t)
        self.file_tree = _tree(self.views, FILE_COLUMN_WIDTHS, 4, t)
        self.views.add(self.key_tree, text=t("db_view_keys"))
        self.views.add(self.file_tree, text=t("db_view_files"))

        bottom = ttk.Frame(self)
        bottom.pack(fill="x", pady=(pad, 0))
        ttk.Button(bottom, text=t("restore_btn"), command=self._restore).pack(side="right")
        ttk.Button(bottom, text=t("refresh_btn"), command=self._rescan).pack(
            side="right", padx=(0, pad))
        ttk.Button(bottom, text=t("delete_btn"), command=self._delete).pack(side="left")
        self.refresh()

    def refresh(self, select=None):
        t = self.app.t
        selected = select or self._selected_database()
        active = settings.active_database()
        linked = settings.databases()
        self.db_tree.delete(*self.db_tree.get_children())
        for path in linked:
            state = self.app.db_state.get(path, "checking")
            if state != "missing" and self.app.db_locks.get(path):
                state = "in_use"
            remembered = settings.remembered_login(path) is not None
            self.db_tree.insert("", "end", iid=path, values=(
                os.path.basename(path), t("db_status_" + state),
                t("yes") if path == active else "", t("yes") if remembered else "", path))
        if selected not in linked:
            selected = active
        if selected:
            self.db_tree.selection_set(selected)
        self._show_contents()

    def _rescan(self):
        self.app.scan_databases(settings.databases(), ask_login=False)

    def _selected_database(self):
        selection = self.db_tree.selection()
        return selection[0] if selection else None

    def _require_database(self):
        path = self._selected_database()
        if path is None:
            self.app._status(self.app.t("db_select_database"), "error")
        return path

    def _show_contents(self):
        t = self.app.t
        self._request += 1
        self.contents = None
        self.key_tree.delete(*self.key_tree.get_children())
        self.file_tree.delete(*self.file_tree.get_children())
        path = self._selected_database()
        if path is None:
            self.contents_title.set(t("db_none_linked") if not settings.databases() else "")
            return
        name = os.path.basename(path)
        state = self.app.db_state.get(path, "checking")
        if state == "missing":
            self.contents_title.set(t("db_keys_missing", name=name))
            return
        if state == "checking" and path not in self.app.unlocked:
            self.contents_title.set(t("db_checking", name=name))
            return
        if path not in self.app.unlocked:
            self.contents_title.set(t("db_keys_locked", name=name))
            return
        self.contents_title.set(t("db_loading", name=name))
        request = self._request
        password = self.app.unlocked[path]
        self.app.run_in_background(lambda: load_contents(path, password),
                                   lambda result: self._contents_loaded(request, path, result))

    def _contents_loaded(self, request, path, result):
        if request != self._request:
            return
        data, error = result
        if error is not None:
            self.contents_title.set(self.app.t("registry_error", err=error))
            return
        self.contents = data
        file_counts = {}
        for fid, entry in sorted(data["files"].items(), key=lambda item: item[1].get("path", "")):
            fp = entry.get("fingerprint")
            file_counts[fp] = file_counts.get(fp, 0) + 1
            label = data["keys"].get(fp, {}).get("label", fp)
            self.file_tree.insert("", "end", iid=fid, values=(
                os.path.basename(entry.get("path", "")), label, entry.get("encrypted", ""),
                entry.get("path", "")))
        for fp, entry in sorted(data["keys"].items(), key=lambda item: item[1].get("label", "")):
            self.key_tree.insert("", "end", iid=fp, values=(
                entry.get("label", ""), fp, entry.get("created", ""),
                file_counts.get(fp, 0), entry.get("path", "")))
        title = self.app.t("db_keys_title", name=os.path.basename(path), keys=len(data["keys"]),
                           files=len(data["files"]))
        lock = self.app.db_locks.get(path)
        if lock:
            title += "  |  " + self._lock_text(lock)
        self.contents_title.set(title)

    def _lock_text(self, lock):
        return self.app.t("db_lock_info", owner=lock["owner"], since=lock["since_text"])

    def _written(self, outcome, message):
        result, error = outcome
        if error is not None:
            self.app._status(self.app.t("registry_error", err=error), "error")
            return
        self.app._status(message(result), "success")
        self.app.databases_changed()

    def _open(self):
        path = filedialog.askopenfilename(
            title=self.app.t("dlg_open_db"),
            filetypes=[("OBELISK database", "*" + registry.EXTENSION)])
        if not path:
            return
        path = settings.link_database(os.path.normpath(path))
        self.refresh(select=path)
        if path not in self.app.unlocked:
            self.app.scan_databases([path], ask_login=True)

    def _new(self):
        t = self.app.t
        path = filedialog.asksaveasfilename(
            title=t("dlg_new_db"), defaultextension=registry.EXTENSION, confirmoverwrite=False,
            filetypes=[("OBELISK database", "*" + registry.EXTENSION)])
        if not path:
            return
        path = registry.with_extension(os.path.normpath(path))
        if os.path.exists(path):
            self.app._status(t("db_exists", path=path), "error")
            return
        answer = gui_dialogs.ask_password(self.app, t("db_pw_title"), t("db_pw_new"),
                                          confirm=True, remember=True)
        if answer is None:
            return
        password, remember = answer
        self.app._status(t("db_working"), "working")
        self.app.write_databases(lambda unlocked, active: registry.create(path, password),
                                 lambda outcome: self._created(outcome, path, password, remember))

    def _created(self, outcome, path, password, remember):
        if outcome[1] is not None:
            self.app._status(self.app.t("registry_error", err=outcome[1]), "error")
            return
        path = settings.link_database(path)
        self.app.unlocked[path] = password
        self.app.db_state[path] = "unlocked"
        if remember:
            settings.remember_login(path, password)
        self.app._status(self.app.t("db_created", path=path), "success")
        self.refresh(select=path)
        self.app.databases_changed()

    def _login(self):
        path = self._require_database()
        if path is None:
            return
        if self.app.db_state.get(path) == "missing":
            self.app._status(self.app.t("db_keys_missing", name=os.path.basename(path)), "error")
            return
        if path in self.app.unlocked:
            self.app._status(self.app.t("db_already_unlocked"), "info")
            return
        self.app.login_database(path)

    def _logout(self):
        path = self._require_database()
        if path is None:
            return
        if self.app.unlocked.pop(path, None) is not None:
            self.app.db_state[path] = "locked"
        settings.forget_login(path)
        self.app._status(self.app.t("db_logged_out", name=os.path.basename(path)), "info")
        self.app.databases_changed()

    def _set_active(self):
        path = self._require_database()
        if path is None:
            return
        settings.set_active_database(path)
        self.app._status(self.app.t("db_active_set", name=os.path.basename(path)), "success")
        self.refresh()

    def _change_password(self):
        t = self.app.t
        path = self._require_database()
        if path is None:
            return
        name = os.path.basename(path)
        if self.app.db_state.get(path) == "missing":
            self.app._status(t("db_keys_missing", name=name), "error")
            return
        current = gui_dialogs.ask_password(self.app, t("db_pw_title"),
                                           t("pw_current_for", name=name))
        if current is None:
            return
        new = self.app.ask_new_password(t("db_pw_title"), t("db_pw_new_for", name=name))
        if new is None:
            return
        self.app._status(t("db_working"), "working")
        self.app.write_databases(
            lambda unlocked, active: registry.change_password(path, current[0], new),
            lambda outcome: self._password_changed(outcome, path, new))

    def _password_changed(self, outcome, path, password):
        if outcome[1] is not None:
            self.app._status(self.app.t("registry_error", err=outcome[1]), "error")
            return
        self.app.unlocked[path] = password
        self.app.db_state[path] = "unlocked"
        if settings.remembered_login(path) is not None:
            settings.remember_login(path, password)
        self.app._status(self.app.t("db_pw_changed", name=os.path.basename(path)), "success")
        self.app.databases_changed()

    def _release_lock(self):
        t = self.app.t
        path = self._require_database()
        if path is None:
            return
        lock = self.app.db_locks.get(path)
        if not lock:
            self.app._status(t("db_no_lock", name=os.path.basename(path)), "info")
            return
        if not messagebox.askyesno(t("release_lock_btn"), t("db_release_confirm",
                                   name=os.path.basename(path), info=self._lock_text(lock))):
            return
        self.app.run_in_background(lambda: registry.release_lock(path),
                                   lambda _released: self._lock_released(path))

    def _lock_released(self, path):
        self.app._status(self.app.t("db_lock_released", name=os.path.basename(path)), "success")
        self.app.db_locks[path] = None
        self.app.scan_databases([path], ask_login=False)

    def _unlink(self):
        t = self.app.t
        path = self._require_database()
        if path is None or not messagebox.askyesno(t("unlink_btn"), t("db_unlink_confirm", path=path)):
            return
        self.app.unlocked.pop(path, None)
        self.app.db_state.pop(path, None)
        settings.unlink_database(path)
        self.app._status(t("db_unlinked", name=os.path.basename(path)), "info")
        self.app.databases_changed()

    def _delete(self):
        t = self.app.t
        path = self._selected_database()
        if path not in self.app.unlocked or self.contents is None:
            self.app._status(t("db_select_item"), "error")
            return
        if self.views.select() == str(self.key_tree):
            selected = self.key_tree.selection()
            if not selected:
                self.app._status(t("db_select_item"), "error")
                return
            fp = selected[0]
            label = self.key_tree.set(fp, "label")
            files = int(self.key_tree.set(fp, "files"))
            if not messagebox.askyesno(t("delete_btn"), t("db_delete_key_confirm",
                                                          label=label, fp=fp, files=files)):
                return
            self.app.write_databases(
                lambda unlocked, active: registry.remove_key(path, unlocked.get(path), fp),
                lambda outcome: self._written(
                    outcome, lambda removed: t("db_key_deleted", label=label, files=removed)))
            return
        selected = self.file_tree.selection()
        if not selected:
            self.app._status(t("db_select_item"), "error")
            return
        fid = selected[0]
        name = self.file_tree.set(fid, "file")
        if not messagebox.askyesno(t("delete_btn"), t("db_delete_file_confirm", name=name)):
            return
        self.app.write_databases(
            lambda unlocked, active: registry.remove_file(path, unlocked.get(path), fid),
            lambda outcome: self._written(outcome, lambda _: t("db_file_deleted", name=name)))

    def _restore(self):
        t = self.app.t
        path = self._selected_database()
        selected = self.key_tree.selection()
        if path not in self.app.unlocked or not selected:
            self.app._status(t("db_select_key"), "error")
            return
        fp = selected[0]
        current = self.key_tree.set(fp, "path")
        out = filedialog.asksaveasfilename(
            title=t("dlg_restore_keyfile"), defaultextension=".key",
            initialdir=os.path.dirname(current), initialfile=os.path.basename(current),
            filetypes=[("OBELISK keyfile", "*.key")])
        if not out:
            return
        out = os.path.normpath(out)
        self.app.write_databases(
            lambda unlocked, active: registry.restore_keyfile(path, unlocked.get(path), fp, out),
            lambda outcome: self._written(outcome, lambda _: t("keyfile_restored", path=out)))
