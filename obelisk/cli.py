from __future__ import annotations

import argparse
import functools
import getpass
import os
import sys

from . import aead
from . import ciphers
from . import registry
from . import settings
from .filecrypt import encrypt_path, decrypt_file, inspect, file_id, FileFormatError
from .keyfile import (
    generate_keyfile, load_keyfile, protect_keyfile, change_keyfile_password, read_keyfile_info,
    parse_hex_key, fingerprint, KeyfileError, KeyfilePasswordRequired,
)

_PROMPT = "\x00prompt"


def _prompt_password(confirm, prompt="Password"):
    pw = getpass.getpass(f"{prompt}: ")
    if confirm:
        if pw != getpass.getpass(f"Confirm {prompt.lower()}: "):
            sys.exit("error: passwords did not match")
    if not pw:
        sys.exit("error: empty password")
    return pw


@functools.lru_cache(maxsize=None)
def _databases():
    states, unlocked, _ = settings.scan_databases(settings.databases())
    active = settings.active_database()
    if active is not None and states.get(active) == "locked":
        password = getpass.getpass(
            f"Database password ({os.path.basename(active)}, empty to skip): ")
        if password:
            try:
                registry.load(active, password)
                unlocked[active] = password
            except (registry.RegistryError, OSError) as e:
                print(f"warning: database {os.path.basename(active)} not used: {e}",
                      file=sys.stderr)
    locked = 0
    for path, state in states.items():
        if state == "locked" and path not in unlocked:
            locked += 1
    if locked:
        print(f"note: {locked} database(s) locked; to remember a login run: "
              "obelisk database --login PATH --remember", file=sys.stderr)
    return unlocked, active


def _with_merge(operation):
    try:
        return operation()
    except registry.LockReleased as e:
        print(f"warning: {e}; merging changes into the latest version", file=sys.stderr)
        return operation()
    except registry.DatabaseBusy as e:
        raise registry.RegistryError(
            f"{e}; if that lock is stuck run: obelisk database --release-lock {e.path}")


def _register_keyfile(path):
    unlocked, active = _databases()
    try:
        _with_merge(lambda: registry.record_keyfile(unlocked, active, path))
    except (registry.RegistryError, KeyfileError, OSError) as e:
        print(f"warning: key database not updated: {e}", file=sys.stderr)


def _open_keyfile(path):
    try:
        try:
            key = load_keyfile(path)
            print(f"warning: keyfile is not password-protected; run: obelisk protect-key {path}",
                  file=sys.stderr)
        except KeyfilePasswordRequired:
            key = load_keyfile(path, _prompt_password(confirm=False, prompt="Keyfile password"))
    except (KeyfileError, OSError) as e:
        sys.exit(f"error: {e}")
    _register_keyfile(path)
    return key


def _registry_keyfile(infile):
    unlocked, _ = _databases()
    if not unlocked:
        return None
    try:
        return registry.find_keyfile(unlocked, file_id(infile))
    except (FileFormatError, OSError):
        return None


def _database_path(raw):
    return registry.with_extension(os.path.abspath(raw))


def _remember_login(path, password):
    try:
        settings.remember_login(path, password)
    except OSError as e:
        print(f"warning: login not remembered: {e}", file=sys.stderr)
        return
    print("login remembered on this device")


def _database_password(path):
    password = settings.remembered_login(path)
    if password is None:
        password = _prompt_password(confirm=False, prompt=f"Database password ({os.path.basename(path)})")
    return password


def _database_command(args):
    if args.restore and not args.out:
        sys.exit("error: --restore needs --out <keyfile path>")
    if args.new:
        path = _database_path(args.new)
        password = _prompt_password(confirm=True, prompt="Database password")
        try:
            _with_merge(lambda: registry.create(path, password))
        except (registry.RegistryError, OSError) as e:
            sys.exit(f"error: {e}")
        settings.link_database(path)
        print(f"created and linked {path}")
        print("remember this password; without it the database cannot be opened.")
        if args.remember:
            _remember_login(path, password)
        return
    if args.open or args.login:
        path = _database_path(args.open or args.login)
        if not os.path.exists(path):
            sys.exit(f"error: not found: {path}")
        if args.open:
            path = settings.link_database(path)
            print(f"linked {path}")
        elif settings.linked_path(path) is None:
            sys.exit("error: database is not linked; link it with: obelisk database --open PATH")
        if args.login or args.remember:
            password = _prompt_password(confirm=False, prompt="Database password")
            try:
                registry.load(path, password)
            except (registry.RegistryError, OSError) as e:
                sys.exit(f"error: {e}")
            print("password ok")
            if args.remember:
                _remember_login(path, password)
        return
    if args.release_lock:
        path = _database_path(args.release_lock)
        lock = registry.lock_status(path)
        if lock is None:
            print("no lock present")
            return
        registry.release_lock(path)
        print(f"released the lock of {lock['owner']} (since {lock['since_text']})")
        return
    if args.logout:
        settings.forget_login(_database_path(args.logout))
        print("remembered login removed")
        return
    if args.active:
        if settings.set_active_database(_database_path(args.active)) is None:
            sys.exit("error: database is not linked; link it with: obelisk database --open PATH")
        print("new keys are now written to this database")
        return
    if args.unlink:
        settings.unlink_database(_database_path(args.unlink))
        print("unlinked (the file itself is kept)")
        return
    if args.show:
        path = _database_path(args.show)
        try:
            data = registry.load(path, _database_password(path))
        except (registry.RegistryError, OSError) as e:
            sys.exit(f"error: {e}")
        print("keys:")
        for fp, entry in sorted(data["keys"].items()):
            restorable = "restorable" if entry.get("keyfile") else "not stored"
            print(f"  {fp}  {entry.get('label', ''):<20}  {restorable:<10}  {entry.get('path', '')}")
        print("files:")
        for fid, entry in sorted(data["files"].items()):
            print(f"  {fid}  key {entry.get('fingerprint', '')}  {entry.get('path', '')}")
        print(f"{len(data['keys'])} key(s), {len(data['files'])} encrypted file(s)")
        return
    if args.change_password:
        path = _database_path(args.change_password)
        current = _prompt_password(confirm=False, prompt="Current database password")
        new = _prompt_password(confirm=True, prompt="New database password")
        try:
            _with_merge(lambda: registry.change_password(path, current, new))
        except (registry.RegistryError, OSError) as e:
            sys.exit(f"error: {e}")
        if settings.remembered_login(path) is not None:
            _remember_login(path, new)
        print("database password changed; others using this database need the new password.")
        return
    if args.remove_key or args.remove_file:
        path = _database_path(args.db) if args.db else settings.active_database()
        if not path:
            sys.exit("error: no active database; pass --db PATH")
        password = _database_password(path)
        try:
            if args.remove_key:
                removed = _with_merge(lambda: registry.remove_key(path, password, args.remove_key))
                print(f"key removed from {os.path.basename(path)} "
                      f"({removed} file record(s) removed)")
            else:
                target = args.remove_file
                if os.path.isfile(target):
                    target = file_id(target)
                _with_merge(lambda: registry.remove_file(path, password, target))
                print(f"file record removed from {os.path.basename(path)}")
        except (registry.RegistryError, FileFormatError, OSError) as e:
            sys.exit(f"error: {e}")
        return
    if args.restore:
        unlocked, _ = _databases()
        for path, password in unlocked.items():
            try:
                if args.restore not in registry.load(path, password)["keys"]:
                    continue
                _with_merge(lambda: registry.restore_keyfile(path, password, args.restore, args.out))
            except (registry.RegistryError, OSError) as e:
                sys.exit(f"error: {e}")
            print(f"restored keyfile -> {args.out} (from {os.path.basename(path)})")
            return
        sys.exit("error: fingerprint not found in any unlocked database")
    active = settings.active_database()
    linked = settings.databases()
    for path in linked:
        if not os.path.exists(path):
            state = "not found"
        elif settings.remembered_login(path) is not None:
            state = "remembered"
        else:
            state = "locked"
        lock = registry.lock_status(path)
        if lock:
            state += f", in use by {lock['owner']} since {lock['since_text']}"
        print(f"{'*' if path == active else ' '} {state:<10}  {path}")
    if linked:
        print("* = active (new keys are written here)")
    else:
        print("no databases linked; create one with: obelisk database --new PATH")


def _key_from_args(args):
    pw = getattr(args, "password", None)
    sources = [bool(getattr(args, "keyfile", None)),
               bool(getattr(args, "key", None)),
               pw is not None]
    if sum(sources) == 0:
        keyfile = _registry_keyfile(args.infile) if args.cmd == "decrypt" else None
        if not keyfile:
            sys.exit("error: provide --keyfile <file>, --key <hex> or --password")
        print(f"using keyfile from database: {keyfile}", file=sys.stderr)
        return _open_keyfile(keyfile), None
    if sum(sources) > 1:
        sys.exit("error: choose only one of --keyfile / --key / --password")
    if getattr(args, "keyfile", None):
        return _open_keyfile(args.keyfile), None
    if getattr(args, "key", None):
        try:
            return parse_hex_key(args.key), None
        except ValueError as e:
            sys.exit(f"error: --{e}")
    if pw == _PROMPT or pw == "":
        pw = _prompt_password(confirm=(args.cmd == "encrypt"))
    return None, pw


def _add_key_opts(p):
    p.add_argument("--keyfile", help="path to an OBELISK keyfile")
    p.add_argument("--key", help="16-byte key as 32 hex chars")
    p.add_argument("--password", nargs="?", const=_PROMPT,
                   help="prompt for a password (avoid passing it inline)")


def main(argv=None):
    p = argparse.ArgumentParser(prog="obelisk", description="OBELISK file encryption (research-grade)")
    sub = p.add_subparsers(dest="cmd", required=True)

    pe = sub.add_parser("encrypt", help="encrypt a file or folder")
    pe.add_argument("infile", help="file or folder to encrypt")
    pe.add_argument("outfile")
    pe.add_argument("--cipher", default=ciphers.DEFAULT, choices=ciphers.names(),
                    help=f"cipher to use (default {ciphers.DEFAULT}; "
                         "chacha20/aes256gcm are vetted)")
    _add_key_opts(pe)

    pd = sub.add_parser("decrypt", help="decrypt a file (folders extract into outfile dir)")
    pd.add_argument("infile")
    pd.add_argument("outfile")
    _add_key_opts(pd)

    pi = sub.add_parser("info", help="show an .obl file's header (cipher, flags)")
    pi.add_argument("infile")

    pg = sub.add_parser("genkey", help="generate a key (hex), optionally save a keyfile")
    pg.add_argument("--out", help="write a password-protected keyfile to this path")
    pg.add_argument("--label", default="", help="optional label stored in the keyfile")

    pp = sub.add_parser("protect-key", help="protect an old plaintext keyfile with a password")
    pp.add_argument("keyfile")

    pc = sub.add_parser("change-password", help="change the password of a keyfile")
    pc.add_argument("keyfile")

    pf = sub.add_parser("fingerprint", help="show a key's fingerprint (backup id)")
    pf.add_argument("--keyfile")
    pf.add_argument("--key")

    pr = sub.add_parser("database", help="manage linked key databases (.obldb); "
                                         "without options: list them")
    action = pr.add_mutually_exclusive_group()
    action.add_argument("--new", metavar="PATH", help="create a password-protected database and link it")
    action.add_argument("--open", metavar="PATH", help="link an existing database (local or network)")
    action.add_argument("--login", metavar="PATH", help="check the password of a linked database")
    action.add_argument("--logout", metavar="PATH", help="forget the remembered login")
    action.add_argument("--active", metavar="PATH", help="write new keys to this database")
    action.add_argument("--unlink", metavar="PATH", help="remove from the list (the file is kept)")
    action.add_argument("--release-lock", metavar="PATH",
                        help="remove a stuck lock (only when no one is writing)")
    action.add_argument("--show", metavar="PATH", help="list the keys and files in a database")
    action.add_argument("--change-password", metavar="PATH", help="change a database password")
    action.add_argument("--remove-key", metavar="FINGERPRINT",
                        help="remove a key and its file records (keyfile itself is kept)")
    action.add_argument("--remove-file", metavar="FILE",
                        help="remove a file record, by .obl path or file id")
    action.add_argument("--restore", metavar="FINGERPRINT",
                        help="write a stored keyfile back to disk (searches unlocked databases)")
    pr.add_argument("--db", metavar="PATH",
                    help="database for --remove-key/--remove-file (default: the active one)")
    pr.add_argument("--out", help="where --restore writes the keyfile")
    pr.add_argument("--remember", action="store_true",
                    help="with --new/--open/--login: remember the login on this device")

    args = p.parse_args(argv)

    if args.cmd == "genkey":
        if args.out:
            password = _prompt_password(confirm=True, prompt="Keyfile password")
            try:
                key, fp = generate_keyfile(args.out, password, label=args.label)
            except (KeyfileError, OSError) as e:
                sys.exit(f"error: {e}")
            print(f"keyfile  -> {args.out}")
            print(f"fingerprint: {fp}")
            print("back up this file and its password; losing either means losing your data.")
            _register_keyfile(args.out)
        else:
            print(os.urandom(aead.KEY_BYTES).hex())
        return

    if args.cmd == "protect-key":
        try:
            info = read_keyfile_info(args.keyfile)
        except (KeyfileError, OSError) as e:
            sys.exit(f"error: {e}")
        if info["protected"]:
            sys.exit("error: keyfile is already password-protected")
        password = _prompt_password(confirm=True, prompt="Keyfile password")
        try:
            fp = protect_keyfile(args.keyfile, password)
        except (KeyfileError, OSError) as e:
            sys.exit(f"error: {e}")
        print(f"protected {args.keyfile} (fingerprint {fp})")
        print("back up this file and its password; losing either means losing your data.")
        _register_keyfile(args.keyfile)
        return

    if args.cmd == "change-password":
        try:
            protected = read_keyfile_info(args.keyfile)["protected"]
        except (KeyfileError, OSError) as e:
            sys.exit(f"error: {e}")
        if not protected:
            sys.exit(f"error: keyfile is not password-protected; run: obelisk protect-key {args.keyfile}")
        current = _prompt_password(confirm=False, prompt="Current keyfile password")
        new = _prompt_password(confirm=True, prompt="New keyfile password")
        try:
            fp = change_keyfile_password(args.keyfile, current, new)
        except (KeyfileError, OSError) as e:
            sys.exit(f"error: {e}")
        print(f"keyfile password changed (fingerprint {fp})")
        unlocked, _ = _databases()
        try:
            for path in _with_merge(lambda: registry.update_stored_keyfile(unlocked, args.keyfile)):
                print(f"stored copy updated in {os.path.basename(path)}")
        except (registry.RegistryError, KeyfileError, OSError) as e:
            print(f"warning: key database not updated: {e}", file=sys.stderr)
        return

    if args.cmd == "database":
        _database_command(args)
        return

    if args.cmd == "fingerprint":
        if args.keyfile:
            try:
                print(read_keyfile_info(args.keyfile)["fingerprint"])
            except (KeyfileError, OSError) as e:
                sys.exit(f"error: {e}")
            return
        if args.key:
            try:
                key = parse_hex_key(args.key)
            except ValueError as e:
                sys.exit(f"error: --{e}")
        else:
            sys.exit("error: provide --keyfile or --key")
        print(fingerprint(key))
        return

    if args.cmd == "info":
        try:
            meta = inspect(args.infile)
        except (FileFormatError, FileNotFoundError) as e:
            sys.exit(f"error: {e}")
        for k, v in meta.items():
            print(f"{k:>10}: {v}")
        return

    key, password = _key_from_args(args)
    try:
        if args.cmd == "encrypt":
            encrypt_path(args.infile, args.outfile, key=key, password=password, cipher=args.cipher)
            kind = "folder" if os.path.isdir(args.infile) else "file"
            print(f"encrypted {kind} ({args.cipher}) -> {args.outfile}")
            if key is not None:
                fp = fingerprint(key)
                print(f"key fingerprint: {fp}")
                unlocked, active = _databases()
                try:
                    _with_merge(lambda: registry.record_file(unlocked, active, file_id(args.outfile),
                                                             fp, args.outfile, args.cipher))
                except (registry.RegistryError, OSError) as e:
                    print(f"warning: key database not updated: {e}", file=sys.stderr)
        else:
            decrypt_file(args.infile, args.outfile, key=key, password=password)
            print(f"decrypted -> {args.outfile}")
    except ciphers.CipherUnavailable as e:
        sys.exit(f"error: {e}")
    except aead.TagMismatch:
        sys.exit("error: authentication failed (wrong key/password or file was tampered with)")
    except (FileFormatError, FileNotFoundError, ValueError) as e:
        sys.exit(f"error: {e}")


if __name__ == "__main__":
    main()
