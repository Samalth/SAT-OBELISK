from __future__ import annotations

import argparse
import getpass
import os
import sys

from . import aead
from . import ciphers
from .filecrypt import encrypt_path, decrypt_file, inspect, FileFormatError
from .keyfile import (
    generate_keyfile, load_keyfile, save_keyfile, fingerprint, KeyfileError,
)

_PROMPT = "\x00prompt"


def _prompt_password(confirm):
    pw = getpass.getpass("Password: ")
    if confirm:
        if pw != getpass.getpass("Confirm password: "):
            sys.exit("error: passwords did not match")
    if not pw:
        sys.exit("error: empty password")
    return pw


def _key_from_args(args):
    pw = getattr(args, "password", None)
    sources = [bool(getattr(args, "keyfile", None)),
               bool(getattr(args, "key", None)),
               pw is not None]
    if sum(sources) == 0:
        sys.exit("error: provide --keyfile <file>, --key <hex> or --password")
    if sum(sources) > 1:
        sys.exit("error: choose only one of --keyfile / --key / --password")
    if getattr(args, "keyfile", None):
        try:
            return load_keyfile(args.keyfile), None
        except (KeyfileError, FileNotFoundError) as e:
            sys.exit(f"error: {e}")
    if getattr(args, "key", None):
        try:
            k = bytes.fromhex(args.key)
        except ValueError:
            sys.exit("error: --key must be hex")
        if len(k) != aead.KEY_BYTES:
            sys.exit(f"error: --key must be {aead.KEY_BYTES} bytes ({aead.KEY_BYTES * 2} hex chars)")
        return k, None
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
    pg.add_argument("--out", help="write a keyfile to this path")
    pg.add_argument("--label", default="", help="optional label stored in the keyfile")

    pf = sub.add_parser("fingerprint", help="show a key's fingerprint (backup id)")
    pf.add_argument("--keyfile")
    pf.add_argument("--key")

    args = p.parse_args(argv)

    if args.cmd == "genkey":
        if args.out:
            try:
                key, fp = generate_keyfile(args.out, label=args.label)
            except OSError as e:
                sys.exit(f"error: {e}")
            print(f"keyfile  -> {args.out}")
            print(f"fingerprint: {fp}")
            print("keep this file safe; losing it means losing your data.")
        else:
            print(os.urandom(aead.KEY_BYTES).hex())
        return

    if args.cmd == "fingerprint":
        if args.keyfile:
            try:
                key = load_keyfile(args.keyfile)
            except (KeyfileError, FileNotFoundError) as e:
                sys.exit(f"error: {e}")
        elif args.key:
            try:
                key = bytes.fromhex(args.key)
            except ValueError:
                sys.exit("error: --key must be hex")
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
                print(f"key fingerprint: {fingerprint(key)}")
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
