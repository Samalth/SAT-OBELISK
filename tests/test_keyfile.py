import os
import sys
import shutil
import tempfile
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from obelisk import (
    encrypt_file, decrypt_file, file_id, KEY_BYTES,
    generate_keyfile, load_keyfile, protect_keyfile, change_keyfile_password, read_keyfile_info,
    fingerprint, KeyfileError, KeyfilePasswordRequired,
)
from obelisk import ciphers, credentials, pwseal, registry, settings

PASSWORD = "correct horse battery staple"


def _workdir():
    return tempfile.mkdtemp(prefix="obelisk-keyfile-")


def _write_v1(path, key, label="old"):
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join([
            "OBELISK-KEYFILE v1",
            f"label={label}",
            "created=2025-01-01T00:00:00Z",
            f"key={key.hex()}",
            f"fingerprint={fingerprint(key)}",
            "",
        ]))


def test_protected_keyfile_hides_key():
    work = _workdir()
    try:
        path = os.path.join(work, "a.key")
        key, fp = generate_keyfile(path, PASSWORD, label="laptop")
        raw = open(path, "rb").read()
        assert key.hex().encode() not in raw
        assert key.hex().upper().encode() not in raw
        assert key not in raw
        assert b"key=" not in raw
        assert load_keyfile(path, PASSWORD) == key
        try:
            load_keyfile(path); assert False
        except KeyfilePasswordRequired:
            pass
        try:
            load_keyfile(path, "wrong password"); assert False
        except KeyfileError as e:
            assert not isinstance(e, KeyfilePasswordRequired)
        info = read_keyfile_info(path)
        assert info == {"label": "laptop", "created": info["created"], "fingerprint": fp,
                        "protected": True}
        print("ok  protected keyfile: key not in file, password required, wrong password rejected")
    finally:
        shutil.rmtree(work, ignore_errors=True)


def test_empty_password_rejected():
    work = _workdir()
    try:
        try:
            generate_keyfile(os.path.join(work, "a.key"), ""); assert False
        except KeyfileError:
            pass
        print("ok  keyfile without password is refused")
    finally:
        shutil.rmtree(work, ignore_errors=True)


def test_header_tampering_detected():
    work = _workdir()
    try:
        path = os.path.join(work, "a.key")
        generate_keyfile(path, PASSWORD)
        original = open(path, encoding="utf-8").read().split("\n")
        changes = [
            ("fingerprint", "0" * 16),
            ("kdf", "sponge" if "kdf=argon2id" in original else "argon2id"),
            ("iters", "1499"),
            ("iters", "abc"),
            ("salt", "00" * 16),
            ("cipher", "aes256gcm"),
            ("cipher", "unknown"),
            ("ciphertext", "zz"),
        ]
        for field, value in changes:
            lines = []
            for line in original:
                if line.startswith(field + "="):
                    line = f"{field}={value}"
                lines.append(line)
            with open(path, "w", encoding="utf-8") as f:
                f.write("\n".join(lines))
            try:
                load_keyfile(path, PASSWORD); assert False, field
            except KeyfileError:
                pass
        print("ok  tampering with fingerprint/kdf/iters/salt/cipher is rejected as KeyfileError")
    finally:
        shutil.rmtree(work, ignore_errors=True)


def test_fallbacks_without_argon2_or_cryptography():
    work = _workdir()
    saved_argon2, saved_default = pwseal.argon2_available, ciphers.DEFAULT
    try:
        pwseal.argon2_available = lambda: False
        ciphers.DEFAULT = "obelisk"
        path = os.path.join(work, "a.key")
        key, _ = generate_keyfile(path, PASSWORD)
        text = open(path, encoding="utf-8").read()
        assert "kdf=sponge" in text and "cipher=obelisk" in text
        assert load_keyfile(path, PASSWORD) == key
        print("ok  keyfile with sponge KDF + obelisk cipher round-trips")
    finally:
        pwseal.argon2_available, ciphers.DEFAULT = saved_argon2, saved_default
        shutil.rmtree(work, ignore_errors=True)


def test_v1_keyfile_loads_and_can_be_protected():
    work = _workdir()
    try:
        path = os.path.join(work, "old.key")
        key = os.urandom(KEY_BYTES)
        _write_v1(path, key)
        assert load_keyfile(path) == key
        assert read_keyfile_info(path)["protected"] is False
        assert protect_keyfile(path, PASSWORD) == fingerprint(key)
        assert key.hex().encode() not in open(path, "rb").read()
        info = read_keyfile_info(path)
        assert info["protected"] and info["label"] == "old"
        assert info["created"] == "2025-01-01T00:00:00Z"
        assert load_keyfile(path, PASSWORD) == key
        try:
            protect_keyfile(path, PASSWORD); assert False
        except KeyfileError:
            pass
        bare = os.path.join(work, "bare.key")
        with open(bare, "w", encoding="utf-8") as f:
            f.write(f"OBELISK-KEYFILE v1\nkey={key.hex()}\n")
        assert read_keyfile_info(bare)["fingerprint"] == fingerprint(key)
        print("ok  v1 keyfile still loads, protect_keyfile keeps label/date and hides key")
    finally:
        shutil.rmtree(work, ignore_errors=True)


def test_not_a_keyfile():
    work = _workdir()
    try:
        path = os.path.join(work, "x.key")
        with open(path, "wb") as f:
            f.write(os.urandom(64))
        for fn in (load_keyfile, read_keyfile_info):
            try:
                fn(path); assert False
            except KeyfileError:
                pass
        print("ok  random bytes are rejected as KeyfileError")
    finally:
        shutil.rmtree(work, ignore_errors=True)


def test_file_id_unique_and_rename_stable():
    work = _workdir()
    try:
        src = os.path.join(work, "in.txt")
        with open(src, "wb") as f:
            f.write(b"same data")
        key = os.urandom(KEY_BYTES)
        a, b = os.path.join(work, "a.obl"), os.path.join(work, "b.obl")
        encrypt_file(src, a, key=key)
        encrypt_file(src, b, key=key)
        id_a = file_id(a)
        assert id_a != file_id(b)
        moved = os.path.join(work, "renamed.obl")
        os.replace(a, moved)
        assert file_id(moved) == id_a
        print("ok  file_id is unique per encryption and survives rename")
    finally:
        shutil.rmtree(work, ignore_errors=True)


DB_PASSWORD = "team database secret"


def test_database_associates_file_with_keyfile():
    work = _workdir()
    try:
        db = os.path.join(work, "share", "team.obldb")
        registry.create(db, DB_PASSWORD)
        assert registry.load(db, DB_PASSWORD) == {"keys": {}, "files": {}}
        kf = os.path.join(work, "k.key")
        key, fp = generate_keyfile(kf, PASSWORD, label="team")
        assert registry.add_keyfile(db, DB_PASSWORD, kf) == fp
        src, enc, dec = (os.path.join(work, n) for n in ("in.txt", "in.txt.obl", "out.txt"))
        with open(src, "wb") as f:
            f.write(b"payload")
        encrypt_file(src, enc, key=key)
        registry.add_file(db, DB_PASSWORD, file_id(enc), fp, enc, "chacha20")
        found = registry.keyfile_for(db, DB_PASSWORD, file_id(enc))
        assert found == os.path.abspath(kf)
        decrypt_file(enc, dec, key=load_keyfile(found, PASSWORD))
        assert open(dec, "rb").read() == b"payload"
        assert registry.load(db, DB_PASSWORD)["keys"][fp]["label"] == "team"
        other = os.path.join(work, "other.obl")
        encrypt_file(src, other, key=os.urandom(KEY_BYTES))
        assert registry.keyfile_for(db, DB_PASSWORD, file_id(other)) is None
        print("ok  database maps encrypted file -> keyfile")
    finally:
        shutil.rmtree(work, ignore_errors=True)


def test_database_is_unreadable_without_password():
    work = _workdir()
    try:
        db = os.path.join(work, "team.obldb")
        registry.create(db, DB_PASSWORD)
        kf = os.path.join(work, "secret-project.key")
        key, fp = generate_keyfile(kf, PASSWORD, label="secret-project")
        registry.add_keyfile(db, DB_PASSWORD, kf)
        raw = open(db, "rb").read()
        for needle in (fp, "secret-project", key.hex(), "fingerprint", "keys"):
            assert needle.encode() not in raw, needle
        for wrong in ("", "wrong"):
            try:
                registry.load(db, wrong); assert False
            except registry.RegistryError:
                pass
        try:
            registry.create(db, DB_PASSWORD); assert False
        except registry.RegistryError:
            pass
        print("ok  database content (labels, fingerprints, paths) is encrypted, wrong password rejected")
    finally:
        shutil.rmtree(work, ignore_errors=True)


def test_restore_keyfile_from_database():
    work = _workdir()
    try:
        db = os.path.join(work, "team.obldb")
        registry.create(db, DB_PASSWORD)
        kf = os.path.join(work, "k.key")
        key, fp = generate_keyfile(kf, PASSWORD, label="team")
        registry.add_keyfile(db, DB_PASSWORD, kf)
        os.remove(kf)
        restored = os.path.join(work, "restored", "k.key")
        os.makedirs(os.path.dirname(restored))
        registry.restore_keyfile(db, DB_PASSWORD, fp, restored)
        assert load_keyfile(restored, PASSWORD) == key
        assert registry.load(db, DB_PASSWORD)["keys"][fp]["path"] == os.path.abspath(restored)
        try:
            registry.restore_keyfile(db, DB_PASSWORD, "0" * 16, restored); assert False
        except registry.RegistryError:
            pass
        old = os.path.join(work, "old.key")
        old_key = os.urandom(KEY_BYTES)
        _write_v1(old, old_key)
        old_fp = registry.add_keyfile(db, DB_PASSWORD, old)
        assert old_key.hex().encode() not in open(db, "rb").read()
        assert registry.load(db, DB_PASSWORD)["keys"][old_fp]["keyfile"] is None
        try:
            registry.restore_keyfile(db, DB_PASSWORD, old_fp, restored); assert False
        except registry.RegistryError:
            pass
        print("ok  keyfile restored from database; plaintext v1 keys are never stored")
    finally:
        shutil.rmtree(work, ignore_errors=True)


def test_multiple_databases_route_keys_and_files():
    work = _workdir()
    try:
        team, personal = os.path.join(work, "team.obldb"), os.path.join(work, "personal.obldb")
        registry.create(team, "team-pw")
        registry.create(personal, "personal-pw")
        unlocked = {team: "team-pw", personal: "personal-pw"}
        team_kf, own_kf = os.path.join(work, "team.key"), os.path.join(work, "own.key")
        team_key, team_fp = generate_keyfile(team_kf, PASSWORD)
        own_key, own_fp = generate_keyfile(own_kf, PASSWORD)
        assert registry.record_keyfile(unlocked, team, team_kf) == team
        assert registry.record_keyfile(unlocked, personal, team_kf) is None
        assert registry.record_keyfile(unlocked, personal, own_kf) == personal
        assert registry.record_keyfile({}, personal, own_kf) is None
        src = os.path.join(work, "in.txt")
        with open(src, "wb") as f:
            f.write(b"x")
        team_obl, own_obl = os.path.join(work, "t.obl"), os.path.join(work, "o.obl")
        encrypt_file(src, team_obl, key=team_key)
        encrypt_file(src, own_obl, key=own_key)
        assert registry.record_file(unlocked, personal, file_id(team_obl), team_fp, team_obl,
                                    "chacha20") == [team]
        assert registry.record_file(unlocked, team, file_id(own_obl), own_fp, own_obl,
                                    "chacha20") == [personal]
        assert registry.find_keyfile(unlocked, file_id(team_obl)) == os.path.abspath(team_kf)
        assert registry.find_keyfile(unlocked, file_id(own_obl)) == os.path.abspath(own_kf)
        assert registry.find_keyfile({team: "team-pw"}, file_id(own_obl)) is None
        assert registry.find_keyfile({team: "wrong"}, file_id(team_obl)) is None
        assert registry.known_keyfiles(unlocked) == sorted([os.path.abspath(team_kf),
                                                            os.path.abspath(own_kf)])
        print("ok  multiple databases: keys go to the active db, files follow their key")
    finally:
        shutil.rmtree(work, ignore_errors=True)


def test_linked_databases_and_remembered_logins():
    work = _workdir()
    saved_appdata = os.environ.get("APPDATA")
    os.environ["APPDATA"] = work
    try:
        a, b = os.path.join(work, "a.obldb"), os.path.join(work, "b.obldb")
        assert settings.databases() == [] and settings.active_database() is None
        assert settings.link_database(a) == a
        assert settings.link_database(a.upper()) == a
        settings.link_database(b)
        assert settings.databases() == [a, b] and settings.active_database() == a
        assert settings.set_active_database(b) == b and settings.active_database() == b
        assert settings.set_active_database(os.path.join(work, "x.obldb")) is None
        if credentials.available():
            settings.remember_login(a, "secret-db-pw")
            assert settings.remembered_login(a) == "secret-db-pw"
            assert settings.remembered_login(a.upper()) == "secret-db-pw"
            config = open(os.path.join(work, settings.APP_DIR_NAME, settings.CONFIG_FILE),
                          encoding="utf-8").read()
            assert "secret-db-pw" not in config
        assert settings.remembered_login(b) is None
        settings.unlink_database(b)
        assert settings.databases() == [a] and settings.active_database() == a
        settings.unlink_database(a)
        assert settings.remembered_login(a) is None
        assert settings.databases() == [] and settings.active_database() is None
        print("ok  linked databases, active database and remembered (DPAPI) logins")
    finally:
        if saved_appdata is None:
            os.environ.pop("APPDATA", None)
        else:
            os.environ["APPDATA"] = saved_appdata
        shutil.rmtree(work, ignore_errors=True)


def test_change_passwords_and_remove_entries():
    work = _workdir()
    try:
        db = os.path.join(work, "team.obldb")
        registry.create(db, DB_PASSWORD)
        kf = os.path.join(work, "k.key")
        key, fp = generate_keyfile(kf, PASSWORD, label="team")
        registry.add_keyfile(db, DB_PASSWORD, kf)
        src = os.path.join(work, "in.txt")
        with open(src, "wb") as f:
            f.write(b"x")
        ids = []
        for name in ("a.obl", "b.obl"):
            out = os.path.join(work, name)
            encrypt_file(src, out, key=key)
            ids.append(file_id(out))
            registry.add_file(db, DB_PASSWORD, ids[-1], fp, out, "chacha20")

        try:
            registry.change_password(db, "wrong", "new-db-pw"); assert False
        except registry.RegistryError:
            pass
        registry.change_password(db, DB_PASSWORD, "new-db-pw")
        try:
            registry.load(db, DB_PASSWORD); assert False
        except registry.RegistryError:
            pass
        assert fp in registry.load(db, "new-db-pw")["keys"]

        try:
            change_keyfile_password(kf, "wrong", "new-kf-pw"); assert False
        except KeyfileError:
            pass
        assert change_keyfile_password(kf, PASSWORD, "new-kf-pw") == fp
        assert load_keyfile(kf, "new-kf-pw") == key
        assert registry.update_stored_keyfile({db: "new-db-pw"}, kf) == [db]
        restored = os.path.join(work, "restored.key")
        registry.restore_keyfile(db, "new-db-pw", fp, restored)
        assert load_keyfile(restored, "new-kf-pw") == key

        registry.remove_file(db, "new-db-pw", ids[0])
        assert list(registry.load(db, "new-db-pw")["files"]) == [ids[1]]
        try:
            registry.remove_file(db, "new-db-pw", ids[0]); assert False
        except registry.RegistryError:
            pass
        assert registry.remove_key(db, "new-db-pw", fp) == 1
        data = registry.load(db, "new-db-pw")
        assert data["keys"] == {} and data["files"] == {}
        assert os.path.exists(kf)
        print("ok  change database/keyfile password, stored copy follows, remove key/file records")
    finally:
        shutil.rmtree(work, ignore_errors=True)


def test_concurrent_writers_do_not_lose_updates():
    work = _workdir()
    try:
        db = os.path.join(work, "team.obldb")
        registry.create(db, DB_PASSWORD)
        errors = []

        def writer(name):
            for i in range(4):
                try:
                    registry.add_file(db, DB_PASSWORD, f"{name}-{i}", "fp", f"{name}-{i}.obl",
                                      "chacha20")
                except Exception as e:
                    errors.append(e)

        threads = []
        for name in ("anna", "bart", "cees"):
            threads.append(threading.Thread(target=writer, args=(name,)))
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        assert errors == [], errors
        assert len(registry.load(db, DB_PASSWORD)["files"]) == 12
        assert registry.lock_status(db) is None
        print("ok  3 concurrent writers x 4 records: all 12 kept, lock cleaned up")
    finally:
        shutil.rmtree(work, ignore_errors=True)


def test_lock_busy_stale_and_released():
    work = _workdir()
    saved_wait = registry.LOCK_WAIT_SECONDS
    saved_seal = pwseal.seal
    try:
        registry.LOCK_WAIT_SECONDS = 0.5
        db = os.path.join(work, "team.obldb")
        registry.create(db, DB_PASSWORD)
        lock = db + registry.LOCK_SUFFIX

        with open(lock, "w", encoding="utf-8") as f:
            f.write('{"owner": "anna@pc1", "token": "abc"}')
        try:
            registry.add_file(db, DB_PASSWORD, "id1", "fp", "a.obl", "chacha20"); assert False
        except registry.DatabaseBusy as e:
            assert e.status["owner"] == "anna@pc1" and not e.status["stale"]
        assert registry.release_lock(db, "wrong-token") is False and os.path.exists(lock)

        old = time.time() - registry.LOCK_STALE_SECONDS - 5
        os.utime(lock, (old, old))
        assert registry.lock_status(db)["stale"]
        registry.add_file(db, DB_PASSWORD, "id1", "fp", "a.obl", "chacha20")
        assert "id1" in registry.load(db, DB_PASSWORD)["files"]
        assert not os.path.exists(lock)

        before = open(db, "rb").read()

        def seal_and_release(*args):
            registry.release_lock(db)
            return saved_seal(*args)

        pwseal.seal = seal_and_release
        try:
            registry.add_file(db, DB_PASSWORD, "id2", "fp", "b.obl", "chacha20"); assert False
        except registry.LockReleased as e:
            assert e.path == db
        pwseal.seal = saved_seal
        assert open(db, "rb").read() == before
        assert not [n for n in os.listdir(work) if n.endswith(".tmp")]

        try:
            registry.load(db, "wrong"); assert False
        except registry.WrongPassword as e:
            assert e.path == db
        print("ok  lock: busy reported with owner, stale lock broken, released lock writes nothing")
    finally:
        registry.LOCK_WAIT_SECONDS = saved_wait
        pwseal.seal = saved_seal
        shutil.rmtree(work, ignore_errors=True)


PINNED_KEY = bytes(range(50, 66))
PINNED_KEYFILES = [
    "OBELISK-KEYFILE v2\nlabel=kat\ncreated=2026-01-01T00:00:00Z\nfingerprint=5c919d8aaaa028a4\n"
    "cipher=chacha20\nkdf=sponge\niters=1500\nsalt=9425192b4b4a43b6772440948f6840f7\n"
    "nonce=65d9f227ea2be5f1126d67d8\n"
    "ciphertext=65d1aa5ac492c46d82abc79f4d3086572a87eda42fe590083f3b3ab2754a2afb\n",
    "OBELISK-KEYFILE v2\nlabel=kat\ncreated=2026-01-01T00:00:00Z\nfingerprint=5c919d8aaaa028a4\n"
    "cipher=obelisk\nkdf=sponge\niters=1500\nsalt=a9224b002b7cafcb543034f2a54f0a41\n"
    "nonce=10c225d0f3ab94fdba23dab94c33b597\n"
    "ciphertext=6bc5fa2ab39379271b01bfafb05e3a880278aa43af34ea28ccd8c71577205247\n",
]
PINNED_DATABASE = (
    '{"format": "OBELISK-DB", "version": 1, "cipher": "chacha20", "kdf": "sponge", '
    '"iters": "1500", "salt": "37b32e4e96b17ba65943f6492fbff42c", '
    '"nonce": "c1ac47135c3154dcc11484d5", "ciphertext": "'
    "9a4c7f369feb12d927a15374f97a740c3c68274bb3fae533efe58b2531fb41fca9232b08be2d416cac3d6c77"
    "e1ccf5290ad3fead11765ba6da96541aa1809c50c6fa67d6013c9df32b3e76d1070b3e46ddf31001ebf30792"
    "dddbfeb0c554ed7ca53cc2b4409850a94e7d3d5dcf77d0746cf4cd2d3c1f473c8e54c9d5cf2a2b83ae5f1dc8"
    "3185260c17b5472ad982ac6574bc32df145e81c8cdcdcd10297c6ed09a35a56f7393900c0876cba7e04a"
    '"}'
)


def test_pinned_keyfile_and_database_formats_still_open():
    work = _workdir()
    try:
        for i, text in enumerate(PINNED_KEYFILES):
            path = os.path.join(work, f"k{i}.key")
            with open(path, "w", encoding="utf-8", newline="") as f:
                f.write(text)
            assert load_keyfile(path, "kat-pw") == PINNED_KEY
        db = os.path.join(work, "kat.obldb")
        with open(db, "w", encoding="utf-8") as f:
            f.write(PINNED_DATABASE)
        data = registry.load(db, "kat-db-pw")
        assert data["keys"] == {} and list(data["files"]) == ["fid"]
        entry = data["files"]["fid"]
        assert entry["fingerprint"] == "fp" and entry["cipher"] == "chacha20"
        assert os.path.basename(entry["path"]) == "x.obl"
        print("ok  pinned keyfiles (chacha20 + obelisk) and database written by earlier code still open")
    finally:
        shutil.rmtree(work, ignore_errors=True)


def test_corrupt_database_is_not_overwritten():
    work = _workdir()
    try:
        db = os.path.join(work, "team.obldb")
        with open(db, "w", encoding="utf-8") as f:
            f.write("{ not json")
        kf = os.path.join(work, "k.key")
        generate_keyfile(kf, PASSWORD)
        for fn, args in ((registry.load, (db, DB_PASSWORD)),
                         (registry.add_keyfile, (db, DB_PASSWORD, kf)),
                         (registry.add_file, (db, DB_PASSWORD, "id", "fp", "x.obl", "chacha20"))):
            try:
                fn(*args); assert False
            except registry.RegistryError:
                pass
        assert open(db, encoding="utf-8").read() == "{ not json"
        print("ok  corrupt database raises RegistryError and is left untouched")
    finally:
        shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
    print("\nALL KEYFILE TESTS PASSED")
