#!/usr/bin/env python3
"""PoC 5 — macOS installer upgrades pip without a pin or hash (CWE-494, Low).

Vulnerable code: install-macos.sh:22-24
    # requirements.txt pins every package with its hash, so pip installs exactly those files or nothing.
    "$VENV/bin/python" -m pip install --quiet --upgrade pip
    "$VENV/bin/python" -m pip install --quiet -r "$ROOT/requirements.txt"
"""
import argparse
from pathlib import Path

from poc_common import orbi_arg, load_orbi


def main():
    ap = argparse.ArgumentParser()
    orbi_arg(ap)
    args = ap.parse_args()
    root = load_orbi(args)

    lines = (root / "install-macos.sh").read_text().splitlines()
    idx = next(i for i, line in enumerate(lines) if "pip install" in line and "--upgrade pip" in line)
    cmd = lines[idx].strip()
    claim = lines[idx - 1].strip()
    pinned_line = next(line.strip() for line in lines if "requirements.txt" in line and " pip install " in line)
    examples = [line for line in (root / "requirements.txt").read_text().splitlines()
                if line.startswith(("fastapi==", "pynetgear=="))]

    print(f"[*] claim : {claim}")
    print(f"[*] actual: {cmd}")
    print(f"[*] next  : {pinned_line}")
    print(f"[*] hash-pinned examples: {examples[:2]}")

    assert "--upgrade pip" in cmd
    assert "==" not in cmd and "--require-hashes" not in cmd and "sha256" not in cmd.lower()
    print("[+] CONFIRMED: pip itself is fetched unpinned, before hash checking applies")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
