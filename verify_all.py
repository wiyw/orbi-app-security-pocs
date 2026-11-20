#!/usr/bin/env python3
"""Runs the four self-contained PoCs (2-5) and summarizes the result."""
import subprocess
import sys
from pathlib import Path

SCRIPTS = [
    "poc2_cert_pin_retrust.py",
    "poc3_move_file_tamper.py",
    "poc4_keychain_permissive_acl.py",
    "poc5_unpinned_pip_upgrade.py",
]


def main():
    here = Path(__file__).resolve().parent
    failed = []
    for script in SCRIPTS:
        print(f"\n===== {script} =====")
        result = subprocess.run([sys.executable, str(here / script)], cwd=here)
        if result.returncode != 0:
            failed.append(script)
    print(f"\n{'ALL PoCs REPRODUCED' if not failed else 'FAILED: ' + ', '.join(failed)}")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
