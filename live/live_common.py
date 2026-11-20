"""Shared helpers for the live Orbi Control PoCs.

Unlike the scripts in ``tests/``, these operate on the machine they are run on:
the real settings file, real Keychain, real data dir, or a real HTTP endpoint.
Every mutating script requires ``--confirm`` and makes a backup first.
"""
import argparse
import os
import shutil
import sys
import time
from pathlib import Path


def _default_orbi_path() -> str:
    env = os.environ.get("ORBI_PATH")
    if env:
        return env
    here = Path(__file__).resolve()
    for candidate in (here.parent.parent / "orbi-app", here.parents[2] / "orbi-app",
                      Path.home() / "Projects" / "orbi-app"):
        if (candidate / "orbi").is_dir():
            return str(candidate)
    return str(here.parent.parent / "orbi-app")


def orbi_arg(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--orbi-path", default=_default_orbi_path(),
                        help="path to the Orbi Control checkout (or set ORBI_PATH)")


def confirm_arg(parser: argparse.ArgumentParser, what: str) -> None:
    parser.add_argument("--confirm", action="store_true",
                        help=f"required: confirm that you own this machine and want to {what}")


def load_orbi(args: argparse.Namespace) -> Path:
    root = Path(args.orbi_path).resolve()
    if not (root / "orbi").is_dir():
        raise SystemExit(f"[!] Orbi Control checkout not found at {root}; pass --orbi-path or set ORBI_PATH")
    sys.path.insert(0, str(root))
    return root


def require_confirm(args: argparse.Namespace) -> None:
    if not getattr(args, "confirm", False):
        raise SystemExit("[!] Refusing to change a real machine without --confirm. "
                         "Use tests/ for the harmless reproductions.")


def real_data_dir(args: argparse.Namespace, root: Path) -> Path:
    env = os.environ.get("ORBI_DATA_DIR")
    if getattr(args, "data_dir", None):
        return Path(args.data_dir).expanduser().resolve()
    if env:
        return Path(env).expanduser().resolve()
    from orbi import osdep
    return Path(osdep.default_data_dir())


def data_arg(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--data-dir", help="real Orbi Control data dir "
                        "(default: $ORBI_DATA_DIR or the OS default)")


def backup(path: Path, tag: str) -> Path:
    if not path.exists():
        raise SystemExit(f"[!] Nothing to back up at {path}")
    dest = path.with_name(f"{path.name}-before-{tag}-{time.strftime('%Y%m%d-%H%M%S')}")
    if path.is_dir():
        shutil.copytree(path, dest, ignore=shutil.ignore_patterns("orbi.lock"))
    else:
        shutil.copy2(path, dest)
    print(f"[*] backup: {dest}")
    return dest
