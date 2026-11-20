"""Shared helpers for the self-contained Orbi Control PoC tests.

The tests import the real application code but use temp dirs, mocks and a local
HTTP listener, so they never change a configured machine. The live versions live
in the sibling ``live/`` directory.
"""
import argparse
import os
import sys
from pathlib import Path


def _default_orbi_path() -> str:
    env = os.environ.get("ORBI_PATH")
    if env:
        return env
    here = Path(__file__).resolve()
    for candidate in (here.parent / "orbi-app", here.parent.parent / "orbi-app",
                      here.parents[2] / "orbi-app", Path.home() / "Projects" / "orbi-app"):
        if (candidate / "orbi").is_dir():
            return str(candidate)
    return str(here.parent.parent / "orbi-app")


def orbi_arg(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--orbi-path",
        default=_default_orbi_path(),
        help="path to the Orbi Control checkout (or set ORBI_PATH)",
    )


def load_orbi(args: argparse.Namespace) -> Path:
    root = Path(args.orbi_path).resolve()
    if not (root / "orbi").is_dir():
        raise SystemExit(f"[!] Orbi Control checkout not found at {root}; pass --orbi-path or set ORBI_PATH")
    sys.path.insert(0, str(root))
    return root
