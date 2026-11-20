"""Shared helpers for the Orbi Control PoCs."""
import argparse
import os
import sys
from pathlib import Path


def orbi_arg(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--orbi-path",
        default=os.environ.get("ORBI_PATH", str(Path(__file__).resolve().parent.parent / "orbi-app")),
        help="path to the Orbi Control checkout (or set ORBI_PATH)",
    )


def load_orbi(args: argparse.Namespace) -> Path:
    root = Path(args.orbi_path).resolve()
    if not (root / "orbi").is_dir():
        raise SystemExit(f"[!] Orbi Control checkout not found at {root}; pass --orbi-path or set ORBI_PATH")
    sys.path.insert(0, str(root))
    return root
