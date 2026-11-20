# Writeup 1 — Unauthenticated first-run PIN setup

**Finding:** CWE-306 (Missing Authentication for Critical Function) / CWE-1188, High
**PoC:** `tests/poc1_lan_setup_takeover.py` · live: `live/poc1_live_setup_takeover.py`

## How the vulnerability works

The web server is started with `host="0.0.0.0"` (`orbi/__main__.py:63`), so it is reachable from
every device on the LAN. The auth middleware exempts three paths (`orbi/web.py:29,234`):

```python
OPEN_PATHS = {"/api/session", "/api/login", "/api/setup"}
...
if path.startswith("/api/") and path not in OPEN_PATHS:
    if not auth.valid_session(...): return 401
```

`/api/setup` is one of them. Its handler (`orbi/web.py:299-309`) has exactly two checks: no PIN
has been set yet, and the submitted PIN is at least 6 characters. There is no setup token, no
proof that the caller is at the keyboard, no source-IP restriction, and no rate limit. On success
it writes the attacker's PIN hash and immediately issues a valid session cookie.

The app's own threat model says LAN devices are untrusted (`orbi/auth.py:1-5`), which makes the
missing check a design flaw rather than an accepted risk. Windows' firewall helper refuses to
open port 8470 until a PIN exists (`allow-phone-access.ps1:15-21`), but the macOS helper
(`allow-phone-access-macos.sh:4-6`) explicitly assumes the Application Firewall may be off, so
the endpoint is exposed immediately on macOS.

## How the PoC works

1. `GET /api/session` with a fresh cookie jar — reads `pin_set` to confirm the target is still
   unconfigured; aborts cleanly if not.
2. `POST /api/setup` with `{"pin": "ATTACKER123"}` from a plain `urllib` request. No cookie,
   token, or header is needed.
3. The response sets `orbi_session`; the script prints the cookie name to show a session was
   minted for the unauthenticated caller.
4. `GET /api/security` using that cookie succeeds, proving the session authenticates against a
   protected route.
5. A second `POST /api/setup` from a clean client returns `409 Already set up`, demonstrating
   that the legitimate owner can no longer initialize the app.
6. The script exits 0 only if the cookie exists, `/api/session` reports `authenticated: true`,
   and the owner's setup attempt is rejected.

No app imports or extra dependencies are required — only Python's standard library.

## What you can achieve

An attacker with LAN access who reaches the instance before the owner does becomes the
administrator of the parental-control system:

- Sign in at will with the chosen PIN; read the device list, activity history, alerts, and settings.
- Change profiles, schedules, blocks, and parental rules.
- Lock the owner out of first-run setup. Recovery requires local access to edit `settings.json`
  and clear `pin_hash`; there is no remote reset path.
- Optionally supply `router_password` in the same request, which is saved via
  `_save_router_password()` (`orbi/web.py:305-306`).

The transport is plain HTTP, so the PIN and cookie are also sniffable by anyone with a capture
position on the LAN — a risk the project documents but accepts. Practical precondition: the
target must be in the unconfigured state, so the window is right after installation.

## Fully-local use with an already-configured device

**No.** `/api/setup` is a one-shot endpoint: once `pin_hash` exists it returns
`409 Already set up` (`orbi/web.py:300-301`). A locally reachable instance that has already been
set up cannot be re-enrolled, so this PoC has no effect no matter where the request comes from.
The bug is only triggerable during the first-run window before a PIN exists. Even then the normal
vector is LAN (loopback from the host itself would also work), but an already-configured target is
out of scope.

**Fix direction:** bind to loopback until setup is complete; require a one-time token printed in
the host UI or tray; apply the PIN throttle to setup attempts as well.
