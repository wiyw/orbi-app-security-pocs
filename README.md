# Orbi Control — vulnerability PoCs

Reproductions for the five findings in the `inspectormamba/orbi-app` security review.

> **Authorized testing only.** These target one specific build of Orbi Control and are for the
> app owner's own lab. PoC 1 changes the target's PIN — run it only against a disposable,
> unconfigured instance.

| # | Severity | Finding | Script | Writeup |
|---|----------|---------|--------|---------|
| 1 | High | Unauthenticated first-run PIN setup from the LAN | `poc1_lan_setup_takeover.py` | [01](writeups/01-unauthenticated-first-run-setup.md) |
| 2 | High | Router cert pin silently replaced by a LAN impersonator | `poc2_cert_pin_retrust.py` | [02](writeups/02-router-certificate-retrust.md) |
| 3 | Medium | Move-file HMAC leaves `orbi.db`/backups unauthenticated | `poc3_move_file_tamper.py` | [03](writeups/03-move-file-hmac-gap.md) |
| 4 | Medium | macOS Keychain secrets stored with a wildcard (`-A`) ACL | `poc4_keychain_permissive_acl.py` | [04](writeups/04-keychain-wildcard-acl.md) |
| 5 | Low | macOS installer upgrades pip without a pin or hash | `poc5_unpinned_pip_upgrade.py` | [05](writeups/05-unpinned-pip-upgrade.md) |

## Writeups

Each writeup explains the root cause and data flow, how the PoC reproduces it, what an attacker
gains, and a fix direction. See [`writeups/`](writeups/).

## Setup

PoCs 2–5 import the application code, so they need an Orbi Control checkout and its dependencies:

```sh
git clone https://github.com/inspectormamba/orbi-app.git ../orbi-app
python3 -m venv .venv
.venv/bin/python -m pip install -r ../orbi-app/requirements.in
export ORBI_PATH="$PWD/../orbi-app"
```

Every script also accepts `--orbi-path`. PoC 1 needs only Python's standard library.

## Running

```sh
# PoC 1 — live, unconfigured instance on your LAN
.venv/bin/python poc1_lan_setup_takeover.py http://192.168.1.50:8470

# PoCs 2–5 — self-contained, no network, no root, no real router
.venv/bin/python poc2_cert_pin_retrust.py
.venv/bin/python poc3_move_file_tamper.py
.venv/bin/python poc4_keychain_permissive_acl.py
.venv/bin/python poc5_unpinned_pip_upgrade.py

# or all self-contained ones at once
.venv/bin/python verify_all.py
```

Each script prints the vulnerable source location, the attacker-controlled input, and the
observed state. It exits `0` only when the vulnerability reproduced, and non-zero otherwise.
