# Orbi Control — vulnerability PoCs

Reproductions for the five findings in the `inspectormamba/orbi-app` security review.

> **Authorized testing only.** These target one specific build of Orbi Control and are for the
> app owner's own lab. The `live/` scripts change real machine state — use them only on your own
> configured device, after reading the matching writeup. `tests/` are harmless lab reproductions.

| # | Severity | Finding | Lab test (`tests/`) | Live (`live/`) | Writeup |
|---|----------|---------|---------------------|----------------|---------|
| 1 | High | Unauthenticated first-run PIN setup from the LAN | `poc1_lan_setup_takeover.py` | `poc1_live_setup_takeover.py` | [01](writeups/01-unauthenticated-first-run-setup.md) |
| 2 | High | Router cert pin silently replaced by a LAN impersonator | `poc2_cert_pin_retrust.py` | `poc2_live_cert_retrust.py` | [02](writeups/02-router-certificate-retrust.md) |
| 3 | Medium | Move-file HMAC leaves `orbi.db`/backups unauthenticated | `poc3_move_file_tamper.py` | `poc3_live_move_file_takeover.py` | [03](writeups/03-move-file-hmac-gap.md) |
| 4 | Medium | macOS Keychain secrets stored with a wildcard (`-A`) ACL | `poc4_keychain_permissive_acl.py` | `poc4_live_keychain_dump.py` | [04](writeups/04-keychain-wildcard-acl.md) |
| 5 | Low | macOS installer upgrades pip without a pin or hash | `poc5_unpinned_pip_upgrade.py` | `poc5_live_unpinned_pip.py` | [05](writeups/05-unpinned-pip-upgrade.md) |

## Two folders

- **`tests/`** — self-contained reproductions. Temp dirs, mocks and a local HTTP listener; they
  never change a configured machine. Safe to run in a lab. See [`tests/README.md`](tests/README.md).
- **`live/`** — versions that operate on an actual machine: the real HTTP endpoint, real
  `settings.json`, real Keychain, real data dir, real installer. Every mutating script requires
  `--confirm` and makes a backup first. See [`live/README.md`](live/README.md).

## Writeups

Each writeup explains the root cause and data flow, how the PoC reproduces it, what an attacker
gains, a fix direction, and whether it is usable with only local access to an already-configured
device. See [`writeups/`](writeups/).

### Fully-local use (already-configured device)

| # | Works fully locally? | Reason |
|---|---|---|
| 1 | No | `/api/setup` returns `409 Already set up` once a PIN exists; first-run only. |
| 2 | No | Needs L2 ARP spoofing plus a brief router outage; loopback has no ARP entry. |
| 3 | Yes | Stop the app, import a self-sealed ZIP with `--force`; replaces `orbi.db` and `settings.json` (PIN, router password, secrets). |
| 4 | Yes | Same-user macOS process reads `settings.json` + Keychain secrets with no prompt; works *because* the device is set up. |
| 5 | No | Install-time only; nothing re-triggers it on a configured app. |

Bottom line: with only local access to a configured device, **#3 gives control of the app's
configuration and credentials**, **#4 gives read access to all stored secrets**, and #1/#2/#5
need outside conditions (unconfigured instance, LAN position, or install-time access).

## Setup

The `tests/` and `live/` scripts import the application code, so they need an Orbi Control checkout
and its dependencies:

```sh
git clone https://github.com/inspectormamba/orbi-app.git ../orbi-app
python3 -m venv .venv
.venv/bin/python -m pip install -r ../orbi-app/requirements.in
export ORBI_PATH="$PWD/../orbi-app"
```

Every script also accepts `--orbi-path`. The lab PoC 1 needs only Python's standard library.
PoC 1 in either folder talks to a real HTTP endpoint; it needs no app imports.

## Running

```sh
# Harmless lab reproductions (2-5), no network, no root, no real router
.venv/bin/python tests/verify_all.py

# Live scripts — require --confirm, operate on this machine / target
.venv/bin/python live/poc1_live_setup_takeover.py http://192.168.1.50:8470 --confirm
.venv/bin/python live/poc2_live_cert_retrust.py --confirm --serve
.venv/bin/python live/poc3_live_move_file_takeover.py --confirm --force
.venv/bin/python live/poc4_live_keychain_dump.py --confirm --mask
.venv/bin/python live/poc5_live_unpinned_pip.py --confirm
```

Each script prints the vulnerable source location, the attacker-controlled input, and the
observed state. The `tests/` scripts exit `0` only when the vulnerability reproduced.
