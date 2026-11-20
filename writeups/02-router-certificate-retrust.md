# Writeup 2 — Router certificate pin silently replaced by a LAN impersonator

**Finding:** CWE-295 (Improper Certificate Validation), High
**PoC:** `tests/poc2_cert_pin_retrust.py` · live: `live/poc2_live_cert_retrust.py`

## How the vulnerability works

The router uses a self-signed certificate, so the app pins its SHA-256 fingerprint on first use
(`routercert.pinned()`, `orbi/routercert.py:152-159`). Every password-bearing request requires that
exact fingerprint (`routercert.session()` sets `assert_fingerprint`, `:196-211`; the router UI and
log/backup fetchers call `routercert.check()` first). The module docstring promises that a LAN
impostor is refused before the password is sent (`routercert.py:1-7`).

Two auto-trust paths undermine that promise for "unasked" restarts:

1. `check_health()` sets `_router_dropped = True` after a **single** failed TCP probe to the
   router's 443 or 80 (`orbi/monitor.py:271-288`).
2. `_trust_unasked_restart()` (`orbi/monitor.py:722-766`) then replaces the pin when all of these
   hold:
   - `_router_dropped` is set and there was a previous good scan;
   - the new certificate "looks like" a Netgear router certificate;
   - its `not_before` is not in the future;
   - the OS ARP table still maps the router IP to the previously stored MAC.

`looks_like_router_cert()` (`routercert.py:96-99`) compares only three strings: subject
`CN=routerlogin.net`, `O=NetgearFieldDevices`, and issuer `CN=routerlogin.net`. There is no
signature verification, no public-key check, and no chain validation — the DER parser at
`:51-93` reads names and a timestamp only. Any self-signed certificate with those strings and a
plausible date passes.

The "same hardware" check is also attacker-controlled: `gateway_mac()` reads the local ARP table
(`:162-166`), which reflects whatever ARP replies the host last accepted. An attacker on the same
L2 segment can send ARP replies using the real router's MAC as the source address, so both
`_trust_unasked_restart()` and the fake-router watch (`monitor.py:1218-1256`) see the expected
MAC. `_cert_alert()` calls the trust functions *before* raising any alert (`monitor.py:768-786`),
so the pin is replaced and then a reassuring "trusted automatically" event is recorded.

## How the PoC works

The PoC never touches a network. It calls the real application functions with attacker-controlled
inputs:

1. Builds a minimal DER certificate using the same TLV helpers as the app's own test suite. It has
   the required Netgear subject/issuer strings and a current `not_before`, but the signature bytes
   are filler — no valid signature exists.
2. Prints `routercert.describe()` and `looks_like_router_cert()` to show the forged cert is
   accepted as "the router's own".
3. Writes a known-good pin into a temporary `settings.json`, then monkeypatches
   `routercert.presented_der`, `presented`, and `gateway_mac` to simulate the attacker's TLS
   endpoint and spoofed ARP entry.
4. Constructs a real `Monitor` with a temporary `Store` and a null router factory, sets
   `_router_dropped = True`, stores the expected gateway MAC, and calls `_cert_alert()` with a
   `CertificateChanged` error — exactly what a scan gets when the pin no longer matches.
5. Reads the pin back from config. It now equals the SHA-256 of the forged certificate, and a
   "Router restarted" notification was emitted without any user confirmation. Exit 0 asserts the
   replacement happened.

## What you can achieve

An attacker with L2 adjacency to the LAN can:

- Briefly block the real router's TCP 443/80 to set `_router_dropped`.
- Answer for the router IP with ARP replies carrying its MAC, and present a forged certificate
  with the Netgear strings.
- Have the app silently replace the pin, then receive the router admin password on the next SOAP
  login, admin-page automation, or log/backup fetch.
- Use that password for full router takeover: change DNS, disable parental controls, alter port
  forwards, or persist access.

The app only notifies *after* trusting, and the notification says the same hardware was
confirmed — misleading the owner. The initial TOFU acceptance at first use is a related, documented
limitation: an attacker present before first setup receives the password even without this bug.

## Fully-local use with an already-configured device

**No.** The PoC runs locally, but the *attack* does not: reaching the auto-trust path requires
L2 adjacency to spoof ARP for the router IP and the ability to briefly drop the real router's
TCP 443/80 to set `_router_dropped` (`orbi/monitor.py:271-288,722-766`). None of that is available
to a process that only has local access to the configured host. Pointing `router_host` at
`127.0.0.1` cannot trigger it either — loopback has no ARP entry, so `gateway_mac()` returns
`None` and the trust check exits early (`:745-748`). With local access you could edit the pin
directly in config, but that bypasses this vulnerability rather than exploiting it.

**Fix direction:** identify the router by its public key or a signature over the certificate, not
by subject strings; treat ARP table entries as unauthenticated hints, not identity proof;
require several consistent probes and explicit user confirmation for unasked restarts; alert
before re-trusting, not after.
