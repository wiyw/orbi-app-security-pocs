# Writeup 4 — macOS Keychain secrets stored with a wildcard ACL

**Finding:** CWE-732 (Incorrect Permission Assignment) / CWE-522, Medium
**PoC:** `tests/poc4_keychain_permissive_acl.py` · live: `live/poc4_live_keychain_dump.py`

## How the vulnerability works

On macOS the app stores secrets in the login Keychain (`orbi/osdep/macos.py:39-48`). `protect()`
writes each secret with:

```python
subprocess.run(["security", "add-generic-password", "-s", KEYCHAIN_SERVICE,
                "-a", acct, "-w", text, "-U", "-A"], ...)
```

`-A` means "allow any application to access this password without warning". The return value is a
`keychain:<acct>` reference written in plaintext to `settings.json`. `unprotect()` (`:51-59`) reads
the value back with only the service name and that account id:

```python
security find-generic-password -s OrbiControl -a <acct> -w
```

Because the account id is persisted and the ACL grants access to every application, the Keychain
provides storage encryption but no access-control boundary between the app and other processes
running as the same macOS user. The secrets affected are listed in `orbi/migrate.py:39`: the
router admin password, push topic, heartbeat URL, NextDNS link, and OpenDNS password.

## How the PoC works

The PoC does not write to your Keychain. It patches `macos.subprocess.run` with a fake that records
the argument vector and returns a successful result, then calls the **real** `protect()` and
`unprotect()` functions:

1. `protect("TEST_SECRET_VALUE")` — the captured argv shows `-w <redacted> -U -A` and returns a
   `keychain:<acct>` token.
2. `unprotect(token)` — the captured argv shows `find-generic-password -s ... -a <acct> -w`, and
   the secret is returned with no prompt or ACL grant.
3. Asserts that `-A` is present on the write, absent from the read, and that the value round-trips.

This proves the flag comes from the application's own code, not from an assumption about how the
Keychain works.

## What you can achieve

Any application or script running as the same macOS user can:

- Read `settings.json`, collect every `keychain:<acct>` reference, and call
  `security find-generic-password -s OrbiControl -a <acct> -w` silently.
- Recover the router admin password and all DNS/push/heartbeat credentials without a Keychain
  prompt, and without needing the user's login password.

The boundary crossed is "app secrets are isolated" → "same-user process can read them". It does
not cross OS-user boundaries and it does not help a remote attacker on its own — it matters when
malware or an untrusted helper already runs in the user's session, or when combined with an
arbitrary-file-read issue.

## Fully-local use with an already-configured device

**Yes — this is the cleanest fully-local finding.** With same-user access to the configured Mac,
no network position, router contact, victim action, or install-time access is needed: read
`settings.json` for the `keychain:<acct>` references, then call
`security find-generic-password -s OrbiControl -a <acct> -w` for each. Because the items were
written with `-A`, there is no prompt or ACL grant. This works precisely *because* the device is
already set up and has secrets stored. The limitation is scope: same macOS user only — it does not
cross OS-user boundaries, and it recovers secrets rather than altering settings.

**Fix direction:** scope the ACL to the app binary with `security add-generic-password -T
/path/to/app` (and `-T ""` only where a prompt is acceptable), or use the Data Protection keychain
with an app access group. Keep only the reference in settings, as the app already does.
