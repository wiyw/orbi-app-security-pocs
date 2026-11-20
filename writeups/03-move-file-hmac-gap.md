# Writeup 3 — Move-file HMAC leaves the database and backups unauthenticated

**Finding:** CWE-345 (Insufficient Verification of Data Authenticity) / CWE-347, Medium
**PoC:** `poc3_move_file_tamper.py`

## How the vulnerability works

`orbi/migrate.py` exports the app state to a passphrase-protected `orbi-move.zip`. Its docstring
states that the cipher is "HMAC-SHA256 in counter mode with an HMAC-SHA256 tag over everything"
(`migrate.py:16-18`). The implementation tags only one member:

- `seal()` (`:66-72`) encrypts a **JSON payload** of settings/secrets and computes the tag over
  `header + "\n" + ciphertext`.
- `export()` (`:122-138`) puts that blob in `sealed.bin`, but also writes `orbi.db`,
  `kev_ids.json`, and `router-backups/*` into the same ZIP **unsealed**, with no per-file hashes.
- `import_()` (`:148-176`) checks the manifest format and verifies `sealed.bin`, then iterates
  every other ZIP entry and copies it to disk *before* applying the sealed settings at
  `:178-192`.

So the HMAC authenticates the settings/secrets portion only. Any other entry can be modified
without the passphrase and will still be installed.

## How the PoC works

1. Creates a payload with no secrets (so no Keychain/DPAPI calls occur) and seals it with
   `migrate.seal()` using the correct passphrase.
2. Creates a small SQLite `orbi.db` with a marker row, and builds a "legitimate" move ZIP with
   `manifest.json`, `sealed.bin`, and that DB.
3. Creates a second "tampered" ZIP by copying every entry byte-for-byte except `orbi.db`, which
   is replaced with a DB containing a different marker row. `sealed.bin` and its tag remain
   identical.
4. Prints proof that `unseal()` succeeds and returns the original payload for the tampered file.
5. Calls the real `migrate.import_()` on both archives with the correct passphrase and reads back
   the imported DB. Both imports succeed; the databases differ exactly as the attacker chose.
   Exit 0 asserts that difference.

The PoC uses only temp directories and the real `migrate` module, so it demonstrates the actual
import path rather than a reimplementation.

## What you can achieve

Anyone who can modify the move file while it is stored or in transit — a shared folder, email
attachment, USB stick, or backup location — can inject arbitrary state into the destination
machine without knowing the passphrase:

- Device rows, aliases, profiles, schedules, hold/allow lists, and alert history in `orbi.db`.
- Forged router-setting backups under `router-backups/`.
- Manipulated KEV identifier data in `kev_ids.json`.

This is an integrity attack, not a disclosure: PINs, session secret, router password, DNS logins,
and push/heartbeat URLs remain inside the authenticated `sealed.bin`. The practical trigger is
the victim importing the file with the correct passphrase. A `--force` import replaces an existing
data dir after making a backup, but the backup is made from the *current* machine, not from the
attacker's entries.

**Fix direction:** include a SHA-256 for every ZIP entry in the manifest and cover that manifest
with the HMAC; verify all entries before writing anything to disk; or use an authenticated archive
format end to end.
