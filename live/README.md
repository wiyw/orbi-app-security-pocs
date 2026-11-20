# live/ — versions for actual machines

These operate on real state: a running HTTP endpoint, the machine's real `settings.json`,
Keychain, data dir, or installer. **Only use them on your own devices.** Every mutating script
requires `--confirm` and makes a backup first.

All scripts import the app code; set `ORBI_PATH` (or pass `--orbi-path`) and run from the repo
root with the project venv.

| Script | What it changes | Preconditions |
|---|---|---|
| `poc1_live_setup_takeover.py` | Sets the PIN on a live unconfigured instance | Reachable `http://host:8470`, first-run state |
| `poc2_live_cert_retrust.py` | Replaces the real router-cert pin in `settings.json`; optional HTTPS listener | Configured instance, `--data-dir` or OS default |
| `poc3_live_move_file_takeover.py` | Replaces the real data dir (PIN, settings, `orbi.db`) via a self-sealed move ZIP | App stopped, `--force`, backup made |
| `poc4_live_keychain_dump.py` | Reads (prints) all Keychain secrets referenced in `settings.json` | macOS, same user as the app |
| `poc5_live_unpinned_pip.py` | Runs the installer's exact unpinned pip command in a throwaway venv against a local fake index | Checkout with `install-macos.sh` |

Examples:

```sh
.venv/bin/python live/poc1_live_setup_takeover.py http://192.168.1.50:8470 --confirm
.venv/bin/python live/poc2_live_cert_retrust.py --confirm --serve
.venv/bin/python live/poc3_live_move_file_takeover.py --confirm --force
.venv/bin/python live/poc4_live_keychain_dump.py --confirm --mask
.venv/bin/python live/poc5_live_unpinned_pip.py --confirm
```

Notes:
- PoC 2's full LAN attack (password capture) still needs L2 adjacency, ARP replies using the
  router's MAC, and a brief outage of the real router's TCP 443/80. The script does the local
  pin-replacement half and can present the forged certificate locally with `--serve`.
- PoC 3 backs up the data dir before `--force`; the app must be stopped because `migrate.import_`
  checks the data-dir lock.
- PoC 4 prints values by default; use `--mask` when you only need proof of readability.
