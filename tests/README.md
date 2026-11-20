# tests/ — harmless lab reproductions

These are the original PoCs. They import the real application code but keep all state in
temporary directories, mock the network/Keychain/subprocess boundaries, and never change a
configured machine. Safe to run in a lab.

```sh
export ORBI_PATH=/path/to/orbi-app
.venv/bin/python verify_all.py
```

- `poc1_lan_setup_takeover.py` — needs an unconfigured HTTP endpoint; only sets a PIN on that target.
- `poc2_cert_pin_retrust.py` — monkeypatches `presented_der`/`gateway_mac`; temp `settings.json`.
- `poc3_move_file_tamper.py` — builds temp move ZIPs and imports into temp data dirs.
- `poc4_keychain_permissive_acl.py` — mocks `security`; nothing is written to your Keychain.
- `poc5_unpinned_pip_upgrade.py` — source-level check of `install-macos.sh`.

For versions that operate on an actual machine, see [`../live/`](../live/).
