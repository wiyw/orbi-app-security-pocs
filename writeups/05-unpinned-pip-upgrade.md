# Writeup 5 — macOS installer upgrades pip without a pin or hash

**Finding:** CWE-494 (Download of Code Without Integrity Check), Low
**PoC:** `poc5_unpinned_pip_upgrade.py`

## How the vulnerability works

`install-macos.sh:22-24` first claims that every package is hash-pinned, then does this:

```sh
"$VENV/bin/python" -m pip install --quiet --upgrade pip
"$VENV/bin/python" -m pip install --quiet -r "$ROOT/requirements.txt"
```

`requirements.txt` is genuinely hash-pinned, but the tool that is supposed to enforce those
hashes — pip itself — is upgraded *first*, with no version specifier and no hash. The new pip is
downloaded, installed, and executed before any of the project's hashes are checked. If that
download is malicious or the distribution channel is compromised, attacker-controlled code runs
with the installing user's privileges while the script still appears to be doing a verified
install.

## How the PoC works

The PoC is a source-level reproduction, which is the appropriate demonstration here: exploiting
it would require a compromised upstream artifact. It:

1. Reads `install-macos.sh` and locates the `pip install --upgrade pip` line.
2. Prints the preceding security claim, the upgrade command, and the following hash-pinned
   `requirements.txt` command side by side.
3. Prints two real `==`/SHA-256 entries from `requirements.txt` for contrast.
4. Asserts the upgrade line contains `--upgrade pip` but no `==` pin, no `--require-hashes`, and
   no hash — then exits 0.

While building the test environment for these PoCs we also observed that the hash-pinned
requirements file fails on this Python version: `pystray` pulls `pyobjc-framework-Quartz>=7.0`,
which is not pinned, so `--require-hashes` aborts with "all requirements must have their versions
pinned with `==`". That is a separate reproducibility problem in the same supply-chain path.

## What you can achieve

This is a supply-chain exposure rather than a directly triggerable remote bug. An attacker who can
cause a malicious pip release to be served — via upstream compromise, account takeover of a
mirror, or a compromised proxy — gets arbitrary code execution as the user running the installer,
before any project hashes are verified. The installer runs without `sudo`, so the impact is the
user's account: home directory, Keychain items available to that user, and the installed app.

## Fully-local use with an already-configured device

**No.** This is an install-time exposure only. The unpinned `pip install --upgrade pip` line runs
once, inside `install-macos.sh`, before the app is set up. On an already-configured device that
path has completed; there is no local action against the running app that re-triggers it.
Exploiting it requires control of the upstream pip artifact or distribution channel at install
time, which is outside manipulation by definition.

**Fix direction:** pin pip itself (version and hash) or use the OS-provided pip; install all
dependencies in a single `--require-hashes` invocation; and pin transitive dependencies such as
the pyobjc packages so the hash mode can actually complete.
