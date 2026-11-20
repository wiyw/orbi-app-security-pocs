#!/usr/bin/env python3
"""PoC 4 — Keychain secrets stored with a wildcard ACL (CWE-732, Medium).

Vulnerable code: orbi/osdep/macos.py:42-48 calls
    security add-generic-password ... -w <secret> -U -A
`-A` lets any application read the item with no Keychain prompt. The account id needed for
the read is persisted in plaintext settings.json (see unprotect(), macos.py:51-59).

This captures the real argv protect() passes to `security` through a mock — nothing is
written to your Keychain.
"""
import argparse
from unittest import mock

from poc_common import orbi_arg, load_orbi

SECRET = "TEST_SECRET_VALUE"


def redacted(argv):
    out, skip = [], False
    for part in argv:
        if skip:
            out.append("<redacted>")
            skip = False
            continue
        out.append(part)
        if part == "-w":
            skip = True
    return out


def main():
    ap = argparse.ArgumentParser()
    orbi_arg(ap)
    args = ap.parse_args()
    load_orbi(args)

    from orbi.osdep import macos

    calls = []

    class Result:
        returncode = 0
        stdout = SECRET + "\n"
        stderr = ""

    def fake_run(argv, **kwargs):
        calls.append(list(argv))
        return Result()

    with mock.patch.object(macos.subprocess, "run", fake_run):
        token = macos.protect(SECRET)
        read_back = macos.unprotect(token)

    write_argv, read_argv = calls
    print(f"[*] protect() argv      : {' '.join(redacted(write_argv))}")
    print(f"[*] token in settings   : {token}")
    print(f"[*] unprotect() argv    : {' '.join(read_argv)}")
    print(f"[*] read back, no prompt: {read_back!r}")

    assert "-A" in write_argv, "expected -A on the write"
    assert "-A" not in read_argv, "read needs no ACL grant and shows no prompt"
    assert read_back == SECRET
    print("[+] CONFIRMED: any local app holding the account id reads the secret silently")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
