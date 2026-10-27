#!/usr/bin/env python3
"""Check the Universal Router command table in src/router.rs against Commands.sol.

Why this exists: command values must never be typed from memory. This script
reads the router's own `Commands.sol` (and `Dispatcher.sol`, to confirm every
named command has a handler) and compares them with the `commands! { .. }`
block, `FLAG_ALLOW_REVERT` and `COMMAND_TYPE_MASK` in src/router.rs.

Usage:
    python3 -I tools/verify_commands.py Commands.sol [Dispatcher.sol]

Fetch the files yourself, from the router version you care about, e.g.
    curl -sSLO https://raw.githubusercontent.com/Uniswap/universal-router/main/contracts/libraries/Commands.sol
    curl -sSLO https://raw.githubusercontent.com/Uniswap/universal-router/main/contracts/base/Dispatcher.sol
The files are not vendored here: they are GPL-3.0-or-later and this crate is MIT.
The script prints the SHA-256 of what it read so the README can record it.

Exit status: 0 = identical, 1 = mismatch, 2 = bad usage or unreadable input.
"""
import hashlib
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROUTER_RS = os.path.join(HERE, "..", "src", "router.rs")


def strip_comments(text: str) -> str:
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
    return re.sub(r"//[^\n]*", "", text)


def read(path: str) -> str:
    with open(path, "rb") as fh:
        raw = fh.read()
    print(f"{hashlib.sha256(raw).hexdigest()}  {os.path.basename(path)}")
    return raw.decode()


def solidity_commands(text: str) -> dict:
    out = {}
    for name, val in re.findall(
        r"uint256\s+(?:internal\s+)?constant\s+([A-Z0-9_]+)\s*=\s*(0x[0-9a-fA-F]+)\s*;",
        strip_comments(text),
    ):
        if name in out:
            sys.exit(f"duplicate constant {name} in Commands.sol")
        out[name] = int(val, 16)
    return out


def solidity_flags(text: str) -> dict:
    return {
        name: int(val, 16)
        for name, val in re.findall(
            r"bytes1\s+(?:internal\s+)?constant\s+(FLAG_ALLOW_REVERT|COMMAND_TYPE_MASK)\s*=\s*(0x[0-9a-fA-F]+)\s*;",
            strip_comments(text),
        )
    }


def rust_table(text: str):
    m = re.search(r"commands!\s*\{(.*?)\n\}", text, flags=re.S)
    if not m:
        sys.exit("cannot find the commands! { .. } block in src/router.rs")
    table = {}
    for name, val in re.findall(r"^\s*([A-Z0-9_]+)\s*=\s*(0x[0-9a-fA-F]+)\s*;", m.group(1), flags=re.M):
        if name in table:
            sys.exit(f"duplicate constant {name} in router.rs")
        table[name] = int(val, 16)
    flags = {
        name: int(val, 16)
        for name, val in re.findall(
            r"pub const (FLAG_ALLOW_REVERT|COMMAND_TYPE_MASK): u8 = (0x[0-9a-fA-F]+);", text
        )
    }
    return table, flags


def main() -> int:
    if len(sys.argv) not in (2, 3):
        print(__doc__)
        return 2
    try:
        sol = read(sys.argv[1])
        disp = read(sys.argv[2]) if len(sys.argv) == 3 else None
        rs = open(ROUTER_RS).read()
    except OSError as e:
        print(f"cannot read input: {e}")
        return 2

    want, want_flags = solidity_commands(sol), solidity_flags(sol)
    have, have_flags = rust_table(rs)
    bad = []

    for name in sorted(set(want) | set(have)):
        if name not in have:
            bad.append(f"{name} = {want[name]:#04x} is in Commands.sol but not in router.rs")
        elif name not in want:
            bad.append(f"{name} = {have[name]:#04x} is in router.rs but not in Commands.sol")
        elif want[name] != have[name]:
            bad.append(f"{name}: Commands.sol says {want[name]:#04x}, router.rs says {have[name]:#04x}")
    if len(set(want.values())) != len(want):
        bad.append("two names share a value in Commands.sol")
    for name in ("FLAG_ALLOW_REVERT", "COMMAND_TYPE_MASK"):
        if name not in want_flags:
            bad.append(f"{name} not found in Commands.sol")
        elif want_flags[name] != have_flags.get(name):
            got = have_flags.get(name)
            got = "missing" if got is None else f"{got:#04x}"
            bad.append(f"{name}: Commands.sol says {want_flags[name]:#04x}, router.rs says {got}")

    if disp is not None:
        used = set(re.findall(r"Commands\.([A-Z0-9_]+)\b", strip_comments(disp)))
        for name in sorted(set(want) - used):
            bad.append(f"{name} is named in Commands.sol but Dispatcher.sol never uses it (no handler?)")
        for name in sorted(used - set(want) - {"FLAG_ALLOW_REVERT", "COMMAND_TYPE_MASK"}):
            bad.append(f"Dispatcher.sol uses Commands.{name}, which Commands.sol does not define")

    print(f"{len(want)} commands in Commands.sol, {len(have)} in router.rs")
    if bad:
        print("MISMATCH:")
        for b in bad:
            print("  -", b)
        return 1
    print("identical" + (" (and every command has a handler in Dispatcher.sol)" if disp else ""))
    return 0


if __name__ == "__main__":
    sys.exit(main())
