#!/usr/bin/env python3
"""Generate the SYNTHETIC seed cases in corpus/.

These are NOT real transactions. They exist so the corpus harness has
something to run and so each rule in src/risk.rs is exercised end to end by
calldata that was encoded by code that shares nothing with the crate:
selectors come from the independent Keccak in verify_selectors.py and the ABI
encoding is written out here by hand.

The expected verdicts below are written from the rules in the README, not
copied from the crate's output. If the crate disagrees, one of the two is
wrong and that is exactly what the corpus is for.

Usage: python3 -I tools/gen_synthetic_corpus.py     (rewrites corpus/synthetic-*.case)
"""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from verify_selectors import keccak256  # noqa: E402  (our own file, not input data)

OUT = os.path.join(HERE, "..", "corpus")


def sel(sig: str) -> bytes:
    return keccak256(sig.encode())[:4]


def word(n: int) -> bytes:
    return n.to_bytes(32, "big")


def addr(b: int) -> bytes:
    return bytes(12) + bytes([b]) * 20


MAX256 = (1 << 256) - 1
MAX160 = (1 << 160) - 1
MAX48 = (1 << 48) - 1

TRUSTED = bytes([0x11]) * 20
STRANGER = 0x99


def approve(spender: int, amount: int) -> bytes:
    return sel("approve(address,uint256)") + addr(spender) + word(amount)


def set_for_all(operator: int, approved: bool) -> bytes:
    return sel("setApprovalForAll(address,bool)") + addr(operator) + word(int(approved))


def transfer(to: int, amount: int) -> bytes:
    return sel("transfer(address,uint256)") + addr(to) + word(amount)


def permit_2612(spender: int, value: int, deadline: int) -> bytes:
    return (sel("permit(address,address,uint256,uint256,uint8,bytes32,bytes32)")
            + addr(0x22) + addr(spender) + word(value) + word(deadline)
            + word(27) + word(1) + word(2))


def permit_dai(spender: int, expiry: int, allowed: bool) -> bytes:
    return (sel("permit(address,address,uint256,uint256,bool,uint8,bytes32,bytes32)")
            + addr(0x22) + addr(spender) + word(0) + word(expiry) + word(int(allowed))
            + word(27) + word(1) + word(2))


def permit2_approve(spender: int, amount: int, expiration: int) -> bytes:
    return (sel("approve(address,address,uint160,uint48)")
            + addr(0x33) + addr(spender) + word(amount) + word(expiration))


def bytes_array(items) -> bytes:
    """ABI tail encoding of bytes[]: length, offsets (relative to the first
    offset), then each element as length + data padded to 32 bytes."""
    n = len(items)
    elems = []
    for it in items:
        pad = (-len(it)) % 32
        elems.append(word(len(it)) + it + bytes(pad))
    offsets, pos = [], 32 * n
    for e in elems:
        offsets.append(word(pos))
        pos += len(e)
    return word(n) + b"".join(offsets) + b"".join(elems)


def multicall(items) -> bytes:
    return sel("multicall(bytes[])") + word(0x20) + bytes_array(items)


# ---- Multicall3 -----------------------------------------------------------
# A small, generic ABI encoder (head/tail) so that the tuple-array layouts below
# come from the ABI rules, not from a copy of the layout the crate reads.
# Types: ("address",) ("bool",) ("uint256",) ("bytes",) ("tuple", [types])
# ("array", elem_type). Static tuples are laid out inline (head_size).

def is_dynamic(t) -> bool:
    if t[0] in ("bytes", "array"):
        return True
    if t[0] == "tuple":
        return any(is_dynamic(x) for x in t[1])
    return False


def encode(t, v) -> bytes:
    kind = t[0]
    if kind == "address":
        return bytes(12) + v
    if kind == "bool":
        return word(int(v))
    if kind == "uint256":
        return word(v)
    if kind == "bytes":
        return word(len(v)) + v + bytes((-len(v)) % 32)
    if kind == "array":
        return word(len(v)) + encode_seq([t[1]] * len(v), v)
    if kind == "tuple":
        return encode_seq(t[1], v)
    raise ValueError(kind)


def head_size(t) -> int:
    """Bytes a member occupies in the head: one offset word if dynamic, else
    its inline size (a static tuple is the sum of its members)."""
    if is_dynamic(t):
        return 32
    if t[0] == "tuple":
        return sum(head_size(x) for x in t[1])
    return 32


def encode_seq(types, values) -> bytes:
    head_len = sum(head_size(t) for t in types)
    heads, tails = [], b""
    for t, v in zip(types, values):
        if is_dynamic(t):
            heads.append(word(head_len + len(tails)))
            tails += encode(t, v)
        else:
            heads.append(encode(t, v))
    return b"".join(heads) + tails


CALL3 = ("tuple", [("address",), ("bool",), ("bytes",)])
CALL3V = ("tuple", [("address",), ("bool",), ("uint256",), ("bytes",)])
CALL2 = ("tuple", [("address",), ("bytes",)])


def a20(b: int) -> bytes:
    return bytes([b]) * 20


def aggregate3(items) -> bytes:
    """items: (target byte, allowFailure, calldata)"""
    return sel("aggregate3((address,bool,bytes)[])") + encode_seq(
        [("array", CALL3)], [[(a20(a), f, d) for a, f, d in items]])


def aggregate3_value(items) -> bytes:
    """items: (target byte, allowFailure, value, calldata)"""
    return sel("aggregate3Value((address,bool,uint256,bytes)[])") + encode_seq(
        [("array", CALL3V)], [[(a20(a), f, v, d) for a, f, v, d in items]])


def try_aggregate(require_success, items) -> bytes:
    """items: (target byte, calldata)"""
    return sel("tryAggregate(bool,(address,bytes)[])") + encode_seq(
        [("bool",), ("array", CALL2)], [require_success, [(a20(a), d) for a, d in items]])


def swap_like() -> bytes:
    return bytes.fromhex("04e45aaf") + word(1)


def patched(data: bytes, at: int, new: bytes) -> bytes:
    return data[:at] + new + data[at + len(new):]


# aggregate3 with one tuple: selector(4) | array offset(32) | length(32) |
# offset table(32) | tuple: target(32) allowFailure(32) bytes-offset(32) ...
A3_TUPLE0 = 4 + 32 + 32 + 32
_one = aggregate3([(0xa1, False, approve(STRANGER, 5))])
_two = aggregate3([(0xa1, False, transfer(0x44, 1)), (0xa2, False, transfer(0x44, 2))])


# ---- Universal Router -----------------------------------------------------
# Encoded with the same generic head/tail encoder as Multicall3 above. The
# layouts come from the ABI rules applied to the Solidity types in
# Dispatcher.sol / IUniversalRouter.sol, not from the crate's reader:
#   execute(bytes commands, bytes[] inputs [, uint256 deadline])
#   PERMIT2_PERMIT       input = abi.encode(PermitSingle, bytes)
#   PERMIT2_PERMIT_BATCH input = abi.encode(PermitBatch, bytes)
#   EXECUTE_SUB_PLAN     input = abi.encode(bytes, bytes[])
# with PermitDetails = (address token, uint160 amount, uint48 expiration,
# uint48 nonce) as in Permit2's IAllowanceTransfer.sol.

DETAILS = ("tuple", [("address",), ("uint256",), ("uint256",), ("uint256",)])
PERMIT_SINGLE = ("tuple", [DETAILS, ("address",), ("uint256",)])
PERMIT_BATCH = ("tuple", [("array", DETAILS), ("address",), ("uint256",)])
SIG = bytes([0x5a]) * 65

# command bytes (values from Commands.sol)
C_V3_SWAP_EXACT_IN, C_PERMIT2_PERMIT_BATCH, C_PERMIT2_PERMIT = 0x00, 0x03, 0x0a
C_SUB_PLAN = 0x21


def ur_details(token, amount, expiration, nonce):
    return (a20(token), amount, expiration, nonce)


def permit_single_input(spender, amount, expiration, token=0xaa, nonce=1):
    return encode_seq(
        [PERMIT_SINGLE, ("bytes",)],
        [(ur_details(token, amount, expiration, nonce), a20(spender), 0xffff), SIG])


def permit_batch_input(spender, details):
    return encode_seq(
        [PERMIT_BATCH, ("bytes",)],
        [([ur_details(*d) for d in details], a20(spender), 0xffff), SIG])


def plan(commands: bytes, inputs) -> bytes:
    """abi.encode(bytes, bytes[]): a plan without selector (and a sub plan input)."""
    return encode_seq([("bytes",), ("array", ("bytes",))], [commands, inputs])


def execute(commands: bytes, inputs) -> bytes:
    return sel("execute(bytes,bytes[])") + plan(commands, inputs)


def execute_deadline(commands: bytes, inputs, deadline: int) -> bytes:
    return sel("execute(bytes,bytes[],uint256)") + encode_seq(
        [("bytes",), ("array", ("bytes",)), ("uint256",)], [commands, inputs, deadline])


def swap_input() -> bytes:
    return bytes(range(1, 40))  # opaque: this crate does not judge swaps


# Router spend commands (layouts read from Dispatcher.sol, SHA-256 4d22b791...):
#   PERMIT2_TRANSFER_FROM / SWEEP / TRANSFER / PAY_PORTION[_FULL_PRECISION]:
#       abi.decode(inputs, (address token, address recipient, uint256 amount))
#   UNWRAP_WETH: abi.decode(inputs, (address recipient, uint256 amountMin))
C_PERMIT2_TRANSFER_FROM, C_SWEEP, C_TRANSFER, C_PAY_PORTION = 0x02, 0x04, 0x05, 0x06
C_PAY_PORTION_FULL_PRECISION, C_V2_SWAP_EXACT_IN, C_UNWRAP_WETH = 0x07, 0x08, 0x0c
C_PERMIT2_TRANSFER_FROM_BATCH = 0x0d

ADDRESS_1 = bytes(19) + b"\x01"  # ActionConstants.MSG_SENDER
ADDRESS_2 = bytes(19) + b"\x02"  # ActionConstants.ADDRESS_THIS
ADDRESS_3 = bytes(19) + b"\x03"  # an ordinary address that merely looks close


def spend3(recipient: bytes, amount: int = 1000) -> bytes:
    return encode_seq([("address",), ("address",), ("uint256",)], [a20(0xaa), recipient, amount])


def unwrap_in(recipient: bytes, amount: int = 1000) -> bytes:
    return encode_seq([("address",), ("uint256",)], [recipient, amount])


def v3_swap_input(recipient: bytes) -> bytes:
    """abi.decode(inputs, (address, uint256, uint256, bytes, bool, uint256[]))"""
    return encode_seq(
        [("address",), ("uint256",), ("uint256",), ("bytes",), ("bool",), ("array", ("uint256",))],
        [recipient, 10**18, 1, bytes(range(43)), True, []])


_ur_plain = execute(bytes([C_PERMIT2_PERMIT]), [permit_single_input(0x11, 1000, 5000)])
_ur_two = execute(bytes([C_PERMIT2_PERMIT, C_V3_SWAP_EXACT_IN]),
                  [permit_single_input(0x11, 1000, 5000), swap_input()])

# name -> (note, expect, flags or None, error or None, calldata)
CASES = {
    "approve-max-stranger": (
        "unlimited approve to an address nobody trusts",
        "high", "UNLIMITED_AMOUNT UNTRUSTED_SPENDER", None, approve(STRANGER, MAX256)),
    "approve-max-trusted": (
        "unlimited approve to a trusted router: worth a look, not an alarm",
        "review", "UNLIMITED_AMOUNT", None, approve(0x11, MAX256)),
    "approve-small-trusted": (
        "bounded approve to a trusted router",
        "safe", "", None, approve(0x11, 1000)),
    "approve-small-stranger": (
        "bounded approve to a stranger",
        "review", "UNTRUSTED_SPENDER", None, approve(STRANGER, 1000)),
    "approve-zero-stranger": (
        "approve(x, 0) is a revocation, whoever x is",
        "safe", "REVOCATION", None, approve(STRANGER, 0)),
    "set-for-all-stranger": (
        "blanket NFT approval to a stranger",
        "high", "BLANKET_APPROVAL UNTRUSTED_SPENDER", None, set_for_all(STRANGER, True)),
    "set-for-all-revoke": (
        "setApprovalForAll(x, false) revokes",
        "safe", "REVOCATION", None, set_for_all(STRANGER, False)),
    "permit-max-forever-stranger": (
        "EIP-2612 permit: max value, max deadline, stranger",
        "high", "UNLIMITED_AMOUNT UNTRUSTED_SPENDER NO_EXPIRY", None,
        permit_2612(STRANGER, MAX256, MAX256)),
    "permit-dai-allowed-no-expiry": (
        "DAI-style permit: allowed=true means max, expiry 0 means never",
        "high", "UNLIMITED_AMOUNT UNTRUSTED_SPENDER NO_EXPIRY", None,
        permit_dai(STRANGER, 0, True)),
    "permit2-max-forever-stranger": (
        "Permit2 approve: uint160 max amount, uint48 max expiration",
        "high", "UNLIMITED_AMOUNT UNTRUSTED_SPENDER NO_EXPIRY", None,
        permit2_approve(STRANGER, MAX160, MAX48)),
    "transfer-plain": (
        "a plain transfer carries no approval risk",
        "safe", "", None, transfer(0x44, 5)),
    "approve-trailing-bytes": (
        "bounded approve to a trusted router plus bytes the EVM ignores",
        "review", "TRAILING_DATA", None, approve(0x11, 1000) + b"\xab" * 7),
    "multicall-hidden-approve": (
        "an unlimited approve to a stranger buried in a batch of harmless calls",
        "high", "UNLIMITED_AMOUNT UNTRUSTED_SPENDER", None,
        multicall([transfer(0x44, 1), approve(STRANGER, MAX256), transfer(0x44, 2)])),
    "multicall-unknown-inner": (
        "a batch whose only call this crate cannot read: cannot vouch, so Review",
        "review", "", None, multicall([bytes.fromhex("deadbeef") + word(1)])),
    "aggregate3-hidden-approve": (
        "Multicall3 aggregate3: an unlimited approve to a stranger between harmless transfers",
        "high", "UNLIMITED_AMOUNT UNTRUSTED_SPENDER", None,
        aggregate3([(0xa1, False, transfer(0x44, 1)),
                    (0xa2, False, approve(STRANGER, MAX256)),
                    (0xa1, True, transfer(0x44, 2))])),
    "aggregate3-trusted-router-approve-max": (
        "unlimited approve to the trusted router inside aggregate3: worth a look, not an alarm",
        "review", "UNLIMITED_AMOUNT", None,
        aggregate3([(0xa2, False, approve(0x11, MAX256))])),
    "aggregate3-only-revocations": (
        "aggregate3 made only of revocations is good news",
        "safe", "REVOCATION", None,
        aggregate3([(0xa2, False, approve(STRANGER, 0)),
                    (0xa3, False, set_for_all(STRANGER, False))])),
    "aggregate3-unknown-inner": (
        "aggregate3 whose only call is a swap this crate cannot read: cannot vouch, so Review",
        "review", "", None, aggregate3([(0xa4, False, swap_like())])),
    "aggregate3value-hidden-approve": (
        "aggregate3Value carrying ETH plus an unlimited approve to a stranger",
        "high", "UNLIMITED_AMOUNT UNTRUSTED_SPENDER", None,
        aggregate3_value([(0xa5, False, 10**18, swap_like()),
                          (0xa2, False, 0, approve(STRANGER, MAX256))])),
    "try-aggregate-small-stranger": (
        "tryAggregate(false, ...) with a bounded approve to a stranger",
        "review", "UNTRUSTED_SPENDER", None,
        try_aggregate(False, [(0xa2, approve(STRANGER, 1000))])),
    "aggregate3-inside-multicall": (
        "a Multicall3 batch with an unlimited approve to a stranger nested in a multicall(bytes[])",
        "high", "UNLIMITED_AMOUNT UNTRUSTED_SPENDER", None,
        multicall([transfer(0x44, 1), aggregate3([(0xa2, False, approve(STRANGER, MAX256))])])),
    "aggregate3-trailing-bytes": (
        "aggregate3 of harmless transfers plus bytes the EVM ignores",
        "review", "TRAILING_DATA", None, _two + b"\xcd" * 9),
    "aggregate3-dirty-target": (
        "aggregate3 whose target address word has non-zero padding",
        "undecodable", None, "DirtyElementField",
        patched(_one, A3_TUPLE0 + 3, b"\x01")),
    "aggregate3-bad-allow-failure": (
        "aggregate3 whose allowFailure word is 2",
        "undecodable", None, "DirtyElementField",
        patched(_one, A3_TUPLE0 + 32, word(2))),
    "aggregate3-bytes-offset-into-head": (
        "aggregate3 whose callData offset points back into the tuple's own head",
        "undecodable", None, "BadMemberOffset",
        patched(_one, A3_TUPLE0 + 64, word(32))),
    "aggregate3-aliased-tuples": (
        "aggregate3 whose second tuple offset equals the first: overlapping regions",
        "undecodable", None, "OverlappingElement",
        patched(_two, 4 + 32 + 32 + 32, _two[4 + 32 + 32:4 + 32 + 32 + 32])),
    "aggregate3-truncated": (
        "aggregate3 cut off inside the callData padding",
        "undecodable", None, "Truncated", _one[:-5]),
    "truncated-approve": (
        "approve cut off in the middle of the amount word",
        "undecodable", None, "Truncated", approve(0x11, 1000)[:-5]),
    "dirty-address-padding": (
        "address word with non-zero bytes in the 12 padding bytes",
        "undecodable", None, "DirtyPadding",
        sel("approve(address,uint256)") + bytes([0x01]) + bytes(11) + bytes([0x99]) * 20 + word(1)),
    # ---- Universal Router: expectations written from the README rules before
    # the crate was run on them.
    "ur-permit-max-stranger": (
        "router PERMIT2_PERMIT: uint160 max allowance to a stranger",
        "high", "UNLIMITED_AMOUNT UNTRUSTED_SPENDER", None,
        execute(bytes([C_PERMIT2_PERMIT]), [permit_single_input(STRANGER, MAX160, 5000)])),
    "ur-permit-max-forever-stranger": (
        "router PERMIT2_PERMIT: max amount, expiration 2^47 (half of uint48), stranger",
        "high", "UNLIMITED_AMOUNT UNTRUSTED_SPENDER NO_EXPIRY", None,
        execute(bytes([C_PERMIT2_PERMIT]), [permit_single_input(STRANGER, MAX160, 1 << 47)])),
    "ur-permit-trusted-router-bounded": (
        "bounded permit to the trusted router and nothing else in the plan",
        "safe", "", None, _ur_plain),
    "ur-permit-trusted-router-max": (
        "unlimited permit to the trusted router: worth a look, not an alarm",
        "review", "UNLIMITED_AMOUNT", None,
        execute(bytes([C_PERMIT2_PERMIT]), [permit_single_input(0x11, MAX160, 5000)])),
    "ur-permit-revoke": (
        "a permit with amount 0 revokes, whoever the spender is",
        "safe", "REVOCATION", None,
        execute(bytes([C_PERMIT2_PERMIT]), [permit_single_input(STRANGER, 0, 5000)])),
    "ur-swap-with-permit": (
        "bounded permit to the trusted router plus a swap this crate does not judge",
        "review", "", None, _ur_two),
    "ur-permit-hidden-between-swaps": (
        "an unlimited permit to a stranger between two swap commands this crate does not judge",
        "high", "UNLIMITED_AMOUNT UNTRUSTED_SPENDER", None,
        execute(bytes([C_V3_SWAP_EXACT_IN, C_PERMIT2_PERMIT, C_V2_SWAP_EXACT_IN]),
                [swap_input(), permit_single_input(STRANGER, MAX160, 5000), swap_input()])),
    "ur-permit-allow-revert-bit": (
        "command byte 0x8a: PERMIT2_PERMIT with the allow-revert flag still counts",
        "high", "UNLIMITED_AMOUNT UNTRUSTED_SPENDER", None,
        execute(bytes([0x80 | C_PERMIT2_PERMIT]), [permit_single_input(STRANGER, MAX160, 5000)])),
    "ur-deadline-variant-permit": (
        "execute(bytes,bytes[],uint256) with an unlimited permit to a stranger",
        "high", "UNLIMITED_AMOUNT UNTRUSTED_SPENDER", None,
        execute_deadline(bytes([C_PERMIT2_PERMIT]),
                         [permit_single_input(STRANGER, MAX160, 5000)], 1_900_000_000)),
    "ur-permit-batch-stranger": (
        "PERMIT2_PERMIT_BATCH: one unlimited and one bounded allowance to a stranger",
        "high", "UNLIMITED_AMOUNT UNTRUSTED_SPENDER", None,
        execute(bytes([C_PERMIT2_PERMIT_BATCH]),
                [permit_batch_input(STRANGER, [(0xa1, MAX160, 5000, 1), (0xa2, 5, 5000, 2)])])),
    "ur-permit-batch-trusted-with-revoke": (
        "PERMIT2_PERMIT_BATCH to the trusted router: one unlimited, one revoked",
        "review", "UNLIMITED_AMOUNT REVOCATION", None,
        execute(bytes([C_PERMIT2_PERMIT_BATCH]),
                [permit_batch_input(0x11, [(0xa1, MAX160, 5000, 1), (0xa2, 0, 5000, 2)])])),
    "ur-permit-batch-empty": (
        "PERMIT2_PERMIT_BATCH with no allowances grants nothing",
        "safe", "", None,
        execute(bytes([C_PERMIT2_PERMIT_BATCH]), [permit_batch_input(STRANGER, [])])),
    "ur-permit-in-sub-plan": (
        "an unlimited permit to a stranger inside EXECUTE_SUB_PLAN",
        "high", "UNLIMITED_AMOUNT UNTRUSTED_SPENDER", None,
        execute(bytes([C_V3_SWAP_EXACT_IN, C_SUB_PLAN]),
                [swap_input(),
                 plan(bytes([C_PERMIT2_PERMIT]), [permit_single_input(STRANGER, MAX160, 5000)])])),
    # ---- Universal Router spends: recipient judgment. Rules written first:
    # an account recipient not in `trusted` is High (UNTRUSTED_RECIPIENT);
    # address(1) and address(2) are never flagged; address(0)/address(3) are
    # ordinary accounts; an unreadable spend is "cannot vouch" (Review).
    "ur-transfer-stranger": (
        "router TRANSFER of the signer's tokens to a stranger",
        "high", "UNTRUSTED_RECIPIENT", None,
        execute(bytes([C_TRANSFER]), [spend3(a20(STRANGER))])),
    "ur-transfer-trusted": (
        "router TRANSFER to the trusted router: nothing to flag",
        "safe", "", None,
        execute(bytes([C_TRANSFER]), [spend3(a20(0x11))])),
    "ur-sweep-msg-sender": (
        "SWEEP to address(1) (MSG_SENDER): the signer gets it back",
        "safe", "", None,
        execute(bytes([C_SWEEP]), [spend3(ADDRESS_1)])),
    "ur-sweep-address-this": (
        "SWEEP to address(2) (ADDRESS_THIS): stays in the router",
        "safe", "", None,
        execute(bytes([C_SWEEP]), [spend3(ADDRESS_2)])),
    "ur-sweep-address-three": (
        "SWEEP to address(3): not special, an ordinary account nobody listed",
        "high", "UNTRUSTED_RECIPIENT", None,
        execute(bytes([C_SWEEP]), [spend3(ADDRESS_3)])),
    "ur-sweep-address-zero": (
        "SWEEP to address(0): not special either",
        "high", "UNTRUSTED_RECIPIENT", None,
        execute(bytes([C_SWEEP]), [spend3(bytes(20))])),
    "ur-permit2-transfer-from-stranger": (
        "PERMIT2_TRANSFER_FROM pulling the signer's tokens to a stranger",
        "high", "UNTRUSTED_RECIPIENT", None,
        execute(bytes([C_PERMIT2_TRANSFER_FROM]), [spend3(a20(STRANGER))])),
    "ur-pay-portion-stranger": (
        "PAY_PORTION to a stranger",
        "high", "UNTRUSTED_RECIPIENT", None,
        execute(bytes([C_PAY_PORTION]), [spend3(a20(STRANGER), 50)])),
    "ur-pay-portion-full-precision-stranger": (
        "PAY_PORTION_FULL_PRECISION to a stranger",
        "high", "UNTRUSTED_RECIPIENT", None,
        execute(bytes([C_PAY_PORTION_FULL_PRECISION]), [spend3(a20(STRANGER), 50)])),
    "ur-unwrap-weth-stranger": (
        "UNWRAP_WETH (recipient is word 0, not word 1) to a stranger",
        "high", "UNTRUSTED_RECIPIENT", None,
        execute(bytes([C_UNWRAP_WETH]), [unwrap_in(a20(STRANGER))])),
    "ur-unwrap-weth-trusted": (
        "UNWRAP_WETH to the trusted router",
        "safe", "", None,
        execute(bytes([C_UNWRAP_WETH]), [unwrap_in(a20(0x11))])),
    "ur-transfer-stranger-allow-revert-bit": (
        "command byte 0x85: TRANSFER with the allow-revert flag to a stranger still counts",
        "high", "UNTRUSTED_RECIPIENT", None,
        execute(bytes([0x80 | C_TRANSFER]), [spend3(a20(STRANGER))])),
    "ur-transfer-in-sub-plan": (
        "a TRANSFER to a stranger inside EXECUTE_SUB_PLAN",
        "high", "UNTRUSTED_RECIPIENT", None,
        execute(bytes([C_SUB_PLAN]), [plan(bytes([C_TRANSFER]), [spend3(a20(STRANGER))])])),
    "ur-permit-then-sweep-to-stranger": (
        "a bounded permit to the trusted router (no flags) followed by a SWEEP to a stranger",
        "high", "UNTRUSTED_RECIPIENT", None,
        execute(bytes([C_PERMIT2_PERMIT, C_SWEEP]),
                [permit_single_input(0x11, 1000, 5000), spend3(a20(STRANGER))])),
    "ur-spend-dirty-recipient": (
        "TRANSFER whose recipient word has non-zero padding: unreadable, cannot vouch",
        "review", "", None,
        execute(bytes([C_TRANSFER]), [patched(spend3(a20(STRANGER)), 32, b"\x01")])),
    "ur-spend-truncated-input": (
        "TRANSFER whose input is only 64 bytes: the third word is missing, cannot vouch",
        "review", "", None,
        execute(bytes([C_TRANSFER]), [spend3(a20(0x11))[:64]])),
    "ur-spend-extra-bytes": (
        "SWEEP to the trusted router plus 5 bytes after its static words",
        "review", "TRAILING_DATA", None,
        execute(bytes([C_SWEEP]), [spend3(a20(0x11)) + b"\xcd" * 5])),
    "ur-transfer-from-batch-not-judged": (
        "KNOWN GAP: PERMIT2_TRANSFER_FROM_BATCH is not decoded yet, so it is only Review",
        "review", "", None,
        execute(bytes([C_PERMIT2_TRANSFER_FROM_BATCH]), [spend3(a20(STRANGER))])),
    "ur-v3-swap-to-stranger-not-judged": (
        "KNOWN GAP: a V3 swap paying a stranger is not judged (swap recipients are word 0 "
        "but unread), so it is only Review. If swaps get judged this case must flip to high",
        "review", "", None,
        execute(bytes([C_V3_SWAP_EXACT_IN]), [v3_swap_input(a20(STRANGER))])),
    "ur-unassigned-command-0x16": (
        "0x16 is a placeholder in the dispatcher followed (no APPROVE_ERC20): cannot vouch",
        "review", "", None, execute(bytes([0x16]), [bytes(32)])),
    "ur-dirty-permit-amount": (
        "PERMIT2_PERMIT whose uint160 amount has bits above 160: permit unreadable, cannot vouch",
        "review", "", None,
        execute(bytes([C_PERMIT2_PERMIT]),
                [permit_single_input(STRANGER, MAX256, 5000)])),
    "ur-trailing-bytes": (
        "bounded permit to the trusted router plus bytes the EVM ignores after the plan",
        "review", "TRAILING_DATA", None, _ur_plain + b"\xcd" * 9),
    "ur-inside-aggregate3": (
        "Multicall3 aggregate3 carrying a router execute with an unlimited permit to a stranger",
        "high", "UNLIMITED_AMOUNT UNTRUSTED_SPENDER", None,
        aggregate3([(0xa6, False, execute(bytes([C_PERMIT2_PERMIT]),
                                          [permit_single_input(STRANGER, MAX160, 5000)]))])),
    "ur-length-mismatch": (
        "two command bytes but one input: the router reverts with LengthMismatch",
        "undecodable", None, "LengthMismatch",
        execute(bytes([C_PERMIT2_PERMIT, C_PERMIT2_PERMIT]),
                [permit_single_input(STRANGER, MAX160, 5000)])),
    "ur-inputs-before-commands": (
        "plan whose inputs array precedes the commands bytes: non-canonical order",
        "undecodable", None, "BadOffset",
        sel("execute(bytes,bytes[])")
        + word(64 + len(encode(("array", ("bytes",)), [b"\x01"]))) + word(64)
        + encode(("array", ("bytes",)), [b"\x01"]) + encode(("bytes",), bytes([0x08]))),
    "ur-truncated": (
        "router plan whose last input lost part of its zero padding",
        "undecodable", None, "Truncated",
        execute(bytes([C_V3_SWAP_EXACT_IN]), [swap_input()])[:-5]),
    "ur-cut-inside-an-input": (
        "router plan cut off inside the data of its last input: the length no longer fits",
        "undecodable", None, "BadElementLength", _ur_plain[:-40]),
    "ur-execute-signed-selector": (
        "executeSigned exists in the router but is not decoded here: cannot vouch",
        "undecodable", None, "UnknownSelector",
        sel("executeSigned(bytes,bytes[],bytes32,bytes32,bool,bytes32,bytes,uint256)") + bytes(256)),
    "unknown-selector-top-level": (
        "a selector this crate does not know: cannot vouch",
        "undecodable", None, "UnknownSelector", bytes.fromhex("deadbeef") + word(1)),
}


def render(name, note, expect, flags, error, data) -> str:
    lines = [
        "source: synthetic",
        f"note: {note}",
        f"expect: {expect}",
    ]
    if flags is not None:
        lines.append(f"flags: {flags}".rstrip())
    if error is not None:
        lines.append(f"error: {error}")
    lines.append("trusted: 0x" + TRUSTED.hex())
    lines.append("calldata: 0x" + data.hex())
    return "\n".join(lines) + "\n"


def main():
    os.makedirs(OUT, exist_ok=True)
    for name, (note, expect, flags, error, data) in CASES.items():
        path = os.path.join(OUT, f"synthetic-{name}.case")
        with open(path, "w") as fh:
            fh.write(render(name, note, expect, flags, error, data))
    print(f"wrote {len(CASES)} cases to corpus/")


if __name__ == "__main__":
    main()
