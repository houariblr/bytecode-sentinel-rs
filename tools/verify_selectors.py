#!/usr/bin/env python3
"""Verify 4-byte function selectors with an independent Keccak-256.

Why this exists: selectors in src/calldata.rs must never be typed from memory.
Python's hashlib.sha3_256 is NIST SHA-3 and gives DIFFERENT output from
Ethereum's Keccak-256 (different padding), so this file carries its own
implementation, self-tested against the known empty-input digest.

Usage: python3 -I tools/verify_selectors.py
Edit the `sigs` list at the bottom (the module is also importable:
tools/gen_synthetic_corpus.py uses its keccak256) to check new signatures, then copy the
printed 4 bytes into the code and into the README table.
"""
M = (1 << 64) - 1

def rol(x, n):
    n %= 64
    return ((x << n) | (x >> (64 - n))) & M if n else x

def rc_bit(t):
    if t % 255 == 0:
        return 1
    R = 1
    for _ in range(t % 255):
        R <<= 1
        if R & 0x100:
            R ^= 0x171
    return R & 1

RC = []
for ir in range(24):
    c = 0
    for j in range(7):
        if rc_bit(j + 7 * ir):
            c |= 1 << ((1 << j) - 1)
    RC.append(c)

ROT = [[0] * 5 for _ in range(5)]
x, y = 1, 0
for t in range(24):
    ROT[x][y] = ((t + 1) * (t + 2) // 2) % 64
    x, y = y, (2 * x + 3 * y) % 5

def f(A):
    for ir in range(24):
        C = [A[x][0] ^ A[x][1] ^ A[x][2] ^ A[x][3] ^ A[x][4] for x in range(5)]
        D = [C[(x - 1) % 5] ^ rol(C[(x + 1) % 5], 1) for x in range(5)]
        A = [[A[x][y] ^ D[x] for y in range(5)] for x in range(5)]
        B = [[0] * 5 for _ in range(5)]
        for x in range(5):
            for y in range(5):
                B[y][(2 * x + 3 * y) % 5] = rol(A[x][y], ROT[x][y])
        A = [[B[x][y] ^ (~B[(x + 1) % 5][y] & B[(x + 2) % 5][y]) & M for y in range(5)] for x in range(5)]
        A[0][0] ^= RC[ir]
    return A

def keccak256(data: bytes) -> bytes:
    rate = 136
    p = bytearray(data) + b"\x01"
    while len(p) % rate:
        p += b"\x00"
    p[-1] |= 0x80
    A = [[0] * 5 for _ in range(5)]
    for off in range(0, len(p), rate):
        blk = p[off:off + rate]
        for i in range(rate // 8):
            A[i % 5][i // 5] ^= int.from_bytes(blk[8 * i:8 * i + 8], "little")
        A = f(A)
    out = b""
    for i in range(4):
        out += A[i % 5][i // 5].to_bytes(8, "little")
    return out

# Self-test against the well-known empty-input digest.
assert keccak256(b"").hex() == "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470", "keccak self-test failed"

if __name__ == "__main__":
    sigs = [
        "transfer(address,uint256)",
        "transferFrom(address,address,uint256)",
        "approve(address,uint256)",
        "increaseAllowance(address,uint256)",
        "setApprovalForAll(address,bool)",
        "permit(address,address,uint256,uint256,uint8,bytes32,bytes32)",
        "permit(address,address,uint256,uint256,bool,uint8,bytes32,bytes32)",
        "approve(address,address,uint160,uint48)",
        "multicall(bytes[])",
        "multicall(uint256,bytes[])",
        "multicall(bytes32,bytes[])",
        # Multicall3
        "aggregate((address,bytes)[])",
        "tryAggregate(bool,(address,bytes)[])",
        "blockAndAggregate((address,bytes)[])",
        "tryBlockAndAggregate(bool,(address,bytes)[])",
        "aggregate3((address,bool,bytes)[])",
        "aggregate3Value((address,bool,uint256,bytes)[])",
        # Universal Router (signatures as in IUniversalRouter.sol)
        "execute(bytes,bytes[])",
        "execute(bytes,bytes[],uint256)",
        # present in the router but NOT decoded by this crate (see README)
        "executeSigned(bytes,bytes[],bytes32,bytes32,bool,bytes32,bytes,uint256)",
    ]
    print("keccak self-test OK")
    for s in sigs:
        print(keccak256(s.encode())[:4].hex(), s)
