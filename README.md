# bytecode-sentinel

A `no_std`, zero-dependency, zero-allocation Rust toolkit for answering two
questions *before* you sign or call something on an EVM chain:

1. **Bytecode**: what instructions does this contract really contain?
2. **Calldata**: what authorization does this transaction grant, and to whom?

Status: **v0.6.0.** Core pieces work and are heavily tested on synthetic
input. Universal Router plans are judged for permits (grants) and for the
recipient of the simple spends. Not yet validated against any real on-chain
data (see [Verification status](#verification-status)).

## What it is, and what it is not

It reports **facts about the instruction stream and about the authorization
in the calldata**, plus one opinionated summary (`Severity`). It does **not**
decide whether a contract is "malicious". `DELEGATECALL` is normal in a proxy;
an unlimited approval to a router you chose is normal.

Most wallet drainers are not visible in bytecode at all. They are
authorizations (`approve`, `permit`, `setApprovalForAll`, EIP-712 signatures)
sent to a legitimate-looking contract. That is why the calldata half exists.

## Quick start

```sh
cargo test                                   # 232 unit + 2 corpus + 9 judge_json + 17 randomized + 1 doctest (builds the examples and the binary)
cargo clippy --all-targets                   # clean
cargo run --example scan_hex -- 0x<bytecode> -d      # disassemble + census + selectors
cargo run --example check_calldata -- 0x<calldata> [trusted-address ...]   # single call, multicall, Multicall3 or Universal Router execute
cargo run --bin judge_json -- [--trust 0x<addr>]... [--trusted-file PATH] < calldata.txt   # JSON filter, see below
python3 -I tools/verify_selectors.py         # independent selector check
python3 -I tools/verify_commands.py Commands.sol Dispatcher.sol   # router command table vs the router's own source
```

`check_calldata` exit codes: `0` Safe, `1` Review, `2` High, `3` could not
decode (**never** a safe verdict), `4` bad command-line input.

### `judge_json`: the check as a filter for other programs

Reads calldata hex on stdin, one transaction per line, and writes one JSON
object per line on stdout. A wallet or an agent keeps the process open: write
a line, read a line.

```text
$ printf '%s\n' 0x095ea7b3...ffff | judge_json --trust 0xa1a1...a1a1
{"line":1,"verdict":"review","allow":false,"severity":"Review","flags":["UNLIMITED_AMOUNT"],"reasons":["unlimited amount"],"inspected":1,"unknown":0,"malformed":0,"hidden_bytes":0}
```

- `verdict` is `safe`, `review`, `high`, `undecodable` or `bad_input`.
  **`allow` is `true` only for `safe`**, so a caller that reads `allow` alone
  fails closed. Undecodable and bad input are never allowed.
- The trusted list comes from `--trust` / `--trusted-file` (one address per
  line, `#` comments), **never from the input line**; text after the hex is
  `bad_input`. Whoever can write the calldata must not be able to extend the
  list: keep the file out of the agent's reach.
- Blank lines are skipped; `line` counts every input line from 1. A bad line
  does not stop the stream. A line over 2 MiB, or input that is not UTF-8,
  yields one `bad_input` and ends the run (the next line boundary is unknown).
  A closed output pipe ends the run with status 4.
- Exit status is the worst line: `0` all safe (or no input), `1` review,
  `2` high, `3` undecodable, `4` bad input or bad command line.
- No HTTP server on purpose: a pipe or a Unix socket wrapper (`socat`,
  systemd socket activation) adds no code that could be attacked. Build the
  server later if a real caller needs it.

```rust
use bytecode_sentinel::{assess, decode, Address, Context, Severity};

let trusted = [Address([0x11; 20])];
match decode(&calldata) {
    Ok(decoded) => {
        let verdict = assess(&decoded, &Context::new(&trusted));
        if verdict.severity == Severity::High { /* block or warn */ }
    }
    // Cannot vouch for it: warn the user, never treat as safe.
    Err(_) => {}
}
```

## Layout

One responsibility per module. Each module depends only on modules listed
before it in its own half.

| Half | Module | Responsibility | Key items |
|---|---|---|---|
| Bytecode | `opcode` | Opcode constants, immediate sizes, mnemonics | `imm_len`, `Op` (Display) |
| Bytecode | `jumpdest` | Valid `JUMPDEST` bitmap into a caller buffer | `JumpdestMap::build`, `words_needed` |
| Bytecode | `disasm` | Lazy instruction iterator, PUSH data kept out of opcodes | `disassemble`, `Instruction` |
| Bytecode | `scan` | Dangerous-opcode census, dispatcher selector extraction | `scan`, `Report`, `extract_selectors` |
| Calldata | `abi` | Strict reading of static ABI words | `Address`, `Word`, `Args`, `DecodeError` |
| Calldata | `dynabi` | Strict, offset-based readers for `bytes`, `bytes[]` and `(static.., bytes)[]` (validate once, then infallible) | `DynBytes`, `BytesArray`, `TupleArray`, `Field`, `Entry` |
| Calldata | `calldata` | Selector to typed `Call` (decoding only, no judgement) | `decode`, `Call`, `Decoded`, `SEL_*` |
| Calldata | `multicall` | Selector to batch (`multicall` and Multicall3 `aggregate*`); fixed-depth walk over nested inner calls | `decode_multicall`, `calls`, `Calls`, `InnerCall`, `Items`, `MAX_DEPTH` |
| Calldata | `router` | Universal Router `execute`: plan reader (`commands` + `inputs`), command table and classification, strict readers for the two Permit2 permit commands and for the recipient of the simple spends, walk into `EXECUTE_SUB_PLAN` | `decode_execute`, `commands`, `Plan`, `Kind`, `kind_of`, `decode_permit_single`, `decode_permit_batch`, `PermitDetails::to_call`, `decode_spend`, `Recipient`, `Spend` |
| Calldata | `risk` | Judges a decoded call or a spend recipient, nothing else | `assess`, `assess_recipient`, `Flags`, `Severity`, `Context` |
| Calldata | `batch` | The only module that composes the others: walk, decode, judge, combine | `assess_calldata`, `BatchAssessment` |
| Tool | `src/bin/judge_json.rs` | Thin stdin/stdout JSON filter over `assess_calldata`; no judging of its own | `judge_json` binary |

Other files: `tests/robustness.rs` (randomized + differential tests, with its own naive reference parser and encoder),
`examples/` (two CLIs, shared `examples/common/hex.rs`), `tests/judge_json.rs` (runs every corpus case through the real binary),
`tools/verify_selectors.py` (selector verification),
`tools/verify_commands.py` (router command table vs `Commands.sol`/`Dispatcher.sol`),
`corpus/` + `tests/corpus.rs` (verdicts a human wrote down, checked against the crate; see `corpus/README.md`),
`tools/gen_synthetic_corpus.py` (writes the synthetic seed cases using the independent Keccak).

## Behavior reference

### Decoded calls and selectors

All verified with `tools/verify_selectors.py` (independent Keccak-256).

| Signature | Selector |
|---|---|
| `transfer(address,uint256)` | `a9059cbb` |
| `transferFrom(address,address,uint256)` | `23b872dd` |
| `approve(address,uint256)` | `095ea7b3` |
| `increaseAllowance(address,uint256)` | `39509351` |
| `setApprovalForAll(address,bool)` | `a22cb465` |
| EIP-2612 `permit(address,address,uint256,uint256,uint8,bytes32,bytes32)` | `d505accf` |
| DAI-style `permit(address,address,uint256,uint256,bool,uint8,bytes32,bytes32)` | `8fcbaf0c` |
| Permit2 `approve(address,address,uint160,uint48)` | `87517c45` |
| `multicall(bytes[])` | `ac9650d8` |
| `multicall(uint256,bytes[])` | `5ae401dc` |
| `multicall(bytes32,bytes[])` | `1f0464d1` |
| Multicall3 `aggregate((address,bytes)[])` | `252dba42` |
| Multicall3 `tryAggregate(bool,(address,bytes)[])` | `bce38bd7` |
| Multicall3 `blockAndAggregate((address,bytes)[])` | `c3077fa9` |
| Multicall3 `tryBlockAndAggregate(bool,(address,bytes)[])` | `399542e9` |
| Multicall3 `aggregate3((address,bool,bytes)[])` | `82ad56cb` |
| Multicall3 `aggregate3Value((address,bool,uint256,bytes)[])` | `174dea71` |
| Universal Router `execute(bytes,bytes[])` | `24856bc3` |
| Universal Router `execute(bytes,bytes[],uint256)` | `3593564c` |

`executeSigned(bytes,bytes[],bytes32,bytes32,bool,bytes32,bytes,uint256)` (`44684dc3`) exists in the router and is **not** decoded: it comes back as `UnknownSelector`.

### Risk flags

| Flag | Meaning |
|---|---|
| `UNLIMITED_AMOUNT` | Amount is at least half the type's range (see decisions below) |
| `UNTRUSTED_SPENDER` | Spender/operator not in the caller's trusted list |
| `BLANKET_APPROVAL` | `setApprovalForAll(.., true)` |
| `NO_EXPIRY` | Permit deadline at least half range; DAI expiry `0`; Permit2 expiration at least half of `uint48` |
| `REVOCATION` | Zero amount, `false`, or DAI `allowed == false` |
| `TRAILING_DATA` | Bytes after the arguments (the EVM ignores them) |
| `UNTRUSTED_RECIPIENT` | A router spend (`TRANSFER`, `SWEEP`, ...) pays an account that is not in the caller's trusted list and is not one of the router's two special values |

Severity: **Safe** if nothing other than `REVOCATION` is set; **High** if
`UNTRUSTED_SPENDER` and (`UNLIMITED_AMOUNT` or `BLANKET_APPROVAL`), or if
`UNTRUSTED_RECIPIENT` is set (on its own: it is not a grant, the tokens
leave); **Review** for everything else. `transfer` and `transferFrom` carry no
authorization flags (only possibly `TRAILING_DATA`).

### Batches (`multicall` and Multicall3)

`assess_calldata` accepts either one supported call or a batch (any of the
nine selectors above), walks
every inner call (descending into nested batches up to `MAX_DEPTH` = 4
levels, outermost included), decodes each with `decode` and judges it with
`assess`. Combination rules:

- `flags` is the **union** of the inner flags (for display).
- `severity` is the **maximum** of the per-call severities. It is never
  derived from the union: an untrusted spender in one call plus an unlimited
  amount in another is not a High grant to one party.
- An inner call that cannot be decoded is not judged. It is counted in
  `unknown` (selector not known, e.g. a router swap) or `malformed` (known
  selector, bad arguments) and raises the floor to `Review`.
- Bytes the EVM ignores (gaps inside a batch, trailing bytes) set
  `TRAILING_DATA`, are counted in `hidden_bytes`, and raise the floor to
  `Review`.
- A batch that cannot be read completely is an `Err`, never a verdict.
  Strict layout rules (see `dynabi`): offsets and lengths must fit in 64
  bits and point inside the data, array and element offsets must be
  multiples of 32, the array may not point into the head, elements may not
  overlap or alias, padding must be present and zero.
- Multicall3 tuples follow the same rules *inside* each tuple: the `bytes`
  offset is relative to the tuple, aligned, and may not point into the
  tuple's own head; the tuple's static fields must be canonical (address
  padding zero, `allowFailure` and `requireSuccess` exactly 0 or 1); the next
  tuple may not start before the previous tuple's `bytes` ends. Gaps inside a
  tuple count as hidden bytes like any other gap.
- Each leaf reports the `target` it is sent to and the `value` it carries
  when the signature has them (`InnerCall::target`, `InnerCall::value`). They
  are **facts for display, not judged**: the verdict depends only on the inner
  calldata. A `value` sent to an unknown contract is not flagged.

### Universal Router (`execute`)

`assess_calldata` also accepts `execute(bytes commands, bytes[] inputs
[, uint256 deadline])`. A *plan* is one command byte per command plus one
`bytes` input per command. Bit 7 of a command byte is the allow-revert flag
and bits 0..=6 are the type (`FLAG_ALLOW_REVERT = 0x80`,
`COMMAND_TYPE_MASK = 0x7f`).

**Sources this follows** (`Uniswap/universal-router` `main` as of
2026-10-25; the project owner's copies of `Commands.sol` and `Dispatcher.sol`
were byte-identical to `main`, and their SHA-256 were re-checked against the
table on 2026-10-27: `Commands.sol` `688122af…ead0b3` and `Dispatcher.sol`
`4d22b791…7937f2` both match, and `tools/verify_commands.py` reports the
command table identical). The files carry no version number, so the version is
"main on that date", not a release tag.

| File | SHA-256 | Used for |
|---|---|---|
| `contracts/libraries/Commands.sol` | `688122af…ead0b3` | command values, flag and mask |
| `contracts/base/Dispatcher.sol` | `4d22b791…7937f2` | which commands exist, each input layout |
| `contracts/UniversalRouter.sol` | `68b206fe…749251` | entry points, `LengthMismatch`, allow-revert handling |
| `contracts/interfaces/IUniversalRouter.sol` | `2555fe57…b6c076` | exact `execute`/`executeSigned` signatures |
| Permit2 `src/interfaces/IAllowanceTransfer.sol` (`main`) | `a31c712c…b87` | `PermitDetails` = `(token, amount uint160, expiration uint48, nonce uint48)` |
| `contracts/modules/uniswap/v3/BytesLib.sol` | `60077f3f…f2d` | `decodeCommandsAndInputs` = `abi.decode(bytes, bytes[])` |
| `v4-periphery` `CalldataDecoder.sol` at the commit the router pins (`a7af5b3`) | `93ee8bc3…2ed3` | that decoder accepts only the canonical layout |
| `v4-periphery` `ActionConstants.sol` (`main`) | `8e88393d…ec79` | `MSG_SENDER = address(1)`, `ADDRESS_THIS = address(2)` (read, not used yet) |

Facts taken from them: the `execute` with a deadline calls the plain one;
`execute` reverts with `LengthMismatch` unless there are as many inputs as
command bytes; a command whose flag bit is clear reverts the whole call if it
fails; a command value with no handler reverts with `InvalidCommandType`;
**this version has no `APPROVE_ERC20`** (`0x16` is a placeholder);
`PERMIT2_PERMIT`'s input is `abi.encode(PermitSingle, bytes)` and
`PERMIT2_PERMIT_BATCH`'s is `abi.encode(PermitBatch, bytes)`, both with the
caller (`msgSender()`, "the initiator of the lock") as the Permit2 owner;
`EXECUTE_SUB_PLAN`'s input is `abi.encode(bytes, bytes[])`.

Layouts of the simple spends, read from `Dispatcher.sol` (each branch does
`calldataload` at fixed offsets, then `map(recipient)`):

| Command | `abi.decode` of the input | Recipient |
|---|---|---|
| `PERMIT2_TRANSFER_FROM` (`0x02`), `SWEEP` (`0x04`), `TRANSFER` (`0x05`), `PAY_PORTION` (`0x06`), `PAY_PORTION_FULL_PRECISION` (`0x07`) | `(address token, address recipient, uint256 amount)` | word 1 |
| `UNWRAP_WETH` (`0x0c`) | `(address recipient, uint256 amountMin)` | word 0 |

`map` turns `address(1)` into the signer and `address(2)` into the router
itself and leaves every other value alone. The dispatcher reads these inputs
with `calldataload` and checks neither their length nor the padding of the
address word; this crate does both and calls the result "cannot vouch".

What is judged:

- **`PERMIT2_PERMIT` and `PERMIT2_PERMIT_BATCH`** (the grants). Each allowance
  becomes the same `Call::Permit2Approve` a direct Permit2 `approve` decodes
  to and goes through `assess` with no new rules: unlimited = amount at least
  2^159, no expiry = expiration at least 2^47, untrusted spender, revocation
  = amount 0.
- **The simple spends** (`PERMIT2_TRANSFER_FROM`, `SWEEP`, `TRANSFER`,
  `PAY_PORTION`, `PAY_PORTION_FULL_PRECISION`, `UNWRAP_WETH`): only the
  **recipient** is judged, by `risk::assess_recipient`. `address(1)` and
  `address(2)` are never flagged; any other account that is not in the trusted
  list is `UNTRUSTED_RECIPIENT`, which is `High`. The token and the amount are
  not judged. An unreadable spend (short input, dirty recipient word) is
  `malformed`: counted, never judged, floor `Review`. Bytes after the static
  words are counted as hidden.
- **Every other command is not judged**, counted in `unknown`, and raises the
  floor to `Review`: swaps (**including the recipient of a swap**, see Known
  limitations), `WRAP_ETH`, `PERMIT2_TRANSFER_FROM_BATCH`, position-manager
  calls, `ACROSS_V4_DEPOSIT_V3`, and any command value the dispatcher assigns
  to nothing. A typical swap therefore comes out `Review`.
- **`EXECUTE_SUB_PLAN`** is entered (same reader, depth limit `router::MAX_DEPTH`
  = 4 plans including the outermost) and its commands are judged like any
  other. A sub plan that cannot be read, or nesting that is too deep, is an `Err`.
- The allow-revert flag is reported (`Command::allow_revert`) and **not
  judged**: a permit with the flag set is judged exactly like one without.
- A permit input that cannot be read (dirty padding, bad offsets, truncated)
  is `malformed`: counted, never judged, floor `Review`.
- Layout rules are stricter than the router's: `commands` before `inputs`,
  aligned offsets, nothing pointing into a head, zero padding, canonical
  static words, and in a permit batch the struct, then the `details` array,
  then the signature. Gaps and trailing bytes are counted in `hidden_bytes`.
- An `execute` found inside a `multicall` or Multicall3 batch is judged the
  same way; if it cannot be read it counts as one `malformed` inner call.

## Design rules (keep these)

- No heap, no `unsafe` (`#![forbid(unsafe_code)]`), no dependencies. Output
  goes to caller-provided buffers or iterators.
- Hostile input never panics. Every index in library code is guarded; no
  `unwrap`, `expect` or `assert` outside tests.
- A decode **error is never a safe verdict**. Callers must treat it as
  "cannot vouch for this".
- Strict decoding: non-canonical padding is an error, never masked.
- Flags are facts; severity is one opinion derived from them. Keep them apart.
- Decoding (`calldata`) and judging (`risk`) never mix. `risk` takes a
  `Decoded`, never raw bytes.
- Offsets and lengths are never trusted: checked arithmetic, bounds against the
  actual data, and no overlapping regions (that is also what bounds the work).
- Never type a selector from memory. Verify with `tools/verify_selectors.py`.
- Every new module ships unit tests, and anything with a faster-than-obvious
  implementation also gets a differential test against a naive reference in
  `tests/robustness.rs`.

## Decisions already made

- **"Unlimited" = value at least 2^(bits-1)** of the type's own width, so a
  `uint160` Permit2 amount is judged by 160 bits, not 256. Chosen because the
  calldata alone cannot know token supply or decimals.
- **Trailing bytes are a flag, not an error.** Rejecting them would let an
  attacker disguise calldata by appending junk.
- **Dirty padding is an error.** Contracts differ on how they read it, so a
  scanner must not guess.
- **Trusted spenders come from the caller** (`Context`). The crate ships no
  allowlist.
- **`transfer`/`transferFrom` are not judged**: that needs balances and
  intent, which the calldata does not carry.
- **Overlapping or aliased `bytes[]` elements are an error**, not a flag. They
  have no legitimate use in canonical encodings and are the standard way to
  amplify work or confuse a scanner. Gaps between regions are only counted
  (`slack`), because some encoders leave them.
- **Missing padding after the last element is an error** (`Truncated`), even
  though the Solidity decoder may tolerate it. The safe direction is "cannot
  vouch".
- **Unaligned offsets are an error** (`BadOffset`, `BadElementOffset`).
  Canonical encoders always emit multiples of 32, but the Solidity decoder
  also accepts other values. Accepting them here would let an attacker place
  data where this parser and the contract read it differently, so the safe
  direction is "cannot vouch". Test encoders that add gaps or head padding
  must therefore use multiples of 32; the unaligned cases live in the
  `dynabi` unit tests.
- **Nested batches deeper than `MAX_DEPTH` are an error**, not skipped.
- **Batch severity is the max of the per-call severities**, with a `Review`
  floor for anything undecoded or hidden. Router swaps inside a batch will
  therefore normally yield `Review`.
- **Revocations are good news** and suppress the other flags for that call.
- **Inner calls of Multicall3 are judged as if the signer had sent them.**
  Multicall3 really makes the call itself (or, under a smart wallet's
  `delegatecall`, the wallet does), so an `approve` inside `aggregate3` may
  not be an approval *from the signer*. Judging it anyway is the safe
  direction: the signer is told about it and can decide.
- **A bad static tuple field is an error**, like dirty padding anywhere else:
  `allowFailure = 2` or a target with non-zero upper bytes is not read
  leniently.
- **Multicall3 return-value layouts are not read**, only the call side.
- **Router permits are judged as the caller's own grant.** The router passes
  `msgSender()` as the Permit2 owner, so a permit in a plan is a grant *from
  whoever sends the plan*. Judged through the existing Permit2 rules.
- **In a router plan, grants are judged in full and the simple spends only by
  their recipient.** The amount of a spend needs balances and intent, which the
  calldata does not carry, so it is not judged (consistent with
  `transfer`/`transferFrom` above). The recipient needs only the trusted list.
- **An untrusted recipient is `High` on its own.** A spend is not a grant, so
  the spender-and-breadth rule does not apply; the tokens simply leave. The
  cost is that an honest plan paying the signer's *own* address (instead of
  `MSG_SENDER`) or a fee address is `High` unless the caller lists those as
  trusted. That is the safe direction, but it will show up as false positives
  in real traffic.
- **Exactly two recipient values are special**: `address(1)` and `address(2)`.
  `address(0)` and `address(3)` are ordinary accounts and are judged.
- **A command value the dispatcher assigns to nothing is "cannot vouch", not
  an error and not safe.** It reverts in the router followed here, but a router
  of another version may give it a meaning.
- **The number of commands must equal the number of inputs**, as in
  `UniversalRouter.execute`; otherwise `DecodeError::LengthMismatch`.
- **`commands` must precede `inputs`; a permit batch must be struct, details,
  signature.** Solidity's decoder accepts other orders; the safe direction is
  "cannot vouch".
- **`executeSigned` is not decoded.** Its signed-route context (`RouteSigner`,
  `verifySender`, `intent`) has not been read, so no claim is made about whose
  grant a permit inside it would be.

## Verification status

Verified in this environment for **0.6.0** (Rust 1.97.0, Linux, 2026-10-27):

- 261 tests pass in debug and release (`cargo test`, `cargo test --release`):
  232 unit, 2 corpus, 9 `judge_json` end-to-end, 17 randomized, 1 doctest. `cargo fmt --check`,
  `cargo clippy --all-targets -- -D warnings` and
  `RUSTDOCFLAGS="-D warnings" cargo doc --no-deps` are clean. Always run the
  *plain* `cargo test` and `clippy --all-targets`: `--lib` and `--test` do not
  build `examples/`, and the 0.5.1 archive had examples that did not compile
  (they called functions that had been removed) while every `--lib` and
  `--test` run was green.
- **Not re-run on Rust 1.75** for 0.5.2 (the toolchain is not installed in this
  session). 0.5.0 was checked on 1.75.0 (Ubuntu 24 packages); nothing newer
  than 1.75 was knowingly used since, but that is unverified.
- Router spend recipients (0.5.2): 21 deliberate bugs in `router`, `risk` and
  `batch` (recipient read from the wrong word, wrong minimum length, a special
  value not special or everything special, extra bytes not counted, dirty
  padding accepted, a command kind not classified, trusted list ignored or
  inverted, untrusted recipient only `Review`, special values flagged, hidden
  bytes / unreadable spend / severity / flags dropped in `batch`, the recipient
  never judged) were run one at a time in an isolated copy.
  All 21 were caught by at least three tests each; none survived and none
  had to be written off as equivalent. (The harness is a scratch script, not
  part of the crate.)
- `judge_json` (0.6.0): 16 deliberate bugs (review/high/undecodable/bad input
  allowed, exit status best instead of worst, blank lines judged, size limit
  off, line numbers off by one, flags not listed, `--trust` ignored, trusted
  file comments not stripped, unknown argument ignored, oversized line not
  ending the run, closed output pipe ignored, quote not escaped, hex errors
  with the wrong status) were run one at a time in an isolated copy. 14 were
  caught at once; the closed-pipe one **survived** until
  `a_closed_output_pipe_stops_the_run_with_status_4` was added, and one
  mutant's pattern was wrong and was rerun. All 16 are now caught. It has
  never been connected to a real agent or run against real traffic.
- The corpus currently holds 71 *synthetic* cases and 0 real transactions
  (52 from 0.5.1 plus 19 for router spends). One older case,
  `ur-permit-hidden-between-swaps`, used command `0x04` as "a swap this crate
  does not judge"; `0x04` is `SWEEP`, which is now judged, so it uses `0x08`
  (`V2_SWAP_EXACT_IN`) instead. It is the only older case whose bytes changed.
  Two of the 19 new cases (`ur-transfer-from-batch-not-judged`,
  `ur-v3-swap-to-stranger-not-judged`) are marked `KNOWN GAP` in their notes:
  they record what the crate does *not* judge yet and must flip when it does.
  It checks that the crate agrees with an independent encoder and with
  hand-written expectations; it says nothing yet about real-world traffic.
  The 13 Multicall3 cases were encoded by a generic head/tail ABI encoder in
  `tools/gen_synthetic_corpus.py` that shares nothing with the crate, and
  their verdicts were written before the crate was run on them. The 22
  Universal Router cases were encoded the same way (the generic encoder was
  fixed to size static tuples inline) and their verdicts were also written
  first. Running them found two errors **in the generator's side** and none in
  the crate: the encoder had assumed every static member is one word (it laid
  out `PermitSingle` wrongly, and the crate correctly refused it), and one
  expectation (`Truncated` for a cut that actually damages the data, which is
  `BadElementLength`). The 30 older cases are byte-identical to 0.4.0's.
- Randomized tests (fixed seeds) cover: no panics on arbitrary bytes; JUMPDEST
  map, opcode census and selector extraction each agree with an independent
  naive reference; structural invariants of `assess`; and, for batches,
  `BytesArray` and the nested walk agree with a naive reference (absolute
  coordinates, u128 arithmetic, a coverage map, recursion) on well-formed,
  gappy and corrupted inputs, including the exact slack and hidden-byte
  counts; leaves are always non-overlapping sub-slices of the input;
  `assess_calldata` equals the documented per-call composition, never masks a
  High call, and never calls undecodable or hidden data Safe. For the router:
  the plan walk (including nested sub plans, the depth limit, gaps and
  trailing bytes at every level) and both permit decoders agree with naive
  references on well-formed, gappy and corrupted inputs, `assess_calldata` on
  a plan equals the per-command composition, and nothing panics on arbitrary
  bytes.
- Universal Router mutation check (0.5.0): 35 deliberate bugs in `DynBytes`,
  `router` and `batch` (offset into the head or unaligned, gaps or trailing
  bytes not counted at each region, inputs allowed to overlap commands, length
  mismatch allowed, permit and batch kinds swapped, flag bit not masked, depth
  limit off by one, sub plans not entered or their hidden bytes dropped,
  expiration and nonce swapped, a width unchecked, tuple stride wrong, wrong
  spender, only the first allowance judged, floor removed, severity not
  maximised, unreadable inner `execute` swallowed, ...) were each run against
  the tests. All 35 are caught. Two (a gap before the `PermitBatch` struct,
  and permit-batch hidden bytes in `batch`) were first caught only by the
  randomized tests, so they got unit tests and are now caught by those too. One
  mutation run was invalidated (the process was killed mid-mutation and left
  the copy mutated) and redone from a clean copy.
- `tools/verify_commands.py` against the uploaded files: 22 commands identical,
  every one used by `Dispatcher.sol`. Negative controls (a wrong value, a
  missing constant, a wrong mask) are each reported as a mismatch.
- Mutation check (0.3.x): the four earlier deliberate bugs plus 17 new ones in
  `dynabi`, `multicall` and `batch` (overlap check removed or weakened,
  padding unchecked, array may point into the head, slack or hidden bytes not
  counted, depth limit off by one, wrong head index for the deadline variant,
  floors removed, severity from the union, errors swallowed, ...) were each
  caught by the tests.
- `cargo doc` warning-free. `cargo clippy --all-targets` has one warning on
  1.75, in `examples/common/hex.rs` (`format!` in an iterator); the library
  and tests are clean.
- Multicall3 (added in 0.4.0): 22 further deliberate bugs in the tuple reader
  and the batch walk (overlap check removed, member offset allowed into the
  tuple head or unaligned, static fields or `bool`s not validated, slack inside
  a tuple or between tuples not counted, tuple head bounds unchecked, wrong
  field used for target or value, wrong schema for `aggregate3` or
  `aggregate3Value`, `requireSuccess` unvalidated or read from the wrong slot,
  a selector missing from `is_multicall`, nested slack not added, depth limit
  off by one, ...) were run one at a time. 19 were caught at once, 1 only
  differed in which error variant is returned and got a unit test that now
  catches it, and 2 are equivalent (an unreachable branch in `Calls`, and a
  `has_value` flag that `Entry::field` already bounds).
- Re-run on Rust 1.97 (2026-10-25, 0.4.0): `cargo test`, `cargo test --release`,
  `cargo clippy --all-targets -- -D warnings`, `cargo fmt --check` and
  `RUSTDOCFLAGS="-D warnings" cargo doc` all pass. Not re-run on 1.75 (the
  toolchain still cannot be installed here); nothing newer than 1.75 was used
  knowingly, but that is unverified.
- Earlier re-run on Rust 1.97 (2026-10-12): `cargo test`, `cargo test --release` and
  `cargo clippy --all-targets -- -D warnings` all pass. Not re-run on 1.75
  (that toolchain could not be installed in that environment); the changes
  made for it use only APIs that exist on 1.75 (`Vec::resize`, `%`).
- Two std APIs newer than 1.75 (`iter::repeat_n`, `usize::is_multiple_of`)
  were replaced by equivalents so the crate builds on 1.75. Earlier notes
  claimed Rust 1.97; that run was not repeated here.

**Not verified yet:**

- That the compiled router behaves as `Dispatcher.sol` reads: nothing here ran
  a real router. In particular how it treats an address word with dirty upper
  bits, or an input shorter than its layout (it reads past the input without a
  check), was not tested; the crate refuses both, so it does not depend on it.
- Which Universal Router **version** a given address runs. The command table
  and layouts follow `main` as of 2026-10-25. A router deployed earlier or on
  another chain may assign different meanings to command bytes or lay inputs
  out differently; the crate cannot know, and the verdict is only as good as
  the match. Check the router's own source for the deployment you care about
  (`tools/verify_commands.py` takes any `Commands.sol`).
- `executeSigned`, `RouteSigner.sol` and `Lock.sol` (who `msgSender()` is in
  each entry point) were not read.
- That a permit's signature or nonce is valid: a permit can still revert
  on-chain.
- `wasm32` build (not attempted this session).
- Any real on-chain bytecode or transaction. All inputs are still synthetic,
  including the batch encodings: the encoders in the tests follow the ABI
  specification as understood here, not output captured from a real router.
- Minimum supported Rust version below 1.75.
- `cargo-fuzz`, benchmarks, performance claims.

## Known limitations

- Selector extraction is a heuristic (`PUSH4 sel [DUPn] EQ`). It misses
  binary-search dispatchers (`GT`/`LT`) and Vyper variants.
- Calldata coverage is the eight functions above plus the three
  `multicall(bytes[])` signatures, the six Multicall3 signatures and the two
  Universal Router `execute` signatures (permits, and the recipient of the
  simple spends; see the section above).
  Not covered: Universal Router `executeSigned`, Safe `execTransaction` and
  MultiSend (packed encoding), `safeTransferFrom`, ERC-1155, ERC-4626. Swaps
  inside a batch or plan are reported as not judged.
- A malicious Universal Router plan does not need a permit. `PERMIT2_TRANSFER_FROM`,
  `TRANSFER`, `SWEEP`, `PAY_PORTION*` and `UNWRAP_WETH` with an attacker's
  recipient are `High`. **Not covered**, so a plan using them stays at best
  `Review`: the recipient of the swap commands (`V3_SWAP_EXACT_IN/OUT`,
  `V2_SWAP_EXACT_IN/OUT`: word 0 of the input, also passed through `map`),
  `WRAP_ETH` (word 0), the per-element recipients of
  `PERMIT2_TRANSFER_FROM_BATCH`, and everything inside `V4_SWAP` and the
  position-manager calls. The batch transfer's array layout has not been read
  from the source yet, and swap recipients need a rule for "the signer's own
  address", which the calldata cannot know.
- The Universal Router layouts and command table are tied to one version of
  the router source (see above).
- The Multicall3 and Universal Router encoders in the tests and in the corpus
  generator follow the ABI specification and the router source as understood
  here; no real Multicall3 or router transaction has been run through the
  crate yet.
- No EIP-712 typed-data (the off-chain signatures behind most real drainers).
- Static scan cannot see state-dependent behavior (blocklists, conditional
  honeypots) and does not resolve proxies. `DELEGATECALL` means the bytecode
  you see may not be the logic that runs.
- Trailing Solidity CBOR metadata is decoded as if it were instructions; it
  can surface as a spurious `truncated_push`.
- Half-range "unlimited" misses large-but-finite approvals (for example
  `2^128`), which many apps use.
- Permit2 `expiration == 0` (expires immediately) is not specially handled.

## Roadmap, in priority order

1. **Dynamic ABI + `multicall`/router decoding.** *Done for `bytes[]`
   multicall, Multicall3's tuple arrays and the Universal Router `execute`
   plan with its Permit2 permits and sub plans* (`dynabi`, `multicall`,
   `router`, `batch`). **Remaining, in this order:**
   (a) *done for the simple spends* (recipient judged against `MSG_SENDER`,
   `ADDRESS_THIS` and the trusted list). **Remaining:** the recipient of the
   swap commands and `WRAP_ETH` (word 0, layouts already visible in
   `Dispatcher.sol`; needs a decision first on how to treat the signer's own
   address, or honest swaps become `High`), and `PERMIT2_TRANSFER_FROM_BATCH`
   (`AllowanceTransferDetails[]`; read the struct from Permit2's
   `IAllowanceTransfer.sol` first);
   (b) `executeSigned`, after reading `RouteSigner.sol` and `Lock.sol`;
   (c) decoding common swap commands so they can be judged instead of counted;
   (d) **real router and Multicall3 transactions** to validate the encoders
   and the router version assumption before relying on any of this.
2. **EIP-712 typed data** for `Permit`, Permit2 `PermitSingle`/`PermitBatch`,
   and possibly Seaport orders. Decide the input format first: structured
   fields from the wallet, or a minimal allocation-free JSON scanner for
   `eth_signTypedData_v4`. Keep it in its own module; it reuses `risk`.
3. **Basic-block CFG** with PUSH-then-JUMP resolution and a small symbolic
   stack (arena or fixed arrays). Reuses `JumpdestMap`. Enables reachability
   of `SELFDESTRUCT` and whether a `DELEGATECALL` target is calldata-derived.
4. **Proxy awareness**: EIP-1167 minimal-proxy pattern detection in bytecode;
   EIP-1967 slot reads belong outside the core (needs RPC).
5. **Metadata-tail detection** so trailing CBOR is excluded from instructions.
6. **Real-world validation**: the harness exists (`corpus/`, `tests/corpus.rs`)
   and holds synthetic seeds only. **Next: add real transactions** (known
   drainers and benign router traffic) to measure false positives and
   negatives. Then:
   `cargo-fuzz` on all decoders; `wasm32` build and size check; benchmarks;
   MSRV; `#![deny(missing_docs)]`. (`LICENSE` exists; Cargo.toml says MIT.
   **`publish = true` is currently set**: switch it to `false` unless you
   mean to publish.)
7. **Optional**: connect to the zero-copy mmap state cache idea (cached chain
   state feeding the scanner), kept as a separate crate.

## Resuming in a new session

1. Unpack, then run `cargo test` (plain, so the examples are built). Expect 261 passing (232 + 2 + 9 + 17 + 1).
2. Read this file, then `src/risk.rs`, `src/calldata.rs` and `src/batch.rs`
   (the pattern every new module should follow).
3. Keep the design rules above. When adding a function selector, run
   `tools/verify_selectors.py` first.
4. Suggested opening prompt (Arabic):

   > اقرأ README.md في مشروع bytecode-sentinel وراجع الكود الحالي، ثم تابع
   > الجزء المتبقي من البند الأول من خارطة الطريق (مستلمو أوامر swap وWRAP_ETH
   > وPERMIT2_TRANSFER_FROM_BATCH في Universal Router، ثم executeSigned) أو انتقل
   > إلى البند الثاني (EIP-712)
   > بتأنٍّ، مع فصل المسؤوليات بين الوحدات واختبارات مقارنة مع تنفيذ مرجعي
   > ساذج. إن توفرت معاملات حقيقية (Multicall3 أو راوتر)، أضفها أولاً إلى
   > corpus/ بعد كتابة الحكم المتوقع قبل التشغيل. لا تكتب قيمة أمر أو تخطيط
   > مدخل من الذاكرة: اقرأ ملف الراوتر نفسه ثم شغّل tools/verify_commands.py. لا تنتقل للبند التالي قبل
   > نجاح الاختبارات و clippy.
