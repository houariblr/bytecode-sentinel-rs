//! Randomized robustness and differential tests.
//!
//! Two goals:
//! 1. Hostile input never panics, whatever the bytes.
//! 2. Each fast implementation agrees with a deliberately naive reference
//!    written here, independently of the crate's own code paths.
//!
//! The generator is a fixed-seed xorshift, so every run is reproducible.

use bytecode_sentinel::calldata::{
    SEL_APPROVE, SEL_INCREASE_ALLOWANCE, SEL_PERMIT, SEL_PERMIT2_APPROVE, SEL_PERMIT_DAI,
    SEL_SET_APPROVAL_FOR_ALL, SEL_TRANSFER, SEL_TRANSFER_FROM,
};
use bytecode_sentinel::{
    assess, decode, disassemble, extract_selectors, scan, words_needed, Address, Call, Context,
    DecodeError, Flags, JumpdestMap, Severity,
};

// ---------------------------------------------------------------- generator

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
    fn byte(&mut self) -> u8 {
        (self.next() >> 32) as u8
    }
    fn chance(&mut self, percent: u64) -> bool {
        self.next() % 100 < percent
    }
}

/// Opcodes that matter to the scanner, so random code actually hits them.
const INTERESTING: [u8; 19] = [
    0x5b, 0x5b, 0x60, 0x61, 0x63, 0x7f, 0x14, 0x80, 0x81, 0xf4, 0xf2, 0xff, 0x32, 0xf0, 0xf5, 0xf1,
    0xfa, 0x55, 0x00,
];

fn gen_code(rng: &mut Rng) -> Vec<u8> {
    let target = rng.below(300);
    let mut code = Vec::with_capacity(target + 40);
    while code.len() < target {
        match rng.below(5) {
            // Dispatcher-style chunk: [DUP1] PUSH4 sel [DUPn] EQ.
            0 => {
                if rng.chance(50) {
                    code.push(0x80);
                }
                code.push(0x63);
                for _ in 0..4 {
                    code.push(rng.byte());
                }
                if rng.chance(30) {
                    code.push(0x80 + (rng.byte() % 16));
                }
                code.push(0x14);
            }
            // A few notable opcodes.
            1 => {
                for _ in 0..=rng.below(3) {
                    code.push(INTERESTING[rng.below(INTERESTING.len())]);
                }
            }
            // One fully random byte.
            2 => code.push(rng.byte()),
            // PUSHn whose immediate is full of JUMPDEST/opcode lookalikes.
            3 => {
                let n = 1 + rng.below(32);
                code.push(0x5f + n as u8);
                for _ in 0..n {
                    code.push(if rng.chance(70) {
                        INTERESTING[rng.below(INTERESTING.len())]
                    } else {
                        rng.byte()
                    });
                }
            }
            // Possibly truncated PUSH at an arbitrary spot.
            _ => code.push(0x60 + (rng.byte() % 32)),
        }
    }
    code
}

// ----------------------------------------------------- independent reference

fn ref_push_len(op: u8) -> usize {
    if (0x60..=0x7f).contains(&op) {
        usize::from(op - 0x5f)
    } else {
        0
    }
}

/// (pc, opcode) for every real instruction, walking the code by hand.
fn ref_walk(code: &[u8]) -> Vec<(usize, u8)> {
    let mut out = Vec::new();
    let mut pc = 0;
    while pc < code.len() {
        out.push((pc, code[pc]));
        pc += 1 + ref_push_len(code[pc]);
    }
    out
}

fn ref_selectors(code: &[u8]) -> Vec<[u8; 4]> {
    let mut out: Vec<[u8; 4]> = Vec::new();
    for (pc, op) in ref_walk(code) {
        // A full PUSH4 only.
        if op != 0x63 || pc + 5 > code.len() {
            continue;
        }
        let sel = [code[pc + 1], code[pc + 2], code[pc + 3], code[pc + 4]];
        let next = code.get(pc + 5).copied();
        let after = code.get(pc + 6).copied();
        let matched = match next {
            Some(0x14) => true,
            Some(0x80..=0x8f) => after == Some(0x14),
            _ => false,
        };
        if matched && !out.contains(&sel) {
            out.push(sel);
        }
    }
    out
}

// ------------------------------------------------------------ bytecode tests

const BYTECODE_ROUNDS: usize = 30_000;

#[test]
fn bytecode_apis_never_panic() {
    let mut rng = Rng(0x9e37_79b9_7f4a_7c15);
    for _ in 0..BYTECODE_ROUNDS {
        let code = gen_code(&mut rng);
        let _ = disassemble(&code).count();
        let _ = scan(&code);
        let mut words = vec![0u64; words_needed(code.len())];
        let map = JumpdestMap::build(&code, &mut words).unwrap();
        let _ = map.is_valid(rng.below(code.len() + 3));
        let mut sels = [[0u8; 4]; 8];
        let _ = extract_selectors(&code, &mut sels);
    }
}

#[test]
fn jumpdest_map_matches_naive_reference() {
    let mut rng = Rng(0x1234_5678_9abc_def1);
    for _ in 0..BYTECODE_ROUNDS {
        let code = gen_code(&mut rng);
        let expected: Vec<usize> = ref_walk(&code)
            .into_iter()
            .filter(|&(_, op)| op == 0x5b)
            .map(|(pc, _)| pc)
            .collect();

        let mut words = vec![0u64; words_needed(code.len())];
        let map = JumpdestMap::build(&code, &mut words).unwrap();

        assert_eq!(map.count(), expected.len());
        for pc in 0..code.len() + 3 {
            assert_eq!(
                map.is_valid(pc),
                expected.contains(&pc),
                "pc {pc} in {code:02x?}"
            );
        }
    }
}

#[test]
fn scan_counts_match_naive_reference() {
    let mut rng = Rng(0x0fed_cba9_8765_4321);
    for _ in 0..BYTECODE_ROUNDS {
        let code = gen_code(&mut rng);
        let walk = ref_walk(&code);
        let count = |op: u8| walk.iter().filter(|&&(_, o)| o == op).count() as u32;
        let truncated = walk
            .iter()
            .any(|&(pc, op)| pc + 1 + ref_push_len(op) > code.len());

        let r = scan(&code);
        assert_eq!(r.len, code.len());
        assert_eq!(r.instructions as usize, walk.len());
        assert_eq!(r.call, count(0xf1));
        assert_eq!(r.staticcall, count(0xfa));
        assert_eq!(r.delegatecall, count(0xf4));
        assert_eq!(r.callcode, count(0xf2));
        assert_eq!(r.selfdestruct, count(0xff));
        assert_eq!(r.origin, count(0x32));
        assert_eq!(r.create, count(0xf0));
        assert_eq!(r.create2, count(0xf5));
        assert_eq!(r.sstore, count(0x55));
        assert_eq!(r.truncated_push, truncated, "{code:02x?}");
    }
}

#[test]
fn selector_extraction_matches_naive_reference() {
    let mut rng = Rng(0x5eed_5eed_5eed_5eed);
    let mut total = 0usize;
    for _ in 0..BYTECODE_ROUNDS {
        let code = gen_code(&mut rng);
        let expected = ref_selectors(&code);
        total += expected.len();

        let mut out = vec![[0u8; 4]; 4096];
        let n = extract_selectors(&code, &mut out);
        assert_eq!(&out[..n], &expected[..], "{code:02x?}");
    }
    assert!(
        total > 1_000,
        "generator produced too few selectors: {total}"
    );
}

// ------------------------------------------------------------ calldata tests

#[derive(Clone, Copy)]
enum Kind {
    Addr,
    Uint,
    Bool,
    U160,
    U48,
    Sig,
}
use Kind::*;

const SPECS: [([u8; 4], &[Kind]); 8] = [
    (SEL_TRANSFER, &[Addr, Uint]),
    (SEL_TRANSFER_FROM, &[Addr, Addr, Uint]),
    (SEL_APPROVE, &[Addr, Uint]),
    (SEL_INCREASE_ALLOWANCE, &[Addr, Uint]),
    (SEL_SET_APPROVAL_FOR_ALL, &[Addr, Bool]),
    (SEL_PERMIT, &[Addr, Addr, Uint, Uint, Sig, Sig, Sig]),
    (
        SEL_PERMIT_DAI,
        &[Addr, Addr, Uint, Uint, Bool, Sig, Sig, Sig],
    ),
    (SEL_PERMIT2_APPROVE, &[Addr, Addr, U160, U48]),
];

/// A small pool, so that "trusted" and "stranger" collide often.
const POOL: [[u8; 20]; 3] = [[0x11; 20], [0x99; 20], [0xab; 20]];

fn gen_word(rng: &mut Rng, kind: Kind) -> [u8; 32] {
    let mut w = [0u8; 32];
    match kind {
        Addr => {
            if rng.chance(70) {
                w[12..].copy_from_slice(&POOL[rng.below(POOL.len())]);
            } else {
                for b in &mut w[12..] {
                    *b = rng.byte();
                }
            }
        }
        Uint => match rng.below(6) {
            0 => {}
            1 => w[31] = 1,
            2 => w = [0xff; 32],
            3 => w[0] = 0x80,
            4 => {
                w[0] = 0x7f;
                w[1..].fill(0xff);
            }
            _ => w.iter_mut().for_each(|b| *b = rng.byte()),
        },
        Bool => w[31] = u8::from(rng.chance(50)),
        U160 => match rng.below(4) {
            0 => {}
            1 => w[12..].fill(0xff),
            2 => w[12] = 0x80,
            _ => w[12..].iter_mut().for_each(|b| *b = rng.byte()),
        },
        U48 => match rng.below(4) {
            0 => {}
            1 => w[26..].fill(0xff),
            2 => w[26] = 0x80,
            _ => w[26..].iter_mut().for_each(|b| *b = rng.byte()),
        },
        Sig => w.iter_mut().for_each(|b| *b = rng.byte()),
    }
    w
}

fn gen_calldata(rng: &mut Rng) -> Vec<u8> {
    let (sel, kinds) = SPECS[rng.below(SPECS.len())];
    let mut data = sel.to_vec();
    for &k in kinds {
        data.extend_from_slice(&gen_word(rng, k));
    }
    // Occasional corruption, so the error paths run too.
    if rng.chance(10) {
        let i = 4 + rng.below(data.len() - 4);
        data[i] |= 1; // may dirty padding, or change a value
    }
    if rng.chance(10) {
        let i = 4 + rng.below(32 * kinds.len());
        data[i - (i - 4) % 32] = rng.byte().max(1); // dirty the first byte of a word
    }
    if rng.chance(8) {
        let cut = rng.below(data.len() + 1);
        data.truncate(cut);
    }
    if rng.chance(8) {
        for _ in 0..1 + rng.below(4) {
            data.push(rng.byte());
        }
    }
    data
}

fn spender_of(call: &Call) -> Option<Address> {
    match call {
        Call::Transfer { .. } | Call::TransferFrom { .. } => None,
        Call::Approve { spender, .. }
        | Call::IncreaseAllowance { spender, .. }
        | Call::Permit { spender, .. }
        | Call::PermitDai { spender, .. }
        | Call::Permit2Approve { spender, .. } => Some(*spender),
        Call::SetApprovalForAll { operator, .. } => Some(*operator),
    }
}

const CALLDATA_ROUNDS: usize = 60_000;

#[test]
fn calldata_apis_never_panic_on_arbitrary_bytes() {
    let mut rng = Rng(0xdead_beef_cafe_f00d);
    for _ in 0..CALLDATA_ROUNDS {
        let len = rng.below(400);
        let data: Vec<u8> = (0..len).map(|_| rng.byte()).collect();
        if let Ok(d) = decode(&data) {
            let _ = assess(&d, &Context::none());
        }
        // Same with a known selector forced in front.
        let mut with_sel = SPECS[rng.below(SPECS.len())].0.to_vec();
        with_sel.extend_from_slice(&data);
        if let Ok(d) = decode(&with_sel) {
            let _ = assess(&d, &Context::none());
        }
    }
}

#[test]
fn assessment_invariants_hold_on_structured_calldata() {
    let mut rng = Rng(0x0bad_c0de_1357_9bdf);
    let (mut ok, mut safe, mut review, mut high) = (0usize, 0usize, 0usize, 0usize);

    for _ in 0..CALLDATA_ROUNDS {
        let data = gen_calldata(&mut rng);
        let Ok(d) = decode(&data) else { continue };
        ok += 1;

        // Deterministic.
        assert_eq!(decode(&data), Ok(d));

        let none = assess(&d, &Context::none());
        match none.severity {
            Severity::Safe => safe += 1,
            Severity::Review => review += 1,
            Severity::High => high += 1,
        }

        // High means: untrusted spender AND (unlimited OR blanket).
        if none.severity == Severity::High {
            assert!(none.flags.contains(Flags::UNTRUSTED_SPENDER));
            assert!(
                none.flags.contains(Flags::UNLIMITED_AMOUNT)
                    || none.flags.contains(Flags::BLANKET_APPROVAL)
            );
        }

        // A revocation carries no other authorization-related flag.
        if none.flags.contains(Flags::REVOCATION) {
            for f in [
                Flags::UNLIMITED_AMOUNT,
                Flags::UNTRUSTED_SPENDER,
                Flags::BLANKET_APPROVAL,
                Flags::NO_EXPIRY,
            ] {
                assert!(!none.flags.contains(f), "revocation with extra flag: {d:?}");
            }
        }

        // Trailing-data flag mirrors the decoder's count exactly.
        assert_eq!(none.flags.contains(Flags::TRAILING_DATA), d.trailing > 0);

        // Plain transfers are never flagged for authorization reasons; the
        // only flag they can carry is the trailing-data one.
        if matches!(d.call, Call::Transfer { .. } | Call::TransferFrom { .. }) {
            assert!(none.flags.is_empty() || none.flags == Flags::TRAILING_DATA);
        }

        // Trusting the spender can only lower severity and removes the flag.
        if let Some(sp) = spender_of(&d.call) {
            let trusted = [sp];
            let with = assess(&d, &Context::new(&trusted));
            assert!(with.severity <= none.severity);
            assert!(!with.flags.contains(Flags::UNTRUSTED_SPENDER));
        }

        // Cutting one byte off the arguments must now fail as Truncated.
        let needed = data.len() - d.trailing;
        assert!(matches!(
            decode(&data[..needed - 1]),
            Err(DecodeError::Truncated { .. })
        ));

        // Appending bytes keeps the same call and grows `trailing`.
        let mut longer = data.clone();
        longer.push(0xaa);
        let d2 = decode(&longer).unwrap();
        assert_eq!(d2.call, d.call);
        assert_eq!(d2.trailing, d.trailing + 1);
    }

    // The generator must exercise the success path, and every severity.
    assert!(ok > CALLDATA_ROUNDS / 2, "only {ok} decodes succeeded");
    assert!(safe > 100, "safe={safe}");
    assert!(review > 100, "review={review}");
    assert!(high > 100, "high={high}");
}

// ======================================================= dynamic ABI / batch
//
// Everything below tests `dynabi`, `multicall` and `batch` against an
// independent, deliberately naive reference: absolute coordinates, u128
// arithmetic, a coverage map instead of running cursors, and recursion
// instead of an explicit stack.

use bytecode_sentinel::multicall::{
    MAX_DEPTH, SEL_AGGREGATE, SEL_AGGREGATE3, SEL_AGGREGATE3_VALUE, SEL_BLOCK_AND_AGGREGATE,
    SEL_MULTICALL, SEL_MULTICALL_DEADLINE, SEL_MULTICALL_PREVHASH, SEL_TRY_AGGREGATE,
    SEL_TRY_BLOCK_AND_AGGREGATE,
};
use bytecode_sentinel::{assess_calldata, calls, is_multicall, BytesArray, Field, TupleArray};

fn be_word(v: u64) -> [u8; 32] {
    let mut w = [0u8; 32];
    w[24..].copy_from_slice(&v.to_be_bytes());
    w
}

fn junk(rng: &mut Rng, n: usize) -> Vec<u8> {
    (0..n).map(|_| rng.byte() | 1).collect() // never zero
}

/// Canonical-or-gappy encoding of a `bytes[]`. Returns the bytes and how many
/// junk bytes were inserted between regions.
fn enc_array(items: &[Vec<u8>], rng: &mut Rng, gappy: bool) -> (Vec<u8>, usize) {
    let table = 32 * items.len();
    let mut bodies: Vec<u8> = Vec::new();
    let mut offs: Vec<u64> = Vec::new();
    let mut gaps = 0;
    for it in items {
        if gappy && rng.chance(30) {
            let g = 32 * (1 + rng.below(2));
            bodies.extend(junk(rng, g));
            gaps += g;
        }
        offs.push((table + bodies.len()) as u64);
        bodies.extend_from_slice(&be_word(it.len() as u64));
        bodies.extend_from_slice(it);
        // Padding is relative to this element, not to the whole region.
        bodies.resize(bodies.len() + (32 - it.len() % 32) % 32, 0);
    }
    let mut out = be_word(items.len() as u64).to_vec();
    for o in offs {
        out.extend_from_slice(&be_word(o));
    }
    out.extend(bodies);
    (out, gaps)
}

/// The batch signatures the crate understands.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Sig {
    Plain,
    Deadline,
    PrevHash,
    Aggregate,
    TryAggregate,
    BlockAndAggregate,
    TryBlockAndAggregate,
    Aggregate3,
    Aggregate3Value,
}

const ALL_SIGS: [Sig; 9] = [
    Sig::Plain,
    Sig::Deadline,
    Sig::PrevHash,
    Sig::Aggregate,
    Sig::TryAggregate,
    Sig::BlockAndAggregate,
    Sig::TryBlockAndAggregate,
    Sig::Aggregate3,
    Sig::Aggregate3Value,
];

impl Sig {
    fn selector(self) -> [u8; 4] {
        match self {
            Sig::Plain => SEL_MULTICALL,
            Sig::Deadline => SEL_MULTICALL_DEADLINE,
            Sig::PrevHash => SEL_MULTICALL_PREVHASH,
            Sig::Aggregate => SEL_AGGREGATE,
            Sig::TryAggregate => SEL_TRY_AGGREGATE,
            Sig::BlockAndAggregate => SEL_BLOCK_AND_AGGREGATE,
            Sig::TryBlockAndAggregate => SEL_TRY_BLOCK_AND_AGGREGATE,
            Sig::Aggregate3 => SEL_AGGREGATE3,
            Sig::Aggregate3Value => SEL_AGGREGATE3_VALUE,
        }
    }
    /// Words in the head: an extra static argument, then the array offset.
    fn head_words(self) -> usize {
        match self {
            Sig::Plain
            | Sig::Aggregate
            | Sig::BlockAndAggregate
            | Sig::Aggregate3
            | Sig::Aggregate3Value => 1,
            Sig::Deadline | Sig::PrevHash | Sig::TryAggregate | Sig::TryBlockAndAggregate => 2,
        }
    }
    /// Static members before `bytes` in each tuple; 0 means a plain `bytes[]`.
    fn tuple_fields(self) -> usize {
        match self {
            Sig::Plain | Sig::Deadline | Sig::PrevHash => 0,
            Sig::Aggregate
            | Sig::TryAggregate
            | Sig::BlockAndAggregate
            | Sig::TryBlockAndAggregate => 1,
            Sig::Aggregate3 => 2,
            Sig::Aggregate3Value => 3,
        }
    }
    /// The extra head word must be a bool for the `try*` variants.
    fn head_is_bool(self) -> bool {
        matches!(self, Sig::TryAggregate | Sig::TryBlockAndAggregate)
    }
}

/// One element of a batch: its static tuple words (empty for `bytes[]`) and
/// its call data.
#[derive(Clone)]
struct BItem {
    fields: Vec<[u8; 32]>,
    data: Vec<u8>,
}

/// Canonical-or-gappy encoding of an array of `(static.., bytes)` tuples.
fn enc_tuple_array(items: &[BItem], rng: &mut Rng, gappy: bool) -> (Vec<u8>, usize) {
    let table = 32 * items.len();
    let mut bodies: Vec<u8> = Vec::new();
    let mut offs: Vec<u64> = Vec::new();
    let mut gaps = 0;
    for it in items {
        if gappy && rng.chance(30) {
            let g = 32 * (1 + rng.below(2));
            bodies.extend(junk(rng, g));
            gaps += g;
        }
        offs.push((table + bodies.len()) as u64);
        for f in &it.fields {
            bodies.extend_from_slice(f);
        }
        let head = 32 * (it.fields.len() + 1);
        let inner = if gappy && rng.chance(30) {
            32 * (1 + rng.below(2))
        } else {
            0
        };
        bodies.extend_from_slice(&be_word((head + inner) as u64));
        bodies.extend(junk(rng, inner));
        gaps += inner;
        bodies.extend_from_slice(&be_word(it.data.len() as u64));
        bodies.extend_from_slice(&it.data);
        bodies.resize(bodies.len() + (32 - it.data.len() % 32) % 32, 0);
    }
    let mut out = be_word(items.len() as u64).to_vec();
    for o in offs {
        out.extend_from_slice(&be_word(o));
    }
    out.extend(bodies);
    (out, gaps)
}

/// Encode a batch of `items` with signature `sig`. Returns the bytes and the
/// number of bytes the EVM would ignore (gaps plus trailing).
fn enc_batch(sig: Sig, items: &[BItem], rng: &mut Rng, gappy: bool) -> (Vec<u8>, usize) {
    let head_words = sig.head_words();
    let head_gap = if gappy && rng.chance(25) {
        32 * (1 + rng.below(2))
    } else {
        0
    };
    let (array, gaps) = if sig.tuple_fields() == 0 {
        let datas: Vec<Vec<u8>> = items.iter().map(|i| i.data.clone()).collect();
        enc_array(&datas, rng, gappy)
    } else {
        enc_tuple_array(items, rng, gappy)
    };
    let mut data = sig.selector().to_vec();
    if head_words == 2 {
        if sig.head_is_bool() {
            data.extend_from_slice(&be_word(rng.below(2) as u64));
        } else {
            data.extend((0..32).map(|_| rng.byte()));
        }
    }
    data.extend_from_slice(&be_word((32 * head_words + head_gap) as u64));
    data.extend(junk(rng, head_gap));
    data.extend(array);
    let trailing = if gappy && rng.chance(25) {
        1 + rng.below(10)
    } else {
        0
    };
    data.extend(junk(rng, trailing));
    (data, head_gap + gaps + trailing)
}

/// A random inner call: some decodable, some unknown, some malformed.
fn gen_leaf(rng: &mut Rng) -> Vec<u8> {
    let addr = |rng: &mut Rng| {
        let mut w = [0u8; 32];
        w[12..].fill(POOL[rng.below(POOL.len())][0]);
        w
    };
    let amount = |rng: &mut Rng| match rng.below(4) {
        0 => [0u8; 32],
        1 => be_word(1 + rng.below(1000) as u64),
        _ => [0xff; 32],
    };
    let mut d: Vec<u8>;
    match rng.below(7) {
        0 | 1 => {
            d = SEL_APPROVE.to_vec();
            d.extend(addr(rng));
            d.extend(amount(rng));
        }
        2 => {
            d = SEL_SET_APPROVAL_FOR_ALL.to_vec();
            d.extend(addr(rng));
            d.extend(be_word(rng.below(2) as u64));
        }
        3 => {
            d = SEL_TRANSFER.to_vec();
            d.extend(addr(rng));
            d.extend(amount(rng));
        }
        4 => {
            d = SEL_PERMIT.to_vec();
            d.extend(addr(rng));
            d.extend(addr(rng));
            d.extend(amount(rng));
            d.extend(amount(rng));
            d.extend([0u8; 96]);
        }
        5 => {
            // Unknown selector (a router swap, say).
            d = vec![0x04, 0xe4, 0x5a, 0xaf];
            d.extend((0..rng.below(100)).map(|_| rng.byte()));
        }
        _ => {
            // Malformed: dirty padding or truncated approve.
            d = SEL_APPROVE.to_vec();
            d.extend(addr(rng));
            d.extend(amount(rng));
            if rng.chance(50) {
                d[4] = 1;
            } else {
                d.truncate(4 + rng.below(60));
            }
        }
    }
    if rng.chance(8) {
        d.push(rng.byte());
    }
    d
}

/// A leaf call as the crate must report it: depth, bytes, target, value.
type Leaf = (usize, Vec<u8>, Option<[u8; 20]>, Option<[u8; 32]>);

struct Built {
    data: Vec<u8>,
    leaves: Vec<Leaf>,
    hidden: usize,
    levels: usize,
}

/// Static tuple words, plus the target and value they encode (if any).
type Fields = (Vec<[u8; 32]>, Option<[u8; 20]>, Option<[u8; 32]>);

/// Random valid static words for a tuple: target, allowFailure, value.
fn gen_fields(rng: &mut Rng, n: usize) -> Fields {
    let b = POOL[rng.below(POOL.len())][0];
    let mut target = [0u8; 32];
    target[12..].fill(b);
    let value = match rng.below(3) {
        0 => [0u8; 32],
        1 => be_word(1 + rng.below(1000) as u64),
        _ => [0xff; 32],
    };
    let all = [target, be_word(rng.below(2) as u64), value];
    (
        all[..n].to_vec(),
        Some([b; 20]),
        if n == 3 { Some(value) } else { None },
    )
}

fn gen_batch(rng: &mut Rng, levels_left: usize, depth: usize, gappy: bool) -> Built {
    let sig = ALL_SIGS[rng.below(ALL_SIGS.len())];
    let nf = sig.tuple_fields();
    let mut items = Vec::new();
    let mut leaves: Vec<Leaf> = Vec::new();
    let mut hidden = 0;
    let mut child_levels = 0;
    // Deep requests always get at least one item, and nest often, so the
    // depth limit is reached regularly instead of rarely.
    let count = if levels_left > 1 {
        1 + rng.below(4)
    } else {
        rng.below(5)
    };
    for _ in 0..count {
        let (fields, target, value) = if nf == 0 {
            (Vec::new(), None, None)
        } else {
            gen_fields(rng, nf)
        };
        if levels_left > 1 && rng.chance(55) {
            let b = gen_batch(rng, levels_left - 1, depth + 1, gappy);
            leaves.extend(b.leaves);
            hidden += b.hidden;
            child_levels = child_levels.max(b.levels);
            items.push(BItem {
                fields,
                data: b.data,
            });
        } else {
            let l = gen_leaf(rng);
            leaves.push((depth, l.clone(), target, value));
            items.push(BItem { fields, data: l });
        }
    }
    let (data, h) = enc_batch(sig, &items, rng, gappy);
    Built {
        data,
        leaves,
        hidden: hidden + h,
        levels: 1 + child_levels,
    }
}

// --------------------------------------------------------- naive reference

fn ref_word(buf: &[u8], pos: u128) -> Option<[u8; 32]> {
    let end = pos.checked_add(32)?;
    if end > buf.len() as u128 {
        return None;
    }
    let mut w = [0u8; 32];
    w.copy_from_slice(&buf[pos as usize..end as usize]);
    Some(w)
}

/// Value of a word as u128 if it is at most u64::MAX, else None.
fn ref_num(w: [u8; 32]) -> Option<u128> {
    let mut v: u128 = 0;
    for &b in &w[16..] {
        v = (v << 8) | b as u128;
    }
    if w[..16].iter().any(|&b| b != 0) || v > u64::MAX as u128 {
        None
    } else {
        Some(v)
    }
}

struct RefArray {
    items: Vec<Vec<u8>>,
    slack: usize,
    end: usize,
}

fn ref_parse(args: &[u8], head_len: usize, arg: usize) -> Option<RefArray> {
    let total = args.len() as u128;
    let off = ref_num(ref_word(args, 32 * arg as u128)?)?;
    if off % 32 != 0 || off < head_len as u128 || off > total {
        return None;
    }
    let n = ref_num(ref_word(args, off)?)?;
    let body = off + 32;
    if n * 32 > total - body {
        return None;
    }
    let mut covered = vec![false; args.len()];
    let mut mark = |from: u128, to: u128| {
        for i in from..to {
            covered[i as usize] = true;
        }
    };
    mark(off, body + n * 32);
    let mut prev_end = body + n * 32;
    let mut items = Vec::new();
    for i in 0..n {
        let rel = ref_num(ref_word(args, body + 32 * i)?)?;
        if rel % 32 != 0 {
            return None;
        }
        let start = body + rel;
        if start < prev_end {
            return None; // overlaps the table or the previous element
        }
        let len = ref_num(ref_word(args, start)?)?;
        let data_start = start + 32;
        let data_end = data_start + len;
        let padded_end = data_start + len.div_ceil(32) * 32;
        if padded_end > total {
            return None;
        }
        if args[data_end as usize..padded_end as usize]
            .iter()
            .any(|&b| b != 0)
        {
            return None;
        }
        items.push(args[data_start as usize..data_end as usize].to_vec());
        mark(start, padded_end);
        prev_end = padded_end;
    }
    let slack = (head_len as u128..prev_end)
        .filter(|&i| !covered[i as usize])
        .count();
    Some(RefArray {
        items,
        slack,
        end: prev_end as usize,
    })
}

/// One parsed tuple: its static words and its `bytes`.
type RefTuple = (Vec<[u8; 32]>, Vec<u8>);

/// A parsed tuple array from the naive reference.
struct RefTuples {
    items: Vec<RefTuple>,
    slack: usize,
    end: usize,
}

/// Is `w` acceptable for static member number `field` of a tuple?
fn ref_field_ok(field: usize, w: &[u8; 32]) -> bool {
    match field {
        0 => w[..12].iter().all(|&b| b == 0),
        1 => w[..31].iter().all(|&b| b == 0) && w[31] <= 1,
        _ => true,
    }
}

/// Naive reference for an array of `(address[, bool[, uint256]], bytes)`
/// tuples: absolute coordinates, u128 arithmetic, a coverage map.
fn ref_parse_tuples(args: &[u8], head_len: usize, arg: usize, nf: usize) -> Option<RefTuples> {
    let total = args.len() as u128;
    let off = ref_num(ref_word(args, 32 * arg as u128)?)?;
    if off % 32 != 0 || off < head_len as u128 || off > total {
        return None;
    }
    let n = ref_num(ref_word(args, off)?)?;
    let body = off + 32;
    if n * 32 > total - body {
        return None;
    }
    let head = 32 * (nf as u128 + 1);
    let mut covered = vec![false; args.len()];
    let mut mark = |from: u128, to: u128| {
        for i in from..to {
            covered[i as usize] = true;
        }
    };
    mark(off, body + n * 32);
    let mut prev_end = body + n * 32;
    let mut items = Vec::new();
    for i in 0..n {
        let rel = ref_num(ref_word(args, body + 32 * i)?)?;
        if rel % 32 != 0 {
            return None;
        }
        let start = body + rel;
        if start < prev_end || start + head > total {
            return None;
        }
        let mut fields = Vec::new();
        for f in 0..nf {
            let w = ref_word(args, start + 32 * f as u128)?;
            if !ref_field_ok(f, &w) {
                return None;
            }
            fields.push(w);
        }
        let mo = ref_num(ref_word(args, start + 32 * nf as u128)?)?;
        if mo % 32 != 0 || mo < head {
            return None;
        }
        let pos = start + mo;
        let len = ref_num(ref_word(args, pos)?)?;
        let data_start = pos + 32;
        let data_end = data_start + len;
        let padded_end = data_start + len.div_ceil(32) * 32;
        if padded_end > total {
            return None;
        }
        if args[data_end as usize..padded_end as usize]
            .iter()
            .any(|&b| b != 0)
        {
            return None;
        }
        items.push((
            fields,
            args[data_start as usize..data_end as usize].to_vec(),
        ));
        mark(start, start + head);
        mark(pos, padded_end);
        prev_end = padded_end;
    }
    let slack = (head_len as u128..prev_end)
        .filter(|&i| !covered[i as usize])
        .count();
    Some(RefTuples {
        items,
        slack,
        end: prev_end as usize,
    })
}

/// Which signature `d` starts with, if any (independent of the crate's table).
fn ref_sig(d: &[u8]) -> Option<Sig> {
    if d.len() < 4 {
        return None;
    }
    let sel = [d[0], d[1], d[2], d[3]];
    ALL_SIGS.iter().copied().find(|s| s.selector() == sel)
}

fn ref_is_multicall(d: &[u8]) -> bool {
    ref_sig(d).is_some()
}

/// Flatten a batch. `None` means "cannot be read completely".
fn ref_leaves(data: &[u8], depth: usize, out: &mut Vec<Leaf>, hidden: &mut usize) -> Option<()> {
    if depth > MAX_DEPTH {
        return None;
    }
    let sig = ref_sig(data)?;
    let (words, arg) = (sig.head_words(), sig.head_words() - 1);
    if data.len() < 4 + 32 * words {
        return None;
    }
    let args = &data[4..];
    if sig.head_is_bool() {
        let w: [u8; 32] = args[..32].try_into().unwrap();
        if !ref_field_ok(1, &w) {
            return None;
        }
    }
    let nf = sig.tuple_fields();
    let (items, slack, end): (Vec<RefTuple>, usize, usize) = if nf == 0 {
        let arr = ref_parse(args, 32 * words, arg)?;
        (
            arr.items.into_iter().map(|d| (Vec::new(), d)).collect(),
            arr.slack,
            arr.end,
        )
    } else {
        let arr = ref_parse_tuples(args, 32 * words, arg, nf)?;
        (arr.items, arr.slack, arr.end)
    };
    *hidden += slack + (args.len() - end);
    for (fields, item) in items {
        if ref_is_multicall(&item) {
            ref_leaves(&item, depth + 1, out, hidden)?;
        } else {
            let target = fields.first().map(|w| {
                let mut a = [0u8; 20];
                a.copy_from_slice(&w[12..]);
                a
            });
            let value = if nf == 3 { Some(fields[2]) } else { None };
            out.push((depth, item, target, value));
        }
    }
    Some(())
}

/// What the crate's walk produced: `None` if any step failed.
fn crate_leaves(data: &[u8]) -> Option<(Vec<Leaf>, usize)> {
    let mut walk = calls(data).ok()?;
    let mut out = Vec::new();
    for item in walk.by_ref() {
        let c = item.ok()?;
        out.push((
            c.depth,
            c.data.to_vec(),
            c.target.map(|a| a.0),
            c.value.map(|w| w.0),
        ));
    }
    Some((out, walk.hidden()))
}

const INTERESTING_WORDS: [u64; 14] = [
    0,
    1,
    2,
    31,
    32,
    33,
    63,
    64,
    96,
    128,
    1 << 20,
    u32::MAX as u64,
    u64::MAX,
    4,
];

/// Overwrite part of `data` with a value likely to hit an edge case.
fn mutate(rng: &mut Rng, data: &mut Vec<u8>) {
    if data.is_empty() {
        return;
    }
    match rng.below(6) {
        0 => {
            let i = rng.below(data.len());
            data[i] = rng.byte();
        }
        1 => {
            let i = rng.below(data.len());
            data[i] ^= 1 << rng.below(8);
        }
        2 | 3 => {
            // Replace a 32-byte word (word-aligned after the selector).
            if data.len() >= 36 {
                let words = (data.len() - 4) / 32;
                let at = 4 + 32 * rng.below(words);
                let v = INTERESTING_WORDS[rng.below(INTERESTING_WORDS.len())];
                let mut w = be_word(v);
                if rng.chance(15) {
                    w = [0xff; 32];
                } else if rng.chance(10) {
                    w = [0u8; 32];
                    w[rng.below(32)] = rng.byte().max(1); // huge / dirty value
                } else if rng.chance(15) {
                    w = be_word(data.len() as u64 + rng.below(3) as u64);
                }
                data[at..at + 32].copy_from_slice(&w);
            }
        }
        4 => {
            let cut = rng.below(data.len() + 1);
            data.truncate(cut);
        }
        _ => {
            for _ in 0..1 + rng.below(40) {
                data.push(rng.byte());
            }
        }
    }
}

// ------------------------------------------------------------------- tests

const DYN_ROUNDS: usize = 40_000;

#[test]
fn bytes_array_matches_naive_reference() {
    let mut rng = Rng(0x5eed_0001_dead_beef);
    let (mut agreed_ok, mut agreed_err) = (0usize, 0usize);
    for round in 0..DYN_ROUNDS {
        let n = rng.below(6);
        let items: Vec<Vec<u8>> = (0..n)
            .map(|_| (0..rng.below(100)).map(|_| rng.byte()).collect())
            .collect();
        let head_gap = if rng.chance(30) {
            32 * (1 + rng.below(2))
        } else {
            0
        };
        let gappy = rng.chance(50);
        let (array, gaps) = enc_array(&items, &mut rng, gappy);
        let mut args = be_word(32 + head_gap as u64).to_vec();
        args.extend(junk(&mut rng, head_gap));
        args.extend(array);
        let trailing = if rng.chance(20) { 1 + rng.below(8) } else { 0 };
        args.extend(junk(&mut rng, trailing));

        // 1. The well-formed encoding must parse to exactly what was encoded.
        let a = BytesArray::parse(&args, 32, 0)
            .unwrap_or_else(|e| panic!("round {round}: valid input rejected: {e:?}"));
        let got: Vec<Vec<u8>> = a.iter().map(|s| s.to_vec()).collect();
        assert_eq!(got, items, "round {round}");
        assert_eq!(a.slack(), head_gap + gaps, "round {round}");
        assert_eq!(args.len() - a.end(), trailing, "round {round}");

        // 2. After arbitrary corruption, crate and reference must agree.
        for _ in 0..3 {
            let mut m = args.clone();
            for _ in 0..1 + rng.below(3) {
                mutate(&mut rng, &mut m);
            }
            let ours = BytesArray::parse(&m, 32, 0);
            let theirs = ref_parse(&m, 32, 0);
            match (ours, theirs) {
                (Ok(a), Some(r)) => {
                    agreed_ok += 1;
                    let got: Vec<Vec<u8>> = a.iter().map(|s| s.to_vec()).collect();
                    assert_eq!(got, r.items, "round {round}: elements differ");
                    assert_eq!(a.slack(), r.slack, "round {round}: slack differs");
                    assert_eq!(a.end(), r.end, "round {round}: end differs");
                    assert_eq!(a.len(), got.len());
                }
                (Err(_), None) => agreed_err += 1,
                (o, t) => panic!(
                    "round {round}: disagreement: crate={:?} reference_ok={} data={:02x?}",
                    o.map(|a| a.len()),
                    t.is_some(),
                    m
                ),
            }
        }
    }
    // Both the accept and the reject paths must have been exercised a lot.
    assert!(agreed_ok > 5_000, "accepted only {agreed_ok}");
    assert!(agreed_err > 5_000, "rejected only {agreed_err}");
}

#[test]
fn bytes_array_never_panics_on_arbitrary_bytes_and_arguments() {
    let mut rng = Rng(0x5eed_0002_0bad_f00d);
    for _ in 0..DYN_ROUNDS {
        let len = rng.below(300);
        let args: Vec<u8> = (0..len).map(|_| rng.byte()).collect();
        let head_len = 32 * rng.below(4);
        let arg = rng.below(6);
        if let Ok(a) = BytesArray::parse(&args, head_len, arg) {
            // Reading what was validated can never fail or leave the input.
            assert_eq!(a.iter().count(), a.len());
            assert!(a.end() <= args.len());
            for s in a.iter() {
                assert!(s.len() <= args.len());
            }
            assert!(a.get(a.len()).is_none());
        }
    }
    // Absurd head arguments must not overflow either.
    let args = [0u8; 64];
    let _ = BytesArray::parse(&args, usize::MAX, usize::MAX);
    let _ = BytesArray::parse(&args, 0, usize::MAX / 32);
}

const SCHEMAS: [&[Field]; 3] = [
    &[Field::Address],
    &[Field::Address, Field::Bool],
    &[Field::Address, Field::Bool, Field::Uint256],
];

#[test]
fn tuple_array_matches_naive_reference() {
    let mut rng = Rng(0x5eed_0006_7a9e_1111);
    let (mut agreed_ok, mut agreed_err, mut with_slack) = (0usize, 0usize, 0usize);
    for round in 0..DYN_ROUNDS {
        let nf = 1 + rng.below(3);
        let schema = SCHEMAS[nf - 1];
        let n = rng.below(6);
        let items: Vec<BItem> = (0..n)
            .map(|_| BItem {
                fields: gen_fields(&mut rng, nf).0,
                data: (0..rng.below(100)).map(|_| rng.byte()).collect(),
            })
            .collect();
        let head_gap = if rng.chance(30) {
            32 * (1 + rng.below(2))
        } else {
            0
        };
        let gappy = rng.chance(50);
        let (array, gaps) = enc_tuple_array(&items, &mut rng, gappy);
        let mut args = be_word(32 + head_gap as u64).to_vec();
        args.extend(junk(&mut rng, head_gap));
        args.extend(array);
        let trailing = if rng.chance(20) { 1 + rng.below(8) } else { 0 };
        args.extend(junk(&mut rng, trailing));

        // 1. The well-formed encoding must parse to exactly what was encoded.
        let t = TupleArray::parse(&args, 32, 0, schema)
            .unwrap_or_else(|e| panic!("round {round}: valid input rejected: {e:?}"));
        assert_eq!(t.len(), items.len(), "round {round}");
        for (i, it) in items.iter().enumerate() {
            let e = t.get(i).unwrap();
            assert_eq!(e.data, &it.data[..], "round {round}: data {i}");
            for (k, f) in it.fields.iter().enumerate() {
                assert_eq!(e.field(k).map(|w| w.0), Some(*f), "round {round}: field");
            }
            assert_eq!(e.field(nf), None);
        }
        assert!(t.get(items.len()).is_none());
        assert_eq!(t.slack(), head_gap + gaps, "round {round}");
        assert_eq!(args.len() - t.end(), trailing, "round {round}");
        if t.slack() > 0 {
            with_slack += 1;
        }

        // 2. After arbitrary corruption, crate and reference must agree.
        for _ in 0..3 {
            let mut m = args.clone();
            for _ in 0..1 + rng.below(3) {
                mutate(&mut rng, &mut m);
            }
            match (
                TupleArray::parse(&m, 32, 0, schema),
                ref_parse_tuples(&m, 32, 0, nf),
            ) {
                (Ok(t), Some(r)) => {
                    agreed_ok += 1;
                    assert_eq!(t.len(), r.items.len(), "round {round}");
                    for (i, (fields, data)) in r.items.iter().enumerate() {
                        let e = t.get(i).unwrap();
                        assert_eq!(e.data, &data[..], "round {round}: data differs");
                        for (k, f) in fields.iter().enumerate() {
                            assert_eq!(e.field(k).map(|w| w.0), Some(*f), "round {round}");
                        }
                    }
                    assert_eq!(t.slack(), r.slack, "round {round}: slack differs");
                    assert_eq!(t.end(), r.end, "round {round}: end differs");
                }
                (Err(_), None) => agreed_err += 1,
                (o, r) => panic!(
                    "round {round}: disagreement: crate={:?} reference_ok={} nf={nf} data={:02x?}",
                    o.map(|t| t.len()),
                    r.is_some(),
                    m
                ),
            }
        }
    }
    assert!(agreed_ok > 5_000, "accepted only {agreed_ok}");
    assert!(agreed_err > 5_000, "rejected only {agreed_err}");
    assert!(
        with_slack > 5_000,
        "slack exercised only {with_slack} times"
    );
}

#[test]
fn tuple_array_never_panics_on_arbitrary_bytes_and_arguments() {
    let mut rng = Rng(0x5eed_0007_0bad_cafe);
    for _ in 0..DYN_ROUNDS {
        let len = rng.below(400);
        let args: Vec<u8> = (0..len).map(|_| rng.byte()).collect();
        let head_len = 32 * rng.below(4);
        let arg = rng.below(6);
        let schema = SCHEMAS[rng.below(3)];
        if let Ok(t) = TupleArray::parse(&args, head_len, arg, schema) {
            assert!(t.end() <= args.len());
            for i in 0..t.len() {
                let e = t.get(i).expect("validated element must be readable");
                assert!(e.data.len() <= args.len());
                assert!(e.field(schema.len() - 1).is_some());
            }
            assert!(t.get(t.len()).is_none());
        }
    }
    let args = [0u8; 64];
    for schema in SCHEMAS {
        let _ = TupleArray::parse(&args, usize::MAX, usize::MAX, schema);
        let _ = TupleArray::parse(&args, 0, usize::MAX / 32, schema);
    }
}

const BATCH_ROUNDS: usize = 15_000;

#[test]
fn batch_walk_matches_naive_reference_and_stays_inside_the_input() {
    let mut rng = Rng(0x5eed_0003_c0ff_ee11);
    let (mut ok, mut err, mut too_deep, mut nested_seen) = (0usize, 0usize, 0usize, 0usize);
    let (mut tuple_leaves, mut value_leaves) = (0usize, 0usize);

    for round in 0..BATCH_ROUNDS {
        let levels = 1 + rng.below(MAX_DEPTH + 1); // sometimes one past the limit
        let gappy = rng.chance(50);
        let b = gen_batch(&mut rng, levels, 1, gappy);

        // 1. Freshly built data: exact leaves, or exactly NestingTooDeep.
        if b.levels > MAX_DEPTH {
            too_deep += 1;
            let mut w = calls(&b.data).unwrap();
            let last = w.by_ref().last();
            assert_eq!(
                last,
                Some(Err(bytecode_sentinel::DecodeError::NestingTooDeep)),
                "round {round}"
            );
        } else {
            let (got, hidden) = crate_leaves(&b.data)
                .unwrap_or_else(|| panic!("round {round}: valid batch rejected"));
            assert_eq!(got, b.leaves, "round {round}");
            assert_eq!(hidden, b.hidden, "round {round}");
            if got.iter().any(|(d, _, _, _)| *d > 1) {
                nested_seen += 1;
            }
            tuple_leaves += got.iter().filter(|l| l.2.is_some()).count();
            value_leaves += got.iter().filter(|l| l.3.is_some()).count();
        }

        // 2. Corrupted data: crate and reference must agree on everything.
        for _ in 0..3 {
            let mut m = b.data.clone();
            for _ in 0..1 + rng.below(3) {
                mutate(&mut rng, &mut m);
            }
            let (mut want, mut want_hidden) = (Vec::new(), 0);
            let reference = ref_leaves(&m, 1, &mut want, &mut want_hidden);
            let ours = crate_leaves(&m);
            match (ours, reference) {
                (Some((got, hidden)), Some(())) => {
                    ok += 1;
                    assert_eq!(got, want, "round {round}: leaves differ");
                    assert_eq!(hidden, want_hidden, "round {round}: hidden differs");

                    // Invariants that make aliasing and amplification
                    // impossible: leaves are sub-slices of the input, do not
                    // overlap, and their number is bounded by its size.
                    let base = m.as_ptr() as usize;
                    let mut spans: Vec<(usize, usize)> = calls(&m)
                        .unwrap()
                        .map(|c| {
                            let d = c.unwrap().data;
                            (d.as_ptr() as usize - base, d.len())
                        })
                        .collect();
                    assert!(spans.iter().all(|&(s, l)| s + l <= m.len()));
                    assert!(spans.len() <= m.len() / 32 + 1, "too many leaves");
                    spans.sort();
                    for pair in spans.windows(2) {
                        let (s0, l0) = pair[0];
                        let (s1, _) = pair[1];
                        assert!(s0 + l0 <= s1 || l0 == 0, "round {round}: leaves overlap");
                    }
                    assert!(spans.iter().map(|s| s.1).sum::<usize>() <= m.len());
                }
                (None, None) => err += 1,
                (o, r) => panic!(
                    "round {round}: disagreement crate_ok={} reference_ok={} data={:02x?}",
                    o.is_some(),
                    r.is_some(),
                    m
                ),
            }
        }
    }
    assert!(ok > 5_000, "accepted only {ok}");
    assert!(err > 5_000, "rejected only {err}");
    assert!(
        too_deep > 500,
        "depth limit exercised only {too_deep} times"
    );
    assert!(
        nested_seen > 500,
        "nesting exercised only {nested_seen} times"
    );
    // Multicall3 leaves must have been compared, targets and values included.
    assert!(tuple_leaves > 5_000, "tuple leaves only {tuple_leaves}");
    assert!(value_leaves > 1_000, "value leaves only {value_leaves}");
}

#[test]
fn batch_apis_never_panic_on_arbitrary_bytes() {
    let mut rng = Rng(0x5eed_0004_1234_5678);
    for _ in 0..BATCH_ROUNDS * 3 {
        let len = rng.below(500);
        let mut data: Vec<u8> = (0..len).map(|_| rng.byte()).collect();
        // Force a multicall selector and a plausible offset most of the time,
        // so the parser gets past its first checks.
        if rng.chance(80) {
            let sig = ALL_SIGS[rng.below(ALL_SIGS.len())];
            let mut v = sig.selector().to_vec();
            if sig.head_words() == 2 {
                // Sometimes a valid bool, sometimes anything.
                if rng.chance(50) {
                    v.extend_from_slice(&be_word(rng.below(2) as u64));
                } else {
                    v.extend((0..32).map(|_| rng.byte()));
                }
            }
            v.extend_from_slice(&be_word(32 * sig.head_words() as u64));
            v.extend(data);
            data = v;
        }
        let _ = is_multicall(&data);
        if let Ok(walk) = calls(&data) {
            for c in walk {
                let _ = c;
            }
        }
        let _ = assess_calldata(&data, &Context::none());
    }
}

#[test]
fn batch_assessment_matches_per_call_composition() {
    let mut rng = Rng(0x5eed_0005_aaaa_5555);
    let (mut compared, mut high, mut review, mut safe) = (0usize, 0usize, 0usize, 0usize);

    for round in 0..BATCH_ROUNDS {
        let (levels, gappy) = (1 + rng.below(MAX_DEPTH), rng.chance(40));
        let b = gen_batch(&mut rng, levels, 1, gappy);
        let trusted: Vec<Address> = POOL
            .iter()
            .filter(|_| rng.chance(40))
            .map(|a| Address(*a))
            .collect();
        let ctx = Context::new(&trusted);
        let mut m = b.data.clone();
        if rng.chance(30) {
            mutate(&mut rng, &mut m);
        }

        let (mut leaves, mut hidden) = (Vec::new(), 0);
        let readable = ref_leaves(&m, 1, &mut leaves, &mut hidden).is_some();
        let got = assess_calldata(&m, &ctx);
        if !readable {
            assert!(
                got.is_err(),
                "round {round}: unreadable batch got a verdict"
            );
            continue;
        }
        let got = got.unwrap_or_else(|e| panic!("round {round}: {e:?}"));
        compared += 1;

        // Reference composition, written out from the documented rules.
        let mut max = Severity::Safe;
        let mut flags = Flags::EMPTY;
        let (mut unknown, mut malformed) = (0, 0);
        for (_, leaf, _, _) in &leaves {
            match decode(leaf) {
                Ok(d) => {
                    let a = assess(&d, &ctx);
                    if a.severity > max {
                        max = a.severity;
                    }
                    flags.insert(a.flags);
                }
                Err(DecodeError::UnknownSelector(_)) => unknown += 1,
                Err(_) => malformed += 1,
            }
        }
        if hidden > 0 {
            flags.insert(Flags::TRAILING_DATA);
        }
        if (unknown > 0 || malformed > 0 || hidden > 0) && max < Severity::Review {
            max = Severity::Review;
        }
        assert_eq!(got.severity, max, "round {round}");
        assert_eq!(got.flags, flags, "round {round}");
        assert_eq!(got.inspected, leaves.len());
        assert_eq!((got.unknown, got.malformed), (unknown, malformed));
        assert_eq!(got.hidden_bytes, hidden);

        // Invariants stated independently of the composition above.
        if leaves
            .iter()
            .any(|(_, l, _, _)| decode(l).map(|d| assess(&d, &ctx).severity) == Ok(Severity::High))
        {
            assert_eq!(got.severity, Severity::High, "a High call was masked");
        }
        if unknown + malformed > 0 || hidden > 0 {
            assert_ne!(got.severity, Severity::Safe, "undecodable data judged Safe");
        }
        match got.severity {
            Severity::Safe => safe += 1,
            Severity::Review => review += 1,
            Severity::High => high += 1,
        }
    }
    assert!(compared > 8_000, "compared only {compared}");
    assert!(safe > 100, "safe={safe}");
    assert!(review > 100, "review={review}");
    assert!(high > 100, "high={high}");
}

// ======================================================================
// Universal Router: `router` and its composition in `batch`, against a
// naive reference (absolute coordinates, u128 arithmetic, a coverage map for
// hidden bytes, recursion for sub plans).
// ======================================================================

use bytecode_sentinel::router::{MAX_DEPTH as PLAN_DEPTH, SEL_EXECUTE, SEL_EXECUTE_DEADLINE};
use bytecode_sentinel::{commands, decode_execute, decode_permit_batch, decode_permit_single};
use bytecode_sentinel::{Decoded, Word};

/// `(depth, index, command byte, input)`
type RLeaf = (usize, usize, u8, Vec<u8>);

struct RefPlan {
    commands: Vec<u8>,
    inputs: Vec<Vec<u8>>,
    slack: usize,
    trailing: usize,
}

/// The `bytes` whose length word is at `off`: data and one past its padding.
fn ref_bytes_at(buf: &[u8], off: u128) -> Option<(Vec<u8>, u128)> {
    let len = ref_num(ref_word(buf, off)?)?;
    let data_start = off + 32;
    let data_end = data_start + len;
    let padded_end = data_start + len.div_ceil(32) * 32;
    if padded_end > buf.len() as u128 {
        return None;
    }
    if buf[data_end as usize..padded_end as usize]
        .iter()
        .any(|&b| b != 0)
    {
        return None;
    }
    Some((
        buf[data_start as usize..data_end as usize].to_vec(),
        padded_end,
    ))
}

/// `args` holds the offset of `commands` in word 0 and of `inputs` in word 1.
fn ref_plan(args: &[u8], head_len: usize) -> Option<RefPlan> {
    let total = args.len() as u128;
    let off = ref_num(ref_word(args, 0)?)?;
    if off % 32 != 0 || off < head_len as u128 || off > total {
        return None;
    }
    let (commands, end) = ref_bytes_at(args, off)?;
    // `inputs` may not start before the end of `commands`.
    let arr = ref_parse(args, end as usize, 1)?;
    if arr.items.len() != commands.len() {
        return None;
    }
    Some(RefPlan {
        commands,
        slack: (off as usize - head_len) + arr.slack,
        trailing: args.len() - arr.end,
        inputs: arr.items,
    })
}

fn ref_execute(data: &[u8]) -> Option<RefPlan> {
    let sel: [u8; 4] = data.get(..4)?.try_into().ok()?;
    match sel {
        SEL_EXECUTE => ref_plan(&data[4..], 64),
        SEL_EXECUTE_DEADLINE if data.len() >= 4 + 96 => ref_plan(&data[4..], 96),
        _ => None,
    }
}

fn ref_cmds(plan: &RefPlan, depth: usize, out: &mut Vec<RLeaf>, hidden: &mut usize) -> Option<()> {
    *hidden += plan.slack + plan.trailing;
    for (i, (&b, input)) in plan.commands.iter().zip(&plan.inputs).enumerate() {
        if b & 0x7f == 0x21 {
            let inner = ref_plan(input, 64)?;
            if depth >= PLAN_DEPTH {
                return None;
            }
            ref_cmds(&inner, depth + 1, out, hidden)?;
        } else {
            out.push((depth, i, b, input.clone()));
        }
    }
    Some(())
}

fn ref_leaves_of(data: &[u8]) -> Option<(Vec<RLeaf>, usize)> {
    let plan = ref_execute(data)?;
    let (mut out, mut hidden) = (Vec::new(), 0);
    ref_cmds(&plan, 1, &mut out, &mut hidden)?;
    Some((out, hidden))
}

fn crate_cmds(data: &[u8]) -> Option<(Vec<RLeaf>, usize)> {
    let mut walk = commands(data).ok()?;
    let mut out = Vec::new();
    for item in walk.by_ref() {
        let c = item.ok()?;
        out.push((c.depth, c.index, c.byte, c.input.to_vec()));
    }
    Some((out, walk.hidden()))
}

// ---- reference permit decoders

type RDetails = ([u8; 20], [u8; 32], [u8; 32], [u8; 32]);

fn ref_addr(w: &[u8; 32]) -> Option<[u8; 20]> {
    if w[..12].iter().any(|&b| b != 0) {
        return None;
    }
    w[12..].try_into().ok()
}

fn ref_fits(w: &[u8; 32], bytes: usize) -> bool {
    w[..32 - bytes].iter().all(|&b| b == 0)
}

/// Details of one `PermitDetails` stored at `at` (four words), validated.
fn ref_details(buf: &[u8], at: u128) -> Option<RDetails> {
    let w: Vec<[u8; 32]> = (0..4)
        .map(|i| ref_word(buf, at + 32 * i))
        .collect::<Option<_>>()?;
    if !ref_fits(&w[1], 20) || !ref_fits(&w[2], 6) || !ref_fits(&w[3], 6) {
        return None;
    }
    Some((ref_addr(&w[0])?, w[1], w[2], w[3]))
}

fn ref_permit_single(input: &[u8]) -> Option<(RDetails, [u8; 20], usize)> {
    let total = input.len() as u128;
    let details = ref_details(input, 0)?;
    let spender = ref_addr(&ref_word(input, 128)?)?;
    ref_word(input, 160)?; // sigDeadline: any value
    let off = ref_num(ref_word(input, 192)?)?;
    if off % 32 != 0 || off < 224 || off > total {
        return None;
    }
    let (_sig, end) = ref_bytes_at(input, off)?;
    let covered = 224 + (end - off);
    Some((details, spender, (total - covered) as usize))
}

fn ref_permit_batch(input: &[u8]) -> Option<(Vec<RDetails>, [u8; 20], usize)> {
    let total = input.len() as u128;
    let pb = ref_num(ref_word(input, 0)?)?;
    let sig_off = ref_num(ref_word(input, 32)?)?;
    if pb % 32 != 0 || pb < 64 || pb > total {
        return None;
    }
    let d = ref_num(ref_word(input, pb)?)?;
    let spender = ref_addr(&ref_word(input, pb + 32)?)?;
    ref_word(input, pb + 64)?; // sigDeadline
    if d % 32 != 0 || d < 96 {
        return None;
    }
    let arr = pb + d;
    let len = ref_num(ref_word(input, arr)?)?;
    let end = arr + 32 + len * 128;
    if end > total {
        return None;
    }
    let mut details = Vec::new();
    for i in 0..len {
        details.push(ref_details(input, arr + 32 + 128 * i)?);
    }
    if sig_off % 32 != 0 || sig_off < end || sig_off > total {
        return None;
    }
    let (_sig, sig_end) = ref_bytes_at(input, sig_off)?;
    let covered = 64 + 96 + (end - arr) + (sig_end - sig_off);
    Some((details, spender, (total - covered) as usize))
}

// ---- generators

fn rand_addr_word(rng: &mut Rng) -> [u8; 32] {
    let mut w = [0u8; 32];
    w[12..].copy_from_slice(&POOL[rng.below(POOL.len())]);
    w
}

/// A random value that fits in the last `bytes` bytes of a word, biased
/// towards the interesting ones (0, small, half range, max).
fn rand_uint_word(rng: &mut Rng, bytes: usize) -> [u8; 32] {
    let mut w = [0u8; 32];
    match rng.below(5) {
        0 => {}
        1 => w[31] = 1 + rng.below(200) as u8,
        2 => w[32 - bytes] = 0x80, // exactly half the range
        3 => w[32 - bytes..].fill(0xff),
        _ => {
            for b in &mut w[32 - bytes..] {
                *b = rng.byte();
            }
        }
    }
    w
}

fn rand_gap(rng: &mut Rng, gappy: bool) -> usize {
    if gappy && rng.chance(40) {
        32 * (1 + rng.below(2))
    } else {
        0
    }
}

fn bytes_tail(data: &[u8]) -> Vec<u8> {
    let mut v = be_word(data.len() as u64).to_vec();
    v.extend_from_slice(data);
    v.resize(32 + data.len().div_ceil(32) * 32, 0);
    v
}

/// A valid `PERMIT2_PERMIT` input and the number of hidden bytes in it.
fn gen_permit_single(rng: &mut Rng, gappy: bool) -> (Vec<u8>, usize) {
    let sig: Vec<u8> = (0..rng.below(100)).map(|_| rng.byte()).collect();
    let gap = rand_gap(rng, gappy);
    let mut v = Vec::new();
    v.extend(rand_addr_word(rng)); // token
    v.extend(rand_uint_word(rng, 20)); // amount
    v.extend(rand_uint_word(rng, 6)); // expiration
    v.extend(rand_uint_word(rng, 6)); // nonce
    v.extend(rand_addr_word(rng)); // spender
    v.extend(rand_uint_word(rng, 32)); // sigDeadline
    v.extend(be_word(224 + gap as u64));
    v.extend(junk(rng, gap));
    v.extend(bytes_tail(&sig));
    let trailing = if rng.chance(15) { 1 + rng.below(6) } else { 0 };
    v.extend(junk(rng, trailing));
    (v, gap + trailing)
}

/// A valid `PERMIT2_PERMIT_BATCH` input and the number of hidden bytes in it.
fn gen_permit_batch(rng: &mut Rng, gappy: bool) -> (Vec<u8>, usize) {
    let n = rng.below(4);
    let sig: Vec<u8> = (0..rng.below(100)).map(|_| rng.byte()).collect();
    let (pb_gap, d_gap, sig_gap) = (
        rand_gap(rng, gappy),
        rand_gap(rng, gappy),
        rand_gap(rng, gappy),
    );
    let mut arr = be_word(n as u64).to_vec();
    for _ in 0..n {
        arr.extend(rand_addr_word(rng));
        arr.extend(rand_uint_word(rng, 20));
        arr.extend(rand_uint_word(rng, 6));
        arr.extend(rand_uint_word(rng, 6));
    }
    let off_sig = 64 + pb_gap + 96 + d_gap + arr.len() + sig_gap;
    let mut v = be_word((64 + pb_gap) as u64).to_vec();
    v.extend(be_word(off_sig as u64));
    v.extend(junk(rng, pb_gap));
    v.extend(be_word((96 + d_gap) as u64));
    v.extend(rand_addr_word(rng));
    v.extend(rand_uint_word(rng, 32));
    v.extend(junk(rng, d_gap));
    v.extend(arr);
    v.extend(junk(rng, sig_gap));
    v.extend(bytes_tail(&sig));
    let trailing = if rng.chance(15) { 1 + rng.below(6) } else { 0 };
    v.extend(junk(rng, trailing));
    (v, pb_gap + d_gap + sig_gap + trailing)
}

/// Canonical-or-gappy `abi.encode(bytes, bytes[])` with `head_words` head
/// words (2, or 3 with a deadline last). Returns the data and the number of
/// junk bytes inserted between regions.
fn enc_plan(
    cmds: &[u8],
    inputs: &[Vec<u8>],
    rng: &mut Rng,
    gappy: bool,
    head_words: usize,
) -> (Vec<u8>, usize) {
    let head = 32 * head_words;
    let cmds_enc = bytes_tail(cmds);
    let (head_gap, mid_gap) = (rand_gap(rng, gappy), rand_gap(rng, gappy));
    let off_c = head + head_gap;
    let off_i = off_c + cmds_enc.len() + mid_gap;
    let (arr, arr_gaps) = enc_array(inputs, rng, gappy);
    let mut v = be_word(off_c as u64).to_vec();
    v.extend(be_word(off_i as u64));
    if head_words == 3 {
        v.extend(rand_uint_word(rng, 32)); // deadline
    }
    v.extend(junk(rng, head_gap));
    v.extend(cmds_enc);
    v.extend(junk(rng, mid_gap));
    v.extend(arr);
    (v, head_gap + mid_gap + arr_gaps)
}

struct PBuilt {
    args: Vec<u8>,
    leaves: Vec<RLeaf>,
    hidden: usize,
    levels: usize,
}

const LEAF_BYTES: [u8; 20] = [
    0x00, 0x04, 0x0a, 0x0a, 0x8a, 0x03, 0x03, 0x16, 0x40, 0x08, // as before
    0x02, 0x05, 0x85, 0x06, 0x07, 0x0c, 0x0d, 0x05, 0x04, 0x8c, // simple spends
];

/// A recipient word for a generated spend: mostly the pool (so the trusted
/// list is hit), the router's two special values and their neighbours, and
/// anything else.
fn gen_recipient_word(rng: &mut Rng) -> [u8; 32] {
    let mut w = [0u8; 32];
    match rng.below(10) {
        0..=3 => w[12..].copy_from_slice(&POOL[rng.below(POOL.len())]),
        4 => w[31] = 1,
        5 => w[31] = 2,
        6 => {
            let low = rng.below(4) as u8;
            w[31] = low + 3 * rng.below(2) as u8; // 0..=6
        }
        _ => w[12..].iter_mut().for_each(|b| *b = rng.byte()),
    }
    w
}

/// Input of a simple spend: `three` words (token, recipient, amount) or two
/// (`UNWRAP_WETH`: recipient, amount), sometimes damaged.
fn gen_spend(rng: &mut Rng, three: bool) -> Vec<u8> {
    let at = if three { 32 } else { 0 };
    let mut v = Vec::new();
    if three {
        v.extend(rand_addr_word(rng)); // token
    }
    v.extend(gen_recipient_word(rng));
    v.extend((0..32).map(|_| rng.byte())); // amount, any value
    match rng.below(20) {
        0 | 1 => {
            // Dirty: a non-zero byte in the 12 padding bytes of the recipient.
            let i = at + rng.below(12);
            v[i] = 1 + rng.byte() % 255;
        }
        2 => {
            let cut = rng.below(v.len());
            v.truncate(cut); // short
        }
        3..=5 => {
            let n = 1 + rng.below(40);
            v.extend(junk(rng, n)); // extra bytes after the static words
        }
        _ => {}
    }
    v
}

fn gen_plan(
    rng: &mut Rng,
    depth: usize,
    levels_left: usize,
    gappy: bool,
    head_words: usize,
) -> PBuilt {
    let n = rng.below(5);
    let (mut cmds, mut inputs, mut leaves) = (Vec::new(), Vec::new(), Vec::new());
    let (mut hidden, mut levels) = (0usize, 1usize);
    for i in 0..n {
        if levels_left > 0 && rng.chance(45) {
            let inner = gen_plan(rng, depth + 1, levels_left - 1, gappy, 2);
            let trail = if rng.chance(20) { 1 + rng.below(6) } else { 0 };
            let mut input = inner.args;
            input.extend(junk(rng, trail));
            hidden += inner.hidden + trail;
            levels = levels.max(1 + inner.levels);
            leaves.extend(inner.leaves);
            cmds.push(if rng.chance(30) { 0xa1 } else { 0x21 });
            inputs.push(input);
        } else {
            let b = LEAF_BYTES[rng.below(LEAF_BYTES.len())];
            let input = match b & 0x7f {
                // Bytes hidden *inside* a permit input are counted by `batch`,
                // not by the plan walk, so they are not added to `hidden`.
                0x0a => gen_permit_single(rng, gappy).0,
                0x03 => gen_permit_batch(rng, gappy).0,
                0x02 | 0x04 | 0x05 | 0x06 | 0x07 => gen_spend(rng, true),
                0x0c => gen_spend(rng, false),
                _ => (0..rng.below(80)).map(|_| rng.byte()).collect(),
            };
            cmds.push(b);
            inputs.push(input.clone());
            leaves.push((depth, i, b, input));
        }
    }
    let (args, gaps) = enc_plan(&cmds, &inputs, rng, gappy, head_words);
    PBuilt {
        args,
        leaves,
        hidden: hidden + gaps,
        levels,
    }
}

/// An `execute` call (either selector) around a generated plan.
fn gen_execute(rng: &mut Rng, levels_left: usize, gappy: bool) -> (Vec<u8>, PBuilt) {
    let deadline = rng.chance(30);
    let b = gen_plan(rng, 1, levels_left, gappy, if deadline { 3 } else { 2 });
    let mut data = if deadline {
        SEL_EXECUTE_DEADLINE
    } else {
        SEL_EXECUTE
    }
    .to_vec();
    data.extend_from_slice(&b.args);
    (data, b)
}

// ---- tests

const ROUTER_ROUNDS: usize = 15_000;

#[test]
fn plan_walk_matches_naive_reference_and_exact_expectations() {
    let mut rng = Rng(0x5eed_0006_7777_1234);
    let (mut ok, mut err, mut too_deep, mut nested, mut hidden_seen) = (0usize, 0, 0, 0, 0);

    for round in 0..ROUTER_ROUNDS {
        let levels_left = rng.below(PLAN_DEPTH + 1); // sometimes one level too many
        let gappy = rng.chance(50);
        let (data, b) = gen_execute(&mut rng, levels_left, gappy);

        // 1. Freshly built data: exactly the commands put in, or exactly
        //    NestingTooDeep.
        if b.levels > PLAN_DEPTH {
            too_deep += 1;
            let last = commands(&data).unwrap().last();
            assert_eq!(
                last,
                Some(Err(bytecode_sentinel::DecodeError::NestingTooDeep)),
                "round {round}"
            );
        } else {
            let (got, hidden) =
                crate_cmds(&data).unwrap_or_else(|| panic!("round {round}: valid plan rejected"));
            assert_eq!(got, b.leaves, "round {round}");
            assert_eq!(hidden, b.hidden, "round {round}");
            nested += got.iter().any(|l| l.0 > 1) as usize;
            hidden_seen += (hidden > 0) as usize;
            // The deadline variant exposes its deadline, the plain one does not.
            let ex = decode_execute(&data).unwrap();
            assert_eq!(ex.deadline.is_some(), data[..4] == SEL_EXECUTE_DEADLINE);
        }

        // 2. After corruption, crate and reference agree, accept or reject.
        for _ in 0..3 {
            let mut m = data.clone();
            for _ in 0..1 + rng.below(3) {
                mutate(&mut rng, &mut m);
            }
            let ours = crate_cmds(&m);
            let theirs = ref_leaves_of(&m);
            match (&ours, &theirs) {
                (Some(_), Some(_)) => ok += 1,
                (None, None) => err += 1,
                _ => panic!(
                    "round {round}: disagreement: crate_ok={} reference_ok={} data={m:02x?}",
                    ours.is_some(),
                    theirs.is_some()
                ),
            }
            assert_eq!(ours, theirs, "round {round}");
        }
    }
    assert!(ok > 4_000, "accepted only {ok}");
    assert!(err > 4_000, "rejected only {err}");
    assert!(too_deep > 200, "too deep only {too_deep}");
    assert!(nested > 1_000, "nested only {nested}");
    assert!(hidden_seen > 1_000, "hidden bytes only {hidden_seen}");
}

#[test]
fn permit_decoders_match_naive_reference() {
    let mut rng = Rng(0x5eed_0007_abcd_0042);
    let (mut s_ok, mut s_err, mut b_ok, mut b_err) = (0usize, 0, 0, 0);

    for round in 0..ROUTER_ROUNDS {
        let gappy = rng.chance(50);
        // Mutation helpers assume a 4-byte selector in front: add and drop one.
        let single = rng.chance(50);
        let (valid, expected_hidden) = if single {
            gen_permit_single(&mut rng, gappy)
        } else {
            gen_permit_batch(&mut rng, gappy)
        };

        // 1. Valid input: accepted, with exactly the hidden bytes inserted.
        if single {
            let p = decode_permit_single(&valid)
                .unwrap_or_else(|e| panic!("round {round}: valid single rejected: {e:?}"));
            assert_eq!(p.hidden, expected_hidden, "round {round}");
        } else {
            let p = decode_permit_batch(&valid)
                .unwrap_or_else(|e| panic!("round {round}: valid batch rejected: {e:?}"));
            assert_eq!(p.hidden, expected_hidden, "round {round}");
        }

        // 2. Corrupted input: same verdict and same values as the reference.
        for _ in 0..3 {
            let mut m = vec![0u8; 4];
            m.extend_from_slice(&valid);
            for _ in 0..1 + rng.below(3) {
                mutate(&mut rng, &mut m);
            }
            if m.len() < 4 {
                continue;
            }
            let input = &m[4..];
            // Both decoders are run on both kinds of data: a single-permit
            // layout read as a batch must be rejected or agree, never panic.
            match (decode_permit_single(input), ref_permit_single(input)) {
                (Ok(p), Some((d, spender, hidden))) => {
                    s_ok += 1;
                    assert_eq!(p.details.token.0, d.0, "round {round}");
                    assert_eq!(p.details.amount.0, d.1, "round {round}");
                    assert_eq!(p.details.expiration.0, d.2, "round {round}");
                    assert_eq!(p.details.nonce.0, d.3, "round {round}");
                    assert_eq!(p.spender.0, spender, "round {round}");
                    assert_eq!(p.hidden, hidden, "round {round}");
                }
                (Err(_), None) => s_err += 1,
                (o, t) => panic!(
                    "round {round}: single disagreement: crate_ok={} ref_ok={} {input:02x?}",
                    o.is_ok(),
                    t.is_some()
                ),
            }
            match (decode_permit_batch(input), ref_permit_batch(input)) {
                (Ok(p), Some((details, spender, hidden))) => {
                    b_ok += 1;
                    let got: Vec<RDetails> = p
                        .iter()
                        .map(|d| (d.token.0, d.amount.0, d.expiration.0, d.nonce.0))
                        .collect();
                    assert_eq!(got, details, "round {round}");
                    assert_eq!(p.len(), details.len());
                    assert_eq!(p.spender.0, spender, "round {round}");
                    assert_eq!(p.hidden, hidden, "round {round}");
                }
                (Err(_), None) => b_err += 1,
                (o, t) => panic!(
                    "round {round}: batch disagreement: crate_ok={} ref_ok={} {input:02x?}",
                    o.is_ok(),
                    t.is_some()
                ),
            }
        }
    }
    assert!(
        s_ok > 1_000 && s_err > 1_000,
        "single ok={s_ok} err={s_err}"
    );
    assert!(b_ok > 1_000 && b_err > 1_000, "batch ok={b_ok} err={b_err}");
}

#[test]
fn router_apis_never_panic_on_arbitrary_bytes() {
    let mut rng = Rng(0x5eed_0008_f00d_beef);
    for _ in 0..ROUTER_ROUNDS * 3 {
        let len = rng.below(600);
        let mut data: Vec<u8> = (0..len).map(|_| rng.byte()).collect();
        // Usually a real selector and plausible head words, so the parsers
        // get past their first checks.
        if rng.chance(80) {
            let (sel, words) = if rng.chance(50) {
                (SEL_EXECUTE, 2)
            } else {
                (SEL_EXECUTE_DEADLINE, 3)
            };
            let mut v = sel.to_vec();
            v.extend(be_word(32 * words));
            v.extend(be_word(32 * words + 32 + rng.below(4) as u64 * 32));
            if words == 3 {
                v.extend(be_word(rng.next()));
            }
            v.extend(data);
            data = v;
        }
        let _ = decode_execute(&data);
        if let Ok(walk) = commands(&data) {
            for c in walk.flatten() {
                let _ = decode_permit_single(c.input);
                let _ = decode_permit_batch(c.input);
            }
        }
        let _ = decode_permit_single(&data);
        let _ = decode_permit_batch(&data);
        let _ = assess_calldata(&data, &Context::none());
    }
}

#[test]
fn router_assessment_matches_per_command_composition() {
    let mut rng = Rng(0x5eed_0009_5a5a_a5a5);
    let (mut compared, mut high, mut review, mut safe) = (0usize, 0usize, 0usize, 0usize);
    // How often each kind of spend recipient was actually judged.
    let (mut listed_n, mut special_n, mut stranger_n, mut broken_n) =
        (0usize, 0usize, 0usize, 0usize);

    for round in 0..ROUTER_ROUNDS {
        let (levels_left, gappy) = (rng.below(PLAN_DEPTH), rng.chance(40));
        let (data, _) = gen_execute(&mut rng, levels_left, gappy);
        let trusted: Vec<Address> = POOL
            .iter()
            .filter(|_| rng.chance(40))
            .map(|a| Address(*a))
            .collect();
        let ctx = Context::new(&trusted);
        let mut m = data.clone();
        if rng.chance(30) {
            mutate(&mut rng, &mut m);
        }

        let reference = ref_leaves_of(&m);
        let got = assess_calldata(&m, &ctx);
        let Some((leaves, mut hidden)) = reference else {
            assert!(got.is_err(), "round {round}: unreadable plan got a verdict");
            continue;
        };
        let got = got.unwrap_or_else(|e| panic!("round {round}: {e:?}"));
        compared += 1;

        // Reference composition, written out from the documented rules.
        let mut max = Severity::Safe;
        let mut flags = Flags::EMPTY;
        let (mut unknown, mut malformed) = (0, 0);
        let judge = |call: Call, max: &mut Severity, flags: &mut Flags| {
            let a = assess(&Decoded { call, trailing: 0 }, &ctx);
            *max = (*max).max(a.severity);
            flags.insert(a.flags);
        };
        let grant = |d: &RDetails, spender: [u8; 20]| Call::Permit2Approve {
            token: Address(d.0),
            spender: Address(spender),
            amount: Word(d.1),
            expiration: Word(d.2),
        };
        for (_, _, byte, input) in &leaves {
            match byte & 0x7f {
                0x0a => match ref_permit_single(input) {
                    Some((d, spender, h)) => {
                        hidden += h;
                        judge(grant(&d, spender), &mut max, &mut flags);
                    }
                    None => malformed += 1,
                },
                0x03 => match ref_permit_batch(input) {
                    Some((details, spender, h)) => {
                        hidden += h;
                        for d in &details {
                            judge(grant(d, spender), &mut max, &mut flags);
                        }
                    }
                    None => malformed += 1,
                },
                // Simple spends: recipient word at a fixed place; written out
                // from the layout table, not from the crate's code.
                ty @ (0x02 | 0x04 | 0x05 | 0x06 | 0x07 | 0x0c) => {
                    let (at, min) = if ty == 0x0c { (0, 64) } else { (32, 96) };
                    if input.len() < min {
                        malformed += 1;
                        broken_n += 1;
                    } else if input[at..at + 12].iter().any(|&b| b != 0) {
                        malformed += 1; // non-canonical address word
                        broken_n += 1;
                    } else {
                        let who = &input[at + 12..at + 32];
                        let special = who[..19].iter().all(|&b| b == 0) && matches!(who[19], 1 | 2);
                        let listed = trusted.iter().any(|t| t.0 == who);
                        if special {
                            special_n += 1;
                        } else if listed {
                            listed_n += 1;
                        } else {
                            stranger_n += 1;
                        }
                        if !special && !listed {
                            flags.insert(Flags::UNTRUSTED_RECIPIENT);
                            max = max.max(Severity::High);
                        }
                        hidden += input.len() - min;
                    }
                }
                0x0d => unknown += 1, // batch transfer still unknown
                _ => unknown += 1,
            }
        }
        if hidden > 0 {
            flags.insert(Flags::TRAILING_DATA);
        }
        if (unknown > 0 || malformed > 0 || hidden > 0) && max < Severity::Review {
            max = Severity::Review;
        }
        assert_eq!(got.severity, max, "round {round}");
        assert_eq!(got.flags, flags, "round {round}");
        assert_eq!(got.inspected, leaves.len(), "round {round}");
        assert_eq!((got.unknown, got.malformed), (unknown, malformed));
        assert_eq!(got.hidden_bytes, hidden, "round {round}");

        // Invariants stated independently of the composition above.
        if unknown + malformed > 0 || hidden > 0 {
            assert_ne!(got.severity, Severity::Safe, "undecodable data judged Safe");
        }
        match got.severity {
            Severity::Safe => safe += 1,
            Severity::Review => review += 1,
            Severity::High => high += 1,
        }
    }
    assert!(compared > 8_000, "compared only {compared}");
    assert!(safe > 50, "safe={safe}");
    assert!(review > 500, "review={review}");
    assert!(high > 500, "high={high}");
    // The spend paths must all have been compared many times.
    assert!(listed_n > 1_000, "trusted recipients only {listed_n}");
    assert!(special_n > 1_000, "special recipients only {special_n}");
    assert!(stranger_n > 1_000, "stranger recipients only {stranger_n}");
    assert!(broken_n > 500, "unreadable spends only {broken_n}");
}
