//! Decode batch calls and walk the calls inside them.
//!
//! Two families are understood (selectors verified with
//! `tools/verify_selectors.py`):
//!
//! | Signature | Selector |
//! |---|---|
//! | `multicall(bytes[])` | `ac9650d8` |
//! | `multicall(uint256,bytes[])` | `5ae401dc` |
//! | `multicall(bytes32,bytes[])` | `1f0464d1` |
//! | Multicall3 `aggregate((address,bytes)[])` | `252dba42` |
//! | Multicall3 `tryAggregate(bool,(address,bytes)[])` | `bce38bd7` |
//! | Multicall3 `blockAndAggregate((address,bytes)[])` | `c3077fa9` |
//! | Multicall3 `tryBlockAndAggregate(bool,(address,bytes)[])` | `399542e9` |
//! | Multicall3 `aggregate3((address,bool,bytes)[])` | `82ad56cb` |
//! | Multicall3 `aggregate3Value((address,bool,uint256,bytes)[])` | `174dea71` |
//!
//! The first three take a `bytes[]` of calls the contract makes on itself
//! (Uniswap-style, through `delegatecall`). The Multicall3 functions take an
//! array of tuples, each naming a `target` address, and the contract calls
//! that target. Both are walked the same way: only the calldata of each inner
//! call is judged, as if the signer had sent it. For Multicall3 the inner
//! call really is made by the Multicall3 contract (or, when a smart wallet
//! delegatecalls it, by the wallet), so an approval inside it may not be an
//! approval *from the signer*. Reporting it anyway is the safe direction.
//!
//! This module only decodes. Each inner call is handed out as raw bytes,
//! with its `target` and `value` where the signature has them; decoding it is
//! [`crate::calldata::decode`]'s job and judging it is [`crate::risk`]'s (see
//! [`crate::batch`] for the composition).
//!
//! Batches may contain batches. [`Calls`] descends into them with a stack of
//! fixed size ([`MAX_DEPTH`]) and never allocates; deeper nesting is an error,
//! not something to skip. Because [`crate::dynabi`] forbids overlapping
//! regions, the total work is bounded by the size of the input times
//! [`MAX_DEPTH`], whatever the offsets say.

use crate::abi::{Address, Args, DecodeError, Word};
use crate::dynabi::{BytesArray, Entry, Field, TupleArray};

/// `multicall(bytes[])`
pub const SEL_MULTICALL: [u8; 4] = [0xac, 0x96, 0x50, 0xd8];
/// `multicall(uint256,bytes[])` (a deadline first, as in Uniswap SwapRouter02)
pub const SEL_MULTICALL_DEADLINE: [u8; 4] = [0x5a, 0xe4, 0x01, 0xdc];
/// `multicall(bytes32,bytes[])` (a previous block hash first)
pub const SEL_MULTICALL_PREVHASH: [u8; 4] = [0x1f, 0x04, 0x64, 0xd1];
/// Multicall3 `aggregate((address,bytes)[])`
pub const SEL_AGGREGATE: [u8; 4] = [0x25, 0x2d, 0xba, 0x42];
/// Multicall3 `tryAggregate(bool,(address,bytes)[])`
pub const SEL_TRY_AGGREGATE: [u8; 4] = [0xbc, 0xe3, 0x8b, 0xd7];
/// Multicall3 `blockAndAggregate((address,bytes)[])`
pub const SEL_BLOCK_AND_AGGREGATE: [u8; 4] = [0xc3, 0x07, 0x7f, 0xa9];
/// Multicall3 `tryBlockAndAggregate(bool,(address,bytes)[])`
pub const SEL_TRY_BLOCK_AND_AGGREGATE: [u8; 4] = [0x39, 0x95, 0x42, 0xe9];
/// Multicall3 `aggregate3((address,bool,bytes)[])`
pub const SEL_AGGREGATE3: [u8; 4] = [0x82, 0xad, 0x56, 0xcb];
/// Multicall3 `aggregate3Value((address,bool,uint256,bytes)[])`
pub const SEL_AGGREGATE3_VALUE: [u8; 4] = [0x17, 0x4d, 0xea, 0x71];

/// Maximum levels of batch nesting, counting the outermost batch.
pub const MAX_DEPTH: usize = 4;

/// `(address target, bytes callData)`
const CALL: &[Field] = &[Field::Address];
/// `(address target, bool allowFailure, bytes callData)`
const CALL3: &[Field] = &[Field::Address, Field::Bool];
/// `(address target, bool allowFailure, uint256 value, bytes callData)`
const CALL3_VALUE: &[Field] = &[Field::Address, Field::Bool, Field::Uint256];

/// Which batch signature was used, with its extra static argument.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// `multicall(bytes[])`
    Plain,
    /// `multicall(uint256 deadline, bytes[])`
    Deadline(Word),
    /// `multicall(bytes32 previousBlockhash, bytes[])`
    PreviousBlockhash(Word),
    /// Multicall3 `aggregate`
    Aggregate,
    /// Multicall3 `tryAggregate(bool requireSuccess, ..)`
    TryAggregate { require_success: bool },
    /// Multicall3 `blockAndAggregate`
    BlockAndAggregate,
    /// Multicall3 `tryBlockAndAggregate(bool requireSuccess, ..)`
    TryBlockAndAggregate { require_success: bool },
    /// Multicall3 `aggregate3`
    Aggregate3,
    /// Multicall3 `aggregate3Value`
    Aggregate3Value,
}

/// One call found in a batch, before any decoding of its calldata.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Item<'a> {
    /// Raw calldata of the call (selector plus arguments).
    pub data: &'a [u8],
    /// The contract the call is sent to. `None` for `multicall(bytes[])`,
    /// where the batch contract calls itself.
    pub target: Option<Address>,
    /// ETH sent with the call; only `aggregate3Value` carries one.
    pub value: Option<Word>,
}

/// The validated array of calls inside a batch.
#[derive(Clone, Copy, Debug)]
pub enum Items<'a> {
    /// A `bytes[]` of calls.
    Bytes(BytesArray<'a>),
    /// An array of `(address, .., bytes)` tuples; `bool` says the tuple has a
    /// `uint256 value` as its third static field.
    Tuples(TupleArray<'a>, bool),
}

impl<'a> Items<'a> {
    /// Number of calls.
    pub fn len(&self) -> usize {
        match self {
            Items::Bytes(a) => a.len(),
            Items::Tuples(t, _) => t.len(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Bytes inside the array region that the layout does not account for.
    pub fn slack(&self) -> usize {
        match self {
            Items::Bytes(a) => a.slack(),
            Items::Tuples(t, _) => t.slack(),
        }
    }

    /// Index into the arguments one past the last byte the array uses.
    pub fn end(&self) -> usize {
        match self {
            Items::Bytes(a) => a.end(),
            Items::Tuples(t, _) => t.end(),
        }
    }

    /// Call `i`, or `None` if `i >= len()`.
    pub fn get(&self, i: usize) -> Option<Item<'a>> {
        match self {
            Items::Bytes(a) => Some(Item {
                data: a.get(i)?,
                target: None,
                value: None,
            }),
            Items::Tuples(t, has_value) => {
                let e: Entry<'a> = t.get(i)?;
                Some(Item {
                    data: e.data,
                    target: e.field(0)?.to_address(),
                    value: if *has_value { e.field(2) } else { None },
                })
            }
        }
    }
}

/// A decoded, fully validated batch call.
#[derive(Clone, Copy, Debug)]
pub struct Multicall<'a> {
    pub kind: Kind,
    /// The inner calls, still as raw bytes.
    pub calls: Items<'a>,
    /// Bytes after the last byte the layout uses. The EVM ignores them.
    pub trailing: usize,
}

fn selector(data: &[u8]) -> Option<[u8; 4]> {
    data.get(..4).map(|s| [s[0], s[1], s[2], s[3]])
}

/// True if `data` starts with one of the batch selectors in the table above.
/// Says nothing about whether the rest decodes.
pub fn is_multicall(data: &[u8]) -> bool {
    matches!(
        selector(data),
        Some(
            SEL_MULTICALL
                | SEL_MULTICALL_DEADLINE
                | SEL_MULTICALL_PREVHASH
                | SEL_AGGREGATE
                | SEL_TRY_AGGREGATE
                | SEL_BLOCK_AND_AGGREGATE
                | SEL_TRY_BLOCK_AND_AGGREGATE
                | SEL_AGGREGATE3
                | SEL_AGGREGATE3_VALUE
        )
    )
}

/// Decode a batch call. Any other selector is `UnknownSelector`.
pub fn decode_multicall(data: &[u8]) -> Result<Multicall<'_>, DecodeError> {
    let sel = selector(data).ok_or(DecodeError::MissingSelector { got: data.len() })?;
    // (head words, head slot of the array, tuple layout if not `bytes[]`)
    let (words, arg, tuple): (usize, usize, Option<&'static [Field]>) = match sel {
        SEL_MULTICALL => (1, 0, None),
        SEL_MULTICALL_DEADLINE | SEL_MULTICALL_PREVHASH => (2, 1, None),
        SEL_AGGREGATE | SEL_BLOCK_AND_AGGREGATE => (1, 0, Some(CALL)),
        SEL_TRY_AGGREGATE | SEL_TRY_BLOCK_AND_AGGREGATE => (2, 1, Some(CALL)),
        SEL_AGGREGATE3 => (1, 0, Some(CALL3)),
        SEL_AGGREGATE3_VALUE => (1, 0, Some(CALL3_VALUE)),
        other => return Err(DecodeError::UnknownSelector(other)),
    };
    // Checks that the head is present; its trailing count is meaningless for
    // dynamic data, so it is ignored in favour of the array's own extent.
    let (head, _) = Args::new(data, words)?;
    let kind = match sel {
        SEL_MULTICALL_DEADLINE => Kind::Deadline(head.uint256(0)?),
        SEL_MULTICALL_PREVHASH => Kind::PreviousBlockhash(head.uint256(0)?),
        SEL_AGGREGATE => Kind::Aggregate,
        SEL_BLOCK_AND_AGGREGATE => Kind::BlockAndAggregate,
        SEL_TRY_AGGREGATE => Kind::TryAggregate {
            require_success: head.boolean(0)?,
        },
        SEL_TRY_BLOCK_AND_AGGREGATE => Kind::TryBlockAndAggregate {
            require_success: head.boolean(0)?,
        },
        SEL_AGGREGATE3 => Kind::Aggregate3,
        SEL_AGGREGATE3_VALUE => Kind::Aggregate3Value,
        _ => Kind::Plain,
    };
    let args = data
        .get(4..)
        .ok_or(DecodeError::MissingSelector { got: data.len() })?;
    let calls = match tuple {
        None => Items::Bytes(BytesArray::parse(args, 32 * words, arg)?),
        Some(fields) => Items::Tuples(
            TupleArray::parse(args, 32 * words, arg, fields)?,
            fields.len() == CALL3_VALUE.len(),
        ),
    };
    let trailing = args.len().saturating_sub(calls.end());
    Ok(Multicall {
        kind,
        calls,
        trailing,
    })
}

/// One leaf call found inside a (possibly nested) batch.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InnerCall<'a> {
    /// 1 for a call directly inside the outermost batch, 2 for a call inside
    /// a batch inside it, and so on.
    pub depth: usize,
    /// Raw calldata of the call (selector plus arguments).
    pub data: &'a [u8],
    /// The contract this call is sent to, if the batch signature names one.
    pub target: Option<Address>,
    /// ETH sent with this call, if the batch signature carries one.
    pub value: Option<Word>,
}

#[derive(Clone, Copy, Debug)]
struct Frame<'a> {
    items: Items<'a>,
    next: usize,
}

/// Iterator over every leaf call of a batch, in order, descending into nested
/// batches. A nested batch is never yielded itself, only its contents.
///
/// After the first `Err` the iterator is finished: a batch that cannot be read
/// completely cannot be vouched for.
#[derive(Clone, Debug)]
pub struct Calls<'a> {
    stack: [Option<Frame<'a>>; MAX_DEPTH],
    depth: usize,
    hidden: usize,
    done: bool,
}

/// Start walking the leaf calls of the batch in `data`.
pub fn calls(data: &[u8]) -> Result<Calls<'_>, DecodeError> {
    let mc = decode_multicall(data)?;
    let mut stack = [None; MAX_DEPTH];
    if let Some(slot) = stack.first_mut() {
        *slot = Some(Frame {
            items: mc.calls,
            next: 0,
        });
    }
    Ok(Calls {
        stack,
        depth: 1,
        hidden: mc.calls.slack().saturating_add(mc.trailing),
        done: false,
    })
}

impl Calls<'_> {
    /// Bytes ignored by the EVM (gaps and trailing bytes) in every batch
    /// entered so far. Read it after the iterator is exhausted.
    pub fn hidden(&self) -> usize {
        self.hidden
    }

    fn fail(&mut self, e: DecodeError) -> Option<Result<InnerCall<'static>, DecodeError>> {
        self.done = true;
        Some(Err(e))
    }
}

impl<'a> Iterator for Calls<'a> {
    type Item = Result<InnerCall<'a>, DecodeError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.done {
            return None;
        }
        loop {
            if self.depth == 0 {
                self.done = true;
                return None;
            }
            let idx = self.depth - 1;
            let Some(frame) = self.stack.get_mut(idx).and_then(|f| f.as_mut()) else {
                self.done = true;
                return None;
            };
            let index = frame.next;
            if index >= frame.items.len() {
                // This level is exhausted; resume its parent.
                if let Some(slot) = self.stack.get_mut(idx) {
                    *slot = None;
                }
                self.depth -= 1;
                continue;
            }
            let Some(item) = frame.items.get(index) else {
                // Unreachable for a validated array. If it ever happened,
                // skipping the call would hide it, so fail instead.
                return self.fail(DecodeError::BadElementOffset { index });
            };
            frame.next += 1;

            if !is_multicall(item.data) {
                return Some(Ok(InnerCall {
                    depth: self.depth,
                    data: item.data,
                    target: item.target,
                    value: item.value,
                }));
            }
            match decode_multicall(item.data) {
                Err(e) => return self.fail(e),
                Ok(_) if self.depth >= MAX_DEPTH => return self.fail(DecodeError::NestingTooDeep),
                Ok(inner) => {
                    self.hidden = self
                        .hidden
                        .saturating_add(inner.calls.slack())
                        .saturating_add(inner.trailing);
                    if let Some(slot) = self.stack.get_mut(self.depth) {
                        *slot = Some(Frame {
                            items: inner.calls,
                            next: 0,
                        });
                    }
                    self.depth += 1;
                }
            }
        }
    }
}

#[cfg(test)]
pub(crate) mod testutil {
    //! Builders for batch calldata in tests.
    use crate::calldata::testutil::uint_word;
    use crate::dynabi::testutil::{args_single, encode_bytes_array, encode_tuples, Tup};
    use std::vec::Vec;

    use super::*;

    pub fn multicall_data(items: &[Vec<u8>]) -> Vec<u8> {
        let mut v = SEL_MULTICALL.to_vec();
        v.extend(args_single(items));
        v
    }

    /// A word holding the address `[b; 20]`.
    pub fn target_word(b: u8) -> [u8; 32] {
        let mut w = [0u8; 32];
        w[12..].fill(b);
        w
    }

    /// Multicall3 call with `head` static words, then the array offset, then a
    /// canonical array of `items`.
    pub fn tuple_batch(sel: [u8; 4], head: &[[u8; 32]], items: &[Tup]) -> Vec<u8> {
        let mut v = sel.to_vec();
        for w in head {
            v.extend_from_slice(w);
        }
        v.extend(uint_word(32 * (head.len() as u64 + 1)));
        v.extend(encode_tuples(items));
        v
    }

    /// `aggregate3` of `(target byte, allowFailure, calldata)`.
    pub fn aggregate3(items: &[(u8, bool, Vec<u8>)]) -> Vec<u8> {
        let t: Vec<Tup> = items
            .iter()
            .map(|(a, f, d)| (vec![target_word(*a), uint_word(*f as u64)], d.clone()))
            .collect();
        tuple_batch(SEL_AGGREGATE3, &[], &t)
    }

    /// `aggregate3Value` of `(target byte, allowFailure, value, calldata)`.
    pub fn aggregate3_value(items: &[(u8, bool, u64, Vec<u8>)]) -> Vec<u8> {
        let t: Vec<Tup> = items
            .iter()
            .map(|(a, f, v, d)| {
                (
                    vec![target_word(*a), uint_word(*f as u64), uint_word(*v)],
                    d.clone(),
                )
            })
            .collect();
        tuple_batch(SEL_AGGREGATE3_VALUE, &[], &t)
    }

    /// `aggregate` of `(target byte, calldata)`.
    pub fn aggregate(items: &[(u8, Vec<u8>)]) -> Vec<u8> {
        let t: Vec<Tup> = items
            .iter()
            .map(|(a, d)| (vec![target_word(*a)], d.clone()))
            .collect();
        tuple_batch(SEL_AGGREGATE, &[], &t)
    }

    /// `multicall(uint256 deadline, bytes[])` with a canonical layout.
    pub fn multicall_deadline(deadline: u64, items: &[Vec<u8>]) -> Vec<u8> {
        let mut v = SEL_MULTICALL_DEADLINE.to_vec();
        v.extend(uint_word(deadline));
        v.extend(uint_word(64));
        v.extend(encode_bytes_array(items));
        v
    }
}

#[cfg(test)]
mod tests {
    use super::testutil::*;
    use super::*;
    use crate::calldata::testutil::{addr_word, calldata, max_word, uint_word};
    use crate::calldata::SEL_APPROVE;
    use std::vec;
    use std::vec::Vec;

    fn approve(spender: u8) -> Vec<u8> {
        calldata(SEL_APPROVE, &[addr_word(spender), max_word()])
    }

    fn leaves(data: &[u8]) -> Result<Vec<(usize, Vec<u8>)>, DecodeError> {
        calls(data)?
            .map(|r| r.map(|c| (c.depth, c.data.to_vec())))
            .collect()
    }

    #[test]
    fn selectors_match_their_signatures() {
        // Verified with tools/verify_selectors.py.
        assert_eq!(SEL_MULTICALL, [0xac, 0x96, 0x50, 0xd8]);
        assert_eq!(SEL_MULTICALL_DEADLINE, [0x5a, 0xe4, 0x01, 0xdc]);
        assert_eq!(SEL_MULTICALL_PREVHASH, [0x1f, 0x04, 0x64, 0xd1]);
    }

    #[test]
    fn plain_batch_decodes() {
        let inner = vec![approve(1), approve(2)];
        let data = multicall_data(&inner);
        assert!(is_multicall(&data));
        let mc = decode_multicall(&data).unwrap();
        assert_eq!(mc.kind, Kind::Plain);
        assert_eq!(mc.calls.len(), 2);
        assert_eq!(mc.trailing, 0);
        assert_eq!(mc.calls.slack(), 0);
        assert_eq!(
            leaves(&data).unwrap(),
            vec![(1, approve(1)), (1, approve(2))]
        );
    }

    #[test]
    fn deadline_variant_keeps_its_static_word() {
        let data = multicall_deadline(1_700_000_000, &[approve(1)]);
        let mc = decode_multicall(&data).unwrap();
        assert_eq!(mc.kind, Kind::Deadline(Word(uint_word(1_700_000_000))));
        assert_eq!(mc.calls.len(), 1);
        assert_eq!(mc.trailing, 0);
    }

    #[test]
    fn previous_blockhash_variant() {
        let mut data = SEL_MULTICALL_PREVHASH.to_vec();
        data.extend([0x77; 32]);
        data.extend(uint_word(64));
        data.extend(crate::dynabi::testutil::encode_bytes_array(&[approve(1)]));
        let mc = decode_multicall(&data).unwrap();
        assert_eq!(mc.kind, Kind::PreviousBlockhash(Word([0x77; 32])));
    }

    #[test]
    fn non_multicall_selector_is_unknown() {
        assert!(!is_multicall(&approve(1)));
        assert!(matches!(
            decode_multicall(&approve(1)),
            Err(DecodeError::UnknownSelector(_))
        ));
        assert!(matches!(
            decode_multicall(&[1, 2]),
            Err(DecodeError::MissingSelector { got: 2 })
        ));
    }

    #[test]
    fn selector_only_is_truncated() {
        for sel in [
            SEL_MULTICALL,
            SEL_MULTICALL_DEADLINE,
            SEL_MULTICALL_PREVHASH,
        ] {
            assert!(matches!(
                decode_multicall(&sel),
                Err(DecodeError::Truncated { .. })
            ));
        }
    }

    #[test]
    fn deadline_variant_reports_the_right_arg_index_on_a_bad_offset() {
        let mut data = multicall_deadline(5, &[approve(1)]);
        data[4 + 32..4 + 64].copy_from_slice(&uint_word(32)); // into the head
        assert_eq!(
            decode_multicall(&data).unwrap_err(),
            DecodeError::BadOffset { arg: 1 }
        );
    }

    #[test]
    fn trailing_bytes_after_the_batch_are_counted() {
        let mut data = multicall_data(&[approve(1)]);
        data.extend([1, 2, 3, 4, 5]);
        assert_eq!(decode_multicall(&data).unwrap().trailing, 5);
        let mut it = calls(&data).unwrap();
        assert_eq!(it.by_ref().count(), 1);
        assert_eq!(it.hidden(), 5);
    }

    #[test]
    fn nested_batches_are_flattened_in_order_with_their_depth() {
        let inner = multicall_data(&[approve(3), approve(4)]);
        let outer = multicall_data(&[approve(1), inner, approve(2)]);
        assert_eq!(
            leaves(&outer).unwrap(),
            vec![
                (1, approve(1)),
                (2, approve(3)),
                (2, approve(4)),
                (1, approve(2)),
            ]
        );
    }

    #[test]
    fn empty_batches_yield_nothing() {
        let outer = multicall_data(&[multicall_data(&[]), multicall_data(&[])]);
        assert_eq!(leaves(&outer).unwrap(), vec![]);
    }

    fn nest(levels: usize) -> Vec<u8> {
        let mut data = multicall_data(&[approve(9)]);
        for _ in 1..levels {
            data = multicall_data(&[data]);
        }
        data
    }

    #[test]
    fn nesting_up_to_the_limit_is_accepted_and_one_more_is_not() {
        let ok = nest(MAX_DEPTH);
        assert_eq!(leaves(&ok).unwrap(), vec![(MAX_DEPTH, approve(9))]);
        let too_deep = nest(MAX_DEPTH + 1);
        assert_eq!(leaves(&too_deep).unwrap_err(), DecodeError::NestingTooDeep);
    }

    #[test]
    fn the_iterator_stops_after_an_error() {
        let data = nest(MAX_DEPTH + 1);
        let mut it = calls(&data).unwrap();
        assert_eq!(it.next(), Some(Err(DecodeError::NestingTooDeep)));
        assert_eq!(it.next(), None);
        assert_eq!(it.next(), None);
    }

    #[test]
    fn a_malformed_nested_batch_fails_the_whole_walk() {
        let mut inner = multicall_data(&[approve(3)]);
        let last = inner.len() - 1;
        inner[last] = 1; // dirty padding inside the nested batch
        let outer = multicall_data(&[approve(1), inner]);
        let mut it = calls(&outer).unwrap();
        assert!(matches!(it.next(), Some(Ok(_))));
        assert!(matches!(
            it.next(),
            Some(Err(DecodeError::DirtyBytesPadding { .. }))
        ));
        assert_eq!(it.next(), None);
    }

    #[test]
    fn nested_slack_is_added_to_hidden() {
        // Inner batch with 32 junk bytes between its head and its array.
        let mut inner = SEL_MULTICALL.to_vec();
        inner.extend(uint_word(32 + 32));
        inner.extend([0xcc; 32]);
        inner.extend(crate::dynabi::testutil::encode_bytes_array(&[approve(3)]));
        let outer = multicall_data(&[inner]);
        let mut it = calls(&outer).unwrap();
        assert_eq!(it.by_ref().filter(|r| r.is_ok()).count(), 1);
        assert_eq!(it.hidden(), 32);
    }

    #[test]
    fn many_offsets_cannot_alias_one_payload() {
        // Classic amplification: N elements all pointing at the same large
        // payload. Rejected by the overlap rule, so work stays linear.
        let payload = multicall_data(&vec![approve(1); 50]);
        let mut args = uint_word(32).to_vec();
        let n = 200u64;
        args.extend(uint_word(n));
        let table = 32 * n;
        for _ in 0..n {
            args.extend(uint_word(table)); // every element at the same place
        }
        args.extend(uint_word(payload.len() as u64));
        args.extend(&payload);
        args.resize(args.len() + (32 - payload.len() % 32) % 32, 0);
        let mut data = SEL_MULTICALL.to_vec();
        data.extend(args);
        assert_eq!(
            leaves(&data).unwrap_err(),
            DecodeError::OverlappingElement { index: 1 }
        );
    }

    #[test]
    fn leaves_are_subslices_of_the_input() {
        let outer = multicall_data(&[approve(1), multicall_data(&[approve(2)])]);
        let base = outer.as_ptr() as usize;
        for c in calls(&outer).unwrap() {
            let c = c.unwrap();
            let p = c.data.as_ptr() as usize;
            assert!(p >= base && p + c.data.len() <= base + outer.len());
        }
    }

    // ------------------------------------------------------------ Multicall3

    use crate::dynabi::testutil::{encode_tuples, Tup};

    fn t(b: u8) -> Address {
        Address([b; 20])
    }

    #[test]
    fn multicall3_selectors_match_their_signatures() {
        // Verified with tools/verify_selectors.py (independent Keccak-256).
        assert_eq!(SEL_AGGREGATE, [0x25, 0x2d, 0xba, 0x42]);
        assert_eq!(SEL_TRY_AGGREGATE, [0xbc, 0xe3, 0x8b, 0xd7]);
        assert_eq!(SEL_BLOCK_AND_AGGREGATE, [0xc3, 0x07, 0x7f, 0xa9]);
        assert_eq!(SEL_TRY_BLOCK_AND_AGGREGATE, [0x39, 0x95, 0x42, 0xe9]);
        assert_eq!(SEL_AGGREGATE3, [0x82, 0xad, 0x56, 0xcb]);
        assert_eq!(SEL_AGGREGATE3_VALUE, [0x17, 0x4d, 0xea, 0x71]);
    }

    #[test]
    fn every_batch_selector_is_recognised_and_nothing_else() {
        for sel in [
            SEL_MULTICALL,
            SEL_MULTICALL_DEADLINE,
            SEL_MULTICALL_PREVHASH,
            SEL_AGGREGATE,
            SEL_TRY_AGGREGATE,
            SEL_BLOCK_AND_AGGREGATE,
            SEL_TRY_BLOCK_AND_AGGREGATE,
            SEL_AGGREGATE3,
            SEL_AGGREGATE3_VALUE,
        ] {
            assert!(is_multicall(&sel));
            assert!(matches!(
                decode_multicall(&sel),
                Err(DecodeError::Truncated { .. })
            ));
        }
        assert!(!is_multicall(&approve(1)));
        assert!(!is_multicall(&[0x82, 0xad, 0x56]));
    }

    #[test]
    fn aggregate3_exposes_target_in_order_and_no_value() {
        let data = aggregate3(&[(0xa1, false, approve(1)), (0xa2, true, approve(2))]);
        let mc = decode_multicall(&data).unwrap();
        assert_eq!(mc.kind, Kind::Aggregate3);
        assert_eq!((mc.calls.len(), mc.calls.slack(), mc.trailing), (2, 0, 0));
        let got: Vec<_> = calls(&data).unwrap().map(|r| r.unwrap()).collect();
        assert_eq!(got.len(), 2);
        assert_eq!(
            (got[0].depth, got[0].target, got[0].value),
            (1, Some(t(0xa1)), None)
        );
        assert_eq!(got[0].data, &approve(1)[..]);
        assert_eq!(got[1].target, Some(t(0xa2)));
        assert_eq!(got[1].data, &approve(2)[..]);
    }

    #[test]
    fn aggregate3_value_exposes_the_value() {
        let data = aggregate3_value(&[(0xa1, false, 7, approve(1)), (0xa2, true, 0, approve(2))]);
        let mc = decode_multicall(&data).unwrap();
        assert_eq!(mc.kind, Kind::Aggregate3Value);
        let got: Vec<_> = calls(&data).unwrap().map(|r| r.unwrap()).collect();
        assert_eq!(got[0].value, Some(Word(uint_word(7))));
        assert_eq!(got[1].value, Some(Word::ZERO));
        assert_eq!(got[1].target, Some(t(0xa2)));
    }

    #[test]
    fn aggregate_variants_decode_and_keep_their_flag() {
        let items: Vec<Tup> = vec![(vec![target_word(0xb1)], approve(1))];
        let data = tuple_batch(SEL_AGGREGATE, &[], &items);
        assert_eq!(decode_multicall(&data).unwrap().kind, Kind::Aggregate);
        let data = tuple_batch(SEL_BLOCK_AND_AGGREGATE, &[], &items);
        assert_eq!(
            decode_multicall(&data).unwrap().kind,
            Kind::BlockAndAggregate
        );
        for flag in [false, true] {
            let head = [uint_word(flag as u64)];
            let data = tuple_batch(SEL_TRY_AGGREGATE, &head, &items);
            assert_eq!(
                decode_multicall(&data).unwrap().kind,
                Kind::TryAggregate {
                    require_success: flag
                }
            );
            let data = tuple_batch(SEL_TRY_BLOCK_AND_AGGREGATE, &head, &items);
            let mc = decode_multicall(&data).unwrap();
            assert_eq!(
                mc.kind,
                Kind::TryBlockAndAggregate {
                    require_success: flag
                }
            );
            assert_eq!(mc.calls.get(0).unwrap().target, Some(t(0xb1)));
            assert_eq!(mc.calls.get(0).unwrap().value, None);
        }
        // The convenience builder agrees.
        let data = aggregate(&[(0xb1, approve(1))]);
        assert_eq!(leaves(&data).unwrap(), vec![(1, approve(1))]);
    }

    #[test]
    fn a_bad_require_success_flag_is_dirty_padding() {
        let items: Vec<Tup> = vec![(vec![target_word(0xb1)], approve(1))];
        let data = tuple_batch(SEL_TRY_AGGREGATE, &[uint_word(2)], &items);
        assert_eq!(
            decode_multicall(&data).unwrap_err(),
            DecodeError::DirtyPadding { arg: 0 }
        );
    }

    #[test]
    fn a_dirty_target_or_allow_failure_is_an_error() {
        let mut data = aggregate3(&[(0xa1, false, approve(1))]);
        // args: offset 4..36, length 36..68, table 68..100, tuple at 100:
        // target 100..132, allowFailure 132..164.
        data[100 + 3] = 1;
        assert_eq!(
            decode_multicall(&data).unwrap_err(),
            DecodeError::DirtyElementField { index: 0, field: 0 }
        );
        let mut data = aggregate3(&[(0xa1, false, approve(1))]);
        data[132 + 31] = 2;
        assert_eq!(
            decode_multicall(&data).unwrap_err(),
            DecodeError::DirtyElementField { index: 0, field: 1 }
        );
    }

    #[test]
    fn batches_of_both_families_nest_inside_each_other() {
        // aggregate3 -> multicall(bytes[]) -> aggregate -> approve
        let leaf = approve(5);
        let level3 = aggregate(&[(0xc3, leaf.clone())]);
        let level2 = multicall_data(&[approve(4), level3]);
        let level1 = aggregate3(&[(0xc1, true, approve(3)), (0xc2, false, level2)]);
        let got: Vec<_> = calls(&level1).unwrap().map(|r| r.unwrap()).collect();
        let view: Vec<_> = got.iter().map(|c| (c.depth, c.target)).collect();
        assert_eq!(
            view,
            vec![
                (1, Some(t(0xc1))), // approve(3), called on 0xc1
                (2, None),          // approve(4) inside multicall(bytes[]): self-call
                (3, Some(t(0xc3))), // approve(5) inside aggregate
            ]
        );
        assert_eq!(got[2].data, &leaf[..]);
    }

    #[test]
    fn the_depth_limit_counts_both_families() {
        let mut data = aggregate3(&[(1, false, approve(9))]);
        for i in 1..MAX_DEPTH {
            data = if i % 2 == 0 {
                aggregate3(&[(1, false, data)])
            } else {
                multicall_data(&[data])
            };
        }
        assert_eq!(leaves(&data).unwrap(), vec![(MAX_DEPTH, approve(9))]);
        let too_deep = aggregate3(&[(1, false, data)]);
        assert_eq!(leaves(&too_deep).unwrap_err(), DecodeError::NestingTooDeep);
    }

    #[test]
    fn hidden_bytes_inside_tuples_are_counted_at_every_level() {
        // Inner aggregate3 with 32 junk bytes between a tuple head and its
        // bytes, wrapped in an outer aggregate3 with 5 trailing bytes.
        let it: Vec<Tup> = vec![(vec![target_word(1), uint_word(0)], approve(3))];
        let mut inner = tuple_batch(SEL_AGGREGATE3, &[], &it);
        // 4 + offset 32 + length 32 + table 32 + head 64 + bytes-offset 32 = 196
        inner.splice(196..196, [0xcc; 32]);
        inner[4 + 32 + 32 + 32 + 64..4 + 32 + 32 + 32 + 96].copy_from_slice(&uint_word(96 + 32));
        let mut outer = aggregate3(&[(7, false, inner)]);
        outer.extend([1, 2, 3, 4, 5]);
        let mut it = calls(&outer).unwrap();
        assert_eq!(it.by_ref().filter(|r| r.is_ok()).count(), 1);
        assert_eq!(it.hidden(), 32 + 5);
    }

    #[test]
    fn a_malformed_nested_aggregate3_fails_the_whole_walk() {
        let mut inner = aggregate3(&[(1, false, approve(3))]);
        let last = inner.len() - 1;
        inner[last] = 1; // dirty padding
        let outer = aggregate3(&[(2, false, approve(1)), (3, false, inner)]);
        let mut walk = calls(&outer).unwrap();
        assert!(matches!(walk.next(), Some(Ok(_))));
        assert!(matches!(
            walk.next(),
            Some(Err(DecodeError::DirtyBytesPadding { .. }))
        ));
        assert_eq!(walk.next(), None);
    }

    #[test]
    fn many_tuple_offsets_cannot_alias_one_payload() {
        // N tuple offsets all pointing at one tuple holding a large batch.
        let payload = multicall_data(&vec![approve(1); 50]);
        let one = encode_tuples(&[(vec![target_word(1), uint_word(0)], payload)]);
        // `one` = len | off | tuple...; rebuild with many offsets to the tuple.
        let n = 200u64;
        let table = 32 * n;
        let mut arr = uint_word(n).to_vec();
        for _ in 0..n {
            arr.extend(uint_word(table));
        }
        arr.extend(&one[64..]); // the tuple itself, without len and offset
        let mut data = SEL_AGGREGATE3.to_vec();
        data.extend(uint_word(32));
        data.extend(arr);
        assert_eq!(
            leaves(&data).unwrap_err(),
            DecodeError::OverlappingElement { index: 1 }
        );
    }

    #[test]
    fn tuple_leaves_are_subslices_of_the_input() {
        let outer = aggregate3(&[
            (1, false, approve(1)),
            (2, true, aggregate(&[(3, approve(2))])),
        ]);
        let base = outer.as_ptr() as usize;
        for c in calls(&outer).unwrap() {
            let c = c.unwrap();
            let p = c.data.as_ptr() as usize;
            assert!(p >= base && p + c.data.len() <= base + outer.len());
        }
    }
}
