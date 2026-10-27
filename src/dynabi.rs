//! Offset-based reading of ABI `bytes[]` and `(static fields.., bytes)[]`
//! arguments. No heap, no panics.
//!
//! Layout being read (all offsets are relative to the start of the region
//! they live in, as the ABI specifies):
//!
//! ```text
//! args:   [ head ... | offset-of-array | ... ]   (head_len bytes)
//! array:  [ n | off_0 .. off_{n-1} | element bodies ... ]
//! body:   [ len | len bytes | zero padding to 32 ]
//! ```
//!
//! The parser is strict on purpose, because a scanner that reads a layout the
//! contract reads differently can be fooled:
//!
//! * every offset and length must fit in 64 bits **and** point inside the
//!   data (no wrap-around, no giant counts);
//! * the array offset may not point into the head (self-reference);
//! * elements must start at or after the end of the offset table and of the
//!   previous element. This rules out overlapping and aliased regions, which
//!   is also what bounds the total work: every byte is visited at most once
//!   per nesting level, so many offsets cannot point at one large payload;
//! * padding after each element must be present and zero;
//! * gaps between regions are **not** an error but are counted in
//!   [`BytesArray::slack`], because the EVM ignores them and an attacker can
//!   hide bytes there.
//!
//! The whole array is validated once in [`BytesArray::parse`]; reading
//! elements afterwards cannot fail.
//!
//! [`TupleArray`] reads arrays of tuples whose members are a few static
//! words followed by one `bytes` (Multicall3's `(address,bytes)`,
//! `(address,bool,bytes)` and `(address,bool,uint256,bytes)`). It applies the
//! same rules to the array, and the same rules again inside each tuple: the
//! `bytes` offset is relative to the start of the tuple, must be aligned and
//! may not point into the tuple's own head; static fields must be canonical;
//! the tuple ends where its `bytes` padding ends, and the next tuple may not
//! start earlier.
//!
//! [`DynBytes`] reads one `bytes` argument under the same rules (aligned
//! offset, not inside the head, length inside the data, zero padding). It is
//! used for the `commands` of a Universal Router plan and for the signature
//! of a Permit2 permit.

use crate::abi::{DecodeError, Word};

/// A 64-bit-bounded `usize`; `None` if the word does not fit.
pub(crate) fn to_usize(w: &Word) -> Option<usize> {
    if !w.fits(64) {
        return None;
    }
    let mut b = [0u8; 8];
    b.copy_from_slice(&w.0[24..]);
    usize::try_from(u64::from_be_bytes(b)).ok()
}

/// The 32 bytes at `pos`, or `None` if they are not all inside `buf`.
pub(crate) fn word_at(buf: &[u8], pos: usize) -> Option<Word> {
    let end = pos.checked_add(32)?;
    let s = buf.get(pos..end)?;
    let mut w = [0u8; 32];
    w.copy_from_slice(s);
    Some(Word(w))
}

/// `Truncated` error in terms of the whole calldata (selector included).
fn truncated(args: &[u8], needed_in_args: usize) -> DecodeError {
    DecodeError::Truncated {
        expected: needed_in_args.saturating_add(4),
        got: args.len().saturating_add(4),
    }
}

/// A validated single `bytes` argument.
#[derive(Clone, Copy, Debug)]
pub struct DynBytes<'a> {
    data: &'a [u8],
    /// Index into `args` of the length word.
    start: usize,
    /// One past the zero padding that follows the data.
    end: usize,
    /// Bytes between `min_offset` and `start`.
    gap: usize,
}

impl<'a> DynBytes<'a> {
    /// Parse the `bytes` whose offset sits in head slot `arg`.
    ///
    /// `args` is the data the offset is relative to. `min_offset` is the
    /// first position the value may start at: the end of the head, or the end
    /// of whatever region must come before it. A smaller offset is
    /// `BadOffset { arg }`.
    pub fn parse(args: &'a [u8], min_offset: usize, arg: usize) -> Result<Self, DecodeError> {
        let slot = arg.saturating_mul(32);
        let off_word =
            word_at(args, slot).ok_or_else(|| truncated(args, slot.saturating_add(32)))?;
        let bad = DecodeError::BadOffset { arg };
        let off = to_usize(&off_word).ok_or(bad)?;
        if off % 32 != 0 || off < min_offset || off > args.len() {
            return Err(bad);
        }
        let body = args.get(off..).ok_or(bad)?;
        let h = Header {
            body,
            body_start: off,
            len: 0,
            table: 0,
            gap: off - min_offset,
        };
        let padded_end = read_bytes(args, &h, 0, arg, bad)?;
        let len = word_at(body, 0)
            .and_then(|w| to_usize(&w))
            .ok_or(DecodeError::BadElementLength { index: arg })?;
        // `read_bytes` already proved `32 + len` is inside `body`.
        let data = body
            .get(32..32usize.saturating_add(len))
            .ok_or(DecodeError::BadElementLength { index: arg })?;
        Ok(Self {
            data,
            start: off,
            end: off.saturating_add(padded_end),
            gap: h.gap,
        })
    }

    /// The bytes themselves.
    pub fn data(&self) -> &'a [u8] {
        self.data
    }

    /// Index into `args` of the length word.
    pub fn start(&self) -> usize {
        self.start
    }

    /// Index into `args` one past the zero padding.
    pub fn end(&self) -> usize {
        self.end
    }

    /// Bytes between `min_offset` and the start of the value. The EVM ignores
    /// them.
    pub fn gap(&self) -> usize {
        self.gap
    }
}

/// A validated `bytes[]` argument.
#[derive(Clone, Copy, Debug)]
pub struct BytesArray<'a> {
    /// Everything after the length word: offset table, then element bodies.
    body: &'a [u8],
    len: usize,
    /// Bytes inside the region that no part of the layout accounts for.
    slack: usize,
    /// One past the last byte used, as an index into the `args` slice.
    end: usize,
}

/// What every `T[]` argument shares: the offset slot, the length word and the
/// offset table. Validated identically for `bytes[]` and tuple arrays.
struct Header<'a> {
    /// Everything after the length word: offset table, then element bodies.
    body: &'a [u8],
    /// Index into `args` of the first byte of `body`.
    body_start: usize,
    len: usize,
    /// Size in bytes of the offset table.
    table: usize,
    /// Bytes between the end of the head and the start of the array.
    gap: usize,
}

fn array_header(args: &[u8], head_len: usize, arg: usize) -> Result<Header<'_>, DecodeError> {
    let slot = arg.saturating_mul(32);
    let off_word = word_at(args, slot).ok_or_else(|| truncated(args, slot.saturating_add(32)))?;
    let off = to_usize(&off_word).ok_or(DecodeError::BadOffset { arg })?;
    // ABI dynamic offsets are word-aligned relative to the start of the
    // argument tuple. Accepting unaligned offsets makes this parser more
    // permissive than canonical ABI encoders and complicates differential
    // reasoning about what a target contract will decode.
    if off % 32 != 0 || off < head_len || off > args.len() {
        return Err(DecodeError::BadOffset { arg });
    }

    let len_word = word_at(args, off).ok_or_else(|| truncated(args, off.saturating_add(32)))?;
    let len = to_usize(&len_word).ok_or(DecodeError::BadArrayLength)?;

    let body_start = off.checked_add(32).ok_or(DecodeError::BadOffset { arg })?;
    let body = args
        .get(body_start..)
        .ok_or(DecodeError::BadOffset { arg })?;

    // The offset table alone must fit: this caps `len` by the data size.
    let table = len
        .checked_mul(32)
        .filter(|t| *t <= body.len())
        .ok_or(DecodeError::BadArrayLength)?;

    Ok(Header {
        body,
        body_start,
        len,
        table,
        gap: off - head_len,
    })
}

/// Validate the `bytes` value whose length word is at `pos` in `h.body` and
/// return one past the zero padding that follows its data.
/// `bad_pos` is the error for a `pos` that leaves no room for a length word.
fn read_bytes(
    args: &[u8],
    h: &Header<'_>,
    pos: usize,
    index: usize,
    bad_pos: DecodeError,
) -> Result<usize, DecodeError> {
    let body = h.body;
    let data_start = pos
        .checked_add(32)
        .filter(|e| *e <= body.len())
        .ok_or(bad_pos)?;
    let l = word_at(body, pos)
        .and_then(|w| to_usize(&w))
        .ok_or(DecodeError::BadElementLength { index })?;
    let data_end = data_start
        .checked_add(l)
        .filter(|e| *e <= body.len())
        .ok_or(DecodeError::BadElementLength { index })?;
    let padded = l
        .checked_add(31)
        .map(|v| v / 32 * 32)
        .ok_or(DecodeError::BadElementLength { index })?;
    let padded_end = data_start
        .checked_add(padded)
        .ok_or(DecodeError::BadElementLength { index })?;
    let pad = body
        .get(data_end..padded_end)
        .ok_or_else(|| truncated(args, h.body_start.saturating_add(padded_end)))?;
    if pad.iter().any(|&b| b != 0) {
        return Err(DecodeError::DirtyBytesPadding { index });
    }
    Ok(padded_end)
}

impl<'a> BytesArray<'a> {
    /// Parse the `bytes[]` whose offset sits in head slot `arg`.
    ///
    /// `args` is the calldata **after** the 4-byte selector. `head_len` is
    /// the size in bytes of the head (static words plus offset slots); the
    /// array may not start inside it.
    pub fn parse(args: &'a [u8], head_len: usize, arg: usize) -> Result<Self, DecodeError> {
        let h = array_header(args, head_len, arg)?;

        let mut cursor = h.table; // first byte an element may start at
        let mut slack = h.gap;
        for index in 0..h.len {
            let eo = word_at(h.body, index.saturating_mul(32))
                .and_then(|w| to_usize(&w))
                .ok_or(DecodeError::BadElementOffset { index })?;
            // Element offsets are relative to the tuple-like region after the
            // array length word, and therefore must also be word-aligned.
            if eo % 32 != 0 {
                return Err(DecodeError::BadElementOffset { index });
            }
            if eo < cursor {
                return Err(DecodeError::OverlappingElement { index });
            }
            let padded_end =
                read_bytes(args, &h, eo, index, DecodeError::BadElementOffset { index })?;
            slack = slack.saturating_add(eo - cursor);
            cursor = padded_end;
        }

        Ok(Self {
            body: h.body,
            len: h.len,
            slack,
            end: h.body_start.saturating_add(cursor),
        })
    }

    /// Number of elements.
    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Bytes inside the array region (and between the head and the array)
    /// that the layout does not account for. The EVM ignores them.
    pub fn slack(&self) -> usize {
        self.slack
    }

    /// Index into `args` one past the last byte this array uses. Bytes from
    /// here to the end of `args` are trailing data.
    pub fn end(&self) -> usize {
        self.end
    }

    /// Element `i`, or `None` if `i >= len()`.
    pub fn get(&self, i: usize) -> Option<&'a [u8]> {
        if i >= self.len {
            return None;
        }
        let eo = word_at(self.body, i.saturating_mul(32)).and_then(|w| to_usize(&w))?;
        let l = word_at(self.body, eo).and_then(|w| to_usize(&w))?;
        let start = eo.checked_add(32)?;
        self.body.get(start..start.checked_add(l)?)
    }

    pub fn iter(&self) -> BytesArrayIter<'a> {
        BytesArrayIter {
            array: *self,
            next: 0,
        }
    }
}

/// Iterator over the elements of a [`BytesArray`].
#[derive(Clone, Debug)]
pub struct BytesArrayIter<'a> {
    array: BytesArray<'a>,
    next: usize,
}

impl<'a> Iterator for BytesArrayIter<'a> {
    type Item = &'a [u8];

    fn next(&mut self) -> Option<Self::Item> {
        let item = self.array.get(self.next)?;
        self.next += 1;
        Some(item)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let left = self.array.len.saturating_sub(self.next);
        (left, Some(left))
    }
}

/// Type of a static tuple member, for validation only.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Field {
    /// `address`: the upper 12 bytes must be zero.
    Address,
    /// `bool`: exactly 0 or 1.
    Bool,
    /// `uint256`: any value.
    Uint256,
}

impl Field {
    fn accepts(self, w: &Word) -> bool {
        match self {
            Field::Address => w.to_address().is_some(),
            Field::Bool => w.to_bool().is_some(),
            Field::Uint256 => true,
        }
    }
}

/// One element of a [`TupleArray`]: its static fields and its `bytes` member.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Entry<'a> {
    fields: &'a [u8],
    /// The tuple's `bytes` member.
    pub data: &'a [u8],
}

impl Entry<'_> {
    /// Static field `i` (0-based, in declaration order).
    pub fn field(&self, i: usize) -> Option<Word> {
        word_at(self.fields, i.checked_mul(32)?)
    }
}

/// A validated array of tuples `(fields.., bytes)`.
///
/// `fields` lists the static members that come before the single `bytes`
/// member, in order. Each tuple is dynamic, so the array holds one offset per
/// tuple and each tuple holds its static words followed by the offset of its
/// `bytes` (relative to the start of the tuple).
#[derive(Clone, Copy, Debug)]
pub struct TupleArray<'a> {
    body: &'a [u8],
    fields: &'static [Field],
    len: usize,
    slack: usize,
    end: usize,
}

impl<'a> TupleArray<'a> {
    /// Parse the array whose offset sits in head slot `arg`. Arguments as in
    /// [`BytesArray::parse`], plus the layout of one tuple.
    pub fn parse(
        args: &'a [u8],
        head_len: usize,
        arg: usize,
        fields: &'static [Field],
    ) -> Result<Self, DecodeError> {
        let h = array_header(args, head_len, arg)?;
        // Size of one tuple's head: the static words and the `bytes` offset.
        let tuple_head = fields
            .len()
            .checked_add(1)
            .and_then(|n| n.checked_mul(32))
            .ok_or(DecodeError::BadArrayLength)?;

        let mut cursor = h.table;
        let mut slack = h.gap;
        for index in 0..h.len {
            let eo = word_at(h.body, index.saturating_mul(32))
                .and_then(|w| to_usize(&w))
                .ok_or(DecodeError::BadElementOffset { index })?;
            if eo % 32 != 0 {
                return Err(DecodeError::BadElementOffset { index });
            }
            if eo < cursor {
                return Err(DecodeError::OverlappingElement { index });
            }
            // The whole tuple head must be inside the region.
            eo.checked_add(tuple_head)
                .filter(|e| *e <= h.body.len())
                .ok_or(DecodeError::BadElementOffset { index })?;
            for (field, kind) in fields.iter().enumerate() {
                let w = word_at(h.body, eo.saturating_add(32 * field))
                    .ok_or(DecodeError::BadElementOffset { index })?;
                if !kind.accepts(&w) {
                    return Err(DecodeError::DirtyElementField { index, field });
                }
            }
            let bad_member = DecodeError::BadMemberOffset { index };
            let mo = word_at(h.body, eo.saturating_add(32 * fields.len()))
                .and_then(|w| to_usize(&w))
                .ok_or(bad_member)?;
            // Relative to the start of this tuple; may not point into its head.
            if mo % 32 != 0 || mo < tuple_head {
                return Err(bad_member);
            }
            let pos = eo.checked_add(mo).ok_or(bad_member)?;
            let padded_end = read_bytes(args, &h, pos, index, bad_member)?;
            slack = slack
                .saturating_add(eo - cursor)
                .saturating_add(mo - tuple_head);
            cursor = padded_end;
        }

        Ok(Self {
            body: h.body,
            fields,
            len: h.len,
            slack,
            end: h.body_start.saturating_add(cursor),
        })
    }

    /// Number of tuples.
    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Bytes inside the array region (and between the head and the array)
    /// that the layout does not account for. The EVM ignores them.
    pub fn slack(&self) -> usize {
        self.slack
    }

    /// Index into `args` one past the last byte this array uses.
    pub fn end(&self) -> usize {
        self.end
    }

    /// Tuple `i`, or `None` if `i >= len()`.
    pub fn get(&self, i: usize) -> Option<Entry<'a>> {
        if i >= self.len {
            return None;
        }
        let eo = word_at(self.body, i.saturating_mul(32)).and_then(|w| to_usize(&w))?;
        let fields_len = self.fields.len().checked_mul(32)?;
        let fields = self.body.get(eo..eo.checked_add(fields_len)?)?;
        let mo = word_at(self.body, eo.checked_add(fields_len)?).and_then(|w| to_usize(&w))?;
        let pos = eo.checked_add(mo)?;
        let l = word_at(self.body, pos).and_then(|w| to_usize(&w))?;
        let start = pos.checked_add(32)?;
        let data = self.body.get(start..start.checked_add(l)?)?;
        Some(Entry { fields, data })
    }
}

#[cfg(test)]
pub(crate) mod testutil {
    //! Canonical encoder used to build well-formed inputs in tests.
    use crate::calldata::testutil::uint_word;
    use std::vec::Vec;

    pub fn pad32(n: usize) -> usize {
        n.div_ceil(32) * 32
    }

    /// `n | off_0 .. off_{n-1} | bodies`, tightly packed (what Solidity emits).
    pub fn encode_bytes_array(items: &[Vec<u8>]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&uint_word(items.len() as u64));
        let table = 32 * items.len();
        let mut bodies: Vec<u8> = Vec::new();
        for it in items {
            out.extend_from_slice(&uint_word((table + bodies.len()) as u64));
            bodies.extend_from_slice(&uint_word(it.len() as u64));
            bodies.extend_from_slice(it);
            bodies.resize(bodies.len() + pad32(it.len()) - it.len(), 0);
        }
        out.extend(bodies);
        out
    }

    /// `args` for a function whose only argument is a `bytes[]`.
    pub fn args_single(items: &[Vec<u8>]) -> Vec<u8> {
        let mut v = uint_word(32).to_vec();
        v.extend(encode_bytes_array(items));
        v
    }

    /// One tuple: its static words and its `bytes`.
    pub type Tup = (Vec<[u8; 32]>, Vec<u8>);

    /// `n | off_0 .. off_{n-1} | tuples`, tightly packed (what Solidity emits
    /// for an array of `(static.., bytes)`).
    pub fn encode_tuples(items: &[Tup]) -> Vec<u8> {
        let table = 32 * items.len();
        let mut out = uint_word(items.len() as u64).to_vec();
        let mut bodies: Vec<u8> = Vec::new();
        for (fields, data) in items {
            out.extend_from_slice(&uint_word((table + bodies.len()) as u64));
            for f in fields {
                bodies.extend_from_slice(f);
            }
            bodies.extend_from_slice(&uint_word(32 * (fields.len() as u64 + 1)));
            bodies.extend_from_slice(&uint_word(data.len() as u64));
            bodies.extend_from_slice(data);
            bodies.resize(bodies.len() + pad32(data.len()) - data.len(), 0);
        }
        out.extend(bodies);
        out
    }

    /// `args` for a function whose only argument is an array of tuples.
    pub fn args_tuples(items: &[Tup]) -> Vec<u8> {
        let mut v = uint_word(32).to_vec();
        v.extend(encode_tuples(items));
        v
    }
}

#[cfg(test)]
mod tests {
    use super::testutil::*;
    use super::*;
    use crate::calldata::testutil::{max_word, uint_word};
    use std::vec;
    use std::vec::Vec;

    fn items(lens: &[usize]) -> Vec<Vec<u8>> {
        lens.iter()
            .enumerate()
            .map(|(i, &l)| vec![(i as u8) + 1; l])
            .collect()
    }

    fn parse(args: &[u8]) -> Result<BytesArray<'_>, DecodeError> {
        BytesArray::parse(args, 32, 0)
    }

    #[test]
    fn empty_array() {
        let args = args_single(&[]);
        let a = parse(&args).unwrap();
        assert!(a.is_empty());
        assert_eq!(a.get(0), None);
        assert_eq!(a.slack(), 0);
        assert_eq!(a.end(), args.len());
    }

    #[test]
    fn round_trip_around_the_padding_boundaries() {
        let it = items(&[0, 1, 31, 32, 33, 64, 65]);
        let args = args_single(&it);
        let a = parse(&args).unwrap();
        assert_eq!(a.len(), it.len());
        let got: Vec<&[u8]> = a.iter().collect();
        let want: Vec<&[u8]> = it.iter().map(|v| v.as_slice()).collect();
        assert_eq!(got, want);
        assert_eq!(a.slack(), 0);
        assert_eq!(a.end(), args.len());
        assert_eq!(a.iter().size_hint(), (7, Some(7)));
    }

    #[test]
    fn trailing_bytes_are_visible_through_end() {
        let mut args = args_single(&items(&[5]));
        let used = args.len();
        args.extend([9, 9, 9]);
        let a = parse(&args).unwrap();
        assert_eq!(a.end(), used);
        assert_eq!(args.len() - a.end(), 3);
    }

    #[test]
    fn array_offset_into_the_head_is_rejected() {
        let mut args = args_single(&items(&[5]));
        args[..32].copy_from_slice(&uint_word(0));
        assert_eq!(parse(&args).unwrap_err(), DecodeError::BadOffset { arg: 0 });
    }

    #[test]
    fn unaligned_array_offset_is_rejected() {
        let mut args = args_single(&items(&[5]));
        args[..32].copy_from_slice(&uint_word(33));
        assert_eq!(parse(&args).unwrap_err(), DecodeError::BadOffset { arg: 0 });
    }

    #[test]
    fn unaligned_element_offset_is_rejected() {
        let mut args = args_single(&items(&[5]));
        // The element offset is the first word in the array's offset table.
        // Array starts at args[32], length is args[32..64], first offset is
        // args[64..96].
        args[64..96].copy_from_slice(&uint_word(65));
        assert_eq!(
            parse(&args).unwrap_err(),
            DecodeError::BadElementOffset { index: 0 }
        );
    }

    #[test]
    fn array_offset_past_the_end_or_huge_is_rejected() {
        let mut args = args_single(&items(&[5]));
        let past = args.len() as u64 + 1;
        args[..32].copy_from_slice(&uint_word(past));
        assert_eq!(parse(&args).unwrap_err(), DecodeError::BadOffset { arg: 0 });
        args[..32].copy_from_slice(&max_word());
        assert_eq!(parse(&args).unwrap_err(), DecodeError::BadOffset { arg: 0 });
        // 2^200: does not fit in 64 bits.
        let mut big = [0u8; 32];
        big[6] = 1;
        args[..32].copy_from_slice(&big);
        assert_eq!(parse(&args).unwrap_err(), DecodeError::BadOffset { arg: 0 });
    }

    #[test]
    fn offset_at_end_of_data_has_no_length_word() {
        let args = uint_word(32).to_vec();
        assert!(matches!(parse(&args), Err(DecodeError::Truncated { .. })));
    }

    #[test]
    fn missing_offset_slot_is_truncated() {
        assert!(matches!(
            parse(&[0u8; 10]),
            Err(DecodeError::Truncated {
                expected: 36,
                got: 14
            })
        ));
    }

    #[test]
    fn absurd_array_lengths_are_rejected_without_overflow() {
        for len in [
            uint_word(1 << 40),
            max_word(),
            {
                // 2^255: len * 32 overflows 256 bits, and does not fit in 64.
                let mut w = [0u8; 32];
                w[0] = 0x80;
                w
            },
            uint_word(u64::MAX),
        ] {
            let mut args = args_single(&items(&[5]));
            args[32..64].copy_from_slice(&len);
            assert_eq!(parse(&args).unwrap_err(), DecodeError::BadArrayLength);
        }
    }

    #[test]
    fn offset_table_larger_than_data_is_rejected() {
        let mut args = args_single(&[]);
        args[32..64].copy_from_slice(&uint_word(3)); // claims 3 elements, no table
        assert_eq!(parse(&args).unwrap_err(), DecodeError::BadArrayLength);
    }

    #[test]
    fn element_offset_into_the_table_is_overlap() {
        let mut args = args_single(&items(&[5, 5]));
        // element 0 offset := 0 (points at the table itself)
        args[64..96].copy_from_slice(&uint_word(0));
        assert_eq!(
            parse(&args).unwrap_err(),
            DecodeError::OverlappingElement { index: 0 }
        );
    }

    #[test]
    fn aliased_elements_are_rejected() {
        let mut args = args_single(&items(&[5, 5]));
        let first = args[64..96].to_vec();
        args[96..128].copy_from_slice(&first); // element 1 := same offset as 0
        assert_eq!(
            parse(&args).unwrap_err(),
            DecodeError::OverlappingElement { index: 1 }
        );
    }

    #[test]
    fn out_of_order_elements_are_rejected() {
        let mut args = args_single(&items(&[5, 5]));
        let (a, b) = (args[64..96].to_vec(), args[96..128].to_vec());
        args[64..96].copy_from_slice(&b);
        args[96..128].copy_from_slice(&a);
        assert_eq!(
            parse(&args).unwrap_err(),
            DecodeError::OverlappingElement { index: 1 }
        );
    }

    #[test]
    fn element_offset_outside_the_region_is_rejected() {
        let mut args = args_single(&items(&[5]));
        args[64..96].copy_from_slice(&uint_word(1 << 20));
        assert_eq!(
            parse(&args).unwrap_err(),
            DecodeError::BadElementOffset { index: 0 }
        );
        args[64..96].copy_from_slice(&max_word());
        assert_eq!(
            parse(&args).unwrap_err(),
            DecodeError::BadElementOffset { index: 0 }
        );
    }

    #[test]
    fn element_length_beyond_the_data_is_rejected() {
        let mut args = args_single(&items(&[5]));
        // body starts at 32 + 32 + 32 = 96; its length word is there
        args[96..128].copy_from_slice(&uint_word(6000));
        assert_eq!(
            parse(&args).unwrap_err(),
            DecodeError::BadElementLength { index: 0 }
        );
        args[96..128].copy_from_slice(&max_word());
        assert_eq!(
            parse(&args).unwrap_err(),
            DecodeError::BadElementLength { index: 0 }
        );
        args[96..128].copy_from_slice(&uint_word(u64::MAX));
        assert_eq!(
            parse(&args).unwrap_err(),
            DecodeError::BadElementLength { index: 0 }
        );
    }

    #[test]
    fn dirty_padding_is_an_error() {
        let mut args = args_single(&items(&[5]));
        let last = args.len() - 1;
        args[last] = 1;
        assert_eq!(
            parse(&args).unwrap_err(),
            DecodeError::DirtyBytesPadding { index: 0 }
        );
    }

    #[test]
    fn missing_final_padding_is_truncated_not_accepted() {
        let mut args = args_single(&items(&[5]));
        args.truncate(args.len() - 1);
        assert!(matches!(parse(&args), Err(DecodeError::Truncated { .. })));
        // The data bytes themselves present, all padding gone.
        let mut args = args_single(&items(&[5]));
        args.truncate(args.len() - 27);
        assert!(matches!(parse(&args), Err(DecodeError::Truncated { .. })));
    }

    #[test]
    fn gap_between_head_and_array_counts_as_slack() {
        let it = items(&[5]);
        let arr = encode_bytes_array(&it);
        let mut args = uint_word(32 + 64).to_vec(); // array starts 64 bytes late
        args.extend([0xee; 64]);
        args.extend(arr);
        let a = parse(&args).unwrap();
        assert_eq!(a.slack(), 64);
        assert_eq!(a.get(0), Some(&it[0][..]));
    }

    #[test]
    fn gap_between_elements_counts_as_slack_and_is_still_readable() {
        let it = items(&[5, 7]);
        let mut args = args_single(&it);
        // Insert 32 junk bytes between the two element bodies and shift the
        // second element's offset accordingly.
        // head + length word + 2-slot table + element 0 (length word + padded data)
        let body0_end = 32 + 32 + 64 + 32 + 32;
        args.splice(body0_end..body0_end, [0xaa; 32]);
        let old = u64::from_be_bytes(args[96 + 24..128].try_into().unwrap());
        args[96..128].copy_from_slice(&uint_word(old + 32));
        let a = parse(&args).unwrap();
        assert_eq!(a.slack(), 32);
        assert_eq!(a.get(0), Some(&it[0][..]));
        assert_eq!(a.get(1), Some(&it[1][..]));
    }

    #[test]
    fn elements_inside_a_wider_head_are_found() {
        // head = [static word, offset]; array offset in slot 1.
        let it = items(&[3]);
        let mut args = uint_word(7).to_vec();
        args.extend(uint_word(64));
        args.extend(encode_bytes_array(&it));
        let a = BytesArray::parse(&args, 64, 1).unwrap();
        assert_eq!(a.get(0), Some(&it[0][..]));
        // The same bytes with head_len = 96 make the offset a self-reference.
        assert_eq!(
            BytesArray::parse(&args, 96, 1).unwrap_err(),
            DecodeError::BadOffset { arg: 1 }
        );
    }

    // ------------------------------------------------------------ TupleArray

    const F1: &[Field] = &[Field::Address];
    const F2: &[Field] = &[Field::Address, Field::Bool];
    const F3: &[Field] = &[Field::Address, Field::Bool, Field::Uint256];

    fn a(b: u8) -> [u8; 32] {
        let mut w = [0u8; 32];
        w[12..].fill(b);
        w
    }

    fn flag(v: bool) -> [u8; 32] {
        uint_word(v as u64)
    }

    /// `n` tuples of schema `F2` with data lengths `lens`.
    fn tuples2(lens: &[usize]) -> Vec<Tup> {
        lens.iter()
            .enumerate()
            .map(|(i, &l)| (vec![a(i as u8 + 1), flag(i % 2 == 0)], vec![i as u8 + 1; l]))
            .collect()
    }

    fn tparse(args: &[u8]) -> Result<TupleArray<'_>, DecodeError> {
        TupleArray::parse(args, 32, 0, F2)
    }

    // Positions inside `args_tuples(&tuples2(&[5]))`: offset 0..32, length
    // 32..64, table entry 64..96, then the tuple: field 0 at 96, field 1 at
    // 128, `bytes` offset at 160, length word at 192, data from 224.
    const T_OFF: usize = 0;
    const T_LEN: usize = 32;
    const T_ELEM0: usize = 64;
    const T_F0: usize = 96;
    const T_F1: usize = 128;
    const T_MO: usize = 160;
    const T_BLEN: usize = 192;

    fn put(args: &mut [u8], at: usize, w: [u8; 32]) {
        args[at..at + 32].copy_from_slice(&w);
    }

    #[test]
    fn empty_tuple_array() {
        let args = args_tuples(&[]);
        let t = tparse(&args).unwrap();
        assert!(t.is_empty());
        assert_eq!(t.get(0), None);
        assert_eq!((t.slack(), t.end()), (0, args.len()));
    }

    #[test]
    fn tuple_round_trip_around_the_padding_boundaries() {
        let it = tuples2(&[0, 1, 31, 32, 33, 64, 65]);
        let args = args_tuples(&it);
        let t = tparse(&args).unwrap();
        assert_eq!(t.len(), it.len());
        for (i, (fields, data)) in it.iter().enumerate() {
            let e = t.get(i).unwrap();
            assert_eq!(e.data, &data[..]);
            assert_eq!(e.field(0), Some(Word(fields[0])));
            assert_eq!(e.field(1), Some(Word(fields[1])));
            assert_eq!(e.field(2), None);
        }
        assert_eq!(t.get(it.len()), None);
        assert_eq!((t.slack(), t.end()), (0, args.len()));
    }

    #[test]
    fn every_schema_round_trips() {
        for (schema, n) in [(F1, 1usize), (F2, 2), (F3, 3)] {
            let fields: Vec<[u8; 32]> = [a(7), flag(true), uint_word(99)][..n].to_vec();
            let it = vec![(fields.clone(), vec![5u8; 40]), (fields, vec![])];
            let args = args_tuples(&it);
            let t = TupleArray::parse(&args, 32, 0, schema).unwrap();
            assert_eq!(t.len(), 2);
            assert_eq!(t.get(0).unwrap().data, &[5u8; 40][..]);
            assert_eq!(t.get(1).unwrap().data, &[] as &[u8]);
            assert_eq!(t.get(0).unwrap().field(n - 1), Some(Word(it[0].0[n - 1])));
            assert_eq!((t.slack(), t.end()), (0, args.len()));
        }
    }

    #[test]
    fn a_schema_that_does_not_match_the_data_is_an_error_not_a_misread() {
        // Encoded with 2 static fields, read as 3: the "bytes offset" the
        // reader sees is really the length word, which is 5 and unaligned.
        let args = args_tuples(&tuples2(&[5]));
        assert_eq!(
            TupleArray::parse(&args, 32, 0, F3).unwrap_err(),
            DecodeError::BadMemberOffset { index: 0 }
        );
    }

    #[test]
    fn dirty_static_fields_are_rejected_with_their_position() {
        let mut args = args_tuples(&tuples2(&[5]));
        args[T_F0 + 3] = 1; // upper bytes of an address
        assert_eq!(
            tparse(&args).unwrap_err(),
            DecodeError::DirtyElementField { index: 0, field: 0 }
        );
        let mut args = args_tuples(&tuples2(&[5]));
        put(&mut args, T_F1, uint_word(2)); // a bool that is neither 0 nor 1
        assert_eq!(
            tparse(&args).unwrap_err(),
            DecodeError::DirtyElementField { index: 0, field: 1 }
        );
        put(&mut args, T_F1, max_word());
        assert_eq!(
            tparse(&args).unwrap_err(),
            DecodeError::DirtyElementField { index: 0, field: 1 }
        );
    }

    #[test]
    fn member_offset_may_not_point_into_the_tuple_head() {
        for bad in [0u64, 32, 64, 65, 97] {
            let mut args = args_tuples(&tuples2(&[5]));
            put(&mut args, T_MO, uint_word(bad));
            assert_eq!(
                tparse(&args).unwrap_err(),
                DecodeError::BadMemberOffset { index: 0 },
                "offset {bad}"
            );
        }
    }

    #[test]
    fn member_offset_outside_the_region_or_huge_is_rejected() {
        for bad in [uint_word(1 << 20), max_word(), uint_word(u64::MAX), {
            let mut w = [0u8; 32];
            w[6] = 1; // 2^200
            w
        }] {
            let mut args = args_tuples(&tuples2(&[5]));
            put(&mut args, T_MO, bad);
            assert_eq!(
                tparse(&args).unwrap_err(),
                DecodeError::BadMemberOffset { index: 0 }
            );
        }
    }

    #[test]
    fn array_level_rules_apply_to_tuples_too() {
        let base = args_tuples(&tuples2(&[5, 5]));
        let mut args = base.clone();
        put(&mut args, T_OFF, uint_word(0)); // into the head
        assert_eq!(
            tparse(&args).unwrap_err(),
            DecodeError::BadOffset { arg: 0 }
        );
        let mut args = base.clone();
        put(&mut args, T_OFF, uint_word(33));
        assert_eq!(
            tparse(&args).unwrap_err(),
            DecodeError::BadOffset { arg: 0 }
        );
        let mut args = base.clone();
        put(&mut args, T_LEN, max_word());
        assert_eq!(tparse(&args).unwrap_err(), DecodeError::BadArrayLength);
        let mut args = base.clone();
        put(&mut args, T_LEN, uint_word(1 << 40));
        assert_eq!(tparse(&args).unwrap_err(), DecodeError::BadArrayLength);
        assert!(matches!(
            tparse(&base[..20]),
            Err(DecodeError::Truncated { .. })
        ));
    }

    #[test]
    fn tuple_offsets_must_be_aligned_inside_and_not_overlap() {
        let base = args_tuples(&tuples2(&[5, 5]));
        // Unaligned.
        let mut args = base.clone();
        put(&mut args, T_ELEM0, uint_word(65));
        assert_eq!(
            tparse(&args).unwrap_err(),
            DecodeError::BadElementOffset { index: 0 }
        );
        // Into the offset table.
        let mut args = base.clone();
        put(&mut args, T_ELEM0, uint_word(0));
        assert_eq!(
            tparse(&args).unwrap_err(),
            DecodeError::OverlappingElement { index: 0 }
        );
        // Aliased: tuple 1 at the same place as tuple 0.
        let mut args = base.clone();
        let first = args[T_ELEM0..T_ELEM0 + 32].to_vec();
        args[T_ELEM0 + 32..T_ELEM0 + 64].copy_from_slice(&first);
        assert_eq!(
            tparse(&args).unwrap_err(),
            DecodeError::OverlappingElement { index: 1 }
        );
        // Out of order.
        let mut args = base.clone();
        let (x, y) = (
            args[T_ELEM0..T_ELEM0 + 32].to_vec(),
            args[T_ELEM0 + 32..T_ELEM0 + 64].to_vec(),
        );
        args[T_ELEM0..T_ELEM0 + 32].copy_from_slice(&y);
        args[T_ELEM0 + 32..T_ELEM0 + 64].copy_from_slice(&x);
        assert_eq!(
            tparse(&args).unwrap_err(),
            DecodeError::OverlappingElement { index: 1 }
        );
        // Beyond the region.
        for bad in [uint_word(1 << 20), max_word()] {
            let mut args = base.clone();
            put(&mut args, T_ELEM0, bad);
            assert_eq!(
                tparse(&args).unwrap_err(),
                DecodeError::BadElementOffset { index: 0 }
            );
        }
    }

    #[test]
    fn bytes_of_one_tuple_may_not_swallow_the_next_tuple() {
        // Two tuples (5 data bytes each). In args coordinates: table at
        // 64..128, tuple 0 at 128 (head 96 bytes, then a 64-byte `bytes`
        // block, so it ends at 288), tuple 1 head at 288..384, its `bytes`
        // block at 384.
        let mut args = args_tuples(&tuples2(&[5, 5]));
        // Tuple 0's `bytes` offset (word at 192) := 256, which lands on
        // tuple 1's own `bytes` block (128 + 256 = 384). That block is a
        // perfectly valid `bytes`, so tuple 0 parses and ends at 448, and
        // tuple 1 (starting at 288) now overlaps it.
        put(&mut args, 192, uint_word(256));
        assert_eq!(
            tparse(&args).unwrap_err(),
            DecodeError::OverlappingElement { index: 1 }
        );
    }

    #[test]
    fn tuple_bytes_length_and_padding_are_checked() {
        let base = args_tuples(&tuples2(&[5]));
        for bad in [uint_word(6000), max_word(), uint_word(u64::MAX)] {
            let mut args = base.clone();
            put(&mut args, T_BLEN, bad);
            assert_eq!(
                tparse(&args).unwrap_err(),
                DecodeError::BadElementLength { index: 0 }
            );
        }
        let mut args = base.clone();
        let last = args.len() - 1;
        args[last] = 1;
        assert_eq!(
            tparse(&args).unwrap_err(),
            DecodeError::DirtyBytesPadding { index: 0 }
        );
        let mut args = base.clone();
        args.truncate(args.len() - 1);
        assert!(matches!(tparse(&args), Err(DecodeError::Truncated { .. })));
    }

    #[test]
    fn a_truncated_tuple_head_is_an_element_error() {
        let base = args_tuples(&tuples2(&[0]));
        // Cut inside the tuple head (after the first static word).
        let args = &base[..T_F0 + 32];
        assert_eq!(
            tparse(args).unwrap_err(),
            DecodeError::BadElementOffset { index: 0 }
        );
        // Cut right before the `bytes` offset word: the static fields are all
        // there, but the head is not, and that is still an element error.
        let args = &base[..T_MO];
        assert_eq!(
            tparse(args).unwrap_err(),
            DecodeError::BadElementOffset { index: 0 }
        );
    }

    #[test]
    fn gaps_inside_a_tuple_and_between_tuples_count_as_slack() {
        // Two tuples. Args coordinates: table entries at 64 and 96; tuple 0
        // at 128 (fields 128, 160; `bytes` offset 192; length word 224;
        // data 256..288); tuple 1 at 288.
        let junk_in_tuple = |args: &mut Vec<u8>| {
            args.splice(224..224, [0xaa; 32]); // between tuple 0's head and its bytes
            put(args, 192, uint_word(96 + 32));
        };
        let shift_second = |args: &mut Vec<u8>| {
            let old = u64::from_be_bytes(args[96 + 24..128].try_into().unwrap());
            put(args, 96, uint_word(old + 32));
        };

        let mut args = args_tuples(&tuples2(&[5, 7]));
        junk_in_tuple(&mut args);
        shift_second(&mut args);
        let t = tparse(&args).unwrap();
        assert_eq!(t.slack(), 32);
        assert_eq!(t.get(0).unwrap().data, &[1u8; 5][..]);
        assert_eq!(t.get(1).unwrap().data, &[2u8; 7][..]);

        // 32 junk bytes between the two tuples.
        let mut args = args_tuples(&tuples2(&[5, 7]));
        args.splice(288..288, [0xbb; 32]);
        shift_second(&mut args);
        let t = tparse(&args).unwrap();
        assert_eq!(t.slack(), 32);
        assert_eq!(t.get(1).unwrap().data, &[2u8; 7][..]);

        // Both kinds at once add up.
        let mut args = args_tuples(&tuples2(&[5, 7]));
        args.splice(288..288, [0xbb; 32]);
        shift_second(&mut args);
        junk_in_tuple(&mut args);
        let old = u64::from_be_bytes(args[96 + 24..128].try_into().unwrap());
        put(&mut args, 96, uint_word(old + 32));
        assert_eq!(tparse(&args).unwrap().slack(), 64);

        // 64 bytes between the head and the array.
        let it = tuples2(&[5]);
        let mut args = uint_word(32 + 64).to_vec();
        args.extend([0xcc; 64]);
        args.extend(encode_tuples(&it));
        assert_eq!(tparse(&args).unwrap().slack(), 64);
    }

    #[test]
    fn trailing_bytes_are_visible_through_end_for_tuples() {
        let mut args = args_tuples(&tuples2(&[5]));
        let used = args.len();
        args.extend([9, 9, 9]);
        let t = tparse(&args).unwrap();
        assert_eq!(t.end(), used);
    }

    #[test]
    fn tuples_inside_a_wider_head_are_found() {
        // head = [static bool, offset]; array offset in slot 1.
        let it = tuples2(&[3]);
        let mut args = flag(true).to_vec();
        args.extend(uint_word(64));
        args.extend(encode_tuples(&it));
        let t = TupleArray::parse(&args, 64, 1, F2).unwrap();
        assert_eq!(t.get(0).unwrap().data, &[1u8; 3][..]);
        assert_eq!(
            TupleArray::parse(&args, 96, 1, F2).unwrap_err(),
            DecodeError::BadOffset { arg: 1 }
        );
    }
}
