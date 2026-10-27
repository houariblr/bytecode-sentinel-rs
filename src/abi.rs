//! Minimal ABI reading for calls whose arguments are all static
//! (fixed-size, 32-byte words in the head). No heap, no panics.
//!
//! Strictness is deliberate: a word that is not canonically padded is an
//! error, never silently masked. Different contracts treat dirty padding
//! differently, and a scanner that reads a value the contract would read
//! another way can be fooled.

/// A 20-byte account address.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Address(pub [u8; 20]);

/// One 32-byte big-endian ABI word.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Word(pub [u8; 32]);

/// Why a calldata blob could not be decoded.
///
/// Any error means "this tool cannot vouch for this calldata". Callers must
/// not treat it as "safe".
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DecodeError {
    /// Fewer than 4 bytes: there is no selector.
    MissingSelector { got: usize },
    /// The selector is not one this crate understands.
    UnknownSelector([u8; 4]),
    /// Fewer bytes than the function's arguments require.
    Truncated { expected: usize, got: usize },
    /// Argument `arg` (0-based) has non-zero padding bits.
    DirtyPadding { arg: usize },
    /// The offset in head slot `arg` is outside the data, does not fit in 64
    /// bits, or points back into the head (a self-reference).
    BadOffset { arg: usize },
    /// An array length that cannot fit in the bytes that follow it.
    BadArrayLength,
    /// The offset of array element `index` is outside the array region.
    BadElementOffset { index: usize },
    /// The length of element `index` does not fit in the array region.
    BadElementLength { index: usize },
    /// Element `index` starts before the end of the offset table or of the
    /// previous element: overlapping, aliased or out-of-order regions.
    OverlappingElement { index: usize },
    /// The padding bytes after element `index` are not all zero.
    DirtyBytesPadding { index: usize },
    /// Batches are nested deeper than [`crate::multicall::MAX_DEPTH`].
    NestingTooDeep,
    /// Static field `field` (0-based) of tuple element `index` is not
    /// canonical for its type (dirty address padding, a bool that is not 0 or 1).
    DirtyElementField { index: usize, field: usize },
    /// The offset of the `bytes` member of tuple element `index` is
    /// unaligned, does not fit, points into the tuple's own head, or lies
    /// outside the array region. Also used for the offset of the `details`
    /// array inside a Permit2 `PermitBatch` (`index` 0).
    BadMemberOffset { index: usize },
    /// A Universal Router plan has `commands` command bytes but `inputs`
    /// input entries. The router itself reverts with `LengthMismatch()` in
    /// this case (checked in `UniversalRouter.execute`).
    LengthMismatch { commands: usize, inputs: usize },
}

impl Word {
    pub const ZERO: Word = Word([0u8; 32]);

    #[inline]
    pub fn is_zero(&self) -> bool {
        self.0.iter().all(|&b| b == 0)
    }

    /// True if the value fits in `bits` bits (`bits` a multiple of 8).
    /// Equivalent to "every bit above `bits` is zero".
    pub fn fits(&self, bits: u32) -> bool {
        let keep = (bits / 8) as usize;
        let skip = 32usize.saturating_sub(keep);
        self.0[..skip].iter().all(|&b| b == 0)
    }

    /// True if the highest bit of a `bits`-wide value is set, i.e. the value
    /// is at least 2^(bits-1). This is the "effectively unlimited" test.
    /// Only meaningful for values that satisfy [`Word::fits`].
    pub fn top_bit_set(&self, bits: u32) -> bool {
        let keep = (bits / 8) as usize;
        if keep == 0 || keep > 32 {
            return false;
        }
        self.0[32 - keep] & 0x80 != 0
    }

    /// Interpret as an address; `None` if the upper 12 bytes are not zero.
    pub fn to_address(&self) -> Option<Address> {
        if !self.fits(160) {
            return None;
        }
        let mut a = [0u8; 20];
        a.copy_from_slice(&self.0[12..]);
        Some(Address(a))
    }

    /// Interpret as a bool; `None` unless the word is exactly 0 or 1.
    pub fn to_bool(&self) -> Option<bool> {
        if !self.fits(8) {
            return None;
        }
        match self.0[31] {
            0 => Some(false),
            1 => Some(true),
            _ => None,
        }
    }
}

/// Reader over the argument words of one call.
///
/// `data` is the whole calldata including the 4-byte selector.
#[derive(Clone, Copy, Debug)]
pub struct Args<'a> {
    data: &'a [u8],
}

impl<'a> Args<'a> {
    /// Check that `data` holds at least `words` argument words after the
    /// selector. Returns the reader and the number of trailing bytes beyond
    /// the expected length (the EVM ignores them, so they are reported, not
    /// rejected).
    pub fn new(data: &'a [u8], words: usize) -> Result<(Self, usize), DecodeError> {
        let expected = 4 + 32 * words;
        if data.len() < expected {
            return Err(DecodeError::Truncated {
                expected,
                got: data.len(),
            });
        }
        Ok((Self { data }, data.len() - expected))
    }

    fn word(&self, i: usize) -> Result<Word, DecodeError> {
        let start = 4 + 32 * i;
        match self.data.get(start..start + 32) {
            Some(s) => {
                let mut w = [0u8; 32];
                w.copy_from_slice(s);
                Ok(Word(w))
            }
            None => Err(DecodeError::Truncated {
                expected: start + 32,
                got: self.data.len(),
            }),
        }
    }

    /// A full-width `uint256`/`bytes32` argument; any value is valid.
    pub fn uint256(&self, i: usize) -> Result<Word, DecodeError> {
        self.word(i)
    }

    /// A `uintN` argument; rejected if bits above `bits` are set.
    pub fn uint_bits(&self, i: usize, bits: u32) -> Result<Word, DecodeError> {
        let w = self.word(i)?;
        if w.fits(bits) {
            Ok(w)
        } else {
            Err(DecodeError::DirtyPadding { arg: i })
        }
    }

    pub fn address(&self, i: usize) -> Result<Address, DecodeError> {
        self.word(i)?
            .to_address()
            .ok_or(DecodeError::DirtyPadding { arg: i })
    }

    pub fn boolean(&self, i: usize) -> Result<bool, DecodeError> {
        self.word(i)?
            .to_bool()
            .ok_or(DecodeError::DirtyPadding { arg: i })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::vec::Vec;

    fn word_with(f: impl FnOnce(&mut [u8; 32])) -> Word {
        let mut w = [0u8; 32];
        f(&mut w);
        Word(w)
    }

    #[test]
    fn zero_detection() {
        assert!(Word::ZERO.is_zero());
        assert!(!word_with(|w| w[31] = 1).is_zero());
        assert!(!word_with(|w| w[0] = 1).is_zero());
    }

    #[test]
    fn fits_checks_the_upper_bytes() {
        let max160 = word_with(|w| w[12..].fill(0xff));
        assert!(max160.fits(160));
        assert!(max160.fits(256));
        assert!(!max160.fits(152));
        let dirty = word_with(|w| w[11] = 1);
        assert!(!dirty.fits(160));
        assert!(Word::ZERO.fits(8));
    }

    #[test]
    fn top_bit_depends_on_width() {
        // 2^255 is "unlimited" for uint256 but a plain small number for uint160.
        let w255 = word_with(|w| w[0] = 0x80);
        assert!(w255.top_bit_set(256));
        let w159 = word_with(|w| w[12] = 0x80);
        assert!(w159.top_bit_set(160));
        assert!(!w159.top_bit_set(256));
        let just_below = word_with(|w| w[0] = 0x7f);
        assert!(!just_below.top_bit_set(256));
        assert!(!w255.top_bit_set(0));
        assert!(!w255.top_bit_set(264));
    }

    #[test]
    fn address_requires_clean_upper_bytes() {
        let ok = word_with(|w| w[12..].fill(0xab));
        assert_eq!(ok.to_address(), Some(Address([0xab; 20])));
        let dirty = word_with(|w| {
            w[12..].fill(0xab);
            w[0] = 1;
        });
        assert_eq!(dirty.to_address(), None);
    }

    #[test]
    fn bool_is_strict() {
        assert_eq!(Word::ZERO.to_bool(), Some(false));
        assert_eq!(word_with(|w| w[31] = 1).to_bool(), Some(true));
        assert_eq!(word_with(|w| w[31] = 2).to_bool(), None);
        assert_eq!(word_with(|w| w[0] = 1).to_bool(), None);
    }

    fn data_of(words: usize) -> Vec<u8> {
        let mut v = std::vec![0xaa, 0xbb, 0xcc, 0xdd];
        v.resize(v.len() + 32 * words, 0);
        v
    }

    #[test]
    fn args_new_checks_length_and_reports_trailing() {
        let mut d = data_of(2);
        let (_, trailing) = Args::new(&d, 2).unwrap();
        assert_eq!(trailing, 0);
        d.extend([1, 2, 3]);
        assert_eq!(Args::new(&d, 2).unwrap().1, 3);
        assert_eq!(
            Args::new(&d, 3).unwrap_err(),
            DecodeError::Truncated {
                expected: 4 + 96,
                got: 4 + 64 + 3
            }
        );
    }

    #[test]
    fn args_new_rejects_selector_only_when_args_expected() {
        assert_eq!(
            Args::new(&[1, 2, 3, 4], 1).unwrap_err(),
            DecodeError::Truncated {
                expected: 36,
                got: 4
            }
        );
        assert!(Args::new(&[1, 2, 3, 4], 0).is_ok());
    }

    #[test]
    fn dirty_arguments_report_their_index() {
        let mut d = data_of(2);
        d[4 + 32 + 5] = 1; // word 1, dirty upper byte
        let (a, _) = Args::new(&d, 2).unwrap();
        assert!(a.address(0).is_ok());
        assert_eq!(a.address(1), Err(DecodeError::DirtyPadding { arg: 1 }));
        assert_eq!(a.boolean(1), Err(DecodeError::DirtyPadding { arg: 1 }));
        assert_eq!(
            a.uint_bits(1, 160),
            Err(DecodeError::DirtyPadding { arg: 1 })
        );
        assert!(a.uint256(1).is_ok(), "uint256 accepts any value");
    }

    #[test]
    fn reading_past_the_declared_words_is_an_error_not_a_panic() {
        let d = data_of(1);
        let (a, _) = Args::new(&d, 1).unwrap();
        assert!(matches!(a.uint256(5), Err(DecodeError::Truncated { .. })));
    }
}
