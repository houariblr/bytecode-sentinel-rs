//! Valid `JUMPDEST` analysis.
//!
//! A `0x5b` byte is a legal jump target only if it is an opcode position,
//! not a byte inside a PUSH immediate. The result is a bitmap stored in a
//! caller-provided `&mut [u64]`, so no allocation is needed.

use crate::opcode::{imm_len, JUMPDEST};

/// Number of `u64` words required to hold a bitmap for `code_len` bytes.
#[inline]
pub const fn words_needed(code_len: usize) -> usize {
    code_len.div_ceil(64)
}

/// The provided buffer is too small for this bytecode.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BufferTooSmall {
    pub needed: usize,
}

/// Bitmap of valid jump destinations for one bytecode blob.
#[derive(Clone, Copy, Debug)]
pub struct JumpdestMap<'a> {
    bits: &'a [u64],
    len: usize,
}

impl<'a> JumpdestMap<'a> {
    /// Build the map into `buf`. `buf` must hold at least
    /// [`words_needed`]`(code.len())` words; it is cleared first.
    pub fn build(code: &[u8], buf: &'a mut [u64]) -> Result<Self, BufferTooSmall> {
        let needed = words_needed(code.len());
        if buf.len() < needed {
            return Err(BufferTooSmall { needed });
        }
        let buf = &mut buf[..needed];
        for w in buf.iter_mut() {
            *w = 0;
        }

        let mut pc = 0usize;
        while pc < code.len() {
            let op = code[pc];
            if op == JUMPDEST {
                buf[pc / 64] |= 1u64 << (pc % 64);
            }
            pc = pc.saturating_add(1 + imm_len(op));
        }

        let bits: &'a [u64] = buf;
        Ok(Self {
            bits,
            len: code.len(),
        })
    }

    /// Is `pc` a legal jump destination?
    #[inline]
    #[must_use]
    pub fn is_valid(&self, pc: usize) -> bool {
        pc < self.len && (self.bits[pc / 64] >> (pc % 64)) & 1 == 1
    }

    /// Number of valid jump destinations.
    pub fn count(&self) -> usize {
        self.bits.iter().map(|w| w.count_ones() as usize).sum()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn map_of(code: &[u8]) -> ([u64; 4], usize) {
        let mut buf = [0u64; 4];
        let n = JumpdestMap::build(code, &mut buf).unwrap().count();
        (buf, n)
    }

    #[test]
    fn plain_jumpdest_is_valid() {
        let code = [0x5b, 0x00, 0x5b];
        let mut buf = [0u64; 1];
        let m = JumpdestMap::build(&code, &mut buf).unwrap();
        assert!(m.is_valid(0));
        assert!(!m.is_valid(1));
        assert!(m.is_valid(2));
        assert_eq!(m.count(), 2);
    }

    #[test]
    fn jumpdest_inside_push_is_invalid() {
        // PUSH2 0x5b5b ; JUMPDEST
        let code = [0x61, 0x5b, 0x5b, 0x5b];
        let mut buf = [0u64; 1];
        let m = JumpdestMap::build(&code, &mut buf).unwrap();
        assert!(!m.is_valid(1));
        assert!(!m.is_valid(2));
        assert!(m.is_valid(3));
        assert_eq!(m.count(), 1);
    }

    #[test]
    fn push32_swallows_32_bytes() {
        let mut code = [0x5bu8; 40];
        code[0] = 0x7f; // PUSH32, covers indexes 1..=32
        let mut buf = [0u64; 1];
        let m = JumpdestMap::build(&code, &mut buf).unwrap();
        for pc in 0..=32 {
            assert!(!m.is_valid(pc), "pc {pc} must be inside the push");
        }
        assert!(m.is_valid(33));
        assert!(m.is_valid(39));
    }

    #[test]
    fn truncated_push_at_end_does_not_panic() {
        let code = [0x62, 0x5b]; // PUSH3 with a single byte
        let (_, n) = map_of(&code);
        assert_eq!(n, 0);
    }

    #[test]
    fn out_of_range_pc_is_false() {
        let code = [0x5b];
        let mut buf = [0u64; 1];
        let m = JumpdestMap::build(&code, &mut buf).unwrap();
        assert!(!m.is_valid(1));
        assert!(!m.is_valid(usize::MAX));
    }

    #[test]
    fn buffer_too_small_is_reported() {
        let code = [0u8; 65]; // needs 2 words
        let mut buf = [0u64; 1];
        assert_eq!(
            JumpdestMap::build(&code, &mut buf).unwrap_err(),
            BufferTooSmall { needed: 2 }
        );
    }

    #[test]
    fn stale_buffer_is_cleared() {
        let code = [0x00u8; 8];
        let mut buf = [u64::MAX; 1];
        let m = JumpdestMap::build(&code, &mut buf).unwrap();
        assert_eq!(m.count(), 0);
    }

    #[test]
    fn works_across_word_boundary() {
        let mut code = [0u8; 130];
        code[63] = 0x5b;
        code[64] = 0x5b;
        code[129] = 0x5b;
        let mut buf = [0u64; 3];
        let m = JumpdestMap::build(&code, &mut buf).unwrap();
        assert!(m.is_valid(63) && m.is_valid(64) && m.is_valid(129));
        assert_eq!(m.count(), 3);
    }
}
