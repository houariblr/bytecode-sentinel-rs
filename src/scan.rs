//! Single-pass static scan: dangerous-opcode census and selector extraction.
//!
//! This reports facts about the instruction stream. It does not decide
//! whether the contract is malicious: DELEGATECALL is normal in a proxy,
//! SELFDESTRUCT can be legacy cleanup, and so on. The caller interprets.

use crate::disasm::disassemble;
use crate::opcode::{
    CALL, CALLCODE, CREATE, CREATE2, DELEGATECALL, DUP1, DUP16, EQ, ORIGIN, PUSH4, SELFDESTRUCT,
    SSTORE, STATICCALL,
};

/// Counts of notable opcodes found at real instruction positions.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Report {
    pub len: usize,
    pub instructions: u32,
    pub call: u32,
    pub staticcall: u32,
    pub delegatecall: u32,
    pub callcode: u32,
    pub selfdestruct: u32,
    pub origin: u32,
    pub create: u32,
    pub create2: u32,
    pub sstore: u32,
    /// A PUSH ran past the end of the code (often trailing metadata or garbage).
    pub truncated_push: bool,
}

impl Report {
    /// Opcodes that deserve a second look before interacting: delegated or
    /// legacy execution, self-destruction, and `tx.origin` auth.
    #[must_use]
    pub fn has_risky_opcodes(&self) -> bool {
        self.delegatecall > 0 || self.callcode > 0 || self.selfdestruct > 0 || self.origin > 0
    }
}

/// Scan `code` once and count notable opcodes.
#[must_use]
pub fn scan(code: &[u8]) -> Report {
    let mut r = Report {
        len: code.len(),
        ..Report::default()
    };
    for ins in disassemble(code) {
        r.instructions = r.instructions.saturating_add(1);
        if ins.truncated {
            r.truncated_push = true;
        }
        let slot = match ins.op {
            CALL => &mut r.call,
            STATICCALL => &mut r.staticcall,
            DELEGATECALL => &mut r.delegatecall,
            CALLCODE => &mut r.callcode,
            SELFDESTRUCT => &mut r.selfdestruct,
            ORIGIN => &mut r.origin,
            CREATE => &mut r.create,
            CREATE2 => &mut r.create2,
            SSTORE => &mut r.sstore,
            _ => continue,
        };
        *slot = slot.saturating_add(1);
    }
    r
}

/// Extract 4-byte function selectors from a Solidity/Vyper-style dispatcher.
///
/// Heuristic: a `PUSH4 <sel>` followed by `EQ`, optionally with one `DUPn`
/// in between. Unique selectors are written to `out` in order of appearance;
/// the number written is returned (capped at `out.len()`).
pub fn extract_selectors(code: &[u8], out: &mut [[u8; 4]]) -> usize {
    let mut n = 0usize;
    // (selector, a DUP has already been seen after the PUSH4)
    let mut pending: Option<([u8; 4], bool)> = None;

    for ins in disassemble(code) {
        match ins.op {
            PUSH4 if ins.imm.len() == 4 => {
                pending = Some(([ins.imm[0], ins.imm[1], ins.imm[2], ins.imm[3]], false));
            }
            EQ => {
                if let Some((sel, _)) = pending.take() {
                    if n < out.len() && !out[..n].contains(&sel) {
                        out[n] = sel;
                        n += 1;
                    }
                }
            }
            DUP1..=DUP16 => match pending {
                Some((sel, false)) => pending = Some((sel, true)),
                _ => pending = None,
            },
            _ => pending = None,
        }
    }
    n
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counts_real_opcodes_only() {
        // DELEGATECALL ; PUSH1 0xff (not SELFDESTRUCT) ; ORIGIN ; SELFDESTRUCT
        let code = [0xf4, 0x60, 0xff, 0x32, 0xff];
        let r = scan(&code);
        assert_eq!(r.delegatecall, 1);
        assert_eq!(r.selfdestruct, 1, "the 0xff inside PUSH1 must not count");
        assert_eq!(r.origin, 1);
        assert_eq!(r.instructions, 4);
        assert!(r.has_risky_opcodes());
        assert!(!r.truncated_push);
    }

    #[test]
    fn clean_code_is_not_flagged() {
        // PUSH1 1 ; PUSH1 2 ; ADD ; STOP
        let r = scan(&[0x60, 1, 0x60, 2, 0x01, 0x00]);
        assert!(!r.has_risky_opcodes());
        assert_eq!(r.instructions, 4);
    }

    #[test]
    fn truncated_push_is_reported() {
        let r = scan(&[0x7f, 0x01]);
        assert!(r.truncated_push);
    }

    #[test]
    fn counts_calls_and_creates() {
        let r = scan(&[0xf1, 0xf1, 0xfa, 0xf0, 0xf5, 0x55]);
        assert_eq!(
            (r.call, r.staticcall, r.create, r.create2, r.sstore),
            (2, 1, 1, 1, 1)
        );
    }

    #[test]
    fn extracts_dispatcher_selectors() {
        // DUP1 PUSH4 a9059cbb EQ PUSH2 0020 JUMPI
        // DUP1 PUSH4 70a08231 EQ PUSH2 0030 JUMPI
        let code = [
            0x80, 0x63, 0xa9, 0x05, 0x9c, 0xbb, 0x14, 0x61, 0x00, 0x20, 0x57, //
            0x80, 0x63, 0x70, 0xa0, 0x82, 0x31, 0x14, 0x61, 0x00, 0x30, 0x57,
        ];
        let mut out = [[0u8; 4]; 8];
        let n = extract_selectors(&code, &mut out);
        assert_eq!(n, 2);
        assert_eq!(out[0], [0xa9, 0x05, 0x9c, 0xbb]);
        assert_eq!(out[1], [0x70, 0xa0, 0x82, 0x31]);
    }

    #[test]
    fn selector_with_dup_between_push_and_eq() {
        // PUSH4 deadbeef DUP2 EQ
        let code = [0x63, 0xde, 0xad, 0xbe, 0xef, 0x81, 0x14];
        let mut out = [[0u8; 4]; 2];
        assert_eq!(extract_selectors(&code, &mut out), 1);
        assert_eq!(out[0], [0xde, 0xad, 0xbe, 0xef]);
    }

    #[test]
    fn push4_without_eq_is_not_a_selector() {
        // PUSH4 11223344 ADD EQ  -> ADD resets the match
        let code = [0x63, 0x11, 0x22, 0x33, 0x44, 0x01, 0x14];
        let mut out = [[0u8; 4]; 2];
        assert_eq!(extract_selectors(&code, &mut out), 0);
    }

    #[test]
    fn duplicates_are_collapsed_and_output_is_capped() {
        let one = [0x63, 1, 2, 3, 4, 0x14];
        let two = [0x63, 5, 6, 7, 8, 0x14];
        let mut code = [0u8; 18];
        code[..6].copy_from_slice(&one);
        code[6..12].copy_from_slice(&one); // duplicate
        code[12..18].copy_from_slice(&two);

        let mut big = [[0u8; 4]; 4];
        assert_eq!(extract_selectors(&code, &mut big), 2);

        let mut tiny = [[0u8; 4]; 1];
        assert_eq!(extract_selectors(&code, &mut tiny), 1);
    }

    #[test]
    fn selector_bytes_inside_other_push_are_ignored() {
        // PUSH5 containing 0x63 .. 0x14 bytes: must not create a selector.
        let code = [0x64, 0x63, 1, 2, 3, 0x14, 0x00];
        let mut out = [[0u8; 4]; 2];
        assert_eq!(extract_selectors(&code, &mut out), 0);
    }
}
