//! Zero-allocation disassembler: an iterator over decoded instructions.

use crate::opcode::imm_len;

/// One decoded instruction. `imm` borrows from the input bytecode.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Instruction<'a> {
    /// Byte offset of the opcode.
    pub pc: usize,
    pub op: u8,
    /// Immediate bytes (PUSH data). Shorter than expected if truncated.
    pub imm: &'a [u8],
    /// True when a PUSH ran past the end of the code.
    pub truncated: bool,
}

/// Iterator returned by [`disassemble`].
#[derive(Clone, Debug)]
pub struct Instructions<'a> {
    code: &'a [u8],
    pc: usize,
}

/// Decode `code` lazily. Never panics, whatever the bytes are.
pub fn disassemble(code: &[u8]) -> Instructions<'_> {
    Instructions { code, pc: 0 }
}

impl<'a> Iterator for Instructions<'a> {
    type Item = Instruction<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.pc >= self.code.len() {
            return None;
        }
        let pc = self.pc;
        let op = self.code[pc];
        let want = imm_len(op);
        let start = pc + 1;
        let end = core::cmp::min(start + want, self.code.len());
        let imm = &self.code[start..end];
        self.pc = start + want;
        Some(Instruction {
            pc,
            op,
            imm,
            truncated: imm.len() < want,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::vec::Vec;

    #[test]
    fn decodes_push_and_plain_ops() {
        // PUSH2 0x1234 ; ADD ; STOP
        let code = [0x61, 0x12, 0x34, 0x01, 0x00];
        let v: Vec<_> = disassemble(&code).collect();
        assert_eq!(v.len(), 3);
        assert_eq!((v[0].pc, v[0].op, v[0].imm), (0, 0x61, &[0x12, 0x34][..]));
        assert_eq!((v[1].pc, v[1].op), (3, 0x01));
        assert_eq!((v[2].pc, v[2].op), (4, 0x00));
        assert!(v.iter().all(|i| !i.truncated));
    }

    #[test]
    fn push_data_is_not_decoded_as_opcodes() {
        // PUSH1 0xff must not yield SELFDESTRUCT.
        let code = [0x60, 0xff];
        let v: Vec<_> = disassemble(&code).collect();
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].imm, &[0xff]);
    }

    #[test]
    fn truncated_push_is_flagged() {
        let code = [0x63, 0xaa, 0xbb];
        let v: Vec<_> = disassemble(&code).collect();
        assert_eq!(v.len(), 1);
        assert!(v[0].truncated);
        assert_eq!(v[0].imm, &[0xaa, 0xbb]);
    }

    #[test]
    fn empty_code_yields_nothing() {
        assert_eq!(disassemble(&[]).count(), 0);
    }

    #[test]
    fn every_single_byte_input_is_safe() {
        for b in 0u8..=255 {
            let _ = disassemble(&[b]).count();
        }
    }

    #[test]
    fn exhaustive_two_byte_inputs_are_safe() {
        for a in 0u8..=255 {
            for b in 0u8..=255 {
                let _ = disassemble(&[a, b]).count();
            }
        }
    }
}
