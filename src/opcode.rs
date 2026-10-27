//! Opcode constants, immediate sizes and mnemonics.

use core::fmt;

pub const STOP: u8 = 0x00;
pub const EQ: u8 = 0x14;
pub const ORIGIN: u8 = 0x32;
pub const SLOAD: u8 = 0x54;
pub const SSTORE: u8 = 0x55;
pub const JUMP: u8 = 0x56;
pub const JUMPI: u8 = 0x57;
pub const JUMPDEST: u8 = 0x5b;
pub const PUSH0: u8 = 0x5f;
pub const PUSH1: u8 = 0x60;
pub const PUSH4: u8 = 0x63;
pub const PUSH32: u8 = 0x7f;
pub const DUP1: u8 = 0x80;
pub const DUP16: u8 = 0x8f;
pub const CREATE: u8 = 0xf0;
pub const CALL: u8 = 0xf1;
pub const CALLCODE: u8 = 0xf2;
pub const RETURN: u8 = 0xf3;
pub const DELEGATECALL: u8 = 0xf4;
pub const CREATE2: u8 = 0xf5;
pub const STATICCALL: u8 = 0xfa;
pub const REVERT: u8 = 0xfd;
pub const INVALID: u8 = 0xfe;
pub const SELFDESTRUCT: u8 = 0xff;

/// Number of immediate bytes that follow `op` (non-zero only for PUSH1..PUSH32).
#[inline]
pub const fn imm_len(op: u8) -> usize {
    if op >= PUSH1 && op <= PUSH32 {
        (op - PUSH0) as usize
    } else {
        0
    }
}

/// An opcode byte with a `Display` impl that prints its mnemonic.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Op(pub u8);

impl fmt::Display for Op {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let op = self.0;
        match op {
            0x60..=0x7f => write!(f, "PUSH{}", op - PUSH0),
            0x80..=0x8f => write!(f, "DUP{}", op - 0x7f),
            0x90..=0x9f => write!(f, "SWAP{}", op - 0x8f),
            0xa0..=0xa4 => write!(f, "LOG{}", op - 0xa0),
            _ => f.write_str(fixed_name(op)),
        }
    }
}

const fn fixed_name(op: u8) -> &'static str {
    match op {
        0x00 => "STOP",
        0x01 => "ADD",
        0x02 => "MUL",
        0x03 => "SUB",
        0x04 => "DIV",
        0x05 => "SDIV",
        0x06 => "MOD",
        0x07 => "SMOD",
        0x08 => "ADDMOD",
        0x09 => "MULMOD",
        0x0a => "EXP",
        0x0b => "SIGNEXTEND",
        0x10 => "LT",
        0x11 => "GT",
        0x12 => "SLT",
        0x13 => "SGT",
        0x14 => "EQ",
        0x15 => "ISZERO",
        0x16 => "AND",
        0x17 => "OR",
        0x18 => "XOR",
        0x19 => "NOT",
        0x1a => "BYTE",
        0x1b => "SHL",
        0x1c => "SHR",
        0x1d => "SAR",
        0x20 => "KECCAK256",
        0x30 => "ADDRESS",
        0x31 => "BALANCE",
        0x32 => "ORIGIN",
        0x33 => "CALLER",
        0x34 => "CALLVALUE",
        0x35 => "CALLDATALOAD",
        0x36 => "CALLDATASIZE",
        0x37 => "CALLDATACOPY",
        0x38 => "CODESIZE",
        0x39 => "CODECOPY",
        0x3a => "GASPRICE",
        0x3b => "EXTCODESIZE",
        0x3c => "EXTCODECOPY",
        0x3d => "RETURNDATASIZE",
        0x3e => "RETURNDATACOPY",
        0x3f => "EXTCODEHASH",
        0x40 => "BLOCKHASH",
        0x41 => "COINBASE",
        0x42 => "TIMESTAMP",
        0x43 => "NUMBER",
        0x44 => "PREVRANDAO",
        0x45 => "GASLIMIT",
        0x46 => "CHAINID",
        0x47 => "SELFBALANCE",
        0x48 => "BASEFEE",
        0x49 => "BLOBHASH",
        0x4a => "BLOBBASEFEE",
        0x50 => "POP",
        0x51 => "MLOAD",
        0x52 => "MSTORE",
        0x53 => "MSTORE8",
        0x54 => "SLOAD",
        0x55 => "SSTORE",
        0x56 => "JUMP",
        0x57 => "JUMPI",
        0x58 => "PC",
        0x59 => "MSIZE",
        0x5a => "GAS",
        0x5b => "JUMPDEST",
        0x5c => "TLOAD",
        0x5d => "TSTORE",
        0x5e => "MCOPY",
        0x5f => "PUSH0",
        0xf0 => "CREATE",
        0xf1 => "CALL",
        0xf2 => "CALLCODE",
        0xf3 => "RETURN",
        0xf4 => "DELEGATECALL",
        0xf5 => "CREATE2",
        0xfa => "STATICCALL",
        0xfd => "REVERT",
        0xfe => "INVALID",
        0xff => "SELFDESTRUCT",
        _ => "UNKNOWN",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::string::ToString;

    #[test]
    fn push_immediate_sizes() {
        assert_eq!(imm_len(PUSH0), 0);
        assert_eq!(imm_len(PUSH1), 1);
        assert_eq!(imm_len(PUSH4), 4);
        assert_eq!(imm_len(PUSH32), 32);
        assert_eq!(imm_len(0x80), 0);
        assert_eq!(imm_len(JUMPDEST), 0);
    }

    #[test]
    fn mnemonics() {
        assert_eq!(Op(0x63).to_string(), "PUSH4");
        assert_eq!(Op(0x80).to_string(), "DUP1");
        assert_eq!(Op(0x9f).to_string(), "SWAP16");
        assert_eq!(Op(0xa2).to_string(), "LOG2");
        assert_eq!(Op(0xf4).to_string(), "DELEGATECALL");
        assert_eq!(Op(0x0c).to_string(), "UNKNOWN");
    }
}
