//! bytecode-sentinel: a `no_std`, zero-dependency, zero-allocation toolkit
//! for checking what you are about to sign or call.
//!
//! Two independent halves:
//!
//! * **Bytecode** (`opcode`, `jumpdest`, `disasm`, `scan`): what instructions
//!   does this contract really contain. `PUSH` immediates are never mistaken
//!   for opcodes, and `JUMPDEST` validity follows the EVM rules.
//! * **Calldata** (`abi`, `dynabi`, `calldata`, `multicall`, `router`, `risk`, `batch`):
//!   what authorization does this transaction grant, and to whom. Decoding
//!   and judging are separate steps; `batch` is the one module that composes
//!   them, so approvals hidden inside a `multicall`, a Multicall3
//!   `aggregate*` call or a Universal Router `execute` plan are judged too.
//!
//! Design rules: no heap, no `unsafe`, and hostile input never panics. Any
//! decode error means "cannot vouch for this", never "safe".
//!
//! # Example
//!
//! ```
//! use bytecode_sentinel::{assess, decode, Address, Context, Severity};
//!
//! // approve(0xdede..de, type(uint256).max)
//! let mut calldata = vec![0x09, 0x5e, 0xa7, 0xb3];
//! calldata.extend_from_slice(&[0u8; 12]);
//! calldata.extend_from_slice(&[0xde; 20]);
//! calldata.extend_from_slice(&[0xff; 32]);
//!
//! let trusted = [Address([0x11; 20])];
//! match decode(&calldata) {
//!     Ok(decoded) => {
//!         let verdict = assess(&decoded, &Context::new(&trusted));
//!         assert_eq!(verdict.severity, Severity::High);
//!     }
//!     // Cannot vouch for it: warn the user, never treat as safe.
//!     Err(_) => unreachable!("well-formed approve"),
//! }
//! ```

#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]

pub mod abi;
pub mod batch;
pub mod calldata;
pub mod disasm;
pub mod dynabi;
pub mod jumpdest;
pub mod multicall;
pub mod opcode;
pub mod risk;
pub mod router;
pub mod scan;

pub use abi::{Address, DecodeError, Word};
pub use batch::{assess_calldata, BatchAssessment};
pub use calldata::{decode, Call, Decoded};
pub use disasm::{disassemble, Instruction, Instructions};
pub use dynabi::{BytesArray, Entry, Field, TupleArray};
pub use jumpdest::{words_needed, BufferTooSmall, JumpdestMap};
pub use multicall::{calls, decode_multicall, is_multicall, InnerCall, Item, Items, Multicall};
pub use opcode::Op;
pub use risk::{assess, assess_recipient, Assessment, Context, Flags, Severity};
pub use router::{
    command_name, commands, decode_execute, decode_permit_batch, decode_permit_single,
    decode_spend, is_execute, kind_of, Command, Commands, Execute, Kind, PermitBatch,
    PermitDetails, PermitSingle, Plan, Recipient, Spend,
};
pub use scan::{extract_selectors, scan, Report};
