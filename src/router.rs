//! Decode Universal Router `execute` calls and walk the commands inside them.
//!
//! A router call is a *plan*: a `bytes` of command bytes and a `bytes[]` with
//! one input per command. Everything here follows the router source it was
//! written against (see the README, "Universal Router"): `Commands.sol` and
//! `Dispatcher.sol` for the command table and each command's input layout,
//! `UniversalRouter.sol` for the entry points, `IAllowanceTransfer.sol` (Permit2)
//! for the permit structs. Command values are not typed from memory:
//! `tools/verify_commands.py` compares the table below with `Commands.sol`.
//!
//! | Signature | Selector |
//! |---|---|
//! | `execute(bytes,bytes[])` | `24856bc3` |
//! | `execute(bytes,bytes[],uint256)` | `3593564c` |
//!
//! (`executeSigned` exists in the source this was written against and is not
//! decoded: its selector comes back as `UnknownSelector`, which is "cannot
//! vouch", never a verdict.)
//!
//! This module only decodes. [`Command::kind`] says which commands this crate
//! can judge; [`decode_permit_single`] and [`decode_permit_batch`] read the
//! two Permit2 permit commands into plain values, and
//! [`PermitDetails::to_call`] turns each into the same [`Call`] that a direct
//! Permit2 `approve` decodes to, so [`crate::risk`] needs no new rules.
//! Composing decode and judgement is [`crate::batch`]'s job.
//!
//! Strictness follows the rest of the crate, and is deliberately stricter than
//! the router: offsets must be aligned and may not point into a head or into
//! the region before them, `commands` comes before `inputs`, padding must be
//! zero, static words must be canonical, and the number of commands must equal
//! the number of inputs (the router reverts with `LengthMismatch` otherwise).
//! Gaps and trailing bytes are not errors; they are counted, because the EVM
//! ignores them.
//!
//! `EXECUTE_SUB_PLAN` inputs are `abi.decode(bytes, bytes[])` (the router's
//! own decoder, which only accepts the canonical layout). [`Commands`]
//! descends into them like [`crate::multicall::Calls`] descends into nested
//! batches, up to [`MAX_DEPTH`] levels.

use crate::abi::{Address, Args, DecodeError, Word};
use crate::calldata::Call;
use crate::dynabi::{to_usize, word_at, BytesArray, DynBytes};

/// `execute(bytes,bytes[])`
pub const SEL_EXECUTE: [u8; 4] = [0x24, 0x85, 0x6b, 0xc3];
/// `execute(bytes,bytes[],uint256)` (with a deadline)
pub const SEL_EXECUTE_DEADLINE: [u8; 4] = [0x35, 0x93, 0x56, 0x4c];

/// Maximum levels of plan nesting, counting the outermost plan.
pub const MAX_DEPTH: usize = 4;

/// Bit 7 of a command byte: the router does not revert if the command fails.
pub const FLAG_ALLOW_REVERT: u8 = 0x80;
/// Bits 0..=6 of a command byte: the command type.
pub const COMMAND_TYPE_MASK: u8 = 0x7f;

/// `ActionConstants.MSG_SENDER` (`address(1)`): the router pays the original
/// `msg.sender`.
pub const MSG_SENDER: Address =
    Address([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
/// `ActionConstants.ADDRESS_THIS` (`address(2)`): the router pays itself.
pub const ADDRESS_THIS: Address =
    Address([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);

/// Head of a plan without a selector: the offsets of `commands` and `inputs`.
const PLAN_HEAD: usize = 64;

macro_rules! commands {
    ($($name:ident = $value:expr;)+) => {
        /// Command type values, as in `Commands.sol`.
        pub mod command {
            $(pub const $name: u8 = $value;)+
        }

        /// Name of command type `ty` (flag bit already removed), if the
        /// router's dispatcher has a handler for it.
        pub fn command_name(ty: u8) -> Option<&'static str> {
            match ty {
                $(command::$name => Some(stringify!($name)),)+
                _ => None,
            }
        }
    };
}

// One line per constant, `NAME = 0x..;`: tools/verify_commands.py parses this
// block and compares it with Commands.sol.
commands! {
    V3_SWAP_EXACT_IN = 0x00;
    V3_SWAP_EXACT_OUT = 0x01;
    PERMIT2_TRANSFER_FROM = 0x02;
    PERMIT2_PERMIT_BATCH = 0x03;
    SWEEP = 0x04;
    TRANSFER = 0x05;
    PAY_PORTION = 0x06;
    PAY_PORTION_FULL_PRECISION = 0x07;
    V2_SWAP_EXACT_IN = 0x08;
    V2_SWAP_EXACT_OUT = 0x09;
    PERMIT2_PERMIT = 0x0a;
    WRAP_ETH = 0x0b;
    UNWRAP_WETH = 0x0c;
    PERMIT2_TRANSFER_FROM_BATCH = 0x0d;
    BALANCE_CHECK_ERC20 = 0x0e;
    V4_SWAP = 0x10;
    V3_POSITION_MANAGER_PERMIT = 0x11;
    V3_POSITION_MANAGER_CALL = 0x12;
    V4_INITIALIZE_POOL = 0x13;
    V4_POSITION_MANAGER_CALL = 0x14;
    EXECUTE_SUB_PLAN = 0x21;
    ACROSS_V4_DEPOSIT_V3 = 0x40;
}

/// What this crate does with a command.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// `PERMIT2_PERMIT`: grants a Permit2 allowance. Decoded and judged.
    Permit2Permit,
    /// `PERMIT2_PERMIT_BATCH`: several Permit2 allowances. Decoded and judged.
    Permit2PermitBatch,
    /// `EXECUTE_SUB_PLAN`: a nested plan. [`Commands`] walks into it.
    ExecuteSubPlan,
    /// Spend whose recipient we decode and judge.
    Permit2TransferFrom,
    Transfer,
    Sweep,
    PayPortion,
    UnwrapWeth,
    /// Multiple recipients; judged when the array can be read.
    Permit2TransferFromBatch,
    /// Dispatcher handles it but this crate does not yet judge the body.
    Other(&'static str),
    /// No handler in the dispatcher this crate follows.
    Unassigned,
}

/// Classify a command byte. The allow-revert flag is ignored.
pub fn kind_of(byte: u8) -> Kind {
    match byte & COMMAND_TYPE_MASK {
        command::PERMIT2_PERMIT => Kind::Permit2Permit,
        command::PERMIT2_PERMIT_BATCH => Kind::Permit2PermitBatch,
        command::EXECUTE_SUB_PLAN => Kind::ExecuteSubPlan,
        command::PERMIT2_TRANSFER_FROM => Kind::Permit2TransferFrom,
        command::TRANSFER => Kind::Transfer,
        command::SWEEP => Kind::Sweep,
        command::PAY_PORTION | command::PAY_PORTION_FULL_PRECISION => Kind::PayPortion,
        command::UNWRAP_WETH => Kind::UnwrapWeth,
        command::PERMIT2_TRANSFER_FROM_BATCH => Kind::Permit2TransferFromBatch,
        ty => match command_name(ty) {
            Some(name) => Kind::Other(name),
            None => Kind::Unassigned,
        },
    }
}

/// True if `data` starts with one of the `execute` selectors. Says nothing
/// about whether the rest decodes.
pub fn is_execute(data: &[u8]) -> bool {
    matches!(data.get(..4), Some(s) if s == SEL_EXECUTE || s == SEL_EXECUTE_DEADLINE)
}

/// A validated plan: the command bytes and one input per command.
#[derive(Clone, Copy, Debug)]
pub struct Plan<'a> {
    commands: &'a [u8],
    inputs: BytesArray<'a>,
    slack: usize,
    trailing: usize,
}

impl<'a> Plan<'a> {
    /// Parse a plan from `args`, which holds `commands`' offset in word 0 and
    /// `inputs`' offset in word 1. `head_len` is the size of the head (64 for
    /// a bare plan; more when other arguments come first).
    pub fn parse(args: &'a [u8], head_len: usize) -> Result<Self, DecodeError> {
        let cmds = DynBytes::parse(args, head_len, 0)?;
        // `inputs` may not start before the end of `commands`: that rules out
        // overlap and the reversed order, which no canonical encoder emits.
        let inputs = BytesArray::parse(args, cmds.end(), 1)?;
        let commands = cmds.data();
        if commands.len() != inputs.len() {
            return Err(DecodeError::LengthMismatch {
                commands: commands.len(),
                inputs: inputs.len(),
            });
        }
        Ok(Self {
            commands,
            slack: cmds.gap().saturating_add(inputs.slack()),
            trailing: args.len().saturating_sub(inputs.end()),
            inputs,
        })
    }

    /// Number of commands (equal to the number of inputs).
    pub fn len(&self) -> usize {
        self.commands.len()
    }

    pub fn is_empty(&self) -> bool {
        self.commands.is_empty()
    }

    /// Bytes inside the plan's layout that nothing accounts for.
    pub fn slack(&self) -> usize {
        self.slack
    }

    /// Bytes after the last byte the plan uses.
    pub fn trailing(&self) -> usize {
        self.trailing
    }

    /// Command byte and input `i`, or `None` if `i >= len()`.
    pub fn get(&self, i: usize) -> Option<(u8, &'a [u8])> {
        Some((*self.commands.get(i)?, self.inputs.get(i)?))
    }
}

/// A decoded `execute` call.
#[derive(Clone, Copy, Debug)]
pub struct Execute<'a> {
    /// The `deadline` of `execute(bytes,bytes[],uint256)`.
    pub deadline: Option<Word>,
    pub plan: Plan<'a>,
}

/// Decode `execute(bytes,bytes[])` or `execute(bytes,bytes[],uint256)`. Any
/// other selector is `UnknownSelector`.
pub fn decode_execute(data: &[u8]) -> Result<Execute<'_>, DecodeError> {
    let sel = match data.get(..4) {
        Some(s) => [s[0], s[1], s[2], s[3]],
        None => return Err(DecodeError::MissingSelector { got: data.len() }),
    };
    let words = match sel {
        SEL_EXECUTE => 2,
        SEL_EXECUTE_DEADLINE => 3,
        other => return Err(DecodeError::UnknownSelector(other)),
    };
    // Checks that the head is present; trailing bytes are measured from the
    // plan's own extent instead.
    let (head, _) = Args::new(data, words)?;
    let deadline = if words == 3 {
        Some(head.uint256(2)?)
    } else {
        None
    };
    let args = data
        .get(4..)
        .ok_or(DecodeError::MissingSelector { got: data.len() })?;
    Ok(Execute {
        deadline,
        plan: Plan::parse(args, 32 * words)?,
    })
}

/// One command found in a plan, with its input still undecoded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Command<'a> {
    /// 1 for a command in the outermost plan, 2 for one inside a sub plan of
    /// it, and so on.
    pub depth: usize,
    /// Position inside its own plan.
    pub index: usize,
    /// The raw command byte (flag bit included).
    pub byte: u8,
    pub input: &'a [u8],
}

impl Command<'_> {
    /// The command type, flag bit removed.
    pub fn ty(&self) -> u8 {
        self.byte & COMMAND_TYPE_MASK
    }

    /// True if a failure of this command is ignored by the router.
    pub fn allow_revert(&self) -> bool {
        self.byte & FLAG_ALLOW_REVERT != 0
    }

    pub fn kind(&self) -> Kind {
        kind_of(self.byte)
    }
}

#[derive(Clone, Copy, Debug)]
struct Frame<'a> {
    plan: Plan<'a>,
    next: usize,
}

/// Iterator over every command of a plan, in order, descending into
/// `EXECUTE_SUB_PLAN` inputs. A sub-plan command is never yielded itself,
/// only its contents.
///
/// After the first `Err` the iterator is finished: a plan that cannot be read
/// completely cannot be vouched for.
#[derive(Clone, Debug)]
pub struct Commands<'a> {
    stack: [Option<Frame<'a>>; MAX_DEPTH],
    depth: usize,
    hidden: usize,
    done: bool,
}

/// Start walking the commands of the `execute` call in `data`.
pub fn commands(data: &[u8]) -> Result<Commands<'_>, DecodeError> {
    let ex = decode_execute(data)?;
    let mut stack = [None; MAX_DEPTH];
    if let Some(slot) = stack.first_mut() {
        *slot = Some(Frame {
            plan: ex.plan,
            next: 0,
        });
    }
    Ok(Commands {
        stack,
        depth: 1,
        hidden: ex.plan.slack().saturating_add(ex.plan.trailing()),
        done: false,
    })
}

impl Commands<'_> {
    /// Bytes ignored by the EVM (gaps and trailing bytes) in every plan
    /// entered so far. Read it after the iterator is exhausted.
    pub fn hidden(&self) -> usize {
        self.hidden
    }

    fn fail(&mut self, e: DecodeError) -> Option<Result<Command<'static>, DecodeError>> {
        self.done = true;
        Some(Err(e))
    }
}

impl<'a> Iterator for Commands<'a> {
    type Item = Result<Command<'a>, DecodeError>;

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
            if index >= frame.plan.len() {
                // This level is exhausted; resume its parent.
                if let Some(slot) = self.stack.get_mut(idx) {
                    *slot = None;
                }
                self.depth -= 1;
                continue;
            }
            let Some((byte, input)) = frame.plan.get(index) else {
                // Unreachable for a validated plan. Skipping the command
                // would hide it, so fail instead.
                return self.fail(DecodeError::BadElementOffset { index });
            };
            frame.next += 1;

            if kind_of(byte) != Kind::ExecuteSubPlan {
                return Some(Ok(Command {
                    depth: self.depth,
                    index,
                    byte,
                    input,
                }));
            }
            match Plan::parse(input, PLAN_HEAD) {
                Err(e) => return self.fail(e),
                Ok(_) if self.depth >= MAX_DEPTH => return self.fail(DecodeError::NestingTooDeep),
                Ok(inner) => {
                    self.hidden = self
                        .hidden
                        .saturating_add(inner.slack())
                        .saturating_add(inner.trailing());
                    if let Some(slot) = self.stack.get_mut(self.depth) {
                        *slot = Some(Frame {
                            plan: inner,
                            next: 0,
                        });
                    }
                    self.depth += 1;
                }
            }
        }
    }
}

// ------------------------------------------------------------------ permits

/// `PermitDetails` of Permit2: `(address token, uint160 amount, uint48
/// expiration, uint48 nonce)`, in this order (`IAllowanceTransfer.sol`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PermitDetails {
    pub token: Address,
    /// A `uint160`.
    pub amount: Word,
    /// A `uint48`: when the allowance stops being valid.
    pub expiration: Word,
    /// A `uint48`.
    pub nonce: Word,
}

impl PermitDetails {
    /// The grant this permit makes, as the same [`Call`] a direct Permit2
    /// `approve(token, spender, amount, expiration)` decodes to.
    pub fn to_call(&self, spender: Address) -> Call {
        Call::Permit2Approve {
            token: self.token,
            spender,
            amount: self.amount,
            expiration: self.expiration,
        }
    }
}

/// A decoded `PERMIT2_PERMIT` input: `abi.encode(PermitSingle, bytes)`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PermitSingle {
    pub details: PermitDetails,
    pub spender: Address,
    /// Deadline of the signature (not of the allowance).
    pub sig_deadline: Word,
    /// Bytes of the input the EVM ignores: a gap before the signature, or
    /// bytes after it.
    pub hidden: usize,
}

fn word_in(buf: &[u8], i: usize) -> Result<Word, DecodeError> {
    word_at(buf, 32usize.saturating_mul(i)).ok_or(DecodeError::Truncated {
        expected: 32usize.saturating_mul(i.saturating_add(1)),
        got: buf.len(),
    })
}

fn address_in(buf: &[u8], i: usize) -> Result<Address, DecodeError> {
    word_in(buf, i)?
        .to_address()
        .ok_or(DecodeError::DirtyPadding { arg: i })
}

fn uint_in(buf: &[u8], i: usize, bits: u32) -> Result<Word, DecodeError> {
    let w = word_in(buf, i)?;
    if w.fits(bits) {
        Ok(w)
    } else {
        Err(DecodeError::DirtyPadding { arg: i })
    }
}

/// Decode the input of `PERMIT2_PERMIT`.
///
/// Layout (`Dispatcher.sol`): the six words of `PermitSingle` inline, then the
/// offset of the signature `bytes` in word 6. In errors, `arg` is the word
/// position in that layout.
pub fn decode_permit_single(input: &[u8]) -> Result<PermitSingle, DecodeError> {
    let details = PermitDetails {
        token: address_in(input, 0)?,
        amount: uint_in(input, 1, 160)?,
        expiration: uint_in(input, 2, 48)?,
        nonce: uint_in(input, 3, 48)?,
    };
    let spender = address_in(input, 4)?;
    let sig_deadline = word_in(input, 5)?;
    let sig = DynBytes::parse(input, 7 * 32, 6)?;
    Ok(PermitSingle {
        details,
        spender,
        sig_deadline,
        hidden: sig
            .gap()
            .saturating_add(input.len().saturating_sub(sig.end())),
    })
}

/// Size of one `PermitDetails` in a `PermitDetails[]`: four static words.
const DETAILS_WORDS: usize = 4;

/// A decoded `PERMIT2_PERMIT_BATCH` input: `abi.encode(PermitBatch, bytes)`.
#[derive(Clone, Copy, Debug)]
pub struct PermitBatch<'a> {
    /// `len * 4` words, every field already validated.
    details: &'a [u8],
    len: usize,
    pub spender: Address,
    /// Deadline of the signature (not of the allowances).
    pub sig_deadline: Word,
    /// Bytes of the input the EVM ignores.
    pub hidden: usize,
}

impl<'a> PermitBatch<'a> {
    /// Number of allowances granted.
    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Allowance `i`, or `None` if `i >= len()`.
    pub fn get(&self, i: usize) -> Option<PermitDetails> {
        if i >= self.len {
            return None;
        }
        let at = i.checked_mul(32 * DETAILS_WORDS)?;
        let e = self.details.get(at..at.checked_add(32 * DETAILS_WORDS)?)?;
        Some(PermitDetails {
            token: word_at(e, 0)?.to_address()?,
            amount: word_at(e, 32)?,
            expiration: word_at(e, 64)?,
            nonce: word_at(e, 96)?,
        })
    }

    pub fn iter(&self) -> PermitBatchIter<'a> {
        PermitBatchIter {
            batch: *self,
            next: 0,
        }
    }
}

/// Iterator over the allowances of a [`PermitBatch`].
#[derive(Clone, Debug)]
pub struct PermitBatchIter<'a> {
    batch: PermitBatch<'a>,
    next: usize,
}

impl Iterator for PermitBatchIter<'_> {
    type Item = PermitDetails;

    fn next(&mut self) -> Option<Self::Item> {
        let item = self.batch.get(self.next)?;
        self.next += 1;
        Some(item)
    }
}

/// Decode the input of `PERMIT2_PERMIT_BATCH`.
///
/// Layout (`Dispatcher.sol`): word 0 is the offset of the `PermitBatch`
/// struct, word 1 the offset of the signature `bytes`. The struct is
/// `(offset of details, spender, sigDeadline)` followed by the `details`
/// array. The struct comes first, then the array, then the signature; any
/// other order is an error.
pub fn decode_permit_batch(input: &[u8]) -> Result<PermitBatch<'_>, DecodeError> {
    const HEAD: usize = 64;
    const STRUCT_HEAD: usize = 96;
    word_in(input, 1)?; // both head words must be present
    let bad_struct = DecodeError::BadOffset { arg: 0 };
    let pb_off = to_usize(&word_in(input, 0)?).ok_or(bad_struct)?;
    if pb_off % 32 != 0 || pb_off < HEAD || pb_off > input.len() {
        return Err(bad_struct);
    }
    let pb = input.get(pb_off..).ok_or(bad_struct)?;
    if pb.len() < STRUCT_HEAD {
        return Err(DecodeError::Truncated {
            expected: pb_off.saturating_add(STRUCT_HEAD),
            got: input.len(),
        });
    }

    let bad_details = DecodeError::BadMemberOffset { index: 0 };
    let d_off = to_usize(&word_in(pb, 0)?).ok_or(bad_details)?;
    if d_off % 32 != 0 || d_off < STRUCT_HEAD {
        return Err(bad_details);
    }
    let spender = address_in(pb, 1)?;
    let sig_deadline = word_in(pb, 2)?;

    // The `details` array: a length word, then `len` four-word tuples.
    let arr = pb_off.checked_add(d_off).ok_or(bad_details)?;
    let len_word = word_at(input, arr).ok_or(bad_details)?;
    let len = to_usize(&len_word).ok_or(DecodeError::BadArrayLength)?;
    let body = arr.checked_add(32).ok_or(DecodeError::BadArrayLength)?;
    let body_end = len
        .checked_mul(32 * DETAILS_WORDS)
        .and_then(|n| body.checked_add(n))
        .filter(|e| *e <= input.len())
        .ok_or(DecodeError::BadArrayLength)?;
    let details = input
        .get(body..body_end)
        .ok_or(DecodeError::BadArrayLength)?;

    for index in 0..len {
        let at = index.saturating_mul(32 * DETAILS_WORDS);
        let e = details
            .get(at..at.saturating_add(32 * DETAILS_WORDS))
            .ok_or(DecodeError::BadArrayLength)?;
        let dirty = |field: usize| DecodeError::DirtyElementField { index, field };
        let field = |i: usize| word_at(e, 32 * i).ok_or(dirty(i));
        if field(0)?.to_address().is_none() {
            return Err(dirty(0));
        }
        if !field(1)?.fits(160) {
            return Err(dirty(1));
        }
        if !field(2)?.fits(48) {
            return Err(dirty(2));
        }
        if !field(3)?.fits(48) {
            return Err(dirty(3));
        }
    }

    // The signature may not start before the end of the array.
    let sig = DynBytes::parse(input, body_end, 1)?;
    let hidden = pb_off
        .saturating_sub(HEAD)
        .saturating_add(d_off.saturating_sub(STRUCT_HEAD))
        .saturating_add(sig.gap())
        .saturating_add(input.len().saturating_sub(sig.end()));
    Ok(PermitBatch {
        details,
        len,
        spender,
        sig_deadline,
        hidden,
    })
}

#[cfg(test)]
pub(crate) mod testutil {
    //! Builders for router calldata in tests (canonical layouts).
    use super::*;
    use crate::calldata::testutil::{addr_word, uint_word};
    use crate::dynabi::testutil::{encode_bytes_array, pad32};
    use std::vec::Vec;

    /// `abi.encode(bytes commands, bytes[] inputs)`: a plan without selector.
    pub fn plan_args(commands: &[u8], inputs: &[Vec<u8>]) -> Vec<u8> {
        let mut v = uint_word(64).to_vec();
        v.extend(uint_word((64 + 32 + pad32(commands.len())) as u64));
        v.extend(uint_word(commands.len() as u64));
        v.extend_from_slice(commands);
        v.resize(v.len() + pad32(commands.len()) - commands.len(), 0);
        v.extend(encode_bytes_array(inputs));
        v
    }

    /// `execute(bytes,bytes[])`.
    pub fn execute_data(commands: &[u8], inputs: &[Vec<u8>]) -> Vec<u8> {
        let mut v = SEL_EXECUTE.to_vec();
        v.extend(plan_args(commands, inputs));
        v
    }

    /// `execute(bytes,bytes[],uint256)`.
    pub fn execute_deadline_data(commands: &[u8], inputs: &[Vec<u8>], deadline: u64) -> Vec<u8> {
        let mut v = SEL_EXECUTE_DEADLINE.to_vec();
        v.extend(uint_word(96));
        v.extend(uint_word((96 + 32 + pad32(commands.len())) as u64));
        v.extend(uint_word(deadline));
        v.extend(uint_word(commands.len() as u64));
        v.extend_from_slice(commands);
        v.resize(v.len() + pad32(commands.len()) - commands.len(), 0);
        v.extend(encode_bytes_array(inputs));
        v
    }

    fn bytes_tail(sig: &[u8]) -> Vec<u8> {
        let mut v = uint_word(sig.len() as u64).to_vec();
        v.extend_from_slice(sig);
        v.resize(v.len() + pad32(sig.len()) - sig.len(), 0);
        v
    }

    /// Input of `PERMIT2_PERMIT`, canonical layout. `token` and `spender`
    /// are address fill bytes.
    pub fn permit_single_input(
        token: u8,
        amount: [u8; 32],
        expiration: u64,
        nonce: u64,
        spender: u8,
        sig: &[u8],
    ) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend(addr_word(token));
        v.extend(amount);
        v.extend(uint_word(expiration));
        v.extend(uint_word(nonce));
        v.extend(addr_word(spender));
        v.extend(uint_word(0xffff)); // sigDeadline
        v.extend(uint_word(7 * 32)); // offset of the signature
        v.extend(bytes_tail(sig));
        v
    }

    /// Input of `PERMIT2_PERMIT_BATCH`, canonical layout. `details` are
    /// `(token fill byte, amount, expiration, nonce)`.
    pub fn permit_batch_input(
        details: &[(u8, [u8; 32], u64, u64)],
        spender: u8,
        sig: &[u8],
    ) -> Vec<u8> {
        let mut pb = uint_word(96).to_vec(); // details right after the struct head
        pb.extend(addr_word(spender));
        pb.extend(uint_word(0xffff));
        pb.extend(uint_word(details.len() as u64));
        for (token, amount, expiration, nonce) in details {
            pb.extend(addr_word(*token));
            pb.extend(*amount);
            pb.extend(uint_word(*expiration));
            pb.extend(uint_word(*nonce));
        }
        let mut v = uint_word(64).to_vec();
        v.extend(uint_word((64 + pb.len()) as u64));
        v.extend(pb);
        v.extend(bytes_tail(sig));
        v
    }
}

#[cfg(test)]
mod tests {
    use super::testutil::*;
    use super::*;
    use crate::calldata::testutil::{max_word, uint_word};
    use crate::dynabi::testutil::encode_bytes_array;
    use std::vec;
    use std::vec::Vec;

    fn a(fill: u8) -> Address {
        Address([fill; 20])
    }

    fn max160() -> [u8; 32] {
        let mut w = [0u8; 32];
        w[12..].fill(0xff);
        w
    }

    fn set_word(v: &mut [u8], at: usize, w: [u8; 32]) {
        v[at..at + 32].copy_from_slice(&w);
    }

    fn sig65() -> Vec<u8> {
        vec![0x5a; 65]
    }

    fn walk(data: &[u8]) -> (Vec<Result<Command<'_>, DecodeError>>, usize) {
        let mut w = commands(data).unwrap();
        let items: Vec<_> = w.by_ref().collect();
        let hidden = w.hidden();
        (items, hidden)
    }

    /// `levels` plans nested through `EXECUTE_SUB_PLAN`, the outermost being
    /// the `execute` call itself; the innermost holds one harmless command.
    fn nested(levels: usize) -> Vec<u8> {
        let mut p = plan_args(&[0x04], &[vec![1]]);
        for _ in 2..levels {
            p = plan_args(&[0x21], &[p]);
        }
        execute_data(&[0x21], &[p])
    }

    // ------------------------------------------------------------- execute

    #[test]
    fn only_the_two_execute_selectors_are_recognised() {
        assert!(is_execute(&execute_data(&[], &[])));
        assert!(is_execute(&execute_deadline_data(&[], &[], 1)));
        assert!(!is_execute(&[0x24, 0x85, 0x6b]));
        assert!(!is_execute(&[]));
        // `executeSigned` is in the router but deliberately not decoded.
        let signed = [0x44, 0x68, 0x4d, 0xc3, 0, 0, 0];
        assert!(!is_execute(&signed));
        assert!(matches!(
            decode_execute(&signed),
            Err(DecodeError::UnknownSelector([0x44, 0x68, 0x4d, 0xc3]))
        ));
        assert!(matches!(
            decode_execute(&[1, 2]),
            Err(DecodeError::MissingSelector { got: 2 })
        ));
        assert!(matches!(
            decode_execute(&SEL_EXECUTE),
            Err(DecodeError::Truncated { .. })
        ));
    }

    #[test]
    fn a_canonical_plan_decodes() {
        let inputs = vec![vec![1u8; 5], vec![2u8; 40], vec![]];
        let data = execute_data(&[0x08, 0x0a, 0x04], &inputs);
        let ex = decode_execute(&data).unwrap();
        assert_eq!(ex.deadline, None);
        assert_eq!(ex.plan.len(), 3);
        assert_eq!((ex.plan.slack(), ex.plan.trailing()), (0, 0));
        assert_eq!(ex.plan.get(0), Some((0x08, &inputs[0][..])));
        assert_eq!(ex.plan.get(1), Some((0x0a, &inputs[1][..])));
        assert_eq!(ex.plan.get(2), Some((0x04, &inputs[2][..])));
        assert_eq!(ex.plan.get(3), None);
    }

    #[test]
    fn an_empty_plan_is_valid() {
        let data = execute_data(&[], &[]);
        let ex = decode_execute(&data).unwrap();
        assert!(ex.plan.is_empty());
        assert_eq!((ex.plan.slack(), ex.plan.trailing()), (0, 0));
    }

    #[test]
    fn the_deadline_variant_carries_its_deadline() {
        let data = execute_deadline_data(&[0x08, 0x04], &[vec![1], vec![2]], 1234);
        let ex = decode_execute(&data).unwrap();
        assert_eq!(ex.deadline, Some(Word(uint_word(1234))));
        assert_eq!(ex.plan.len(), 2);
        assert_eq!((ex.plan.slack(), ex.plan.trailing()), (0, 0));
        assert_eq!(ex.plan.get(1), Some((0x04, &[2u8][..])));
    }

    #[test]
    fn a_length_mismatch_is_an_error() {
        let data = execute_data(&[0x08, 0x04], &[vec![1]]);
        assert!(matches!(
            decode_execute(&data),
            Err(DecodeError::LengthMismatch {
                commands: 2,
                inputs: 1
            })
        ));
        let data = execute_data(&[0x08], &[vec![1], vec![2], vec![3]]);
        assert!(matches!(
            decode_execute(&data),
            Err(DecodeError::LengthMismatch {
                commands: 1,
                inputs: 3
            })
        ));
    }

    #[test]
    fn the_commands_offset_may_not_point_into_the_head() {
        let mut data = execute_data(&[0x08], &[vec![1]]);
        set_word(&mut data, 4, uint_word(32));
        assert!(matches!(
            decode_execute(&data),
            Err(DecodeError::BadOffset { arg: 0 })
        ));
        // The deadline variant has a 96-byte head: 64 is inside it.
        let mut data = execute_deadline_data(&[0x08], &[vec![1]], 9);
        set_word(&mut data, 4, uint_word(64));
        assert!(matches!(
            decode_execute(&data),
            Err(DecodeError::BadOffset { arg: 0 })
        ));
    }

    #[test]
    fn inputs_may_not_overlap_or_precede_commands() {
        // Overlap: `inputs` offset points at the start of `commands`.
        let mut data = execute_data(&[0x08], &[vec![1]]);
        set_word(&mut data, 4 + 32, uint_word(64));
        assert!(matches!(
            decode_execute(&data),
            Err(DecodeError::BadOffset { arg: 1 })
        ));

        // Reversed order: `inputs` first, `commands` after it.
        let arr = encode_bytes_array(&[vec![1u8]]);
        let mut args = uint_word(64 + arr.len() as u64).to_vec(); // commands
        args.extend(uint_word(64)); // inputs
        args.extend(&arr);
        args.extend(uint_word(1));
        let mut cmds = vec![0x08];
        cmds.resize(32, 0);
        args.extend(cmds);
        let mut data = SEL_EXECUTE.to_vec();
        data.extend(args);
        assert!(matches!(
            decode_execute(&data),
            Err(DecodeError::BadOffset { arg: 1 })
        ));
    }

    #[test]
    fn dirty_command_padding_is_an_error() {
        let mut data = execute_data(&[0x08], &[vec![1]]);
        // commands: offset at 4+64, length word then one byte then 31 pad.
        data[4 + 64 + 32 + 5] = 1;
        assert!(matches!(
            decode_execute(&data),
            Err(DecodeError::DirtyBytesPadding { index: 0 })
        ));
    }

    #[test]
    fn gaps_and_trailing_bytes_are_counted_not_rejected() {
        let inputs = vec![vec![1u8; 5], vec![2u8; 7]];
        let commands = [0x08, 0x04];
        let mut cmds_enc = uint_word(2).to_vec();
        cmds_enc.extend_from_slice(&commands);
        cmds_enc.resize(64, 0);
        let (head_gap, mid_gap) = (32usize, 64usize);
        let off_cmd = 64 + head_gap;
        let off_inp = off_cmd + cmds_enc.len() + mid_gap;
        let mut args = uint_word(off_cmd as u64).to_vec();
        args.extend(uint_word(off_inp as u64));
        args.extend(vec![0xee; head_gap]);
        args.extend(&cmds_enc);
        args.extend(vec![0xdd; mid_gap]);
        args.extend(encode_bytes_array(&inputs));
        args.extend(vec![0xcc; 5]);
        let mut data = SEL_EXECUTE.to_vec();
        data.extend(args);

        let ex = decode_execute(&data).unwrap();
        assert_eq!(ex.plan.len(), 2);
        assert_eq!(ex.plan.slack(), head_gap + mid_gap);
        assert_eq!(ex.plan.trailing(), 5);
        assert_eq!(ex.plan.get(1), Some((0x04, &inputs[1][..])));
    }

    // ------------------------------------------------------------ commands

    #[test]
    fn the_flag_bit_and_the_type_are_separated() {
        let c = |byte| Command {
            depth: 1,
            index: 0,
            byte,
            input: &[],
        };
        assert_eq!((c(0x0a).ty(), c(0x0a).allow_revert()), (0x0a, false));
        assert_eq!((c(0x8a).ty(), c(0x8a).allow_revert()), (0x0a, true));
        assert_eq!(c(0x8a).kind(), Kind::Permit2Permit);
        assert_eq!((c(0xff).ty(), c(0xff).allow_revert()), (0x7f, true));
    }

    #[test]
    fn the_classification_matches_the_dispatchers_ranges() {
        // Written from the range comments in Dispatcher.sol, independently of
        // the table in this module: everything below is a placeholder that
        // reverts with InvalidCommandType.
        let placeholder = |ty: u8| {
            ty == 0x0f || (0x15..=0x20).contains(&ty) || (0x22..=0x3f).contains(&ty) || ty >= 0x41
        };
        for ty in 0..=0x7fu8 {
            for byte in [ty, ty | FLAG_ALLOW_REVERT] {
                let k = kind_of(byte);
                assert_eq!(k == Kind::Unassigned, placeholder(ty), "type {ty:#04x}");
                assert_eq!(
                    command_name(ty).is_none(),
                    placeholder(ty),
                    "type {ty:#04x}"
                );
            }
        }
        assert_eq!(kind_of(0x0a), Kind::Permit2Permit);
        assert_eq!(kind_of(0x03), Kind::Permit2PermitBatch);
        assert_eq!(kind_of(0x21), Kind::ExecuteSubPlan);
        assert_eq!(kind_of(0x00), Kind::Other("V3_SWAP_EXACT_IN"));
        assert_eq!(kind_of(0x02), Kind::Permit2TransferFrom);
        assert_eq!(kind_of(0x05), Kind::Transfer);
        assert_eq!(kind_of(0x04), Kind::Sweep);
        assert_eq!(kind_of(0x06), Kind::PayPortion);
        assert_eq!(kind_of(0x07), Kind::PayPortion);
        assert_eq!(kind_of(0x0c), Kind::UnwrapWeth);
        assert_eq!(kind_of(0x0d), Kind::Permit2TransferFromBatch);
        assert_eq!(kind_of(0x40), Kind::Other("ACROSS_V4_DEPOSIT_V3"));
        // This version of the dispatcher has no APPROVE_ERC20.
        assert_eq!(kind_of(0x16), Kind::Unassigned);
    }

    #[test]
    fn commands_come_out_in_order_with_their_flags() {
        let data = execute_data(&[0x08, 0x8a, 0x04], &[vec![1], vec![2], vec![3]]);
        let (items, hidden) = walk(&data);
        let got: Vec<_> = items
            .iter()
            .map(|r| {
                let c = r.as_ref().unwrap();
                (c.depth, c.index, c.byte, c.allow_revert(), c.input.to_vec())
            })
            .collect();
        assert_eq!(
            got,
            vec![
                (1, 0, 0x08, false, vec![1]),
                (1, 1, 0x8a, true, vec![2]),
                (1, 2, 0x04, false, vec![3]),
            ]
        );
        assert_eq!(hidden, 0);
    }

    #[test]
    fn a_sub_plan_is_entered_and_never_yielded_itself() {
        let sub = plan_args(&[0x0a, 0x04], &[vec![7], vec![8]]);
        let data = execute_data(&[0x08, 0x21, 0x04], &[vec![1], sub, vec![3]]);
        let (items, _) = walk(&data);
        let got: Vec<_> = items
            .iter()
            .map(|r| {
                let c = r.as_ref().unwrap();
                (c.depth, c.index, c.byte)
            })
            .collect();
        assert_eq!(
            got,
            vec![(1, 0, 0x08), (2, 0, 0x0a), (2, 1, 0x04), (1, 2, 0x04)]
        );
    }

    #[test]
    fn hidden_bytes_inside_a_sub_plan_are_counted() {
        let mut sub = plan_args(&[0x04], &[vec![7]]);
        sub.extend(vec![0xab; 7]);
        let data = execute_data(&[0x21], &[sub]);
        let (items, hidden) = walk(&data);
        assert_eq!(items.len(), 1);
        assert_eq!(hidden, 7);
    }

    #[test]
    fn a_malformed_sub_plan_is_an_error_and_ends_the_walk() {
        let data = execute_data(&[0x08, 0x21, 0x04], &[vec![1], vec![1, 2, 3], vec![3]]);
        let mut w = commands(&data).unwrap();
        assert!(w.next().unwrap().is_ok());
        assert!(matches!(
            w.next().unwrap(),
            Err(DecodeError::Truncated { .. })
        ));
        assert!(w.next().is_none(), "nothing after an error");
    }

    #[test]
    fn a_sub_plan_with_mismatched_lengths_is_an_error() {
        let sub = plan_args(&[0x04, 0x04], &[vec![1]]);
        let data = execute_data(&[0x21], &[sub]);
        let mut w = commands(&data).unwrap();
        assert!(matches!(
            w.next().unwrap(),
            Err(DecodeError::LengthMismatch {
                commands: 2,
                inputs: 1
            })
        ));
    }

    #[test]
    fn nesting_is_limited_to_max_depth_levels() {
        let ok = nested(MAX_DEPTH);
        let (items, _) = walk(&ok);
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].as_ref().unwrap().depth, MAX_DEPTH);

        let too_deep = nested(MAX_DEPTH + 1);
        let (items, _) = walk(&too_deep);
        assert!(matches!(
            items.last().unwrap(),
            Err(DecodeError::NestingTooDeep)
        ));
    }

    // ------------------------------------------------------------- permits

    #[test]
    fn a_canonical_permit_single_decodes() {
        let input = permit_single_input(0xaa, max160(), 5000, 3, 0x11, &sig65());
        let p = decode_permit_single(&input).unwrap();
        assert_eq!(p.details.token, a(0xaa));
        assert_eq!(p.details.amount, Word(max160()));
        assert_eq!(p.details.expiration, Word(uint_word(5000)));
        assert_eq!(p.details.nonce, Word(uint_word(3)));
        assert_eq!(p.spender, a(0x11));
        assert_eq!(p.sig_deadline, Word(uint_word(0xffff)));
        assert_eq!(p.hidden, 0);
        assert_eq!(
            p.details.to_call(p.spender),
            Call::Permit2Approve {
                token: a(0xaa),
                spender: a(0x11),
                amount: Word(max160()),
                expiration: Word(uint_word(5000)),
            }
        );
    }

    #[test]
    fn permit_single_fields_must_be_canonical() {
        let good = permit_single_input(0xaa, max160(), 5000, 3, 0x11, &sig65());
        // (word index, byte inside it, expected arg)
        for (word, byte, arg) in [(0, 3, 0), (1, 11, 1), (2, 5, 2), (3, 5, 3), (4, 0, 4)] {
            let mut bad = good.clone();
            bad[32 * word + byte] = 1;
            assert_eq!(
                decode_permit_single(&bad),
                Err(DecodeError::DirtyPadding { arg }),
                "word {word}"
            );
        }
        // A uint48 that fits is fine at its maximum.
        let max48 = {
            let mut w = [0u8; 32];
            w[26..].fill(0xff);
            w
        };
        let mut ok = good.clone();
        set_word(&mut ok, 64, max48);
        assert!(decode_permit_single(&ok).is_ok());
    }

    #[test]
    fn permit_single_signature_offset_and_padding_are_checked() {
        let good = permit_single_input(0xaa, max160(), 5000, 3, 0x11, &sig65());
        let mut bad = good.clone();
        set_word(&mut bad, 192, uint_word(192)); // into the struct
        assert_eq!(
            decode_permit_single(&bad),
            Err(DecodeError::BadOffset { arg: 6 })
        );
        let mut bad = good.clone();
        set_word(&mut bad, 192, uint_word(225)); // unaligned
        assert_eq!(
            decode_permit_single(&bad),
            Err(DecodeError::BadOffset { arg: 6 })
        );
        let mut bad = good.clone();
        bad[good.len() - 1] = 1; // padding after the 65 signature bytes
        assert_eq!(
            decode_permit_single(&bad),
            Err(DecodeError::DirtyBytesPadding { index: 6 })
        );
        assert!(matches!(
            decode_permit_single(&good[..100]),
            Err(DecodeError::Truncated { .. })
        ));
        assert!(matches!(
            decode_permit_single(&[]),
            Err(DecodeError::Truncated { .. })
        ));
    }

    #[test]
    fn permit_single_hidden_bytes_are_counted() {
        let good = permit_single_input(0xaa, max160(), 5000, 3, 0x11, &sig65());
        let mut trailing = good.clone();
        trailing.extend(vec![0xcc; 9]);
        assert_eq!(decode_permit_single(&trailing).unwrap().hidden, 9);

        // A 32-byte gap between the head and the signature.
        let mut gap = good[..224].to_vec();
        set_word(&mut gap, 192, uint_word(256));
        gap.extend(vec![0xee; 32]);
        gap.extend(&good[224..]);
        gap.extend(vec![0xcc; 3]);
        assert_eq!(decode_permit_single(&gap).unwrap().hidden, 35);
    }

    fn batch_input() -> Vec<u8> {
        permit_batch_input(
            &[
                (0xa1, max160(), 100, 1),
                (0xa2, uint_word(5), 200, 2),
                (0xa3, max160(), 300, 3),
            ],
            0x11,
            &sig65(),
        )
    }

    #[test]
    fn a_canonical_permit_batch_decodes() {
        let input = batch_input();
        let b = decode_permit_batch(&input).unwrap();
        assert_eq!((b.len(), b.is_empty()), (3, false));
        assert_eq!(b.spender, a(0x11));
        assert_eq!(b.sig_deadline, Word(uint_word(0xffff)));
        assert_eq!(b.hidden, 0);
        let d1 = b.get(1).unwrap();
        assert_eq!(d1.token, a(0xa2));
        assert_eq!(d1.amount, Word(uint_word(5)));
        assert_eq!(d1.expiration, Word(uint_word(200)));
        assert_eq!(d1.nonce, Word(uint_word(2)));
        assert_eq!(b.get(3), None);
        let tokens: Vec<_> = b.iter().map(|d| d.token).collect();
        assert_eq!(tokens, vec![a(0xa1), a(0xa2), a(0xa3)]);
    }

    #[test]
    fn an_empty_permit_batch_is_valid() {
        let input = permit_batch_input(&[], 0x11, &sig65());
        let b = decode_permit_batch(&input).unwrap();
        assert!(b.is_empty());
        assert_eq!(b.iter().count(), 0);
        assert_eq!(b.hidden, 0);
    }

    #[test]
    fn permit_batch_offsets_are_checked() {
        let good = batch_input();
        // Head word 0: offset of the struct.
        for bad_off in [32u64, 65, 1 << 40] {
            let mut bad = good.clone();
            set_word(&mut bad, 0, uint_word(bad_off));
            assert_eq!(
                decode_permit_batch(&bad).unwrap_err(),
                DecodeError::BadOffset { arg: 0 },
                "struct offset {bad_off}"
            );
        }
        // Struct word 0 (at byte 64): offset of the details array.
        for bad_off in [64u64, 97, 1 << 40] {
            let mut bad = good.clone();
            set_word(&mut bad, 64, uint_word(bad_off));
            assert_eq!(
                decode_permit_batch(&bad).unwrap_err(),
                DecodeError::BadMemberOffset { index: 0 },
                "details offset {bad_off}"
            );
        }
        // Head word 1: signature offset inside the details array.
        let mut bad = good.clone();
        set_word(&mut bad, 32, uint_word(200));
        assert_eq!(
            decode_permit_batch(&bad).unwrap_err(),
            DecodeError::BadOffset { arg: 1 }
        );
        // An enormous details count cannot fit.
        let mut bad = good.clone();
        set_word(&mut bad, 64 + 96, uint_word(1 << 40));
        assert_eq!(
            decode_permit_batch(&bad).unwrap_err(),
            DecodeError::BadArrayLength
        );
        assert!(matches!(
            decode_permit_batch(&good[..40]),
            Err(DecodeError::Truncated { .. })
        ));
        assert!(matches!(
            decode_permit_batch(&good[..100]),
            Err(DecodeError::Truncated { .. })
        ));
    }

    #[test]
    fn permit_batch_fields_must_be_canonical() {
        let good = batch_input();
        let first = 64 + 96 + 32; // first details tuple
                                  // (element, field, byte inside the word)
        for (index, field, byte) in [(1usize, 0usize, 2usize), (1, 1, 11), (2, 2, 5), (0, 3, 5)] {
            let mut bad = good.clone();
            bad[first + 128 * index + 32 * field + byte] = 1;
            assert_eq!(
                decode_permit_batch(&bad).unwrap_err(),
                DecodeError::DirtyElementField { index, field },
                "element {index} field {field}"
            );
        }
        // Dirty spender in the struct head.
        let mut bad = good.clone();
        bad[64 + 32] = 1;
        assert_eq!(
            decode_permit_batch(&bad).unwrap_err(),
            DecodeError::DirtyPadding { arg: 1 }
        );
    }

    #[test]
    fn permit_batch_hidden_bytes_are_counted() {
        let good = batch_input();
        let mut trailing = good.clone();
        trailing.extend(vec![0xcc; 5]);
        assert_eq!(decode_permit_batch(&trailing).unwrap().hidden, 5);

        // 32 junk bytes between the struct head and the details array.
        let at = 64 + 96;
        let mut gap = good[..at].to_vec();
        gap.extend(vec![0xee; 32]);
        gap.extend(&good[at..]);
        set_word(&mut gap, 64, uint_word(128)); // details offset
        set_word(
            &mut gap,
            32,
            uint_word(32 + u64::from_be_bytes(sig_off(&good))),
        ); // signature offset
        let b = decode_permit_batch(&gap).unwrap();
        assert_eq!(b.hidden, 32);
        assert_eq!(b.len(), 3);
        assert_eq!(b.get(2).unwrap().token, a(0xa3));
    }

    #[test]
    fn a_gap_before_the_permit_batch_struct_is_counted() {
        let good = batch_input();
        // 64 junk bytes between the two head words and the struct.
        let mut gap = good[..64].to_vec();
        gap.extend(vec![0xee; 64]);
        gap.extend(&good[64..]);
        set_word(&mut gap, 0, uint_word(128)); // struct offset
        set_word(
            &mut gap,
            32,
            uint_word(64 + u64::from_be_bytes(sig_off(&good))),
        );
        let b = decode_permit_batch(&gap).unwrap();
        assert_eq!(b.hidden, 64);
        assert_eq!(b.len(), 3);
        assert_eq!(b.spender, a(0x11));
        assert_eq!(b.get(0).unwrap().token, a(0xa1));
    }

    /// The signature offset (head word 1) of a canonical batch input.
    fn sig_off(input: &[u8]) -> [u8; 8] {
        let mut b = [0u8; 8];
        b.copy_from_slice(&input[32 + 24..64]);
        b
    }

    #[test]
    fn dirty_values_cannot_hide_in_unused_bits_of_a_permit() {
        // Same shape as `permit_single_fields_must_be_canonical`, with the
        // maximum words: nothing is masked silently.
        let mut input = permit_single_input(0xaa, max_word(), 5000, 3, 0x11, &sig65());
        assert_eq!(
            decode_permit_single(&input),
            Err(DecodeError::DirtyPadding { arg: 1 })
        );
        set_word(&mut input, 32, max160());
        assert!(decode_permit_single(&input).is_ok());
    }
}

/// Who a spend command pays, with the router's two special values resolved.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Recipient {
    /// [`MSG_SENDER`]: the signer.
    MsgSender,
    /// [`ADDRESS_THIS`]: the router itself (the tokens stay in the plan).
    AddressThis,
    /// Any other address, including `address(0)` and `address(3)`: the
    /// special values are exactly the two constants, nothing near them.
    Account(Address),
}

impl Recipient {
    /// Resolve the raw address written in a command input.
    pub fn resolve(raw: Address) -> Recipient {
        if raw == MSG_SENDER {
            Recipient::MsgSender
        } else if raw == ADDRESS_THIS {
            Recipient::AddressThis
        } else {
            Recipient::Account(raw)
        }
    }

    /// The account to judge, or `None` for the two special values.
    pub fn account(&self) -> Option<&Address> {
        match self {
            Recipient::Account(a) => Some(a),
            Recipient::MsgSender | Recipient::AddressThis => None,
        }
    }
}

/// A decoded spend command: who is paid, and bytes after the static layout.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Spend {
    pub recipient: Recipient,
    /// Bytes after the last static word. The router ignores them.
    pub extra: usize,
}

/// Decode the recipient of a *simple* spend command, or `None` if `kind` is
/// not one (permits, sub plans, the batch transfer and everything else).
///
/// The input of these commands is all static words, so the recipient is one
/// word at a fixed place. Layouts as read from `Dispatcher.sol` (SHA-256
/// `4d22b791…7937f2`, see the README): each branch does `calldataload` at
/// fixed offsets and passes the recipient through `map(..)`.
///
/// | Kind | Words | Recipient word |
/// |---|---|---|
/// | `PERMIT2_TRANSFER_FROM`, `TRANSFER`, `SWEEP`, `PAY_PORTION[_FULL_PRECISION]` | 3 (token, recipient, amount) | 1 |
/// | `UNWRAP_WETH` | 2 (recipient, amountMin) | 0 |
///
/// The address word must be canonical (`DirtyPadding`) and the input must hold
/// every word (`Truncated`). The router itself does neither check, so this is
/// stricter on purpose: "cannot vouch" is the safe direction.
pub fn decode_spend(kind: Kind, input: &[u8]) -> Option<Result<Spend, DecodeError>> {
    let (word, len) = match kind {
        Kind::Permit2TransferFrom | Kind::Transfer | Kind::Sweep | Kind::PayPortion => (1, 96),
        Kind::UnwrapWeth => (0, 64),
        _ => return None,
    };
    if input.len() < len {
        return Some(Err(DecodeError::Truncated {
            expected: len,
            got: input.len(),
        }));
    }
    Some(address_in(input, word).map(|raw| Spend {
        recipient: Recipient::resolve(raw),
        extra: input.len() - len,
    }))
}

#[cfg(test)]
mod spend_tests {
    use super::*;
    use std::vec;
    use std::vec::Vec;

    fn word_addr(last: u8, fill: u8) -> [u8; 32] {
        let mut w = [0u8; 32];
        w[12..31].fill(fill);
        w[31] = last;
        w
    }

    /// Three words: token (0xaa..), recipient, amount 1.
    fn three_words(recipient: [u8; 32]) -> Vec<u8> {
        let mut v = word_addr(0xaa, 0xaa).to_vec();
        v.extend(recipient);
        let mut amount = [0u8; 32];
        amount[31] = 1;
        v.extend(amount);
        v
    }

    fn two_words(recipient: [u8; 32]) -> Vec<u8> {
        let mut v = recipient.to_vec();
        let mut amount = [0u8; 32];
        amount[31] = 7;
        v.extend(amount);
        v
    }

    const THREE: [Kind; 4] = [
        Kind::Permit2TransferFrom,
        Kind::Transfer,
        Kind::Sweep,
        Kind::PayPortion,
    ];

    #[test]
    fn the_recipient_is_word_one_for_three_word_spends_and_word_zero_for_unwrap() {
        for kind in THREE {
            let d = decode_spend(kind, &three_words(word_addr(0x42, 0x42))).unwrap();
            assert_eq!(
                d,
                Ok(Spend {
                    recipient: Recipient::Account(Address([0x42; 20])),
                    extra: 0
                }),
                "{kind:?}"
            );
            // The token word (0) must not be mistaken for the recipient.
            assert_ne!(
                d.unwrap().recipient,
                Recipient::Account(Address([0xaa; 20]))
            );
        }
        let d = decode_spend(Kind::UnwrapWeth, &two_words(word_addr(0x43, 0x43))).unwrap();
        assert_eq!(
            d.unwrap().recipient,
            Recipient::Account(Address([0x43; 20]))
        );
    }

    #[test]
    fn exactly_the_two_router_constants_are_special() {
        let mut one = [0u8; 32];
        one[31] = 1;
        let mut two = [0u8; 32];
        two[31] = 2;
        let (zero, mut three) = ([0u8; 32], [0u8; 32]);
        three[31] = 3;
        let rec = |w: [u8; 32]| {
            decode_spend(Kind::Transfer, &three_words(w))
                .unwrap()
                .unwrap()
                .recipient
        };
        assert_eq!(rec(one), Recipient::MsgSender);
        assert_eq!(rec(two), Recipient::AddressThis);
        // Nothing near the constants is special.
        assert_eq!(rec(zero), Recipient::Account(Address([0; 20])));
        let mut a3 = [0u8; 20];
        a3[19] = 3;
        assert_eq!(rec(three), Recipient::Account(Address(a3)));
        // `address(1)` with any other byte set is a different address.
        let mut near = one;
        near[12] = 1;
        assert!(matches!(rec(near), Recipient::Account(_)));
        assert_eq!(Recipient::MsgSender.account(), None);
        assert_eq!(Recipient::AddressThis.account(), None);
    }

    #[test]
    fn a_dirty_recipient_word_is_an_error_naming_its_position() {
        for kind in THREE {
            let mut w = word_addr(0x42, 0x42);
            w[0] = 1;
            assert_eq!(
                decode_spend(kind, &three_words(w)),
                Some(Err(DecodeError::DirtyPadding { arg: 1 })),
                "{kind:?}"
            );
        }
        let mut w = word_addr(0x43, 0x43);
        w[11] = 1;
        assert_eq!(
            decode_spend(Kind::UnwrapWeth, &two_words(w)),
            Some(Err(DecodeError::DirtyPadding { arg: 0 }))
        );
    }

    #[test]
    fn a_short_input_is_truncated_and_never_read_partially() {
        let full = three_words(word_addr(0x42, 0x42));
        for kind in THREE {
            for cut in [0, 1, 32, 64, 95] {
                assert_eq!(
                    decode_spend(kind, &full[..cut]),
                    Some(Err(DecodeError::Truncated {
                        expected: 96,
                        got: cut
                    })),
                    "{kind:?} cut {cut}"
                );
            }
        }
        let full = two_words(word_addr(0x43, 0x43));
        for cut in [0, 31, 63] {
            assert_eq!(
                decode_spend(Kind::UnwrapWeth, &full[..cut]),
                Some(Err(DecodeError::Truncated {
                    expected: 64,
                    got: cut
                }))
            );
        }
    }

    #[test]
    fn bytes_after_the_static_words_are_counted_not_rejected() {
        let mut v = three_words(word_addr(0x42, 0x42));
        v.extend([9u8; 5]);
        assert_eq!(decode_spend(Kind::Sweep, &v).unwrap().unwrap().extra, 5);
        let mut v = two_words(word_addr(0x43, 0x43));
        v.extend(vec![9u8; 33]);
        assert_eq!(
            decode_spend(Kind::UnwrapWeth, &v).unwrap().unwrap().extra,
            33
        );
    }

    #[test]
    fn only_the_simple_spends_are_decoded() {
        let v = three_words(word_addr(0x42, 0x42));
        for kind in [
            Kind::Permit2Permit,
            Kind::Permit2PermitBatch,
            Kind::ExecuteSubPlan,
            Kind::Permit2TransferFromBatch,
            Kind::Other("V3_SWAP_EXACT_IN"),
            Kind::Unassigned,
        ] {
            assert_eq!(decode_spend(kind, &v), None, "{kind:?}");
        }
        // Every kind `kind_of` gives a spend layout to is one of the two sets.
        for byte in 0u8..=0x7f {
            let k = kind_of(byte);
            let simple = THREE.contains(&k) || k == Kind::UnwrapWeth;
            assert_eq!(decode_spend(k, &v).is_some(), simple, "byte {byte:#x}");
        }
        // PAY_PORTION and its full-precision variant share one kind.
        assert_eq!(kind_of(command::PAY_PORTION), Kind::PayPortion);
        assert_eq!(
            kind_of(command::PAY_PORTION_FULL_PRECISION),
            Kind::PayPortion
        );
    }
}
