//! Assess calldata that may be a batch (`multicall(bytes[])`, a Multicall3
//! `aggregate*` call) or a Universal Router `execute` call: walk every inner
//! call or command, decode it, judge it with [`crate::risk::assess`], and
//! combine the results.
//!
//! This is the only module that composes the other calldata modules. It adds
//! no new judgement rules of its own beyond how results are combined:
//!
//! * `flags` is the **union** of the inner flags, for display. A batch can
//!   therefore show `REVOCATION` next to `UNLIMITED_AMOUNT`.
//! * `severity` is the **maximum** of the per-call severities, never derived
//!   from the union (an untrusted spender in one call and an unlimited amount
//!   in another is not a `High` grant to the same party).
//! * An inner call this crate cannot decode is not judged. It is counted, and
//!   it raises the floor to `Review`: a decode failure is never a safe
//!   verdict. Router swaps are the usual case, so expect `Review` there.
//! * Bytes the EVM ignores (gaps, trailing bytes) anywhere in the batch set
//!   `TRAILING_DATA` and also raise the floor to `Review`.
//! * A batch that cannot be read completely is an `Err`, never a verdict.
//!
//! Universal Router plans follow the same rules. Of the router's commands only
//! the two Permit2 permits are judged: each allowance they grant is turned
//! into the [`Call::Permit2Approve`] a direct Permit2 `approve` would decode
//! to and goes through [`assess`] unchanged. The owner of a router permit is
//! the transaction sender, so it is judged as the signer's own grant. Every
//! other command counts as `unknown` (not judged), including a command value
//! the router assigns to nothing, **except** the simple spends (`TRANSFER`,
//! `SWEEP`, `PERMIT2_TRANSFER_FROM`, `PAY_PORTION*`, `UNWRAP_WETH`): their
//! recipient is decoded by the router module and judged by
//! [`crate::risk::assess_recipient`], and nothing else about them is. A permit input that cannot be read is
//! `malformed`. Sub plans are walked, and a plan that cannot be read
//! completely is an `Err`. An `execute` call found inside a `multicall` or
//! Multicall3 batch is judged the same way; if it cannot be read, that inner
//! call is `malformed` rather than failing the whole batch, like any other
//! inner call that does not decode.

use crate::abi::DecodeError;
use crate::calldata::{decode, Call, Decoded};
use crate::multicall::{calls, is_multicall};
use crate::risk::{assess, assess_recipient, Context, Flags, Severity};
use crate::router::{
    commands, decode_permit_batch, decode_permit_single, decode_spend, is_execute, Kind,
};

/// Result of [`assess_calldata`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BatchAssessment {
    /// Union of the flags of every inspected call.
    pub flags: Flags,
    /// Maximum per-call severity, raised to at least `Review` if anything was
    /// undecodable or hidden.
    pub severity: Severity,
    /// Leaf calls or router commands found (1 for non-batch calldata).
    pub inspected: usize,
    /// Leaf calls with a selector this crate does not know, and router
    /// commands this crate does not judge (not judged).
    pub unknown: usize,
    /// Leaf calls or permit inputs that could not be decoded for any other
    /// reason (not judged).
    pub malformed: usize,
    /// Bytes the EVM ignores: gaps inside batches and trailing bytes.
    pub hidden_bytes: usize,
}

/// Running totals while walking one batch or plan.
struct Acc {
    flags: Flags,
    severity: Severity,
    inspected: usize,
    unknown: usize,
    malformed: usize,
    hidden: usize,
}

impl Acc {
    fn new() -> Self {
        Acc {
            flags: Flags::EMPTY,
            severity: Severity::Safe,
            inspected: 0,
            unknown: 0,
            malformed: 0,
            hidden: 0,
        }
    }

    fn merge(&mut self, other: Acc) {
        self.flags.insert(other.flags);
        self.severity = self.severity.max(other.severity);
        self.inspected = self.inspected.saturating_add(other.inspected);
        self.unknown = self.unknown.saturating_add(other.unknown);
        self.malformed = self.malformed.saturating_add(other.malformed);
        self.hidden = self.hidden.saturating_add(other.hidden);
    }

    /// Judge one decoded call and fold the result in.
    fn judge(&mut self, decoded: &Decoded, ctx: &Context<'_>) {
        let a = assess(decoded, ctx);
        self.flags.insert(a.flags);
        self.severity = self.severity.max(a.severity);
    }

    /// Walk the `execute` call in `data`. On `Err` nothing is half-counted by
    /// the caller: use a fresh `Acc` and merge it only on success.
    fn plan(&mut self, data: &[u8], ctx: &Context<'_>) -> Result<(), DecodeError> {
        let mut walk = commands(data)?;
        for item in walk.by_ref() {
            let cmd = item?;
            self.inspected = self.inspected.saturating_add(1);
            match cmd.kind() {
                Kind::Permit2Permit => match decode_permit_single(cmd.input) {
                    Ok(p) => {
                        self.hidden = self.hidden.saturating_add(p.hidden);
                        let call = p.details.to_call(p.spender);
                        self.judge(&Decoded { call, trailing: 0 }, ctx);
                    }
                    Err(_) => self.malformed = self.malformed.saturating_add(1),
                },
                Kind::Permit2PermitBatch => match decode_permit_batch(cmd.input) {
                    Ok(b) => {
                        self.hidden = self.hidden.saturating_add(b.hidden);
                        for details in b.iter() {
                            let call: Call = details.to_call(b.spender);
                            self.judge(&Decoded { call, trailing: 0 }, ctx);
                        }
                    }
                    Err(_) => self.malformed = self.malformed.saturating_add(1),
                },
                Kind::Permit2TransferFrom
                | Kind::Transfer
                | Kind::Sweep
                | Kind::PayPortion
                | Kind::UnwrapWeth => match decode_spend(cmd.kind(), cmd.input) {
                    Some(Ok(spend)) => {
                        self.hidden = self.hidden.saturating_add(spend.extra);
                        let a = assess_recipient(spend.recipient.account(), ctx);
                        self.flags.insert(a.flags);
                        self.severity = self.severity.max(a.severity);
                    }
                    Some(Err(_)) => self.malformed = self.malformed.saturating_add(1),
                    None => self.unknown = self.unknown.saturating_add(1),
                },
                // Full array decode of AllowanceTransferDetails[] still TODO;
                // keep as unknown so we never claim Safe on unread data.
                Kind::Permit2TransferFromBatch => {
                    self.unknown = self.unknown.saturating_add(1);
                }
                // `Commands` never yields a sub plan; if that ever changed,
                // counting it as not judged keeps the verdict out of `Safe`.
                Kind::ExecuteSubPlan | Kind::Other(_) | Kind::Unassigned => {
                    self.unknown = self.unknown.saturating_add(1);
                }
            }
        }
        self.hidden = self.hidden.saturating_add(walk.hidden());
        Ok(())
    }

    fn finish(mut self) -> BatchAssessment {
        if self.hidden > 0 {
            self.flags.insert(Flags::TRAILING_DATA);
        }
        if self.unknown > 0 || self.malformed > 0 || self.hidden > 0 {
            self.severity = self.severity.max(Severity::Review);
        }
        BatchAssessment {
            flags: self.flags,
            severity: self.severity,
            inspected: self.inspected,
            unknown: self.unknown,
            malformed: self.malformed,
            hidden_bytes: self.hidden,
        }
    }
}

/// Assess `data`, which may be a single supported call, a `multicall` or a
/// Universal Router `execute`.
pub fn assess_calldata(data: &[u8], ctx: &Context<'_>) -> Result<BatchAssessment, DecodeError> {
    if is_execute(data) {
        let mut acc = Acc::new();
        acc.plan(data, ctx)?;
        return Ok(acc.finish());
    }

    if !is_multicall(data) {
        let decoded = decode(data)?;
        let a = assess(&decoded, ctx);
        return Ok(BatchAssessment {
            flags: a.flags,
            severity: a.severity,
            inspected: 1,
            unknown: 0,
            malformed: 0,
            hidden_bytes: decoded.trailing,
        });
    }

    let mut walk = calls(data)?;
    let mut acc = Acc::new();

    for item in walk.by_ref() {
        let inner = item?;
        if is_execute(inner.data) {
            // Judged as if the signer had sent it, like every inner call. A
            // plan that cannot be read is one malformed inner call.
            let mut sub = Acc::new();
            match sub.plan(inner.data, ctx) {
                Ok(()) => acc.merge(sub),
                Err(_) => {
                    acc.inspected = acc.inspected.saturating_add(1);
                    acc.malformed = acc.malformed.saturating_add(1);
                }
            }
            continue;
        }
        acc.inspected = acc.inspected.saturating_add(1);
        match decode(inner.data) {
            Ok(decoded) => acc.judge(&decoded, ctx),
            Err(DecodeError::UnknownSelector(_)) => acc.unknown = acc.unknown.saturating_add(1),
            Err(_) => acc.malformed = acc.malformed.saturating_add(1),
        }
    }

    acc.hidden = acc.hidden.saturating_add(walk.hidden());
    Ok(acc.finish())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::abi::Address;
    use crate::calldata::testutil::{addr_word, calldata, max_word, uint_word};
    use crate::calldata::{SEL_APPROVE, SEL_SET_APPROVAL_FOR_ALL, SEL_TRANSFER};
    use crate::multicall::testutil::{
        aggregate, aggregate3, aggregate3_value, multicall_data, multicall_deadline,
    };
    use crate::multicall::{MAX_DEPTH, SEL_MULTICALL};
    use std::vec;
    use std::vec::Vec;

    const ROUTER: u8 = 0x11;
    const EVIL: u8 = 0xee;

    fn approve_max(spender: u8) -> Vec<u8> {
        calldata(SEL_APPROVE, &[addr_word(spender), max_word()])
    }

    fn approve_zero(spender: u8) -> Vec<u8> {
        calldata(SEL_APPROVE, &[addr_word(spender), uint_word(0)])
    }

    fn transfer() -> Vec<u8> {
        calldata(SEL_TRANSFER, &[addr_word(0x22), uint_word(5)])
    }

    fn ctx(trusted: &[Address]) -> Context<'_> {
        Context::new(trusted)
    }

    #[test]
    fn non_batch_calldata_is_assessed_like_a_single_call() {
        let t = [Address([ROUTER; 20])];
        let r = assess_calldata(&approve_max(EVIL), &ctx(&t)).unwrap();
        assert_eq!(r.severity, Severity::High);
        assert_eq!(r.inspected, 1);
        assert!(r.flags.contains(Flags::UNTRUSTED_SPENDER));
        let single = assess(&decode(&approve_max(EVIL)).unwrap(), &ctx(&t));
        assert_eq!((r.flags, r.severity), (single.flags, single.severity));
    }

    #[test]
    fn non_batch_errors_propagate() {
        assert!(matches!(
            assess_calldata(&[1, 2, 3, 4], &Context::none()),
            Err(DecodeError::UnknownSelector(_))
        ));
        assert!(matches!(
            assess_calldata(&[], &Context::none()),
            Err(DecodeError::MissingSelector { got: 0 })
        ));
    }

    #[test]
    fn dangerous_approval_inside_a_batch_is_found() {
        let t = [Address([ROUTER; 20])];
        let data = multicall_data(&[transfer(), approve_max(EVIL)]);
        let r = assess_calldata(&data, &ctx(&t)).unwrap();
        assert_eq!(r.severity, Severity::High);
        assert_eq!(r.inspected, 2);
        assert!(r.flags.contains(Flags::UNLIMITED_AMOUNT));
    }

    #[test]
    fn dangerous_approval_in_a_nested_batch_is_found() {
        let t = [Address([ROUTER; 20])];
        let mut data = multicall_data(&[approve_max(EVIL)]);
        for _ in 1..MAX_DEPTH {
            data = multicall_data(&[transfer(), data]);
        }
        let r = assess_calldata(&data, &ctx(&t)).unwrap();
        assert_eq!(r.severity, Severity::High);
        assert_eq!(r.inspected, MAX_DEPTH); // MAX_DEPTH-1 transfers + the approval
    }

    #[test]
    fn trusted_spender_is_not_high() {
        let t = [Address([ROUTER; 20])];
        let data = multicall_deadline(99, &[approve_max(ROUTER)]);
        let r = assess_calldata(&data, &ctx(&t)).unwrap();
        assert_eq!(r.severity, Severity::Review); // unlimited, but to a trusted party
        assert!(!r.flags.contains(Flags::UNTRUSTED_SPENDER));
    }

    #[test]
    fn only_transfers_and_revocations_is_safe_and_flags_are_a_union() {
        let data = multicall_data(&[
            transfer(),
            approve_zero(EVIL),
            calldata(SEL_SET_APPROVAL_FOR_ALL, &[addr_word(EVIL), uint_word(0)]),
        ]);
        let r = assess_calldata(&data, &Context::none()).unwrap();
        assert_eq!(r.severity, Severity::Safe);
        assert_eq!(r.flags, Flags::REVOCATION);
        assert_eq!((r.unknown, r.malformed, r.hidden_bytes), (0, 0, 0));
    }

    #[test]
    fn severity_is_the_max_not_derived_from_the_union() {
        // Call A: unlimited approve to a TRUSTED spender (UNLIMITED only).
        // Call B: finite approve to an UNTRUSTED spender (UNTRUSTED only).
        // Union has both flags, which a union-based rule would call High.
        let t = [Address([ROUTER; 20])];
        let data = multicall_data(&[
            approve_max(ROUTER),
            calldata(SEL_APPROVE, &[addr_word(EVIL), uint_word(10)]),
        ]);
        let r = assess_calldata(&data, &ctx(&t)).unwrap();
        assert!(r.flags.contains(Flags::UNLIMITED_AMOUNT));
        assert!(r.flags.contains(Flags::UNTRUSTED_SPENDER));
        assert_eq!(r.severity, Severity::Review);
    }

    #[test]
    fn an_unknown_inner_call_is_counted_and_never_safe() {
        let swap = calldata([0x04, 0xe4, 0x5a, 0xaf], &[uint_word(1)]);
        let data = multicall_data(&[transfer(), swap]);
        let r = assess_calldata(&data, &Context::none()).unwrap();
        assert_eq!(r.unknown, 1);
        assert_eq!(r.malformed, 0);
        assert_eq!(r.severity, Severity::Review);
    }

    #[test]
    fn a_malformed_known_inner_call_is_counted_separately() {
        let mut bad = approve_max(EVIL);
        bad[4] = 1; // dirty padding in the spender word
        let data = multicall_data(&[bad]);
        let r = assess_calldata(&data, &Context::none()).unwrap();
        assert_eq!((r.unknown, r.malformed), (0, 1));
        assert_eq!(r.severity, Severity::Review);
        // An inner call too short to have a selector is malformed too.
        let data = multicall_data(&[vec![1, 2]]);
        let r = assess_calldata(&data, &Context::none()).unwrap();
        assert_eq!(r.malformed, 1);
    }

    #[test]
    fn a_high_inner_call_is_not_masked_by_unknown_calls() {
        let swap = calldata([0x04, 0xe4, 0x5a, 0xaf], &[]);
        let data = multicall_data(&[swap, approve_max(EVIL)]);
        let r = assess_calldata(&data, &Context::none()).unwrap();
        assert_eq!(r.severity, Severity::High);
        assert_eq!(r.unknown, 1);
    }

    #[test]
    fn trailing_bytes_after_the_batch_set_the_flag_and_the_floor() {
        let mut data = multicall_data(&[transfer()]);
        data.extend([0xab; 7]);
        let r = assess_calldata(&data, &Context::none()).unwrap();
        assert!(r.flags.contains(Flags::TRAILING_DATA));
        assert_eq!(r.hidden_bytes, 7);
        assert_eq!(r.severity, Severity::Review);
    }

    #[test]
    fn a_gap_hiding_bytes_inside_the_batch_is_flagged() {
        // Array placed 32 bytes late; the gap is ignored by the EVM.
        let mut data = SEL_MULTICALL.to_vec();
        data.extend(uint_word(64));
        data.extend([0xcd; 32]);
        data.extend(crate::dynabi::testutil::encode_bytes_array(&[transfer()]));
        let r = assess_calldata(&data, &Context::none()).unwrap();
        assert_eq!(r.hidden_bytes, 32);
        assert!(r.flags.contains(Flags::TRAILING_DATA));
        assert_eq!(r.severity, Severity::Review);
    }

    #[test]
    fn an_empty_batch_is_safe() {
        let r = assess_calldata(&multicall_data(&[]), &Context::none()).unwrap();
        assert_eq!(r.inspected, 0);
        assert_eq!(r.severity, Severity::Safe);
        assert!(r.flags.is_empty());
    }

    #[test]
    fn unreadable_batches_are_errors_not_verdicts() {
        let mut data = multicall_data(&[transfer()]);
        data.truncate(data.len() - 1);
        assert!(assess_calldata(&data, &Context::none()).is_err());

        let mut too_deep = multicall_data(&[transfer()]);
        for _ in 0..MAX_DEPTH {
            too_deep = multicall_data(&[too_deep]);
        }
        assert_eq!(
            assess_calldata(&too_deep, &Context::none()),
            Err(DecodeError::NestingTooDeep)
        );
    }

    #[test]
    fn multicall3_batches_are_judged_like_any_other() {
        let t = [Address([ROUTER; 20])];
        // The target of the inner call does not change the verdict: only the
        // calldata is judged.
        let data = aggregate3(&[(0xa1, false, transfer()), (0xa2, true, approve_max(EVIL))]);
        let r = assess_calldata(&data, &ctx(&t)).unwrap();
        assert_eq!(r.severity, Severity::High);
        assert_eq!(r.inspected, 2);
        assert!(r.flags.contains(Flags::UNLIMITED_AMOUNT));
        let data = aggregate3_value(&[(0xa1, false, 1, approve_max(EVIL))]);
        assert_eq!(
            assess_calldata(&data, &ctx(&t)).unwrap().severity,
            Severity::High
        );
        let data = aggregate(&[(0xa1, approve_max(EVIL))]);
        assert_eq!(
            assess_calldata(&data, &ctx(&t)).unwrap().severity,
            Severity::High
        );
    }

    #[test]
    fn multicall3_batches_inside_multicall_batches_are_found() {
        let t = [Address([ROUTER; 20])];
        let inner = aggregate3(&[(1, false, approve_max(EVIL))]);
        let data = multicall_deadline(5, &[transfer(), inner]);
        let r = assess_calldata(&data, &ctx(&t)).unwrap();
        assert_eq!(r.severity, Severity::High);
        assert_eq!(r.inspected, 2);
    }

    #[test]
    fn multicall3_unknown_calls_and_revocations_follow_the_same_rules() {
        let swap = calldata([0x04, 0xe4, 0x5a, 0xaf], &[uint_word(1)]);
        let data = aggregate3(&[(1, true, swap), (2, false, approve_zero(EVIL))]);
        let r = assess_calldata(&data, &Context::none()).unwrap();
        assert_eq!((r.unknown, r.malformed), (1, 0));
        assert_eq!(r.severity, Severity::Review);
        let data = aggregate3(&[(1, true, transfer()), (2, false, approve_zero(EVIL))]);
        let r = assess_calldata(&data, &Context::none()).unwrap();
        assert_eq!(r.severity, Severity::Safe);
        assert_eq!(r.flags, Flags::REVOCATION);
        // An empty Multicall3 batch has nothing to judge.
        let r = assess_calldata(&aggregate3(&[]), &Context::none()).unwrap();
        assert_eq!((r.inspected, r.severity), (0, Severity::Safe));
    }

    #[test]
    fn unreadable_multicall3_batches_are_errors_not_verdicts() {
        let mut data = aggregate3(&[(1, false, transfer())]);
        data.truncate(data.len() - 1);
        assert!(assess_calldata(&data, &Context::none()).is_err());
        let mut data = aggregate3(&[(1, false, transfer())]);
        data[100 + 3] = 1; // dirty target
        assert_eq!(
            assess_calldata(&data, &Context::none()),
            Err(DecodeError::DirtyElementField { index: 0, field: 0 })
        );
    }

    // ------------------------------------------------- Universal Router

    use crate::router::testutil::{
        execute_data, execute_deadline_data, permit_batch_input, permit_single_input, plan_args,
    };

    fn max160() -> [u8; 32] {
        let mut w = [0u8; 32];
        w[12..].fill(0xff);
        w
    }

    /// `PERMIT2_PERMIT` input: token 0xaa, the given amount and expiration.
    fn permit(spender: u8, amount: [u8; 32], expiration: u64) -> Vec<u8> {
        permit_single_input(0xaa, amount, expiration, 1, spender, &[0x5a; 65])
    }

    fn union(list: &[Flags]) -> Flags {
        let mut f = Flags::EMPTY;
        for x in list {
            f.insert(*x);
        }
        f
    }

    fn router_ctx() -> [Address; 1] {
        [Address([ROUTER; 20])]
    }

    #[test]
    fn a_router_permit_to_a_stranger_is_high() {
        let t = router_ctx();
        let data = execute_data(&[0x0a], &[permit(EVIL, max160(), 5000)]);
        let r = assess_calldata(&data, &ctx(&t)).unwrap();
        assert_eq!(r.severity, Severity::High);
        assert_eq!(
            r.flags,
            union(&[Flags::UNLIMITED_AMOUNT, Flags::UNTRUSTED_SPENDER])
        );
        assert_eq!(
            (r.inspected, r.unknown, r.malformed, r.hidden_bytes),
            (1, 0, 0, 0)
        );
    }

    #[test]
    fn a_router_permit_with_a_far_expiration_gets_no_expiry() {
        let t = router_ctx();
        let data = execute_deadline_data(&[0x0a], &[permit(EVIL, max160(), 1 << 47)], 99);
        let r = assess_calldata(&data, &ctx(&t)).unwrap();
        assert_eq!(r.severity, Severity::High);
        assert!(r.flags.contains(Flags::NO_EXPIRY));
        // One second below half the uint48 range is not flagged.
        let data = execute_data(&[0x0a], &[permit(EVIL, max160(), (1 << 47) - 1)]);
        let r = assess_calldata(&data, &ctx(&t)).unwrap();
        assert!(!r.flags.contains(Flags::NO_EXPIRY));
    }

    #[test]
    fn a_router_permit_to_the_trusted_router_is_review_when_unlimited() {
        let t = router_ctx();
        let data = execute_data(&[0x0a], &[permit(ROUTER, max160(), 5000)]);
        let r = assess_calldata(&data, &ctx(&t)).unwrap();
        assert_eq!(r.severity, Severity::Review);
        assert_eq!(r.flags, Flags::UNLIMITED_AMOUNT);
    }

    #[test]
    fn a_bounded_permit_to_the_trusted_router_is_safe() {
        let t = router_ctx();
        let data = execute_data(&[0x0a], &[permit(ROUTER, uint_word(1000), 5000)]);
        let r = assess_calldata(&data, &ctx(&t)).unwrap();
        assert_eq!(r.severity, Severity::Safe);
        assert!(r.flags.is_empty());
    }

    #[test]
    fn a_revoking_router_permit_is_safe() {
        let data = execute_data(&[0x0a], &[permit(EVIL, uint_word(0), 5000)]);
        let r = assess_calldata(&data, &Context::none()).unwrap();
        assert_eq!(r.severity, Severity::Safe);
        assert_eq!(r.flags, Flags::REVOCATION);
    }

    #[test]
    fn a_swap_next_to_a_permit_floors_the_verdict_at_review() {
        let t = router_ctx();
        let data = execute_data(
            &[0x0a, 0x00],
            &[permit(ROUTER, uint_word(1000), 5000), vec![1, 2, 3]],
        );
        let r = assess_calldata(&data, &ctx(&t)).unwrap();
        assert_eq!(r.severity, Severity::Review);
        assert!(r.flags.is_empty());
        assert_eq!((r.inspected, r.unknown), (2, 1));
    }

    #[test]
    fn a_permit_hidden_among_unjudged_commands_is_found() {
        let t = router_ctx();
        let data = execute_data(
            &[0x08, 0x0a, 0x04],
            &[vec![1], permit(EVIL, max160(), 5000), vec![3]],
        );
        let r = assess_calldata(&data, &ctx(&t)).unwrap();
        assert_eq!(r.severity, Severity::High);
        assert_eq!((r.inspected, r.unknown), (3, 1)); // V2_SWAP unknown; SWEEP now judged
    }

    #[test]
    fn the_allow_revert_bit_does_not_hide_a_permit() {
        let t = router_ctx();
        let data = execute_data(&[0x8a], &[permit(EVIL, max160(), 5000)]);
        let r = assess_calldata(&data, &ctx(&t)).unwrap();
        assert_eq!(r.severity, Severity::High);
        assert_eq!(r.unknown, 0);
    }

    #[test]
    fn a_router_permit_batch_is_judged_per_allowance() {
        let t = router_ctx();
        let details = [
            (0xa1, max160(), 100, 1),
            (0xa2, uint_word(5), 200, 2),
            (0xa3, uint_word(0), 300, 3),
        ];
        let to_router = execute_data(
            &[0x03],
            &[permit_batch_input(&details, ROUTER, &[0x5a; 65])],
        );
        let r = assess_calldata(&to_router, &ctx(&t)).unwrap();
        assert_eq!(r.severity, Severity::Review);
        assert_eq!(
            r.flags,
            union(&[Flags::UNLIMITED_AMOUNT, Flags::REVOCATION])
        );
        assert_eq!((r.inspected, r.unknown, r.malformed), (1, 0, 0));

        let to_stranger = execute_data(&[0x03], &[permit_batch_input(&details, EVIL, &[0x5a; 65])]);
        let r = assess_calldata(&to_stranger, &ctx(&t)).unwrap();
        assert_eq!(r.severity, Severity::High);
        assert!(r.flags.contains(Flags::UNTRUSTED_SPENDER));
    }

    #[test]
    fn an_empty_permit_batch_grants_nothing() {
        let data = execute_data(&[0x03], &[permit_batch_input(&[], EVIL, &[0x5a; 65])]);
        let r = assess_calldata(&data, &Context::none()).unwrap();
        assert_eq!(r.severity, Severity::Safe);
        assert!(r.flags.is_empty());
    }

    #[test]
    fn a_permit_inside_a_sub_plan_is_found() {
        let t = router_ctx();
        let sub = plan_args(&[0x0a], &[permit(EVIL, max160(), 5000)]);
        let data = execute_data(&[0x08, 0x21], &[vec![1], sub]);
        let r = assess_calldata(&data, &ctx(&t)).unwrap();
        assert_eq!(r.severity, Severity::High);
        assert_eq!((r.inspected, r.unknown), (2, 1));
    }

    #[test]
    fn an_unassigned_command_is_not_judged_and_never_safe() {
        // 0x16 is a placeholder in the dispatcher this crate follows (it has
        // no APPROVE_ERC20). A router of another version may assign it.
        let data = execute_data(&[0x16], &[vec![1]]);
        let r = assess_calldata(&data, &Context::none()).unwrap();
        assert_eq!((r.unknown, r.severity), (1, Severity::Review));
    }

    #[test]
    fn an_empty_plan_has_nothing_to_flag() {
        let r = assess_calldata(&execute_data(&[], &[]), &Context::none()).unwrap();
        assert_eq!((r.inspected, r.severity), (0, Severity::Safe));
    }

    #[test]
    fn a_permit_input_that_cannot_be_read_is_malformed_not_safe() {
        let r = assess_calldata(&execute_data(&[0x0a], &[vec![1; 10]]), &Context::none()).unwrap();
        assert_eq!((r.malformed, r.unknown), (1, 0));
        assert_eq!(r.severity, Severity::Review);

        let mut dirty = permit(EVIL, max160(), 5000);
        dirty[32] = 1; // amount has bits above 160
        let r = assess_calldata(&execute_data(&[0x0a], &[dirty]), &Context::none()).unwrap();
        assert_eq!(r.malformed, 1);
        assert_eq!(r.severity, Severity::Review);

        let r = assess_calldata(&execute_data(&[0x03], &[vec![0; 40]]), &Context::none()).unwrap();
        assert_eq!(r.malformed, 1);
    }

    #[test]
    fn a_plan_that_cannot_be_read_is_an_error_not_a_verdict() {
        let data = execute_data(&[0x0a, 0x0a], &[permit(EVIL, max160(), 5000)]);
        assert!(matches!(
            assess_calldata(&data, &Context::none()),
            Err(DecodeError::LengthMismatch {
                commands: 2,
                inputs: 1
            })
        ));
        let sub_garbage = execute_data(&[0x21], &[vec![1, 2, 3]]);
        assert!(assess_calldata(&sub_garbage, &Context::none()).is_err());
    }

    #[test]
    fn bytes_the_evm_ignores_in_a_plan_raise_the_floor() {
        // After the plan.
        let mut data = execute_data(&[0x0a], &[permit(ROUTER, uint_word(10), 5000)]);
        data.extend(vec![0xcc; 9]);
        let t = router_ctx();
        let r = assess_calldata(&data, &ctx(&t)).unwrap();
        assert_eq!((r.hidden_bytes, r.severity), (9, Severity::Review));
        assert!(r.flags.contains(Flags::TRAILING_DATA));

        // After the signature of a permit input.
        let mut input = permit(ROUTER, uint_word(10), 5000);
        input.extend(vec![0xcc; 4]);
        let r = assess_calldata(&execute_data(&[0x0a], &[input]), &ctx(&t)).unwrap();
        assert_eq!((r.hidden_bytes, r.severity), (4, Severity::Review));
    }

    #[test]
    fn bytes_hidden_in_a_permit_batch_input_raise_the_floor() {
        let t = router_ctx();
        let mut input = permit_batch_input(&[(0xa1, uint_word(5), 100, 1)], ROUTER, &[0x5a; 65]);
        let clean = assess_calldata(&execute_data(&[0x03], &[input.clone()]), &ctx(&t)).unwrap();
        assert_eq!((clean.hidden_bytes, clean.severity), (0, Severity::Safe));
        input.extend(vec![0xcc; 6]);
        let r = assess_calldata(&execute_data(&[0x03], &[input]), &ctx(&t)).unwrap();
        assert_eq!((r.hidden_bytes, r.severity), (6, Severity::Review));
        assert!(r.flags.contains(Flags::TRAILING_DATA));
    }

    #[test]
    fn a_router_call_inside_a_batch_is_judged() {
        let t = router_ctx();
        let exec = execute_data(&[0x0a], &[permit(EVIL, max160(), 5000)]);
        let r = assess_calldata(&multicall_data(&[transfer(), exec.clone()]), &ctx(&t)).unwrap();
        assert_eq!(r.severity, Severity::High);
        assert_eq!(r.inspected, 2); // the transfer and the permit command

        let r = assess_calldata(&aggregate3(&[(0xa1, false, exec)]), &ctx(&t)).unwrap();
        assert_eq!(r.severity, Severity::High);
        assert_eq!(r.inspected, 1);
    }

    #[test]
    fn an_unreadable_router_call_inside_a_batch_is_one_malformed_call() {
        let bad = execute_data(&[0x0a, 0x0a], &[vec![1]]);
        let r = assess_calldata(&multicall_data(&[transfer(), bad]), &Context::none()).unwrap();
        assert_eq!((r.inspected, r.malformed, r.unknown), (2, 1, 0));
        assert_eq!(r.severity, Severity::Review);
    }
    #[test]
    fn a_transfer_to_a_stranger_is_high() {
        let t = router_ctx();
        let mut input = vec![0u8; 96];
        // recipient = 0xee..ee at word 1
        input[32 + 12..64].copy_from_slice(&[0xeeu8; 20]);
        input[95] = 1; // amount
        let data = execute_data(&[0x05], &[input]);
        let r = assess_calldata(&data, &ctx(&t)).unwrap();
        assert_eq!(r.severity, Severity::High);
        assert!(r.flags.contains(Flags::UNTRUSTED_RECIPIENT));
        assert_eq!(r.unknown, 0);
        assert_eq!(r.malformed, 0);
    }

    #[test]
    fn a_transfer_to_msg_sender_is_not_flagged() {
        let t = router_ctx();
        let mut input = vec![0u8; 96];
        input[63] = 1; // MSG_SENDER = address(1)
        input[95] = 1;
        let data = execute_data(&[0x05], &[input]);
        let r = assess_calldata(&data, &ctx(&t)).unwrap();
        assert_eq!(r.severity, Severity::Safe);
        assert!(!r.flags.contains(Flags::UNTRUSTED_RECIPIENT));
    }

    #[test]
    fn a_sweep_to_address_this_is_not_flagged() {
        let t = router_ctx();
        let mut input = vec![0u8; 96];
        input[63] = 2; // ADDRESS_THIS
        input[95] = 1;
        let data = execute_data(&[0x04], &[input]);
        let r = assess_calldata(&data, &ctx(&t)).unwrap();
        assert_eq!(r.severity, Severity::Safe);
        assert!(!r.flags.contains(Flags::UNTRUSTED_RECIPIENT));
    }

    // ------------------------------------------------------- router spends

    /// Input of a three-word spend: token, recipient, amount.
    fn spend3(recipient: [u8; 32]) -> Vec<u8> {
        let mut v = addr_word(0xaa).to_vec();
        v.extend(recipient);
        v.extend(uint_word(1));
        v
    }

    /// Input of `UNWRAP_WETH`: recipient, amount.
    fn unwrap_in(recipient: [u8; 32]) -> Vec<u8> {
        let mut v = recipient.to_vec();
        v.extend(uint_word(1));
        v
    }

    /// Builds a spend input from a recipient word.
    type SpendInput = fn([u8; 32]) -> Vec<u8>;

    /// (command byte, input builder) for every simple spend.
    fn spends() -> Vec<(u8, SpendInput)> {
        vec![
            (0x02, spend3),
            (0x04, spend3),
            (0x05, spend3),
            (0x06, spend3),
            (0x07, spend3),
            (0x0c, unwrap_in),
        ]
    }

    #[test]
    fn every_simple_spend_to_a_trusted_recipient_is_safe() {
        let t = router_ctx();
        for (byte, build) in spends() {
            let data = execute_data(&[byte], &[build(addr_word(ROUTER))]);
            let r = assess_calldata(&data, &ctx(&t)).unwrap();
            assert_eq!(
                (r.severity, r.flags, r.unknown, r.malformed, r.hidden_bytes),
                (Severity::Safe, Flags::EMPTY, 0, 0, 0),
                "command {byte:#x}"
            );
            assert_eq!(r.inspected, 1);
        }
    }

    #[test]
    fn every_simple_spend_to_a_stranger_is_high() {
        let t = router_ctx();
        for (byte, build) in spends() {
            let data = execute_data(&[byte], &[build(addr_word(EVIL))]);
            let r = assess_calldata(&data, &ctx(&t)).unwrap();
            assert_eq!(r.severity, Severity::High, "command {byte:#x}");
            assert_eq!(r.flags, Flags::UNTRUSTED_RECIPIENT, "command {byte:#x}");
            assert_eq!((r.unknown, r.malformed), (0, 0));
        }
    }

    #[test]
    fn the_special_values_are_safe_and_their_neighbours_are_not() {
        let t = router_ctx();
        for (byte, build) in spends() {
            for special in [1u64, 2] {
                let data = execute_data(&[byte], &[build(uint_word(special))]);
                let r = assess_calldata(&data, &ctx(&t)).unwrap();
                assert_eq!(r.severity, Severity::Safe, "{byte:#x} address({special})");
            }
            for other in [0u64, 3] {
                let data = execute_data(&[byte], &[build(uint_word(other))]);
                let r = assess_calldata(&data, &ctx(&t)).unwrap();
                assert_eq!(r.severity, Severity::High, "{byte:#x} address({other})");
            }
        }
        // With no trusted list at all the special values still pass.
        let data = execute_data(&[0x05], &[spend3(uint_word(1))]);
        assert_eq!(
            assess_calldata(&data, &Context::none()).unwrap().severity,
            Severity::Safe
        );
    }

    #[test]
    fn an_unreadable_spend_is_counted_malformed_and_never_safe() {
        let t = router_ctx();
        let mut dirty = spend3(addr_word(ROUTER));
        dirty[32] = 1; // upper byte of the recipient word
        let short = spend3(addr_word(ROUTER))[..95].to_vec();
        for input in [dirty, short, vec![]] {
            let data = execute_data(&[0x05], &[input]);
            let r = assess_calldata(&data, &ctx(&t)).unwrap();
            assert_eq!((r.malformed, r.unknown), (1, 0));
            assert_eq!(r.severity, Severity::Review);
            assert!(!r.flags.contains(Flags::UNTRUSTED_RECIPIENT));
        }
    }

    #[test]
    fn bytes_after_a_spend_are_hidden_bytes() {
        let t = router_ctx();
        let mut input = spend3(addr_word(ROUTER));
        input.extend([0xcc; 5]);
        let r = assess_calldata(&execute_data(&[0x04], &[input]), &ctx(&t)).unwrap();
        assert_eq!((r.hidden_bytes, r.severity), (5, Severity::Review));
        assert!(r.flags.contains(Flags::TRAILING_DATA));
        let mut input = unwrap_in(addr_word(ROUTER));
        input.extend([0xcc; 7]);
        let r = assess_calldata(&execute_data(&[0x0c], &[input]), &ctx(&t)).unwrap();
        assert_eq!(r.hidden_bytes, 7);
    }

    #[test]
    fn the_allow_revert_flag_does_not_hide_a_bad_recipient() {
        let t = router_ctx();
        let data = execute_data(&[0x85], &[spend3(addr_word(EVIL))]);
        let r = assess_calldata(&data, &ctx(&t)).unwrap();
        assert_eq!(r.severity, Severity::High);
    }

    #[test]
    fn one_bad_recipient_is_not_masked_by_good_ones() {
        let t = router_ctx();
        let good = spend3(addr_word(ROUTER));
        let data = execute_data(
            &[0x05, 0x04, 0x05, 0x0c],
            &[
                good.clone(),
                good.clone(),
                spend3(addr_word(EVIL)),
                unwrap_in(addr_word(ROUTER)),
            ],
        );
        let r = assess_calldata(&data, &ctx(&t)).unwrap();
        assert_eq!((r.severity, r.inspected), (Severity::High, 4));
    }

    #[test]
    fn a_permit_and_a_bad_recipient_keep_both_sets_of_flags() {
        let t = router_ctx();
        let data = execute_data(
            &[0x0a, 0x05],
            &[permit(EVIL, max160(), 5000), spend3(addr_word(EVIL))],
        );
        let r = assess_calldata(&data, &ctx(&t)).unwrap();
        assert_eq!(r.severity, Severity::High);
        assert_eq!(
            r.flags,
            union(&[
                Flags::UNLIMITED_AMOUNT,
                Flags::UNTRUSTED_SPENDER,
                Flags::UNTRUSTED_RECIPIENT
            ])
        );
    }

    #[test]
    fn a_bad_recipient_in_a_sub_plan_or_a_multicall_is_found() {
        let t = router_ctx();
        let sub = plan_args(&[0x05], &[spend3(addr_word(EVIL))]);
        let data = execute_data(&[0x21], &[sub]);
        let r = assess_calldata(&data, &ctx(&t)).unwrap();
        assert_eq!((r.severity, r.inspected), (Severity::High, 1));
        assert!(r.flags.contains(Flags::UNTRUSTED_RECIPIENT));

        let inner = execute_data(&[0x05], &[spend3(addr_word(EVIL))]);
        let data = multicall_data(&[transfer(), inner]);
        let r = assess_calldata(&data, &ctx(&t)).unwrap();
        assert_eq!(r.severity, Severity::High);
        assert!(r.flags.contains(Flags::UNTRUSTED_RECIPIENT));
    }

    #[test]
    fn the_batch_transfer_is_still_not_judged() {
        let t = router_ctx();
        let data = execute_data(&[0x0d], &[spend3(addr_word(EVIL))]);
        let r = assess_calldata(&data, &ctx(&t)).unwrap();
        assert_eq!((r.unknown, r.malformed), (1, 0));
        assert_eq!(r.severity, Severity::Review);
        assert!(!r.flags.contains(Flags::UNTRUSTED_RECIPIENT));
    }
}
