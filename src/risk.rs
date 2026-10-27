//! Risk assessment of a decoded authorization call.
//!
//! Input is a [`Decoded`] value, never raw bytes. Output is a set of
//! [`Flags`] stating *why* the call deserves attention, plus a coarse
//! [`Severity`]. Flags are facts; severity is one opinionated summary.
//!
//! Scope: this judges authorizations (who may spend, how much, until when).
//! It does not judge plain `transfer`/`transferFrom`, which need balances and
//! intent to evaluate, so those always come back with no flags.

use crate::abi::{Address, Word};
use crate::calldata::{Call, Decoded};

const UINT256: u32 = 256;
const UINT160: u32 = 160;
const UINT48: u32 = 48;

/// A set of reasons, stored as bits.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Flags(u8);

impl Flags {
    pub const EMPTY: Flags = Flags(0);
    /// Allowance is at least half the type's range (treated as "unlimited").
    pub const UNLIMITED_AMOUNT: Flags = Flags(1 << 0);
    /// The spender or operator is not in the caller's trusted list.
    pub const UNTRUSTED_SPENDER: Flags = Flags(1 << 1);
    /// `setApprovalForAll(.., true)`: access to every token of the collection.
    pub const BLANKET_APPROVAL: Flags = Flags(1 << 2);
    /// The grant has no practical expiry.
    pub const NO_EXPIRY: Flags = Flags(1 << 3);
    /// The call removes an authorization (zero amount, or `false`).
    pub const REVOCATION: Flags = Flags(1 << 4);
    /// Extra bytes after the arguments, ignored by the EVM.
    pub const TRAILING_DATA: Flags = Flags(1 << 5);
    /// A router spend (`TRANSFER`, `SWEEP`, ...) pays an account that is neither
    /// trusted nor one of the router's two special values.
    pub const UNTRUSTED_RECIPIENT: Flags = Flags(1 << 6);

    #[inline]
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// True if every bit of `other` is set in `self`.
    #[inline]
    pub const fn contains(self, other: Flags) -> bool {
        self.0 & other.0 == other.0
    }

    /// True if at least one bit of `other` is set in `self`.
    #[inline]
    pub const fn intersects(self, other: Flags) -> bool {
        self.0 & other.0 != 0
    }

    #[inline]
    pub fn insert(&mut self, other: Flags) {
        self.0 |= other.0;
    }

    #[inline]
    const fn without(self, other: Flags) -> Flags {
        Flags(self.0 & !other.0)
    }
}

/// Coarse verdict, ordered from least to most severe.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    /// Nothing to flag. This is not a guarantee the transaction is harmless.
    Safe,
    /// Something deserves a human look.
    Review,
    /// A broad grant to an address the user has not trusted.
    High,
}

/// What the caller knows that the calldata cannot say.
#[derive(Clone, Copy, Debug)]
pub struct Context<'a> {
    /// Spenders and operators the user already trusts (known routers, own
    /// accounts, ...). Anything else is [`Flags::UNTRUSTED_SPENDER`].
    pub trusted: &'a [Address],
}

impl<'a> Context<'a> {
    /// Nothing is trusted: every spender is flagged.
    pub const fn none() -> Context<'static> {
        Context { trusted: &[] }
    }

    pub const fn new(trusted: &'a [Address]) -> Self {
        Context { trusted }
    }

    pub fn trusts(&self, who: &Address) -> bool {
        self.trusted.contains(who)
    }
}

/// Result of [`assess`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Assessment {
    pub flags: Flags,
    pub severity: Severity,
}

/// Assess one decoded call.
#[must_use = "dropping the assessment hides the verdict"]
pub fn assess(decoded: &Decoded, ctx: &Context<'_>) -> Assessment {
    let mut flags = match &decoded.call {
        Call::Transfer { .. } | Call::TransferFrom { .. } => Flags::EMPTY,

        Call::Approve { spender, amount } | Call::IncreaseAllowance { spender, amount } => {
            allowance_flags(ctx, spender, amount, UINT256)
        }

        Call::SetApprovalForAll { operator, approved } => {
            set_approval_for_all_flags(ctx, operator, *approved)
        }

        Call::Permit {
            spender,
            value,
            deadline,
            ..
        } => {
            let mut f = allowance_flags(ctx, spender, value, UINT256);
            if !f.contains(Flags::REVOCATION) && deadline.top_bit_set(UINT256) {
                f.insert(Flags::NO_EXPIRY);
            }
            f
        }

        Call::PermitDai {
            spender,
            expiry,
            allowed,
            ..
        } => permit_dai_flags(ctx, spender, expiry, *allowed),

        Call::Permit2Approve {
            spender,
            amount,
            expiration,
            ..
        } => {
            let mut f = allowance_flags(ctx, spender, amount, UINT160);
            if !f.contains(Flags::REVOCATION) && expiration.top_bit_set(UINT48) {
                f.insert(Flags::NO_EXPIRY);
            }
            f
        }
    };

    if decoded.trailing > 0 {
        flags.insert(Flags::TRAILING_DATA);
    }

    Assessment {
        flags,
        severity: severity_of(flags),
    }
}

/// Flags for an amount-bounded grant (approve, permit, Permit2).
fn allowance_flags(ctx: &Context<'_>, spender: &Address, amount: &Word, bits: u32) -> Flags {
    if amount.is_zero() {
        return Flags::REVOCATION;
    }
    let mut f = Flags::EMPTY;
    if amount.top_bit_set(bits) {
        f.insert(Flags::UNLIMITED_AMOUNT);
    }
    if !ctx.trusts(spender) {
        f.insert(Flags::UNTRUSTED_SPENDER);
    }
    f
}

fn set_approval_for_all_flags(ctx: &Context<'_>, operator: &Address, approved: bool) -> Flags {
    if !approved {
        return Flags::REVOCATION;
    }
    let mut f = Flags::BLANKET_APPROVAL;
    if !ctx.trusts(operator) {
        f.insert(Flags::UNTRUSTED_SPENDER);
    }
    f
}

/// DAI-style permit: `allowed == true` always means the maximum allowance,
/// and `expiry == 0` means it never expires.
fn permit_dai_flags(ctx: &Context<'_>, spender: &Address, expiry: &Word, allowed: bool) -> Flags {
    if !allowed {
        return Flags::REVOCATION;
    }
    let mut f = Flags::UNLIMITED_AMOUNT;
    if !ctx.trusts(spender) {
        f.insert(Flags::UNTRUSTED_SPENDER);
    }
    if expiry.is_zero() || expiry.top_bit_set(UINT256) {
        f.insert(Flags::NO_EXPIRY);
    }
    f
}

/// Judge the recipient of a spend (a router `TRANSFER`, `SWEEP`, ...).
///
/// `None` means the router's special value for "the signer" or "the router
/// itself" (see [`crate::router::Recipient`]): nothing leaves the signer's
/// control, so there is nothing to flag. Any account that is not in the
/// caller's trusted list is `UNTRUSTED_RECIPIENT`, which is `High`: the signer
/// is about to send tokens to somebody they did not list.
///
/// Note what this does not know: an honest swap may pay the signer's *own*
/// address (not `MSG_SENDER`), or a fee address, so the caller must list those
/// as trusted or expect `High`.
#[must_use = "dropping the assessment hides the verdict"]
pub fn assess_recipient(recipient: Option<&Address>, ctx: &Context<'_>) -> Assessment {
    let mut flags = Flags::EMPTY;
    if matches!(recipient, Some(a) if !ctx.trusts(a)) {
        flags.insert(Flags::UNTRUSTED_RECIPIENT);
    }
    Assessment {
        flags,
        severity: severity_of(flags),
    }
}

fn severity_of(flags: Flags) -> Severity {
    // A revocation is good news; judge only what else is present.
    let concerns = flags.without(Flags::REVOCATION);
    if concerns.is_empty() {
        return Severity::Safe;
    }
    let untrusted = concerns.contains(Flags::UNTRUSTED_SPENDER);
    let broad =
        concerns.contains(Flags::UNLIMITED_AMOUNT) || concerns.contains(Flags::BLANKET_APPROVAL);
    // An untrusted recipient is High on its own: the signer is about to send
    // tokens to someone they did not list.
    if (untrusted && broad) || concerns.contains(Flags::UNTRUSTED_RECIPIENT) {
        Severity::High
    } else {
        Severity::Review
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::calldata::testutil::*;
    use crate::calldata::*;

    const TRUSTED: u8 = 0x11;
    const STRANGER: u8 = 0x99;

    fn trusted_list() -> [Address; 1] {
        [Address([TRUSTED; 20])]
    }

    /// Decode then assess, so tests exercise the real pipeline.
    fn run(data: &[u8]) -> Assessment {
        let d = decode(data).expect("test calldata must decode");
        let list = trusted_list();
        assess(&d, &Context::new(&list))
    }

    fn flags_of(parts: &[Flags]) -> Flags {
        let mut f = Flags::EMPTY;
        for p in parts {
            f.insert(*p);
        }
        f
    }

    #[test]
    fn flags_basic_operations() {
        let mut f = Flags::EMPTY;
        assert!(f.is_empty());
        f.insert(Flags::NO_EXPIRY);
        f.insert(Flags::REVOCATION);
        assert!(f.contains(Flags::NO_EXPIRY));
        assert!(f.contains(flags_of(&[Flags::NO_EXPIRY, Flags::REVOCATION])));
        assert!(!f.contains(Flags::UNLIMITED_AMOUNT));
        assert!(f.intersects(flags_of(&[Flags::UNLIMITED_AMOUNT, Flags::REVOCATION])));
        assert_eq!(f.without(Flags::REVOCATION), Flags::NO_EXPIRY);
    }

    #[test]
    fn severity_ordering() {
        assert!(Severity::Safe < Severity::Review);
        assert!(Severity::Review < Severity::High);
    }

    #[test]
    fn plain_transfers_carry_no_flags() {
        let t = calldata(SEL_TRANSFER, &[addr_word(STRANGER), max_word()]);
        let tf = calldata(
            SEL_TRANSFER_FROM,
            &[addr_word(TRUSTED), addr_word(STRANGER), uint_word(1)],
        );
        for data in [t, tf] {
            let r = run(&data);
            assert!(r.flags.is_empty());
            assert_eq!(r.severity, Severity::Safe);
        }
    }

    #[test]
    fn unlimited_approve_to_stranger_is_high() {
        let r = run(&calldata(SEL_APPROVE, &[addr_word(STRANGER), max_word()]));
        assert_eq!(
            r.flags,
            flags_of(&[Flags::UNLIMITED_AMOUNT, Flags::UNTRUSTED_SPENDER])
        );
        assert_eq!(r.severity, Severity::High);
    }

    #[test]
    fn unlimited_approve_to_trusted_is_review() {
        let r = run(&calldata(SEL_APPROVE, &[addr_word(TRUSTED), max_word()]));
        assert_eq!(r.flags, Flags::UNLIMITED_AMOUNT);
        assert_eq!(r.severity, Severity::Review);
    }

    #[test]
    fn limited_approve_to_trusted_is_safe() {
        let r = run(&calldata(
            SEL_APPROVE,
            &[addr_word(TRUSTED), uint_word(1000)],
        ));
        assert!(r.flags.is_empty());
        assert_eq!(r.severity, Severity::Safe);
    }

    #[test]
    fn limited_approve_to_stranger_is_review() {
        let r = run(&calldata(
            SEL_APPROVE,
            &[addr_word(STRANGER), uint_word(1000)],
        ));
        assert_eq!(r.flags, Flags::UNTRUSTED_SPENDER);
        assert_eq!(r.severity, Severity::Review);
    }

    #[test]
    fn approve_of_exactly_half_range_counts_as_unlimited() {
        let mut half = [0u8; 32];
        half[0] = 0x80;
        let r = run(&calldata(SEL_APPROVE, &[addr_word(TRUSTED), half]));
        assert!(r.flags.contains(Flags::UNLIMITED_AMOUNT));
        let mut below = [0u8; 32];
        below[0] = 0x7f;
        below[1..].fill(0xff);
        let r = run(&calldata(SEL_APPROVE, &[addr_word(TRUSTED), below]));
        assert!(!r.flags.contains(Flags::UNLIMITED_AMOUNT));
    }

    #[test]
    fn zero_approval_is_a_safe_revocation_even_for_a_stranger() {
        let r = run(&calldata(SEL_APPROVE, &[addr_word(STRANGER), uint_word(0)]));
        assert_eq!(r.flags, Flags::REVOCATION);
        assert_eq!(r.severity, Severity::Safe);
    }

    #[test]
    fn increase_allowance_is_judged_like_approve() {
        let r = run(&calldata(
            SEL_INCREASE_ALLOWANCE,
            &[addr_word(STRANGER), max_word()],
        ));
        assert_eq!(r.severity, Severity::High);
    }

    #[test]
    fn set_approval_for_all_matrix() {
        let on_stranger = run(&calldata(
            SEL_SET_APPROVAL_FOR_ALL,
            &[addr_word(STRANGER), uint_word(1)],
        ));
        assert_eq!(
            on_stranger.flags,
            flags_of(&[Flags::BLANKET_APPROVAL, Flags::UNTRUSTED_SPENDER])
        );
        assert_eq!(on_stranger.severity, Severity::High);

        let on_trusted = run(&calldata(
            SEL_SET_APPROVAL_FOR_ALL,
            &[addr_word(TRUSTED), uint_word(1)],
        ));
        assert_eq!(on_trusted.flags, Flags::BLANKET_APPROVAL);
        assert_eq!(on_trusted.severity, Severity::Review);

        let off = run(&calldata(
            SEL_SET_APPROVAL_FOR_ALL,
            &[addr_word(STRANGER), uint_word(0)],
        ));
        assert_eq!(off.flags, Flags::REVOCATION);
        assert_eq!(off.severity, Severity::Safe);
    }

    fn permit_data(spender: u8, value: [u8; 32], deadline: [u8; 32]) -> std::vec::Vec<u8> {
        calldata(
            SEL_PERMIT,
            &[
                addr_word(TRUSTED),
                addr_word(spender),
                value,
                deadline,
                uint_word(27),
                [1u8; 32],
                [2u8; 32],
            ],
        )
    }

    #[test]
    fn permit_with_max_value_and_max_deadline() {
        let r = run(&permit_data(STRANGER, max_word(), max_word()));
        assert_eq!(
            r.flags,
            flags_of(&[
                Flags::UNLIMITED_AMOUNT,
                Flags::UNTRUSTED_SPENDER,
                Flags::NO_EXPIRY
            ])
        );
        assert_eq!(r.severity, Severity::High);
    }

    #[test]
    fn permit_with_finite_deadline_has_no_expiry_flag() {
        let r = run(&permit_data(
            TRUSTED,
            uint_word(50),
            uint_word(1_900_000_000),
        ));
        assert!(r.flags.is_empty());
    }

    #[test]
    fn zero_value_permit_is_a_revocation_and_ignores_expiry() {
        let r = run(&permit_data(STRANGER, uint_word(0), max_word()));
        assert_eq!(r.flags, Flags::REVOCATION);
        assert_eq!(r.severity, Severity::Safe);
    }

    fn dai_data(spender: u8, expiry: u64, allowed: u64) -> std::vec::Vec<u8> {
        calldata(
            SEL_PERMIT_DAI,
            &[
                addr_word(TRUSTED),
                addr_word(spender),
                uint_word(0),
                uint_word(expiry),
                uint_word(allowed),
                uint_word(27),
                [1u8; 32],
                [2u8; 32],
            ],
        )
    }

    #[test]
    fn dai_permit_allowed_with_zero_expiry_to_stranger() {
        let r = run(&dai_data(STRANGER, 0, 1));
        assert_eq!(
            r.flags,
            flags_of(&[
                Flags::UNLIMITED_AMOUNT,
                Flags::UNTRUSTED_SPENDER,
                Flags::NO_EXPIRY
            ])
        );
        assert_eq!(r.severity, Severity::High);
    }

    #[test]
    fn dai_permit_allowed_with_finite_expiry_to_trusted() {
        let r = run(&dai_data(TRUSTED, 1_900_000_000, 1));
        assert_eq!(r.flags, Flags::UNLIMITED_AMOUNT);
        assert_eq!(r.severity, Severity::Review);
    }

    #[test]
    fn dai_permit_not_allowed_is_a_revocation() {
        let r = run(&dai_data(STRANGER, 0, 0));
        assert_eq!(r.flags, Flags::REVOCATION);
        assert_eq!(r.severity, Severity::Safe);
    }

    fn permit2_data(spender: u8, amount: [u8; 32], expiration: [u8; 32]) -> std::vec::Vec<u8> {
        calldata(
            SEL_PERMIT2_APPROVE,
            &[addr_word(0xcc), addr_word(spender), amount, expiration],
        )
    }

    fn max_u160() -> [u8; 32] {
        let mut w = [0u8; 32];
        w[12..].fill(0xff);
        w
    }

    fn max_u48() -> [u8; 32] {
        let mut w = [0u8; 32];
        w[26..].fill(0xff);
        w
    }

    #[test]
    fn permit2_max_amount_is_unlimited_for_its_own_width() {
        let r = run(&permit2_data(STRANGER, max_u160(), max_u48()));
        assert_eq!(
            r.flags,
            flags_of(&[
                Flags::UNLIMITED_AMOUNT,
                Flags::UNTRUSTED_SPENDER,
                Flags::NO_EXPIRY
            ])
        );
        assert_eq!(r.severity, Severity::High);
    }

    #[test]
    fn permit2_amount_large_for_u160_is_not_judged_by_u256_width() {
        // 2^159 is "unlimited" for a uint160 even though it is tiny for a uint256.
        let mut w = [0u8; 32];
        w[12] = 0x80;
        let r = run(&permit2_data(TRUSTED, w, uint_word(1_900_000_000)));
        assert_eq!(r.flags, Flags::UNLIMITED_AMOUNT);
        // 2^158 is below the threshold.
        let mut below = [0u8; 32];
        below[12] = 0x40;
        let r = run(&permit2_data(TRUSTED, below, uint_word(1_900_000_000)));
        assert!(r.flags.is_empty());
    }

    #[test]
    fn permit2_finite_expiration_has_no_expiry_flag() {
        let r = run(&permit2_data(
            TRUSTED,
            uint_word(5),
            uint_word(1_900_000_000),
        ));
        assert!(r.flags.is_empty());
    }

    #[test]
    fn trailing_data_is_flagged_and_lifts_a_revocation_to_review() {
        let mut d = calldata(SEL_APPROVE, &[addr_word(STRANGER), uint_word(0)]);
        d.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
        let r = run(&d);
        assert_eq!(
            r.flags,
            flags_of(&[Flags::REVOCATION, Flags::TRAILING_DATA])
        );
        assert_eq!(r.severity, Severity::Review);
    }

    #[test]
    fn empty_context_distrusts_everyone() {
        let d = decode(&calldata(SEL_APPROVE, &[addr_word(TRUSTED), uint_word(1)])).unwrap();
        let r = assess(&d, &Context::none());
        assert_eq!(r.flags, Flags::UNTRUSTED_SPENDER);
    }

    #[test]
    fn a_recipient_nobody_listed_is_high() {
        let list = trusted_list();
        let a = assess_recipient(Some(&Address([STRANGER; 20])), &Context::new(&list));
        assert_eq!(a.flags, Flags::UNTRUSTED_RECIPIENT);
        assert_eq!(a.severity, Severity::High);
    }

    #[test]
    fn a_trusted_recipient_and_the_special_values_are_safe() {
        let list = trusted_list();
        let ctx = Context::new(&list);
        let a = assess_recipient(Some(&Address([TRUSTED; 20])), &ctx);
        assert_eq!((a.flags, a.severity), (Flags::EMPTY, Severity::Safe));
        let a = assess_recipient(None, &ctx);
        assert_eq!((a.flags, a.severity), (Flags::EMPTY, Severity::Safe));
    }

    #[test]
    fn with_no_trusted_list_every_account_recipient_is_high() {
        let a = assess_recipient(Some(&Address([TRUSTED; 20])), &Context::none());
        assert_eq!(a.severity, Severity::High);
        // ... but the special values still are not.
        assert_eq!(
            assess_recipient(None, &Context::none()).severity,
            Severity::Safe
        );
    }

    #[test]
    fn the_recipient_flag_is_independent_of_the_grant_flags() {
        // High by itself, and not merged into the spender rule: a revocation
        // next to it does not soften it.
        let mut f = Flags::UNTRUSTED_RECIPIENT;
        f.insert(Flags::REVOCATION);
        assert_eq!(severity_of(f), Severity::High);
        assert_eq!(severity_of(Flags::UNTRUSTED_SPENDER), Severity::Review);
    }
}
