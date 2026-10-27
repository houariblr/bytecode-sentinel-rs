//! Decode calldata of common token-authorization calls into a typed [`Call`].
//!
//! This module only decodes. Judging whether a decoded call is dangerous is
//! the job of [`crate::risk`].
//!
//! Selectors below were verified against keccak256 of the canonical
//! signatures, not copied from memory.

use crate::abi::{Address, Args, DecodeError, Word};

/// `transfer(address,uint256)`
pub const SEL_TRANSFER: [u8; 4] = [0xa9, 0x05, 0x9c, 0xbb];
/// `transferFrom(address,address,uint256)`
pub const SEL_TRANSFER_FROM: [u8; 4] = [0x23, 0xb8, 0x72, 0xdd];
/// `approve(address,uint256)`
pub const SEL_APPROVE: [u8; 4] = [0x09, 0x5e, 0xa7, 0xb3];
/// `increaseAllowance(address,uint256)`
pub const SEL_INCREASE_ALLOWANCE: [u8; 4] = [0x39, 0x50, 0x93, 0x51];
/// `setApprovalForAll(address,bool)`
pub const SEL_SET_APPROVAL_FOR_ALL: [u8; 4] = [0xa2, 0x2c, 0xb4, 0x65];
/// EIP-2612 `permit(address,address,uint256,uint256,uint8,bytes32,bytes32)`
pub const SEL_PERMIT: [u8; 4] = [0xd5, 0x05, 0xac, 0xcf];
/// DAI-style `permit(address,address,uint256,uint256,bool,uint8,bytes32,bytes32)`
pub const SEL_PERMIT_DAI: [u8; 4] = [0x8f, 0xcb, 0xaf, 0x0c];
/// Permit2 `approve(address,address,uint160,uint48)`
pub const SEL_PERMIT2_APPROVE: [u8; 4] = [0x87, 0x51, 0x7c, 0x45];

/// Bit widths of the narrow integer types used by Permit2.
const UINT160: u32 = 160;
const UINT48: u32 = 48;

/// A decoded call. Signature words (`v`, `r`, `s`) are validated for length
/// only and are not retained.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Call {
    Transfer {
        to: Address,
        amount: Word,
    },
    TransferFrom {
        from: Address,
        to: Address,
        amount: Word,
    },
    Approve {
        spender: Address,
        amount: Word,
    },
    IncreaseAllowance {
        spender: Address,
        amount: Word,
    },
    SetApprovalForAll {
        operator: Address,
        approved: bool,
    },
    /// EIP-2612.
    Permit {
        owner: Address,
        spender: Address,
        value: Word,
        deadline: Word,
    },
    /// DAI-style: `allowed == true` grants the maximum allowance.
    PermitDai {
        holder: Address,
        spender: Address,
        nonce: Word,
        expiry: Word,
        allowed: bool,
    },
    /// Permit2 `approve`: `amount` is a `uint160`, `expiration` a `uint48`.
    Permit2Approve {
        token: Address,
        spender: Address,
        amount: Word,
        expiration: Word,
    },
}

/// A decoded call plus the bytes left over after its arguments.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Decoded {
    pub call: Call,
    /// Bytes after the last argument. The EVM ignores them, so a scanner must
    /// not: they are a known way to disguise calldata.
    pub trailing: usize,
}

/// Decode `data` (selector plus arguments).
pub fn decode(data: &[u8]) -> Result<Decoded, DecodeError> {
    let sel = match data.get(..4) {
        Some(s) => [s[0], s[1], s[2], s[3]],
        None => return Err(DecodeError::MissingSelector { got: data.len() }),
    };

    match sel {
        SEL_TRANSFER => {
            let (a, trailing) = Args::new(data, 2)?;
            let call = Call::Transfer {
                to: a.address(0)?,
                amount: a.uint256(1)?,
            };
            Ok(Decoded { call, trailing })
        }
        SEL_TRANSFER_FROM => {
            let (a, trailing) = Args::new(data, 3)?;
            let call = Call::TransferFrom {
                from: a.address(0)?,
                to: a.address(1)?,
                amount: a.uint256(2)?,
            };
            Ok(Decoded { call, trailing })
        }
        SEL_APPROVE => {
            let (a, trailing) = Args::new(data, 2)?;
            let call = Call::Approve {
                spender: a.address(0)?,
                amount: a.uint256(1)?,
            };
            Ok(Decoded { call, trailing })
        }
        SEL_INCREASE_ALLOWANCE => {
            let (a, trailing) = Args::new(data, 2)?;
            let call = Call::IncreaseAllowance {
                spender: a.address(0)?,
                amount: a.uint256(1)?,
            };
            Ok(Decoded { call, trailing })
        }
        SEL_SET_APPROVAL_FOR_ALL => {
            let (a, trailing) = Args::new(data, 2)?;
            let call = Call::SetApprovalForAll {
                operator: a.address(0)?,
                approved: a.boolean(1)?,
            };
            Ok(Decoded { call, trailing })
        }
        SEL_PERMIT => {
            // owner, spender, value, deadline, v, r, s
            let (a, trailing) = Args::new(data, 7)?;
            let call = Call::Permit {
                owner: a.address(0)?,
                spender: a.address(1)?,
                value: a.uint256(2)?,
                deadline: a.uint256(3)?,
            };
            Ok(Decoded { call, trailing })
        }
        SEL_PERMIT_DAI => {
            // holder, spender, nonce, expiry, allowed, v, r, s
            let (a, trailing) = Args::new(data, 8)?;
            let call = Call::PermitDai {
                holder: a.address(0)?,
                spender: a.address(1)?,
                nonce: a.uint256(2)?,
                expiry: a.uint256(3)?,
                allowed: a.boolean(4)?,
            };
            Ok(Decoded { call, trailing })
        }
        SEL_PERMIT2_APPROVE => {
            let (a, trailing) = Args::new(data, 4)?;
            let call = Call::Permit2Approve {
                token: a.address(0)?,
                spender: a.address(1)?,
                amount: a.uint_bits(2, UINT160)?,
                expiration: a.uint_bits(3, UINT48)?,
            };
            Ok(Decoded { call, trailing })
        }
        other => Err(DecodeError::UnknownSelector(other)),
    }
}

#[cfg(test)]
pub(crate) mod testutil {
    //! Shared helpers for building calldata in tests.
    use std::vec::Vec;

    pub fn addr_word(fill: u8) -> [u8; 32] {
        let mut w = [0u8; 32];
        w[12..].fill(fill);
        w
    }

    pub fn uint_word(v: u64) -> [u8; 32] {
        let mut w = [0u8; 32];
        w[24..].copy_from_slice(&v.to_be_bytes());
        w
    }

    pub fn max_word() -> [u8; 32] {
        [0xff; 32]
    }

    pub fn calldata(sel: [u8; 4], words: &[[u8; 32]]) -> Vec<u8> {
        let mut v = sel.to_vec();
        for w in words {
            v.extend_from_slice(w);
        }
        v
    }
}

#[cfg(test)]
mod tests {
    use super::testutil::*;
    use super::*;

    const ALICE: u8 = 0xa1;
    const BOB: u8 = 0xb2;

    fn a(fill: u8) -> Address {
        Address([fill; 20])
    }

    #[test]
    fn transfer() {
        let d = calldata(SEL_TRANSFER, &[addr_word(BOB), uint_word(5)]);
        let r = decode(&d).unwrap();
        assert_eq!(r.trailing, 0);
        assert_eq!(
            r.call,
            Call::Transfer {
                to: a(BOB),
                amount: Word(uint_word(5))
            }
        );
    }

    #[test]
    fn transfer_from() {
        let d = calldata(
            SEL_TRANSFER_FROM,
            &[addr_word(ALICE), addr_word(BOB), uint_word(7)],
        );
        assert_eq!(
            decode(&d).unwrap().call,
            Call::TransferFrom {
                from: a(ALICE),
                to: a(BOB),
                amount: Word(uint_word(7))
            }
        );
    }

    #[test]
    fn approve_unlimited() {
        let d = calldata(SEL_APPROVE, &[addr_word(BOB), max_word()]);
        assert_eq!(
            decode(&d).unwrap().call,
            Call::Approve {
                spender: a(BOB),
                amount: Word(max_word())
            }
        );
    }

    #[test]
    fn increase_allowance() {
        let d = calldata(SEL_INCREASE_ALLOWANCE, &[addr_word(BOB), uint_word(9)]);
        assert!(matches!(
            decode(&d).unwrap().call,
            Call::IncreaseAllowance { .. }
        ));
    }

    #[test]
    fn set_approval_for_all_both_values() {
        let on = calldata(SEL_SET_APPROVAL_FOR_ALL, &[addr_word(BOB), uint_word(1)]);
        let off = calldata(SEL_SET_APPROVAL_FOR_ALL, &[addr_word(BOB), uint_word(0)]);
        assert_eq!(
            decode(&on).unwrap().call,
            Call::SetApprovalForAll {
                operator: a(BOB),
                approved: true
            }
        );
        assert_eq!(
            decode(&off).unwrap().call,
            Call::SetApprovalForAll {
                operator: a(BOB),
                approved: false
            }
        );
    }

    #[test]
    fn permit_eip2612() {
        let d = calldata(
            SEL_PERMIT,
            &[
                addr_word(ALICE),
                addr_word(BOB),
                max_word(),
                uint_word(1_900_000_000),
                uint_word(27),
                [1u8; 32],
                [2u8; 32],
            ],
        );
        assert_eq!(
            decode(&d).unwrap().call,
            Call::Permit {
                owner: a(ALICE),
                spender: a(BOB),
                value: Word(max_word()),
                deadline: Word(uint_word(1_900_000_000)),
            }
        );
    }

    #[test]
    fn permit_dai() {
        let d = calldata(
            SEL_PERMIT_DAI,
            &[
                addr_word(ALICE),
                addr_word(BOB),
                uint_word(3),
                uint_word(0),
                uint_word(1),
                uint_word(28),
                [1u8; 32],
                [2u8; 32],
            ],
        );
        assert_eq!(
            decode(&d).unwrap().call,
            Call::PermitDai {
                holder: a(ALICE),
                spender: a(BOB),
                nonce: Word(uint_word(3)),
                expiry: Word(uint_word(0)),
                allowed: true,
            }
        );
    }

    #[test]
    fn permit2_approve() {
        let mut amount = [0u8; 32];
        amount[12..].fill(0xff); // type(uint160).max
        let d = calldata(
            SEL_PERMIT2_APPROVE,
            &[
                addr_word(0xcc),
                addr_word(BOB),
                amount,
                uint_word(1_900_000_000),
            ],
        );
        assert_eq!(
            decode(&d).unwrap().call,
            Call::Permit2Approve {
                token: a(0xcc),
                spender: a(BOB),
                amount: Word(amount),
                expiration: Word(uint_word(1_900_000_000)),
            }
        );
    }

    #[test]
    fn missing_selector() {
        assert_eq!(
            decode(&[0x09, 0x5e, 0xa7]).unwrap_err(),
            DecodeError::MissingSelector { got: 3 }
        );
        assert_eq!(
            decode(&[]).unwrap_err(),
            DecodeError::MissingSelector { got: 0 }
        );
    }

    #[test]
    fn unknown_selector() {
        assert_eq!(
            decode(&[1, 2, 3, 4, 0, 0]).unwrap_err(),
            DecodeError::UnknownSelector([1, 2, 3, 4])
        );
    }

    #[test]
    fn truncated_arguments() {
        let mut d = calldata(SEL_APPROVE, &[addr_word(BOB), max_word()]);
        d.pop();
        assert_eq!(
            decode(&d).unwrap_err(),
            DecodeError::Truncated {
                expected: 68,
                got: 67
            }
        );
    }

    #[test]
    fn trailing_bytes_are_counted_not_rejected() {
        let mut d = calldata(SEL_APPROVE, &[addr_word(BOB), max_word()]);
        d.extend_from_slice(&[0xde, 0xad]);
        let r = decode(&d).unwrap();
        assert_eq!(r.trailing, 2);
        assert!(matches!(r.call, Call::Approve { .. }));
    }

    #[test]
    fn dirty_address_padding_is_rejected_with_its_index() {
        let mut dirty = addr_word(BOB);
        dirty[0] = 0x01;
        let d = calldata(SEL_TRANSFER_FROM, &[addr_word(ALICE), dirty, uint_word(1)]);
        assert_eq!(
            decode(&d).unwrap_err(),
            DecodeError::DirtyPadding { arg: 1 }
        );
    }

    #[test]
    fn non_boolean_approval_flag_is_rejected() {
        let d = calldata(SEL_SET_APPROVAL_FOR_ALL, &[addr_word(BOB), uint_word(2)]);
        assert_eq!(
            decode(&d).unwrap_err(),
            DecodeError::DirtyPadding { arg: 1 }
        );
    }

    #[test]
    fn permit2_amount_wider_than_160_bits_is_rejected() {
        let mut amount = [0u8; 32];
        amount[11] = 1; // bit 160 set
        let d = calldata(
            SEL_PERMIT2_APPROVE,
            &[addr_word(0xcc), addr_word(BOB), amount, uint_word(1)],
        );
        assert_eq!(
            decode(&d).unwrap_err(),
            DecodeError::DirtyPadding { arg: 2 }
        );
    }

    #[test]
    fn permit2_expiration_wider_than_48_bits_is_rejected() {
        let mut exp = [0u8; 32];
        exp[25] = 1; // bit 48 set
        let d = calldata(
            SEL_PERMIT2_APPROVE,
            &[addr_word(0xcc), addr_word(BOB), uint_word(1), exp],
        );
        assert_eq!(
            decode(&d).unwrap_err(),
            DecodeError::DirtyPadding { arg: 3 }
        );
    }

    #[test]
    fn no_panic_for_any_length_with_every_known_selector() {
        let sels = [
            SEL_TRANSFER,
            SEL_TRANSFER_FROM,
            SEL_APPROVE,
            SEL_INCREASE_ALLOWANCE,
            SEL_SET_APPROVAL_FOR_ALL,
            SEL_PERMIT,
            SEL_PERMIT_DAI,
            SEL_PERMIT2_APPROVE,
        ];
        for sel in sels {
            for len in 0..320usize {
                let mut d = std::vec![0xffu8; len];
                let n = len.min(4);
                d[..n].copy_from_slice(&sel[..n]);
                let _ = decode(&d);
                let mut z = std::vec![0u8; len];
                z[..n].copy_from_slice(&sel[..n]);
                let _ = decode(&z);
            }
        }
    }
}
