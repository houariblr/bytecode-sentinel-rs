//! Check what a transaction's calldata authorizes.
//!
//! `cargo run --example check_calldata -- <calldata-hex> [trusted-address-hex ...]`
//!
//! Understands single calls, `multicall(bytes[])` batches, Multicall3
//! `aggregate*` batches (nested up to a fixed depth) and Universal Router
//! `execute` calls; every inner call or command is listed. Of the router's
//! commands only the Permit2 permits are judged; the rest are listed as
//! `not judged` and keep the verdict at `Review` at least.
//!
//! Exit status: 0 = Safe, 1 = Review, 2 = High, 3 = could not decode,
//! 4 = bad command-line input. A decode failure is never reported as safe.

#[path = "common/hex.rs"]
mod hex;

use bytecode_sentinel::multicall::MAX_DEPTH;
use bytecode_sentinel::{
    assess, assess_calldata, calls, commands, decode, decode_permit_batch, decode_permit_single,
    decode_spend, is_execute, is_multicall, Address, Call, Context, DecodeError, Flags, Kind,
    Recipient, Severity, Word,
};

const REASONS: [(Flags, &str); 7] = [
    (Flags::UNLIMITED_AMOUNT, "unlimited amount"),
    (Flags::UNTRUSTED_SPENDER, "spender not in your trusted list"),
    (Flags::BLANKET_APPROVAL, "approves the whole collection"),
    (Flags::NO_EXPIRY, "no practical expiry"),
    (Flags::REVOCATION, "revokes an authorization"),
    (Flags::TRAILING_DATA, "extra bytes after the arguments"),
    (
        Flags::UNTRUSTED_RECIPIENT,
        "pays an account that is not in your trusted list",
    ),
];

fn parse_address(s: &str) -> Result<Address, String> {
    let bytes = hex::decode_hex(s)?;
    let arr: [u8; 20] = bytes
        .try_into()
        .map_err(|_| format!("address must be 20 bytes: {s}"))?;
    Ok(Address(arr))
}

fn addr(a: &Address) -> String {
    format!("0x{}", hex::to_hex(&a.0))
}

/// Hex without leading zero bytes; `0` for zero.
fn num(w: &Word) -> String {
    let start = w.0.iter().position(|&b| b != 0).unwrap_or(32);
    if start == 32 {
        "0".into()
    } else {
        format!("0x{}", hex::to_hex(&w.0[start..]))
    }
}

fn summary(call: &Call) -> String {
    match call {
        Call::Transfer { to, amount } => format!("transfer {} to {}", num(amount), addr(to)),
        Call::TransferFrom { from, to, amount } => {
            format!(
                "transferFrom {} -> {} amount {}",
                addr(from),
                addr(to),
                num(amount)
            )
        }
        Call::Approve { spender, amount } => {
            format!("approve {} to spend {}", addr(spender), num(amount))
        }
        Call::IncreaseAllowance { spender, amount } => {
            format!("increaseAllowance {} by {}", addr(spender), num(amount))
        }
        Call::SetApprovalForAll { operator, approved } => {
            format!("setApprovalForAll {} = {approved}", addr(operator))
        }
        Call::Permit {
            owner,
            spender,
            value,
            deadline,
        } => format!(
            "permit owner {} spender {} value {} deadline {}",
            addr(owner),
            addr(spender),
            num(value),
            num(deadline)
        ),
        Call::PermitDai {
            holder,
            spender,
            expiry,
            allowed,
            ..
        } => format!(
            "DAI permit holder {} spender {} allowed={allowed} expiry {}",
            addr(holder),
            addr(spender),
            num(expiry)
        ),
        Call::Permit2Approve {
            token,
            spender,
            amount,
            expiration,
        } => format!(
            "Permit2 approve token {} spender {} amount {} expiration {}",
            addr(token),
            addr(spender),
            num(amount),
            num(expiration)
        ),
    }
}

fn describe_error(e: &DecodeError) -> String {
    match e {
        DecodeError::MissingSelector { got } => format!("only {got} bytes, no selector"),
        DecodeError::UnknownSelector(s) => format!("unknown selector 0x{}", hex::to_hex(s)),
        DecodeError::Truncated { expected, got } => format!("need {expected} bytes, got {got}"),
        DecodeError::DirtyPadding { arg } => {
            format!("argument {arg} has non-canonical padding")
        }
        DecodeError::BadOffset { arg } => format!("bad offset in argument {arg}"),
        DecodeError::BadArrayLength => "array length does not fit the data".into(),
        DecodeError::BadElementOffset { index } => format!("bad offset for element {index}"),
        DecodeError::BadElementLength { index } => format!("bad length for element {index}"),
        DecodeError::OverlappingElement { index } => {
            format!("element {index} overlaps or aliases another region")
        }
        DecodeError::DirtyBytesPadding { index } => {
            format!("element {index} has non-zero padding")
        }
        DecodeError::NestingTooDeep => {
            format!("batches nested deeper than {}", MAX_DEPTH)
        }
        DecodeError::DirtyElementField { index, field } => {
            format!("element {index}, field {field} has non-canonical padding or an invalid value")
        }
        DecodeError::BadMemberOffset { index } => {
            format!("bad offset for the call data of element {index}")
        }
        DecodeError::LengthMismatch { commands, inputs } => {
            format!("{commands} command byte(s) but {inputs} input(s): the router reverts")
        }
    }
}

fn cannot_decode(e: &DecodeError) -> ! {
    println!("cannot decode: {}", describe_error(e));
    println!("this is NOT a safe verdict");
    std::process::exit(3);
}

fn fail(msg: &str) -> ! {
    eprintln!("error: {msg}");
    std::process::exit(4);
}

fn main() {
    let mut args = std::env::args().skip(1);
    let Some(calldata_hex) = args.next() else {
        fail("usage: check_calldata <calldata-hex> [trusted-address-hex ...]");
    };
    let data = hex::decode_hex(&calldata_hex).unwrap_or_else(|e| fail(&e));
    let trusted: Vec<Address> = args
        .map(|a| parse_address(&a).unwrap_or_else(|e| fail(&e)))
        .collect();
    let ctx = Context::new(&trusted);

    if is_execute(&data) {
        // As for batches: validate the whole plan first.
        let result = assess_calldata(&data, &ctx).unwrap_or_else(|e| cannot_decode(&e));
        println!("Universal Router execute, {} command(s):", result.inspected);
        if let Ok(walk) = commands(&data) {
            for cmd in walk.flatten() {
                let pad = "  ".repeat(cmd.depth);
                let tag = if cmd.allow_revert() {
                    " [allow-revert]"
                } else {
                    ""
                };
                match cmd.kind() {
                    Kind::Permit2Permit => match decode_permit_single(cmd.input) {
                        Ok(p) => println!("{pad}- {}{tag}", summary(&p.details.to_call(p.spender))),
                        Err(e) => println!(
                            "{pad}- PERMIT2_PERMIT not judged: {}{tag}",
                            describe_error(&e)
                        ),
                    },
                    Kind::Permit2PermitBatch => match decode_permit_batch(cmd.input) {
                        Ok(b) => {
                            println!("{pad}- PERMIT2_PERMIT_BATCH, {} allowance(s){tag}", b.len());
                            for d in b.iter() {
                                println!("{pad}    {}", summary(&d.to_call(b.spender)));
                            }
                        }
                        Err(e) => println!(
                            "{pad}- PERMIT2_PERMIT_BATCH not judged: {}{tag}",
                            describe_error(&e)
                        ),
                    },
                    Kind::Permit2TransferFrom
                    | Kind::Transfer
                    | Kind::Sweep
                    | Kind::PayPortion
                    | Kind::UnwrapWeth => match decode_spend(cmd.kind(), cmd.input) {
                        Some(Ok(spend)) => {
                            let who = match &spend.recipient {
                                Recipient::MsgSender => {
                                    "address(1), the signer (MSG_SENDER)".into()
                                }
                                Recipient::AddressThis => {
                                    "address(2), the router (ADDRESS_THIS)".into()
                                }
                                Recipient::Account(a) => {
                                    let a = addr(a);
                                    if trusted.iter().any(|t| addr(t) == a) {
                                        format!("{a} (trusted)")
                                    } else {
                                        format!("{a} (NOT in your trusted list)")
                                    }
                                }
                            };
                            println!("{pad}- {:?} pays {who}{tag}", cmd.kind());
                        }
                        Some(Err(e)) => println!(
                            "{pad}- {:?} not judged: {}{tag}",
                            cmd.kind(),
                            describe_error(&e)
                        ),
                        None => println!("{pad}- {:?}: not judged{tag}", cmd.kind()),
                    },
                    Kind::Permit2TransferFromBatch => {
                        println!("{pad}- PERMIT2_TRANSFER_FROM_BATCH: recipients not fully judged yet{tag}");
                    }
                    Kind::Other(name) => println!("{pad}- {name}: not judged{tag}"),
                    Kind::Unassigned => println!(
                        "{pad}- command type {:#04x}: assigned to nothing in the router \
                         version this crate follows; not judged{tag}",
                        cmd.ty()
                    ),
                    Kind::ExecuteSubPlan => println!("{pad}- EXECUTE_SUB_PLAN{tag}"),
                }
            }
        }
        if result.unknown + result.malformed > 0 {
            println!(
                "{} command(s) not judged ({} not judged by design or unassigned, {} unreadable)",
                result.unknown + result.malformed,
                result.unknown,
                result.malformed
            );
        }
        if result.hidden_bytes > 0 {
            println!(
                "{} byte(s) the EVM ignores are hidden in the plan",
                result.hidden_bytes
            );
        }
        report(result.severity, result.flags);
    }

    if is_multicall(&data) {
        // Validate the whole batch first: a batch that cannot be read
        // completely gets no verdict, not even a partial listing.
        let result = assess_calldata(&data, &ctx).unwrap_or_else(|e| cannot_decode(&e));
        println!("batch, {} call(s):", result.inspected);
        if let Ok(walk) = calls(&data) {
            for item in walk.flatten() {
                let pad = "  ".repeat(item.depth);
                let mut line = match decode(item.data) {
                    Ok(d) => summary(&d.call),
                    Err(e) => format!("not judged: {}", describe_error(&e)),
                };
                if let Some(target) = &item.target {
                    line.push_str(&format!(" [on {}]", addr(target)));
                }
                if let Some(value) = item.value.as_ref().filter(|v| !v.is_zero()) {
                    line.push_str(&format!(" [sends value {}]", num(value)));
                }
                println!("{pad}- {line}");
            }
        }
        if result.unknown + result.malformed > 0 {
            println!(
                "{} call(s) not judged ({} unknown selector, {} malformed)",
                result.unknown + result.malformed,
                result.unknown,
                result.malformed
            );
        }
        if result.hidden_bytes > 0 {
            println!(
                "{} byte(s) the EVM ignores are hidden in the batch",
                result.hidden_bytes
            );
        }
        report(result.severity, result.flags);
    }

    let decoded = decode(&data).unwrap_or_else(|e| cannot_decode(&e));
    let result = assess(&decoded, &ctx);
    println!("{}", summary(&decoded.call));
    report(result.severity, result.flags);
}

/// Print the verdict and exit with the matching status.
fn report(severity: Severity, flags: Flags) -> ! {
    println!("severity: {severity:?}");
    for (flag, text) in REASONS {
        if flags.contains(flag) {
            println!("  - {text}");
        }
    }
    std::process::exit(match severity {
        Severity::Safe => 0,
        Severity::Review => 1,
        Severity::High => 2,
    });
}
