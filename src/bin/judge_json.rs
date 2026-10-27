//! `judge_json`: the pre-sign check as a filter for other programs.
//!
//! Reads calldata hex from standard input, one transaction per line, and
//! writes one line of JSON per input line to standard output. A wallet or an
//! agent keeps the process open, writes a line, reads a line.
//!
//! ```text
//! judge_json [--trust 0xADDRESS]... [--trusted-file PATH]
//! ```
//!
//! The trusted list comes from the command line or a file (one address per
//! line, `#` comments allowed) and **never from the input**. Whoever can write
//! the calldata must not be able to extend the list.
//!
//! Output, one object per input line (empty lines are skipped, `line` counts
//! from 1 over all input lines):
//!
//! ```text
//! {"line":1,"verdict":"safe","allow":true,"severity":"Safe","flags":[],"reasons":[],
//!  "inspected":1,"unknown":0,"malformed":0,"hidden_bytes":0}
//! {"line":2,"verdict":"undecodable","allow":false,"error":"Truncated","detail":"Truncated { .. }"}
//! {"line":3,"verdict":"bad_input","allow":false,"error":"invalid hex digit 'z'"}
//! ```
//!
//! `allow` is `true` **only** for `safe`. `review`, `high`, `undecodable` and
//! `bad_input` are all `false`: a caller that checks `allow` alone fails
//! closed. An input that is too large, or not valid UTF-8, ends the run after
//! its `bad_input` line instead of guessing where the next line starts.
//!
//! Exit status: the worst result seen. 0 = every line safe (or no input),
//! 1 = review, 2 = high, 3 = undecodable, 4 = bad input or bad command line.

#[allow(dead_code)]
#[path = "../../examples/common/hex.rs"]
mod hex;

use bytecode_sentinel::{assess_calldata, Address, Context, DecodeError, Flags, Severity};
use std::io::{BufRead, Read, Write};

/// Longest accepted input line, in bytes of hex text (2 MiB). Real calldata is
/// far smaller; the limit only bounds memory.
const MAX_LINE: usize = 2 * 1024 * 1024;

const REASONS: [(Flags, &str, &str); 7] = [
    (
        Flags::UNLIMITED_AMOUNT,
        "UNLIMITED_AMOUNT",
        "unlimited amount",
    ),
    (
        Flags::UNTRUSTED_SPENDER,
        "UNTRUSTED_SPENDER",
        "spender not in your trusted list",
    ),
    (
        Flags::BLANKET_APPROVAL,
        "BLANKET_APPROVAL",
        "approves the whole collection",
    ),
    (Flags::NO_EXPIRY, "NO_EXPIRY", "no practical expiry"),
    (Flags::REVOCATION, "REVOCATION", "revokes an authorization"),
    (
        Flags::TRAILING_DATA,
        "TRAILING_DATA",
        "extra bytes after the arguments",
    ),
    (
        Flags::UNTRUSTED_RECIPIENT,
        "UNTRUSTED_RECIPIENT",
        "pays an account that is not in your trusted list",
    ),
];

/// JSON string literal for `s` (quotes included).
fn json_str(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// How bad a line was; the process exits with the maximum.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Outcome {
    Safe = 0,
    Review = 1,
    High = 2,
    Undecodable = 3,
    BadInput = 4,
}

fn parse_address(s: &str) -> Result<Address, String> {
    let bytes = hex::decode_hex(s)?;
    let arr: [u8; 20] = bytes
        .try_into()
        .map_err(|_| format!("address must be 20 bytes: {s}"))?;
    Ok(Address(arr))
}

fn read_trusted_file(path: &str) -> Result<Vec<Address>, String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("{path}: {e}"))?;
    let mut out = Vec::new();
    for (i, line) in text.lines().enumerate() {
        let line = line.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        out.push(parse_address(line).map_err(|e| format!("{path}:{}: {e}", i + 1))?);
    }
    Ok(out)
}

fn parse_args(args: impl Iterator<Item = String>) -> Result<Vec<Address>, String> {
    let mut trusted = Vec::new();
    let mut args = args;
    while let Some(a) = args.next() {
        match a.as_str() {
            "--trust" => {
                let v = args.next().ok_or("--trust needs an address")?;
                trusted.push(parse_address(&v)?);
            }
            "--trusted-file" => {
                let v = args.next().ok_or("--trusted-file needs a path")?;
                trusted.extend(read_trusted_file(&v)?);
            }
            other => return Err(format!("unknown argument: {other}")),
        }
    }
    Ok(trusted)
}

/// The error's variant name (`Truncated`, `DirtyPadding`, ...).
fn variant_name(e: &DecodeError) -> String {
    let d = format!("{e:?}");
    d.split(|c: char| !c.is_alphanumeric())
        .next()
        .unwrap_or("")
        .to_string()
}

/// Judge one hex line. Returns the JSON object and how bad it was.
fn judge_line(line_no: usize, text: &str, ctx: &Context<'_>) -> (String, Outcome) {
    let data = match hex::decode_hex(text) {
        Ok(d) => d,
        Err(e) => return (bad_input(line_no, &e), Outcome::BadInput),
    };
    match assess_calldata(&data, ctx) {
        Ok(r) => {
            let (verdict, allow, outcome) = match r.severity {
                Severity::Safe => ("safe", true, Outcome::Safe),
                Severity::Review => ("review", false, Outcome::Review),
                Severity::High => ("high", false, Outcome::High),
            };
            let flags: Vec<String> = REASONS
                .iter()
                .filter(|(f, _, _)| r.flags.contains(*f))
                .map(|(_, n, _)| json_str(n))
                .collect();
            let reasons: Vec<String> = REASONS
                .iter()
                .filter(|(f, _, _)| r.flags.contains(*f))
                .map(|(_, _, t)| json_str(t))
                .collect();
            let json = format!(
                "{{\"line\":{line_no},\"verdict\":\"{verdict}\",\"allow\":{allow},\
                 \"severity\":\"{:?}\",\"flags\":[{}],\"reasons\":[{}],\
                 \"inspected\":{},\"unknown\":{},\"malformed\":{},\"hidden_bytes\":{}}}",
                r.severity,
                flags.join(","),
                reasons.join(","),
                r.inspected,
                r.unknown,
                r.malformed,
                r.hidden_bytes
            );
            (json, outcome)
        }
        Err(e) => (
            format!(
                "{{\"line\":{line_no},\"verdict\":\"undecodable\",\"allow\":false,\
                 \"error\":{},\"detail\":{}}}",
                json_str(&variant_name(&e)),
                json_str(&format!("{e:?}"))
            ),
            Outcome::Undecodable,
        ),
    }
}

fn bad_input(line_no: usize, msg: &str) -> String {
    format!(
        "{{\"line\":{line_no},\"verdict\":\"bad_input\",\"allow\":false,\"error\":{}}}",
        json_str(msg)
    )
}

fn main() {
    let trusted = match parse_args(std::env::args().skip(1)) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("error: {e}");
            eprintln!("usage: judge_json [--trust 0xADDRESS]... [--trusted-file PATH]  (calldata hex on stdin, one per line)");
            std::process::exit(4);
        }
    };
    let ctx = Context::new(&trusted);

    let stdin = std::io::stdin();
    let mut input = stdin.lock();
    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    let mut worst = Outcome::Safe;
    let mut line_no = 0usize;
    let mut buf = String::new();

    loop {
        buf.clear();
        line_no += 1;
        // Read at most MAX_LINE + 1 bytes: a longer line is refused, not
        // buffered.
        let read = (&mut input).take(MAX_LINE as u64 + 1).read_line(&mut buf);
        let problem = match read {
            Ok(0) => break,
            Ok(_) if buf.len() > MAX_LINE => Some("input line too large".to_string()),
            Ok(_) => None,
            Err(e) => Some(format!("cannot read input: {e}")),
        };
        if let Some(msg) = problem {
            // After an oversized or unreadable line the next line boundary is
            // unknown, so stop instead of guessing.
            let _ = writeln!(out, "{}", bad_input(line_no, &msg));
            let _ = out.flush();
            std::process::exit(4);
        }
        if buf.trim().is_empty() {
            continue;
        }
        let (json, outcome) = judge_line(line_no, &buf, &ctx);
        worst = worst.max(outcome);
        if writeln!(out, "{json}").and_then(|_| out.flush()).is_err() {
            // The reader went away: nobody can use further verdicts.
            std::process::exit(4);
        }
    }
    std::process::exit(worst as i32);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strings_are_escaped() {
        assert_eq!(json_str("a\"b\\c\n"), "\"a\\\"b\\\\c\\n\"");
        assert_eq!(json_str("\u{1}"), "\"\\u0001\"");
        assert_eq!(json_str("é"), "\"é\"");
    }

    #[test]
    fn bad_hex_is_bad_input_and_never_allowed() {
        let ctx = Context::new(&[]);
        let (json, o) = judge_line(7, "0xzz", &ctx);
        assert!(o == Outcome::BadInput);
        assert!(json.contains("\"allow\":false"));
        assert!(json.contains("\"verdict\":\"bad_input\""));
        assert!(json.starts_with("{\"line\":7,"));
    }

    #[test]
    fn too_short_calldata_is_undecodable_and_never_allowed() {
        let ctx = Context::new(&[]);
        let (json, o) = judge_line(1, "0x1234", &ctx);
        assert!(o == Outcome::Undecodable);
        assert!(json.contains("\"allow\":false"));
        assert!(json.contains("\"error\":\"MissingSelector\""));
    }

    #[test]
    fn the_variant_name_stops_at_the_first_non_word_character() {
        assert_eq!(
            variant_name(&DecodeError::Truncated {
                expected: 4,
                got: 1
            }),
            "Truncated"
        );
        assert_eq!(variant_name(&DecodeError::BadArrayLength), "BadArrayLength");
    }

    #[test]
    fn outcomes_order_by_badness() {
        assert!(Outcome::Safe < Outcome::Review);
        assert!(Outcome::Review < Outcome::High);
        assert!(Outcome::High < Outcome::Undecodable);
        assert!(Outcome::Undecodable < Outcome::BadInput);
    }

    #[test]
    fn arguments_are_checked() {
        let a = |v: &[&str]| parse_args(v.iter().map(|s| s.to_string()));
        assert!(a(&[]).unwrap().is_empty());
        assert_eq!(
            a(&["--trust", "0x1111111111111111111111111111111111111111"])
                .unwrap()
                .len(),
            1
        );
        assert!(a(&["--trust"]).is_err());
        assert!(a(&["--trust", "0x11"]).is_err());
        assert!(a(&["--bogus"]).is_err());
        assert!(a(&["--trusted-file", "/nonexistent/x"]).is_err());
    }
}
