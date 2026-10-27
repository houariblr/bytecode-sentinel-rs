//! Corpus test: run every `corpus/*.case` file through the crate and compare
//! the verdict with the one a human wrote down beforehand.
//!
//! A case file is `key: value` lines (blank lines and `#` comments ignored):
//!
//! ```text
//! source:   synthetic | real:<tx hash or URL>     (required)
//! note:     free text                              (optional)
//! expect:   safe | review | high | undecodable     (required)
//! flags:    NAMES separated by spaces, empty = none (optional, exact match)
//! error:    DecodeError variant name               (optional, with `undecodable`)
//! trusted:  0x<20-byte address>                    (optional, repeatable)
//! calldata: 0x<hex>                                (required)
//! ```
//!
//! Unknown keys, duplicate keys and malformed values fail the test loudly: a
//! corpus that silently skips a case is worse than none.

use bytecode_sentinel::{assess_calldata, Address, Context, Flags, Severity};
use std::fs;
use std::path::{Path, PathBuf};

const FLAG_NAMES: [(&str, Flags); 7] = [
    ("UNLIMITED_AMOUNT", Flags::UNLIMITED_AMOUNT),
    ("UNTRUSTED_SPENDER", Flags::UNTRUSTED_SPENDER),
    ("BLANKET_APPROVAL", Flags::BLANKET_APPROVAL),
    ("NO_EXPIRY", Flags::NO_EXPIRY),
    ("REVOCATION", Flags::REVOCATION),
    ("TRAILING_DATA", Flags::TRAILING_DATA),
    ("UNTRUSTED_RECIPIENT", Flags::UNTRUSTED_RECIPIENT),
];

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
enum Expect {
    Verdict(Severity),
    Undecodable,
}

struct Case {
    name: String,
    real: bool,
    expect: Expect,
    flags: Option<Flags>,
    error: Option<String>,
    trusted: Vec<Address>,
    calldata: Vec<u8>,
}

fn from_hex(s: &str) -> Result<Vec<u8>, String> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    if s.len() % 2 == 1 {
        return Err("odd number of hex digits".into());
    }
    let nib = |c: u8| -> Result<u8, String> {
        match c {
            b'0'..=b'9' => Ok(c - b'0'),
            b'a'..=b'f' => Ok(c - b'a' + 10),
            b'A'..=b'F' => Ok(c - b'A' + 10),
            _ => Err(format!("not a hex digit: {:?}", c as char)),
        }
    };
    s.as_bytes()
        .chunks(2)
        .map(|p| Ok(nib(p[0])? << 4 | nib(p[1])?))
        .collect()
}

fn parse_flags(s: &str) -> Result<Flags, String> {
    let mut f = Flags::EMPTY;
    for word in s.split_whitespace() {
        let (_, flag) = FLAG_NAMES
            .iter()
            .find(|(n, _)| *n == word)
            .ok_or_else(|| format!("unknown flag {word}"))?;
        f.insert(*flag);
    }
    Ok(f)
}

fn parse_case(name: &str, text: &str) -> Result<Case, String> {
    let (mut source, mut expect, mut flags, mut error, mut calldata) =
        (None, None, None, None, None);
    let mut trusted = Vec::new();

    for (i, raw) in text.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let at = |m: &str| format!("line {}: {m}", i + 1);
        let (key, value) = line
            .split_once(':')
            .ok_or_else(|| at("expected `key: value`"))?;
        let (key, value) = (key.trim(), value.trim());
        // A key that may appear only once.
        let once = |slot: &Option<()>| -> Result<(), String> {
            if slot.is_some() {
                Err(at(&format!("duplicate key `{key}`")))
            } else {
                Ok(())
            }
        };
        match key {
            "source" => {
                once(&source.as_ref().map(|_| ()))?;
                if value != "synthetic" && !value.starts_with("real:") {
                    return Err(at("source must be `synthetic` or `real:<tx hash or URL>`"));
                }
                source = Some(value.to_string());
            }
            "note" => {}
            "expect" => {
                once(&expect.as_ref().map(|_| ()))?;
                expect = Some(match value {
                    "safe" => Expect::Verdict(Severity::Safe),
                    "review" => Expect::Verdict(Severity::Review),
                    "high" => Expect::Verdict(Severity::High),
                    "undecodable" => Expect::Undecodable,
                    _ => return Err(at("expect must be safe|review|high|undecodable")),
                });
            }
            "flags" => {
                once(&flags.as_ref().map(|_| ()))?;
                flags = Some(parse_flags(value).map_err(|e| at(&e))?);
            }
            "error" => {
                once(&error.as_ref().map(|_| ()))?;
                error = Some(value.to_string());
            }
            "trusted" => {
                let b = from_hex(value).map_err(|e| at(&e))?;
                let arr: [u8; 20] = b.try_into().map_err(|_| at("address must be 20 bytes"))?;
                trusted.push(Address(arr));
            }
            "calldata" => {
                once(&calldata.as_ref().map(|_| ()))?;
                calldata = Some(from_hex(value).map_err(|e| at(&e))?);
            }
            _ => return Err(at(&format!("unknown key `{key}`"))),
        }
    }

    let source = source.ok_or("missing `source`")?;
    let expect = expect.ok_or("missing `expect`")?;
    let calldata = calldata.ok_or("missing `calldata`")?;
    if expect == Expect::Undecodable && flags.is_some() {
        return Err("`flags` makes no sense with `expect: undecodable`".into());
    }
    if expect != Expect::Undecodable && error.is_some() {
        return Err("`error` only applies to `expect: undecodable`".into());
    }
    Ok(Case {
        name: name.to_string(),
        real: source.starts_with("real:"),
        expect,
        flags,
        error,
        trusted,
        calldata,
    })
}

/// Flag names for failure messages: `Flags(3)` tells nobody anything.
fn names(f: Flags) -> String {
    let v: Vec<&str> = FLAG_NAMES
        .iter()
        .filter(|(_, x)| f.contains(*x))
        .map(|(n, _)| *n)
        .collect();
    if v.is_empty() {
        "(none)".into()
    } else {
        v.join(" ")
    }
}

/// `None` if the crate agrees with the case, otherwise what differed.
fn check(case: &Case) -> Option<String> {
    let ctx = Context::new(&case.trusted);
    match (assess_calldata(&case.calldata, &ctx), case.expect) {
        (Ok(got), Expect::Verdict(want)) => {
            if got.severity != want {
                return Some(format!(
                    "expected {want:?}, got {:?} (flags {})",
                    got.severity,
                    names(got.flags)
                ));
            }
            match case.flags {
                Some(want_flags) if want_flags != got.flags => Some(format!(
                    "expected flags {}, got {}",
                    names(want_flags),
                    names(got.flags)
                )),
                _ => None,
            }
        }
        (Ok(got), Expect::Undecodable) => Some(format!(
            "expected undecodable, got verdict {:?}",
            got.severity
        )),
        (Err(e), Expect::Verdict(want)) => {
            Some(format!("expected {want:?}, got decode error {e:?}"))
        }
        (Err(e), Expect::Undecodable) => match &case.error {
            Some(name) if !format!("{e:?}").starts_with(name.as_str()) => {
                Some(format!("expected error {name}, got {e:?}"))
            }
            _ => None,
        },
    }
}

fn corpus_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("corpus")
}

fn load_cases() -> (Vec<Case>, Vec<String>) {
    let mut cases = Vec::new();
    let mut problems = Vec::new();
    let mut paths: Vec<PathBuf> = fs::read_dir(corpus_dir())
        .expect("corpus/ directory must exist")
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().is_some_and(|x| x == "case"))
        .collect();
    paths.sort();
    for path in paths {
        let name = path.file_stem().unwrap().to_string_lossy().into_owned();
        match fs::read_to_string(&path) {
            Ok(text) => match parse_case(&name, &text) {
                Ok(c) => cases.push(c),
                Err(e) => problems.push(format!("{name}: {e}")),
            },
            Err(e) => problems.push(format!("{name}: cannot read: {e}")),
        }
    }
    (cases, problems)
}

#[test]
fn every_case_gets_the_verdict_a_human_wrote_down() {
    let (cases, mut problems) = load_cases();
    assert!(
        !cases.is_empty() || !problems.is_empty(),
        "corpus/ has no .case files"
    );

    for c in &cases {
        if let Some(diff) = check(c) {
            problems.push(format!("{}: {diff}", c.name));
        }
    }

    let real = cases.iter().filter(|c| c.real).count();
    println!(
        "corpus: {} case(s), {} real, {} synthetic",
        cases.len(),
        real,
        cases.len() - real
    );
    if real == 0 {
        println!("corpus: no real transactions yet; this run proves nothing about the real world");
    }
    assert!(
        problems.is_empty(),
        "corpus problems:\n  {}",
        problems.join("\n  ")
    );
}

#[test]
fn the_case_parser_rejects_sloppy_files() {
    let ok = "source: synthetic\nexpect: safe\ncalldata: 0x00\n";
    assert!(parse_case("t", ok).is_ok());

    let bad: [(&str, &str); 9] = [
        ("missing source", "expect: safe\ncalldata: 0x00\n"),
        ("missing expect", "source: synthetic\ncalldata: 0x00\n"),
        ("missing calldata", "source: synthetic\nexpect: safe\n"),
        (
            "unknown key",
            "source: synthetic\nexpect: safe\ncalldata: 0x00\nfoo: 1\n",
        ),
        (
            "duplicate key",
            "source: synthetic\nexpect: safe\nexpect: high\ncalldata: 0x00\n",
        ),
        (
            "bad source",
            "source: trust me\nexpect: safe\ncalldata: 0x00\n",
        ),
        (
            "odd hex",
            "source: synthetic\nexpect: safe\ncalldata: 0x0\n",
        ),
        (
            "unknown flag",
            "source: synthetic\nexpect: safe\nflags: SCARY\ncalldata: 0x00\n",
        ),
        (
            "flags with undecodable",
            "source: synthetic\nexpect: undecodable\nflags:\ncalldata: 0x00\n",
        ),
    ];
    for (why, text) in bad {
        assert!(parse_case("t", text).is_err(), "should reject: {why}");
    }
}
