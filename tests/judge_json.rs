//! End-to-end tests of the `judge_json` filter: every corpus case goes through
//! the real binary and must come out with the verdict a human wrote down, and
//! the stream behaviour (line numbers, bad lines, exit status, size limit,
//! trusted list sources) is checked on its own.

use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};

const BIN: &str = env!("CARGO_BIN_EXE_judge_json");

struct Run {
    lines: Vec<String>,
    status: i32,
}

fn run(args: &[&str], stdin: &[u8]) -> Run {
    let mut child = Command::new(BIN)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn judge_json");
    // Write from a thread: a large input must not deadlock against the pipe.
    let mut sink = child.stdin.take().unwrap();
    let data = stdin.to_vec();
    let writer = std::thread::spawn(move || {
        let _ = sink.write_all(&data);
    });
    let out = child.wait_with_output().expect("wait");
    writer.join().unwrap();
    Run {
        lines: String::from_utf8(out.stdout)
            .expect("stdout is UTF-8")
            .lines()
            .map(str::to_string)
            .collect(),
        status: out.status.code().expect("exit code"),
    }
}

/// Value of `"key":"..."` (a string without escapes) in a flat JSON line.
fn str_field<'a>(json: &'a str, key: &str) -> Option<&'a str> {
    let pat = format!("\"{key}\":\"");
    let start = json.find(&pat)? + pat.len();
    let end = json[start..].find('"')? + start;
    Some(&json[start..end])
}

/// The names in `"flags":["A","B"]`.
fn flags_field(json: &str) -> Vec<String> {
    let pat = "\"flags\":[";
    let start = json.find(pat).expect("flags field") + pat.len();
    let end = json[start..].find(']').unwrap() + start;
    json[start..end]
        .split(',')
        .filter(|s| !s.is_empty())
        .map(|s| s.trim_matches('"').to_string())
        .collect()
}

struct Case {
    name: String,
    expect: String,
    flags: Option<Vec<String>>,
    error: Option<String>,
    trusted: Vec<String>,
    calldata: String,
}

fn cases() -> Vec<Case> {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("corpus");
    let mut files: Vec<_> = fs::read_dir(&dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|x| x == "case"))
        .collect();
    files.sort();
    files
        .iter()
        .map(|p| {
            let name = p.file_stem().unwrap().to_string_lossy().into_owned();
            let mut c = Case {
                name: name.clone(),
                expect: String::new(),
                flags: None,
                error: None,
                trusted: Vec::new(),
                calldata: String::new(),
            };
            for line in fs::read_to_string(p).unwrap().lines() {
                let line = line.trim();
                if line.is_empty() || line.starts_with('#') {
                    continue;
                }
                let (k, v) = line
                    .split_once(':')
                    .unwrap_or_else(|| panic!("{name}: {line}"));
                let v = v.trim();
                match k {
                    "expect" => c.expect = v.to_string(),
                    "flags" => c.flags = Some(v.split_whitespace().map(str::to_string).collect()),
                    "error" => c.error = Some(v.to_string()),
                    "trusted" => c.trusted.push(v.to_string()),
                    "calldata" => c.calldata = v.to_string(),
                    _ => {}
                }
            }
            assert!(!c.expect.is_empty() && !c.calldata.is_empty(), "{name}");
            c
        })
        .collect()
}

#[test]
fn every_corpus_case_gets_the_recorded_verdict_through_the_binary() {
    let all = cases();
    assert!(all.len() >= 70, "corpus went missing: {}", all.len());
    for c in &all {
        let mut args: Vec<&str> = Vec::new();
        for t in &c.trusted {
            args.push("--trust");
            args.push(t);
        }
        let r = run(&args, format!("{}\n", c.calldata).as_bytes());
        assert_eq!(r.lines.len(), 1, "{}: {:?}", c.name, r.lines);
        let json = &r.lines[0];
        assert_eq!(
            str_field(json, "verdict"),
            Some(c.expect.as_str()),
            "{}: {json}",
            c.name
        );
        // Fail closed: only `safe` may be allowed.
        assert_eq!(
            json.contains("\"allow\":true"),
            c.expect == "safe",
            "{}: {json}",
            c.name
        );
        let want_status = match c.expect.as_str() {
            "safe" => 0,
            "review" => 1,
            "high" => 2,
            "undecodable" => 3,
            other => panic!("{}: {other}", c.name),
        };
        assert_eq!(r.status, want_status, "{}", c.name);
        if let Some(want) = &c.flags {
            let mut got = flags_field(json);
            let mut want = want.clone();
            got.sort();
            want.sort();
            assert_eq!(got, want, "{}: {json}", c.name);
        }
        if let Some(e) = &c.error {
            assert_eq!(
                str_field(json, "error"),
                Some(e.as_str()),
                "{}: {json}",
                c.name
            );
        }
    }
}

const APPROVE_MAX_TO_A1: &str = "0x095ea7b3\
    000000000000000000000000a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1\
    ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";

#[test]
fn lines_are_numbered_blank_lines_are_skipped_and_a_bad_line_does_not_stop_the_stream() {
    let input = format!("\n{APPROVE_MAX_TO_A1}\n\nzz\n0x1234\n{APPROVE_MAX_TO_A1}\n");
    let r = run(&[], input.as_bytes());
    assert_eq!(r.lines.len(), 4, "{:?}", r.lines);
    let lines: Vec<_> = r
        .lines
        .iter()
        .map(|l| {
            (
                str_field(l, "verdict").unwrap(),
                l.contains("\"allow\":true"),
            )
        })
        .collect();
    assert_eq!(
        lines,
        vec![
            ("high", false),
            ("bad_input", false),
            ("undecodable", false),
            ("high", false)
        ]
    );
    assert!(r.lines[0].starts_with("{\"line\":2,"), "{}", r.lines[0]);
    assert!(r.lines[1].starts_with("{\"line\":4,"));
    assert!(r.lines[2].starts_with("{\"line\":5,"));
    assert!(r.lines[3].starts_with("{\"line\":6,"));
    // The worst result decides the status: bad input beats everything.
    assert_eq!(r.status, 4);
}

#[test]
fn the_status_is_the_worst_line_and_empty_input_is_success() {
    assert_eq!(run(&[], b"").status, 0);
    assert_eq!(run(&[], b"\n\n").lines.len(), 0);
    let r = run(&[], format!("{APPROVE_MAX_TO_A1}\n0x1234\n").as_bytes());
    assert_eq!(r.status, 3);
}

#[test]
fn the_trusted_list_comes_from_arguments_and_files_only() {
    let a1 = "0xa1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1";
    let line = format!("{APPROVE_MAX_TO_A1}\n");
    // Unlimited to a trusted spender is Review (unlimited), not High.
    let by_arg = run(&["--trust", a1], line.as_bytes());
    assert_eq!(str_field(&by_arg.lines[0], "verdict"), Some("review"));

    let dir = std::env::temp_dir().join(format!("judge_json_test_{}", std::process::id()));
    fs::create_dir_all(&dir).unwrap();
    let file = dir.join("trusted.txt");
    fs::write(&file, format!("# my list\n\n{a1} # the router\n")).unwrap();
    let by_file = run(&["--trusted-file", file.to_str().unwrap()], line.as_bytes());
    assert_eq!(str_field(&by_file.lines[0], "verdict"), Some("review"));
    fs::remove_dir_all(&dir).unwrap();

    // Extra text on the input line is not a way to extend the list.
    let sneaky = run(
        &[],
        format!("{APPROVE_MAX_TO_A1} --trust {a1}\n").as_bytes(),
    );
    assert_eq!(str_field(&sneaky.lines[0], "verdict"), Some("bad_input"));
}

#[test]
fn bad_command_lines_exit_4_without_reading_input() {
    for args in [
        &["--bogus"][..],
        &["--trust"],
        &["--trust", "0x11"],
        &["--trusted-file", "/nonexistent/file"],
    ] {
        let r = run(args, format!("{APPROVE_MAX_TO_A1}\n").as_bytes());
        assert_eq!(r.status, 4, "{args:?}");
        assert!(r.lines.is_empty(), "{args:?}: {:?}", r.lines);
    }
}

#[test]
fn an_oversized_line_is_refused_and_ends_the_run() {
    let mut input = vec![b'a'; 2 * 1024 * 1024 + 10];
    input.push(b'\n');
    input.extend_from_slice(APPROVE_MAX_TO_A1.as_bytes());
    input.push(b'\n');
    let r = run(&[], &input);
    assert_eq!(r.lines.len(), 1, "{:?}", r.lines);
    assert_eq!(str_field(&r.lines[0], "verdict"), Some("bad_input"));
    assert!(r.lines[0].contains("too large"));
    assert_eq!(r.status, 4);
}

#[test]
fn input_that_is_not_utf8_is_bad_input() {
    let r = run(&[], b"\xff\xfe\n");
    assert_eq!(r.lines.len(), 1);
    assert_eq!(str_field(&r.lines[0], "verdict"), Some("bad_input"));
    assert_eq!(r.status, 4);
}

#[test]
fn a_crlf_line_ending_is_accepted() {
    let r = run(&[], format!("{APPROVE_MAX_TO_A1}\r\n").as_bytes());
    assert_eq!(str_field(&r.lines[0], "verdict"), Some("high"));
}

#[test]
fn a_closed_output_pipe_stops_the_run_with_status_4() {
    // Nobody reads the verdicts: continuing would judge calldata for no one.
    let mut child = Command::new(BIN)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn judge_json");
    drop(child.stdout.take());
    let mut sink = child.stdin.take().unwrap();
    let input = format!("{APPROVE_MAX_TO_A1}\n").repeat(5000);
    let writer = std::thread::spawn(move || {
        let _ = sink.write_all(input.as_bytes());
    });
    let status = child.wait().expect("wait");
    writer.join().unwrap();
    // The same input with a reader would end with status 2 (high).
    assert_eq!(status.code(), Some(4));
}
