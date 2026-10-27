//! Try it: `cargo run --example scan_hex -- 0x6080604052... [-d]`
//! or pipe hex on stdin. `-d` also prints the disassembly.

#[path = "common/hex.rs"]
mod hex;

use bytecode_sentinel::{disassemble, extract_selectors, scan, JumpdestMap, Op};
use std::io::Read;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let show_disasm = args.iter().any(|a| a == "-d");
    let input = match args.iter().find(|a| *a != "-d") {
        Some(h) => h.clone(),
        None => {
            let mut s = String::new();
            std::io::stdin().read_to_string(&mut s).expect("read stdin");
            s
        }
    };

    let code = match hex::decode_hex(&input) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("error: {e}");
            std::process::exit(2);
        }
    };

    if show_disasm {
        for i in disassemble(&code) {
            if i.imm.is_empty() {
                println!("{:04x}  {}", i.pc, Op(i.op));
            } else {
                println!(
                    "{:04x}  {} 0x{}{}",
                    i.pc,
                    Op(i.op),
                    hex::to_hex(i.imm),
                    if i.truncated { "  (truncated)" } else { "" }
                );
            }
        }
        println!();
    }

    println!("{:#?}", scan(&code));

    let mut words = vec![0u64; bytecode_sentinel::words_needed(code.len())];
    let map = JumpdestMap::build(&code, &mut words).expect("buffer sized exactly");
    println!("valid JUMPDESTs: {}", map.count());

    let mut sels = [[0u8; 4]; 64];
    let n = extract_selectors(&code, &mut sels);
    println!("selectors ({n}):");
    for s in &sels[..n] {
        println!("  0x{}", hex::to_hex(s));
    }
}
