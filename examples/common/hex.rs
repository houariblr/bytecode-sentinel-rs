//! Hex helpers shared by the examples.

/// Decode a hex string. Accepts an optional `0x` prefix and ignores ASCII
/// whitespace.
pub fn decode_hex(s: &str) -> Result<Vec<u8>, String> {
    let s = s.trim().trim_start_matches("0x");
    let digits: Vec<u8> = s.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
    if digits.len() % 2 == 1 {
        return Err("odd number of hex digits".into());
    }
    let val = |c: u8| -> Result<u8, String> {
        (c as char)
            .to_digit(16)
            .map(|d| d as u8)
            .ok_or_else(|| format!("invalid hex digit {:?}", c as char))
    };
    digits
        .chunks(2)
        .map(|p| Ok(val(p[0])? << 4 | val(p[1])?))
        .collect()
}

/// Lower-case hex of `bytes`, no prefix.
pub fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
