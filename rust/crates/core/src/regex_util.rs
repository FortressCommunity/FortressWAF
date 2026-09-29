//! Shared byte/string helpers used by several inspectors.
//!
//! These are lifted from `internal/engine/parser.go` and `internal/engine/sqli.go`
//! where the same primitives (single-pass percent decoding, hex classification)
//! appeared. Behaviour is identical.

/// Decode every valid `%XX` escape in `s` exactly once and report whether
/// anything changed. An invalid escape (a bare `%`, `%zz`, a trailing `%A`) is
/// left as-is, so an ordinary value containing `%` cannot loop or be mangled.
///
/// Port of `percentDecodeOnce`.
pub fn percent_decode_once(s: &str) -> (String, bool) {
    let bytes = s.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut changed = false;
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() && is_hex(bytes[i + 1]) && is_hex(bytes[i + 2]) {
            out.push(hex_byte(bytes[i + 1], bytes[i + 2]));
            i += 3;
            changed = true;
            continue;
        }
        out.push(bytes[i]);
        i += 1;
    }
    // Go keeps raw bytes in a string. Use lossy conversion so invalid UTF-8
    // does not drop content.
    (String::from_utf8_lossy(&out).into_owned(), changed)
}

/// `isHex`.
pub fn is_hex(c: u8) -> bool {
    c.is_ascii_digit() || (b'a'..=b'f').contains(&c) || (b'A'..=b'F').contains(&c)
}

/// `hexByte`.
pub fn hex_byte(hi: u8, lo: u8) -> u8 {
    (hex_val(hi) << 4) | hex_val(lo)
}

/// `hexVal`.
pub fn hex_val(c: u8) -> u8 {
    match c {
        b'0'..=b'9' => c - b'0',
        b'a'..=b'f' => c - b'a' + 10,
        b'A'..=b'F' => c - b'A' + 10,
        _ => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_valid_escapes_once() {
        let (out, changed) = percent_decode_once("%252e%252e");
        assert!(changed);
        assert_eq!(out, "%2e%2e");
    }

    #[test]
    fn bare_percent_unchanged() {
        let (out, changed) = percent_decode_once("100%");
        assert!(!changed);
        assert_eq!(out, "100%");
    }

    #[test]
    fn invalid_escape_left_alone() {
        let (out, changed) = percent_decode_once("%zz%2");
        assert!(!changed);
        assert_eq!(out, "%zz%2");
    }
}
