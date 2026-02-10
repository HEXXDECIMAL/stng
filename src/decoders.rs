//! String decoders for base64, hex, URL-encoding, and unicode escapes.
//!
//! This module provides decoders for common string encoding schemes found in malware.
//! Each decoder attempts to decode strings and validates the result to minimize false positives.

use crate::{ExtractedString, StringKind, StringMethod};

/// Minimum length for base64 strings to attempt decoding
pub const MIN_BASE64_LENGTH: usize = 16;

/// Minimum length for hex-encoded strings to attempt decoding
pub const MIN_HEX_LENGTH: usize = 16;

/// Maximum size for decoded output (to prevent memory exhaustion)
pub const MAX_DECODED_SIZE: usize = 10 * 1024 * 1024; // 10MB

/// Decode base64-encoded strings from a list of extracted strings.
///
/// Returns a vector of newly decoded strings with `StringMethod::Base64Decode`.
pub fn decode_base64_strings(strings: &[ExtractedString]) -> Vec<ExtractedString> {
    strings
        .iter()
        .filter(|s| s.kind == StringKind::Base64 || is_likely_base64(&s.value))
        .filter_map(|s| decode_base64_string(s))
        .collect()
}

/// Attempt to decode a single base64 string.
fn decode_base64_string(s: &ExtractedString) -> Option<ExtractedString> {
    if s.value.len() < MIN_BASE64_LENGTH {
        return None;
    }

    // Try standard base64 decoding
    let decoded = base64::Engine::decode(
        &base64::engine::general_purpose::STANDARD,
        s.value.trim(),
    )
    .ok()?;

    // Check size limit
    if decoded.len() > MAX_DECODED_SIZE {
        return None;
    }

    // Validate decoded content (must be printable ASCII or valid UTF-8)
    let decoded_str = if decoded
        .iter()
        .all(|&b| b.is_ascii() && (!b.is_ascii_control() || b == b'\n' || b == b'\r' || b == b'\t'))
    {
        // All printable ASCII (+ newlines/tabs)
        String::from_utf8_lossy(&decoded).to_string()
    } else if let Ok(utf8_str) = std::str::from_utf8(&decoded) {
        // Valid UTF-8
        utf8_str.to_string()
    } else {
        // Not valid text - skip
        return None;
    };

    // Reject if decoded string is too short or just whitespace
    let trimmed = decoded_str.trim();
    if trimmed.len() < 4 {
        return None;
    }

    // Classify before moving
    let kind = classify_decoded_string(&decoded_str);

    // Create new ExtractedString with decoded content
    Some(ExtractedString {
        value: decoded_str,
        data_offset: s.data_offset,
        section: s.section.clone(),
        method: StringMethod::Base64Decode,
        kind,
        library: None,
        fragments: None,
    })
}

/// Decode hex-encoded strings from a list of extracted strings.
///
/// Returns a vector of newly decoded strings with `StringMethod::HexDecode`.
pub fn decode_hex_strings(strings: &[ExtractedString]) -> Vec<ExtractedString> {
    let candidates: Vec<_> = strings
        .iter()
        .filter(|s| s.kind == StringKind::HexEncoded || is_likely_hex(&s.value))
        .collect();

    tracing::debug!("decode_hex_strings: found {} candidates", candidates.len());

    candidates
        .into_iter()
        .filter_map(|s| {
            let result = decode_hex_string(s);
            if result.is_some() {
                tracing::debug!("Successfully decoded hex string of length {}", s.value.len());
            } else {
                tracing::debug!("Failed to decode hex string of length {}", s.value.len());
            }
            result
        })
        .collect()
}

/// Attempt to decode a single hex-encoded string.
fn decode_hex_string(s: &ExtractedString) -> Option<ExtractedString> {
    if s.value.len() < MIN_HEX_LENGTH || s.value.len() % 2 != 0 {
        return None;
    }

    // Decode hex
    let decoded = hex::decode(s.value.trim()).ok()?;

    // Check size limit
    if decoded.len() > MAX_DECODED_SIZE {
        return None;
    }

    // Validate decoded content (must be printable ASCII or valid UTF-8)
    let decoded_str = if decoded
        .iter()
        .all(|&b| b.is_ascii() && (!b.is_ascii_control() || b == b'\n' || b == b'\r' || b == b'\t'))
    {
        // All printable ASCII (+ newlines/tabs)
        String::from_utf8_lossy(&decoded).to_string()
    } else if let Ok(utf8_str) = std::str::from_utf8(&decoded) {
        // Valid UTF-8
        utf8_str.to_string()
    } else {
        // Not valid text - skip
        return None;
    };

    // Reject if too short
    let trimmed = decoded_str.trim();
    if trimmed.len() < 4 {
        return None;
    }

    // Classify before moving
    let kind = classify_decoded_string(&decoded_str);

    Some(ExtractedString {
        value: decoded_str,
        data_offset: s.data_offset,
        section: s.section.clone(),
        method: StringMethod::HexDecode,
        kind,
        library: None,
        fragments: None,
    })
}

/// Decode URL-encoded strings from a list of extracted strings.
///
/// Returns a vector of newly decoded strings with `StringMethod::UrlDecode`.
pub fn decode_url_strings(strings: &[ExtractedString]) -> Vec<ExtractedString> {
    strings
        .iter()
        .filter(|s| s.kind == StringKind::UrlEncoded || is_likely_url_encoded(&s.value))
        .filter_map(|s| decode_url_string(s))
        .collect()
}

/// Attempt to decode a single URL-encoded string.
fn decode_url_string(s: &ExtractedString) -> Option<ExtractedString> {
    // Must contain at least one % escape sequence
    if !s.value.contains('%') {
        return None;
    }

    // URL decode
    let decoded = urlencoding::decode(&s.value).ok()?.to_string();

    // Must be different from original (actually encoded)
    if decoded == s.value {
        return None;
    }

    // Reject if too short
    if decoded.trim().len() < 4 {
        return None;
    }

    // Classify before moving
    let kind = classify_decoded_string(&decoded);

    Some(ExtractedString {
        value: decoded,
        data_offset: s.data_offset,
        section: s.section.clone(),
        method: StringMethod::UrlDecode,
        kind,
        library: None,
        fragments: None,
    })
}

/// Decode unicode escape sequences from a list of extracted strings.
///
/// Returns a vector of newly decoded strings with `StringMethod::UnicodeEscapeDecode`.
pub fn decode_unicode_escape_strings(strings: &[ExtractedString]) -> Vec<ExtractedString> {
    strings
        .iter()
        .filter(|s| s.kind == StringKind::UnicodeEscaped || is_likely_unicode_escaped(&s.value))
        .filter_map(|s| decode_unicode_escape_string(s))
        .collect()
}

/// Attempt to decode a single unicode-escaped string.
fn decode_unicode_escape_string(s: &ExtractedString) -> Option<ExtractedString> {
    // Must contain escape sequences
    if !s.value.contains("\\x") && !s.value.contains("\\u") && !s.value.contains("\\U") {
        return None;
    }

    let decoded = decode_unicode_escapes(&s.value)?;

    // Must be different from original
    if decoded == s.value {
        return None;
    }

    // Reject if too short
    if decoded.trim().len() < 4 {
        return None;
    }

    // Classify before moving
    let kind = classify_decoded_string(&decoded);

    Some(ExtractedString {
        value: decoded,
        data_offset: s.data_offset,
        section: s.section.clone(),
        method: StringMethod::UnicodeEscapeDecode,
        kind,
        library: None,
        fragments: None,
    })
}

/// Decode unicode escape sequences in a string.
///
/// Handles: \xHH, \uHHHH, \UHHHHHHHH
fn decode_unicode_escapes(s: &str) -> Option<String> {
    let mut result = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    let mut changed = false;

    while let Some(ch) = chars.next() {
        if ch == '\\' {
            match chars.peek() {
                Some('x') => {
                    // \xHH - 2 hex digits
                    chars.next(); // consume 'x'
                    if let Some(decoded_char) = parse_hex_escape(&mut chars, 2) {
                        result.push(decoded_char);
                        changed = true;
                        continue;
                    }
                    result.push('\\');
                    result.push('x');
                }
                Some('u') => {
                    // \uHHHH - 4 hex digits
                    chars.next(); // consume 'u'
                    if let Some(decoded_char) = parse_hex_escape(&mut chars, 4) {
                        result.push(decoded_char);
                        changed = true;
                        continue;
                    }
                    result.push('\\');
                    result.push('u');
                }
                Some('U') => {
                    // \UHHHHHHHH - 8 hex digits
                    chars.next(); // consume 'U'
                    if let Some(decoded_char) = parse_hex_escape(&mut chars, 8) {
                        result.push(decoded_char);
                        changed = true;
                        continue;
                    }
                    result.push('\\');
                    result.push('U');
                }
                _ => result.push(ch),
            }
        } else {
            result.push(ch);
        }
    }

    if changed {
        Some(result)
    } else {
        None
    }
}

/// Parse a hex escape sequence of the specified length.
fn parse_hex_escape(chars: &mut std::iter::Peekable<std::str::Chars>, len: usize) -> Option<char> {
    let hex_str: String = chars.take(len).collect();
    if hex_str.len() != len {
        return None;
    }

    let code_point = u32::from_str_radix(&hex_str, 16).ok()?;
    char::from_u32(code_point)
}

/// Check if a string looks like base64-encoded data.
fn is_likely_base64(s: &str) -> bool {
    if s.len() < MIN_BASE64_LENGTH {
        return false;
    }

    let base64_chars = s
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '+' || *c == '/' || *c == '=')
        .count();

    // If >= 80% base64 characters, likely encoded
    (base64_chars as f32 / s.len() as f32) >= 0.8
}

/// Check if a string looks like hex-encoded data.
fn is_likely_hex(s: &str) -> bool {
    if s.len() < MIN_HEX_LENGTH || s.len() % 2 != 0 {
        return false;
    }

    s.chars().all(|c| c.is_ascii_hexdigit())
}

/// Check if a string looks like URL-encoded data.
fn is_likely_url_encoded(s: &str) -> bool {
    if !s.contains('%') {
        return false;
    }

    // Count valid %XX sequences
    let mut percent_count = 0;
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if bytes[i + 1].is_ascii_hexdigit() && bytes[i + 2].is_ascii_hexdigit() {
                percent_count += 1;
                i += 3;
                continue;
            }
        }
        i += 1;
    }

    // At least 3 valid %XX sequences
    percent_count >= 3
}

/// Check if a string looks like it has unicode escape sequences.
fn is_likely_unicode_escaped(s: &str) -> bool {
    s.contains("\\x") || s.contains("\\u") || s.contains("\\U")
}

/// Classify a decoded string into a StringKind.
fn classify_decoded_string(_s: &str) -> StringKind {
    // Reuse stng's classification if available
    // For now, just return Const - this will be refined by DISSECT
    StringKind::Const
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_base64_decode() {
        let input = ExtractedString {
            value: "SGVsbG8gV29ybGQh".to_string(), // "Hello World!"
            data_offset: 0,
            section: None,
            method: StringMethod::RawScan,
            kind: StringKind::Base64,
            library: None,
            fragments: None,
        };

        let result = decode_base64_string(&input).unwrap();
        assert_eq!(result.value, "Hello World!");
        assert_eq!(result.method, StringMethod::Base64Decode);
    }

    #[test]
    fn test_hex_decode() {
        let input = ExtractedString {
            value: "48656c6c6f20576f726c6421".to_string(), // "Hello World!"
            data_offset: 0,
            section: None,
            method: StringMethod::RawScan,
            kind: StringKind::HexEncoded,
            library: None,
            fragments: None,
        };

        let result = decode_hex_string(&input).unwrap();
        assert_eq!(result.value, "Hello World!");
        assert_eq!(result.method, StringMethod::HexDecode);
    }

    #[test]
    fn test_url_decode() {
        let input = ExtractedString {
            value: "Hello%20World%21%20%2B%20More".to_string(), // "Hello World! + More"
            data_offset: 0,
            section: None,
            method: StringMethod::RawScan,
            kind: StringKind::UrlEncoded,
            library: None,
            fragments: None,
        };

        let result = decode_url_string(&input).unwrap();
        assert_eq!(result.value, "Hello World! + More");
        assert_eq!(result.method, StringMethod::UrlDecode);
    }

    #[test]
    fn test_unicode_escape_decode() {
        let input = ExtractedString {
            value: "\\x48\\x65\\x6c\\x6c\\x6f".to_string(), // "Hello"
            data_offset: 0,
            section: None,
            method: StringMethod::RawScan,
            kind: StringKind::UnicodeEscaped,
            library: None,
            fragments: None,
        };

        let result = decode_unicode_escape_string(&input).unwrap();
        assert_eq!(result.value, "Hello");
        assert_eq!(result.method, StringMethod::UnicodeEscapeDecode);
    }

    #[test]
    fn test_is_likely_base64() {
        assert!(is_likely_base64("SGVsbG8gV29ybGQhCg=="));
        assert!(!is_likely_base64("not base64!"));
        assert!(!is_likely_base64("short"));
    }

    #[test]
    fn test_is_likely_hex() {
        assert!(is_likely_hex("48656c6c6f20576f726c6421"));
        assert!(!is_likely_hex("not hex!"));
        assert!(!is_likely_hex("48656c6c6f2")); // odd length
    }
}
