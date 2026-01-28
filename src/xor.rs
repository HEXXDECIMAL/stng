//! XOR string detection for finding obfuscated strings in malware.
//!
//! This module detects strings that have been XOR'd with a single-byte key,
//! a common obfuscation technique in malware. Uses Aho-Corasick for efficient
//! single-pass multi-pattern matching.

use crate::go::classify_string;
use crate::{ExtractedString, StringKind, StringMethod};
use aho_corasick::AhoCorasick;
use std::collections::HashSet;
use std::sync::OnceLock;

/// Minimum length for XOR-decoded strings (default).
pub const DEFAULT_XOR_MIN_LENGTH: usize = 10;

/// XOR keys to skip because they produce too many false positives.
/// 0x20 (space) just flips letter case, causing "GOROOT OBJECT" to become "gorootOBJECT".
const SKIP_XOR_KEYS: &[u8] = &[0x20];

/// Minimal high-signal patterns for XOR detection.
/// These short patterns catch a wide variety of malware indicators:
/// - `://` catches all URL schemes (http://, https://, ftp://, etc.)
/// - `/bin` catches Unix shell paths (/bin/sh, /bin/bash)
/// - `C:\` catches Windows paths
/// - `Mozilla` catches user agent strings
/// - `.exe` catches Windows executables (cmd.exe, powershell.exe)
/// - `passw` catches password/passwd variants
const XOR_PATTERNS: &[&[u8]] = &[b"://", b"/bin", b"C:\\", b"Mozilla", b".exe", b"passw"];

/// Metadata for a pattern in the Aho-Corasick automaton.
#[derive(Clone)]
struct PatternInfo {
    key: u8,
    is_wide: bool,
}

/// Build and cache the ASCII-only Aho-Corasick automaton.
fn get_automaton_ascii() -> &'static (AhoCorasick, Vec<PatternInfo>) {
    static CACHE: OnceLock<(AhoCorasick, Vec<PatternInfo>)> = OnceLock::new();
    CACHE.get_or_init(|| {
        let mut patterns: Vec<Vec<u8>> = Vec::new();
        let mut pattern_info: Vec<PatternInfo> = Vec::new();

        for key in 1u8..=255u8 {
            if SKIP_XOR_KEYS.contains(&key) {
                continue;
            }

            for prefix in XOR_PATTERNS {
                let xored: Vec<u8> = prefix.iter().map(|b| b ^ key).collect();
                patterns.push(xored);
                pattern_info.push(PatternInfo {
                    key,
                    is_wide: false,
                });
            }
        }

        let ac = AhoCorasick::new(&patterns).expect("Failed to build automaton");
        (ac, pattern_info)
    })
}

/// Build and cache the automaton with both ASCII and wide (UTF-16LE) patterns.
/// Used for PE binaries where wide strings are common.
fn get_automaton_with_wide() -> &'static (AhoCorasick, Vec<PatternInfo>) {
    static CACHE: OnceLock<(AhoCorasick, Vec<PatternInfo>)> = OnceLock::new();
    CACHE.get_or_init(|| {
        let mut patterns: Vec<Vec<u8>> = Vec::new();
        let mut pattern_info: Vec<PatternInfo> = Vec::new();

        for key in 1u8..=255u8 {
            if SKIP_XOR_KEYS.contains(&key) {
                continue;
            }

            for prefix in XOR_PATTERNS {
                // ASCII pattern
                let xored: Vec<u8> = prefix.iter().map(|b| b ^ key).collect();
                patterns.push(xored);
                pattern_info.push(PatternInfo {
                    key,
                    is_wide: false,
                });

                // Wide (UTF-16LE) pattern
                let wide_xored: Vec<u8> = prefix.iter().flat_map(|&b| [b ^ key, key]).collect();
                patterns.push(wide_xored);
                pattern_info.push(PatternInfo { key, is_wide: true });
            }
        }

        let ac = AhoCorasick::new(&patterns).expect("Failed to build automaton");
        (ac, pattern_info)
    })
}

/// Extract XOR-encoded strings from binary data.
///
/// Uses Aho-Corasick for efficient single-pass scanning of all XOR'd patterns.
///
/// # Arguments
/// * `data` - Binary data to scan
/// * `min_length` - Minimum string length
/// * `scan_wide` - Whether to scan for UTF-16LE (wide) patterns (use for PE binaries)
pub fn extract_xor_strings(
    data: &[u8],
    min_length: usize,
    scan_wide: bool,
) -> Vec<ExtractedString> {
    let (ac, pattern_info) = if scan_wide {
        get_automaton_with_wide()
    } else {
        get_automaton_ascii()
    };
    let mut results = Vec::new();
    let mut seen: HashSet<(u64, String)> = HashSet::new();

    // Single pass through the data using overlapping matches
    for mat in ac.find_overlapping_iter(data) {
        let info = &pattern_info[mat.pattern().as_usize()];
        let pos = mat.start();

        if info.is_wide {
            if let Some((decoded, start, _end)) =
                expand_xor_wide_string(data, pos, info.key, min_length)
            {
                if let Some(kind) = classify_xor_string(&decoded) {
                    let offset = start as u64;
                    if seen.insert((offset, decoded.clone())) {
                        results.push(ExtractedString {
                            value: format!("XOR(0x{:02X}):16LE: {}", info.key, decoded),
                            data_offset: offset,
                            section: None,
                            method: StringMethod::XorDecode,
                            kind,
                            library: None,
                        });
                    }
                }
            }
        } else if let Some((decoded, start, _end)) =
            expand_xor_string(data, pos, info.key, min_length)
        {
            if let Some(kind) = classify_xor_string(&decoded) {
                let offset = start as u64;
                if seen.insert((offset, decoded.clone())) {
                    results.push(ExtractedString {
                        value: format!("XOR(0x{:02X}): {}", info.key, decoded),
                        data_offset: offset,
                        section: None,
                        method: StringMethod::XorDecode,
                        kind,
                        library: None,
                    });
                }
            }
        }
    }

    // Also scan for IP addresses and hostnames
    scan_dotted_patterns(data, min_length, &mut results, &mut seen);

    results
}

/// Extract strings encrypted with multi-byte XOR keys detected by radare2 analysis.
///
/// Uses high-confidence keys from `r2::verify_xor_keys()` to decrypt data by cycling
/// through key bytes. Only attempts decryption with HIGH confidence keys to minimize
/// false positives.
///
/// # Arguments
/// * `data` - Binary data to scan
/// * `keys` - XOR key candidates from radare2 analysis
/// * `min_length` - Minimum string length
pub fn extract_multikey_xor_strings(
    data: &[u8],
    keys: &[crate::r2::XorKeyInfo],
    min_length: usize,
) -> Vec<ExtractedString> {
    use crate::r2::XorConfidence;
    let mut results = Vec::new();
    let mut seen: HashSet<(u64, String)> = HashSet::new();

    // Only use high-confidence keys for decryption attempts
    for key_info in keys
        .iter()
        .filter(|k| matches!(k.confidence, XorConfidence::High))
    {
        let key_bytes = key_info.key.as_bytes();

        // Scan through data looking for potential encrypted strings
        for start in 0..data.len().saturating_sub(min_length) {
            // Decode using multi-byte key (cycling through key bytes)
            let max_decode_len = (min_length * 4).min(data.len() - start);
            let decoded: Vec<u8> = data[start..start + max_decode_len]
                .iter()
                .enumerate()
                .map(|(i, &byte)| byte ^ key_bytes[i % key_bytes.len()])
                .collect();

            // Try to find a valid string in the decoded data
            if let Ok(decoded_str) = String::from_utf8(decoded.clone()) {
                if let Some((valid_str, _, _)) = find_meaningful_substring(&decoded_str, min_length)
                {
                    if let Some(kind) = classify_xor_string(valid_str) {
                        let offset = start as u64;
                        if seen.insert((offset, valid_str.to_string())) {
                            let key_preview = if key_info.key.len() > 8 {
                                format!("{}...", &key_info.key[..8])
                            } else {
                                key_info.key.clone()
                            };

                            results.push(ExtractedString {
                                value: format!("XOR(key:{}): {}", key_preview, valid_str),
                                data_offset: offset,
                                section: None,
                                method: StringMethod::XorDecode,
                                kind,
                                library: None,
                            });
                        }
                    }
                }
            }
        }
    }

    results
}

/// Find the longest meaningful substring in decoded data.
///
/// Scans for regions of printable ASCII and validates them using the same
/// heuristics as single-byte XOR detection.
fn find_meaningful_substring(s: &str, min_length: usize) -> Option<(&str, usize, usize)> {
    let bytes = s.as_bytes();
    for start in 0..bytes.len().saturating_sub(min_length) {
        for end in (start + min_length..=bytes.len()).rev() {
            if let Ok(substr) = std::str::from_utf8(&bytes[start..end]) {
                if is_meaningful_string(substr) {
                    return Some((substr, start, end));
                }
            }
        }
    }
    None
}

/// Scan for XOR'd IP addresses and hostnames.
/// Uses memchr for fast scanning of XOR'd '.' bytes, then validates surroundings.
fn scan_dotted_patterns(
    data: &[u8],
    min_length: usize,
    results: &mut Vec<ExtractedString>,
    seen: &mut HashSet<(u64, String)>,
) {
    for key in 1u8..=255u8 {
        if SKIP_XOR_KEYS.contains(&key) {
            continue;
        }

        let xored_dot = b'.' ^ key;

        for pos in memchr::memchr_iter(xored_dot, data) {
            if pos == 0 || pos + 1 >= data.len() {
                continue;
            }

            let prev = data[pos - 1] ^ key;
            let next = data[pos + 1] ^ key;

            // Check for IP address (digits around dot)
            if prev.is_ascii_digit() && next.is_ascii_digit() {
                if let Some((ip, start, _end)) = extract_ip_at_dot(data, pos, key) {
                    if ip.len() >= min_length.saturating_sub(2) {
                        let offset = start as u64;
                        if seen.insert((offset, ip.clone())) {
                            results.push(ExtractedString {
                                value: format!("XOR(0x{:02X}): {}", key, ip),
                                data_offset: offset,
                                section: None,
                                method: StringMethod::XorDecode,
                                kind: StringKind::IP,
                                library: None,
                            });
                        }
                    }
                }

                if let Some((ip_port, start, _end)) = extract_ip_port_at_pos(data, pos, key) {
                    if ip_port.len() >= min_length {
                        let offset = start as u64;
                        if seen.insert((offset, ip_port.clone())) {
                            results.push(ExtractedString {
                                value: format!("XOR(0x{:02X}): {}", key, ip_port),
                                data_offset: offset,
                                section: None,
                                method: StringMethod::XorDecode,
                                kind: StringKind::IPPort,
                                library: None,
                            });
                        }
                    }
                }
            }
            // Check for hostname (alphanumeric around dot, like evil.com)
            else if prev.is_ascii_alphanumeric() && next.is_ascii_alphanumeric() {
                if let Some((hostname, start, _end)) =
                    extract_hostname_at_dot(data, pos, key, min_length)
                {
                    let offset = start as u64;
                    if seen.insert((offset, hostname.clone())) {
                        results.push(ExtractedString {
                            value: format!("XOR(0x{:02X}): {}", key, hostname),
                            data_offset: offset,
                            section: None,
                            method: StringMethod::XorDecode,
                            kind: StringKind::Hostname,
                            library: None,
                        });
                    }
                }
            }
        }
    }
}

/// Extract a hostname starting from a dot position.
fn extract_hostname_at_dot(
    data: &[u8],
    dot_pos: usize,
    key: u8,
    min_length: usize,
) -> Option<(String, usize, usize)> {
    // Expand backward
    let mut start = dot_pos;
    while start > 0 {
        let decoded = data[start - 1] ^ key;
        if decoded.is_ascii_alphanumeric() || decoded == b'-' || decoded == b'.' {
            start -= 1;
        } else {
            break;
        }
    }

    // Expand forward
    let mut end = dot_pos + 1;
    while end < data.len() {
        let decoded = data[end] ^ key;
        if decoded.is_ascii_alphanumeric() || decoded == b'-' || decoded == b'.' {
            end += 1;
        } else {
            break;
        }
    }

    if end - start < min_length {
        return None;
    }

    let decoded: Vec<u8> = data[start..end].iter().map(|b| b ^ key).collect();
    let hostname = String::from_utf8(decoded).ok()?;

    // Basic validation: must have at least one dot
    if !hostname.contains('.') {
        return None;
    }

    // Skip common false positives
    if hostname.starts_with('.') || hostname.ends_with('.') || hostname.contains("..") {
        return None;
    }

    // Must have at least 2 parts (e.g., "evil.com")
    let parts: Vec<&str> = hostname.split('.').collect();
    if parts.len() < 2 {
        return None;
    }

    // Only accept .com TLD for single-byte XOR (too many false positives otherwise)
    let tld = parts.last()?;
    if !tld.eq_ignore_ascii_case("com") {
        return None;
    }

    // Reject hostnames with uppercase letters - real hostnames are lowercase
    if hostname.chars().any(|c| c.is_ascii_uppercase()) {
        return None;
    }

    // Reject hostnames with digits in domain parts (before TLD)
    // Real domains rarely have digits except in subdomains like "ns1" or "cdn2"
    for (i, part) in parts.iter().enumerate() {
        if i == parts.len() - 1 {
            continue; // Skip TLD
        }
        if part.chars().any(|c| c.is_ascii_digit()) {
            return None;
        }
    }

    // Domain part (before TLD) should have reasonable chars, not just repeated
    let domain = parts.first()?;
    if domain.len() < 2 {
        return None;
    }

    // Reject if domain is just repeated characters (like "zzz" or "nnn")
    let first_char = domain.chars().next()?;
    if domain.chars().all(|c| c == first_char) {
        return None;
    }

    // Reject hostnames with too many repeated characters (like "ccccccT.cc")
    let unique_chars: std::collections::HashSet<char> =
        hostname.chars().filter(|&c| c != '.').collect();
    let non_dot_len = hostname.chars().filter(|&c| c != '.').count();
    if non_dot_len > 6 && unique_chars.len() * 3 < non_dot_len {
        return None;
    }

    // Reject runs of 4+ consecutive identical characters (like "moooooob" or "lmmmmmj")
    let mut prev_char = '\0';
    let mut run_len = 1;
    for c in hostname.chars() {
        if c == prev_char {
            run_len += 1;
            if run_len >= 4 {
                return None;
            }
        } else {
            prev_char = c;
            run_len = 1;
        }
    }

    // Reject segments starting or ending with hyphen (invalid DNS)
    for part in &parts {
        if part.starts_with('-') || part.ends_with('-') {
            return None;
        }
    }

    // Reject if any single character dominates (>40% of non-dot chars)
    if non_dot_len >= 8 {
        for &c in &unique_chars {
            let count = hostname.chars().filter(|&x| x == c).count();
            if count * 100 / non_dot_len > 40 {
                return None;
            }
        }
    }

    Some((hostname, start, end))
}

/// Maximum expansion distance in each direction from match position.
const MAX_EXPAND_DISTANCE: usize = 200;

/// Expand outward from a match position to find the full XOR'd string.
fn expand_xor_string(
    data: &[u8],
    match_pos: usize,
    key: u8,
    min_length: usize,
) -> Option<(String, usize, usize)> {
    let min_start = match_pos.saturating_sub(MAX_EXPAND_DISTANCE);
    let max_end = (match_pos + MAX_EXPAND_DISTANCE).min(data.len());

    // Expand backward, but stop if we hit a low-entropy region (padding artifacts)
    let mut start = match_pos;
    let mut recent_backward: [u8; 8] = [0; 8];
    let mut backward_idx = 0;
    while start > min_start {
        let decoded = data[start - 1] ^ key;
        if !is_printable_char(decoded) {
            break;
        }
        // Track recent chars to detect low-entropy regions
        recent_backward[backward_idx % 8] = decoded;
        backward_idx += 1;
        if backward_idx >= 8 {
            let unique: HashSet<u8> = recent_backward.iter().copied().collect();
            if unique.len() <= 2 {
                // We've hit a low-entropy region - stop expansion
                break;
            }
        }
        start -= 1;
    }

    // Expand forward with same low-entropy detection
    let mut end = match_pos;
    let mut recent_forward: [u8; 8] = [0; 8];
    let mut forward_idx = 0;
    while end < max_end {
        let decoded = data[end] ^ key;
        if !is_printable_char(decoded) {
            break;
        }
        recent_forward[forward_idx % 8] = decoded;
        forward_idx += 1;
        if forward_idx >= 8 {
            let unique: HashSet<u8> = recent_forward.iter().copied().collect();
            if unique.len() <= 2 {
                // Stop expansion but don't backtrack - let trim_low_entropy handle the suffix
                break;
            }
        }
        end += 1;
    }

    if end - start < min_length {
        return None;
    }

    let decoded: Vec<u8> = data[start..end].iter().map(|b| b ^ key).collect();
    let s = String::from_utf8(decoded).ok()?;

    if s.len() < min_length {
        return None;
    }

    // Trim low-entropy prefix/suffix (common XOR artifact from null padding)
    let (trimmed, trim_start) = trim_low_entropy(&s);
    let new_start = start + trim_start;
    let trimmed_end = new_start + trimmed.len();

    if is_meaningful_string(trimmed) {
        Some((trimmed.to_string(), new_start, trimmed_end))
    } else if is_meaningful_string(&s) {
        // Fallback: try with untrimmed if trimmed fails
        Some((s, start, end))
    } else {
        None
    }
}

/// Trim low-entropy prefix/suffix from a string (XOR artifacts from padding).
/// Returns the trimmed string slice and the number of bytes trimmed from the start.
fn trim_low_entropy(s: &str) -> (&str, usize) {
    let bytes = s.as_bytes();
    if bytes.len() < 4 {
        return (s, 0);
    }

    // Trim leading repeated characters (common XOR artifact from null padding)
    let mut start = 0;
    let first_byte = bytes[0];
    while start < bytes.len() && bytes[start] == first_byte {
        start += 1;
    }
    // Only trim if we found a run of 2+ identical chars
    if start < 2 {
        start = 0;
    }

    // Trim trailing repeated characters
    let mut end = bytes.len();
    if end > start {
        let last_byte = bytes[end - 1];
        while end > start && bytes[end - 1] == last_byte {
            end -= 1;
        }
        // Only trim if we found a run of 2+ identical chars
        if bytes.len() - end < 2 {
            end = bytes.len();
        }
    }

    if start >= end || end - start < 4 {
        return (s, 0);
    }

    (std::str::from_utf8(&bytes[start..end]).unwrap_or(s), start)
}

/// Expand a UTF-16LE XOR'd string from a match position.
fn expand_xor_wide_string(
    data: &[u8],
    match_pos: usize,
    key: u8,
    min_length: usize,
) -> Option<(String, usize, usize)> {
    let mut start = match_pos;
    while start >= 2 {
        let lo = data[start - 2] ^ key;
        let hi = data[start - 1] ^ key;
        if hi != 0 || !is_printable_char(lo) {
            break;
        }
        start -= 2;
    }

    let mut end = match_pos;
    while end + 1 < data.len() {
        let lo = data[end] ^ key;
        let hi = data[end + 1] ^ key;
        if hi != 0 || !is_printable_char(lo) {
            break;
        }
        end += 2;
    }

    let byte_len = end - start;
    if byte_len < min_length * 2 {
        return None;
    }

    let mut decoded = String::with_capacity(byte_len / 2);
    let mut i = start;
    while i + 1 < end {
        let lo = data[i] ^ key;
        decoded.push(lo as char);
        i += 2;
    }

    if is_meaningful_string(&decoded) {
        Some((decoded, start, end))
    } else {
        None
    }
}

/// Try to extract a full IP address starting from a dot position.
fn extract_ip_at_dot(data: &[u8], dot_pos: usize, key: u8) -> Option<(String, usize, usize)> {
    let mut start = dot_pos;
    let mut dots_before = 0;
    while start > 0 {
        let decoded = data[start - 1] ^ key;
        if decoded == b'.' {
            dots_before += 1;
            if dots_before > 3 {
                break;
            }
        } else if !decoded.is_ascii_digit() {
            break;
        }
        start -= 1;
    }

    let mut end = dot_pos + 1;
    let mut dots_after = 0;
    while end < data.len() {
        let decoded = data[end] ^ key;
        if decoded == b'.' {
            dots_after += 1;
            if dots_after > 3 {
                break;
            }
        } else if !decoded.is_ascii_digit() {
            break;
        }
        end += 1;
    }

    let decoded: Vec<u8> = data[start..end].iter().map(|b| b ^ key).collect();
    let ip_str = String::from_utf8(decoded).ok()?;

    if is_valid_ip(&ip_str) {
        Some((ip_str, start, end))
    } else {
        None
    }
}

/// Try to extract IP:port starting from a dot position in the IP.
fn extract_ip_port_at_pos(data: &[u8], dot_pos: usize, key: u8) -> Option<(String, usize, usize)> {
    // First find the IP part
    let mut start = dot_pos;
    let mut dots_before = 0;
    while start > 0 {
        let decoded = data[start - 1] ^ key;
        if decoded == b'.' {
            dots_before += 1;
            if dots_before > 3 {
                break;
            }
        } else if !decoded.is_ascii_digit() {
            break;
        }
        start -= 1;
    }

    // Find end of IP and check for colon
    let mut end = dot_pos + 1;
    let mut dots_after = 0;
    while end < data.len() {
        let decoded = data[end] ^ key;
        if decoded == b'.' {
            dots_after += 1;
            if dots_after > 3 {
                break;
            }
        } else if decoded == b':' {
            // Found colon - now look for port
            end += 1;
            while end < data.len() {
                let d = data[end] ^ key;
                if !d.is_ascii_digit() {
                    break;
                }
                end += 1;
            }
            break;
        } else if !decoded.is_ascii_digit() {
            break;
        }
        end += 1;
    }

    let decoded: Vec<u8> = data[start..end].iter().map(|b| b ^ key).collect();
    let ip_port_str = String::from_utf8(decoded).ok()?;

    // Validate IP:port format
    if let Some((ip, port)) = ip_port_str.rsplit_once(':') {
        if is_valid_ip(ip) && is_valid_port(port) {
            return Some((ip_port_str, start, end));
        }
    }

    None
}

fn is_printable_char(b: u8) -> bool {
    b.is_ascii_graphic() || b == b' ' || b == b'\t'
}

/// Check if a string looks meaningful (not random garbage).
/// This is STRICT for XOR detection - we want high confidence, low false positives.
fn is_meaningful_string(s: &str) -> bool {
    if s.is_empty() {
        return false;
    }

    let len = s.len();
    let mut alpha = 0usize;
    let mut digit = 0usize;
    let mut vowel = 0usize;
    let mut upper = 0usize;
    let mut lower = 0usize;
    let mut punct = 0usize;

    for c in s.chars() {
        if c.is_ascii_alphabetic() {
            alpha += 1;
            if c.is_ascii_uppercase() {
                upper += 1;
            } else {
                lower += 1;
            }
            if matches!(c.to_ascii_lowercase(), 'a' | 'e' | 'i' | 'o' | 'u') {
                vowel += 1;
            }
        } else if c.is_ascii_digit() {
            digit += 1;
        } else if c.is_ascii_punctuation() {
            punct += 1;
        }
    }

    let alnum = alpha + digit;

    if len > 0 && alnum * 100 / len < 60 {
        return false;
    }

    if alpha > 5 {
        let vowel_ratio = vowel * 100 / alpha;
        if vowel_ratio < 15 {
            return false;
        }

        if upper > 0 && lower == 0 && alpha > 6 && punct == 0 && digit == 0 {
            return false;
        }

        if lower > 0 && upper == 0 && vowel == 0 && alpha > 4 {
            return false;
        }
    }

    let unique: HashSet<char> = s.chars().collect();
    if unique.len() * 3 < len && len > 10 {
        return false;
    }

    let backslash_count = s.chars().filter(|&c| c == '\\').count();
    if backslash_count > 3 && backslash_count * 4 > len {
        return false;
    }

    true
}

fn is_valid_ip(s: &str) -> bool {
    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() != 4 {
        return false;
    }

    let mut octets: Vec<u16> = Vec::with_capacity(4);
    for part in &parts {
        match part.parse::<u16>() {
            Ok(n) if n <= 255 => octets.push(n),
            _ => return false,
        }
        // Reject leading zeros (e.g., "01.02.03.04")
        if part.len() > 1 && part.starts_with('0') {
            return false;
        }
    }

    // Reject x.0.0.0 patterns
    if octets.len() == 4 && octets[1] == 0 && octets[2] == 0 && octets[3] == 0 {
        return false;
    }

    // Reject localhost and reserved
    if s == "127.0.0.1" || s == "0.0.0.0" || s.starts_with("127.") {
        return false;
    }

    // Reject if first octet is 0 (0.x.x.x is not valid for hosts)
    if octets[0] == 0 {
        return false;
    }

    // Reject if first octet < 10 (very low octets are usually XOR artifacts, not real C2)
    if octets[0] < 10 {
        return false;
    }

    // Reject if all four octets are the same (clear XOR artifact like 182.182.182.182)
    if octets[0] == octets[1] && octets[1] == octets[2] && octets[2] == octets[3] {
        return false;
    }

    // Reject if .0 appears in first or last octet (only allow in middle two)
    if octets[0] == 0 || octets[3] == 0 {
        return false;
    }

    true
}

fn is_valid_port(s: &str) -> bool {
    matches!(s.parse::<u32>(), Ok(n) if n > 0 && n <= 65535)
}

/// Keywords that indicate credential/sensitive data when XOR-encoded.
const CREDENTIAL_KEYWORDS: &[&str] = &[
    "password",
    "passwd",
    "pwd",
    "username",
    "user",
    "secret",
    "token",
    "apikey",
    "api_key",
    "bearer",
    "auth",
    "credential",
    "private",
    "key",
    "admin",
    "root",
];

/// Classify an XOR-decoded string. Returns None if it doesn't look interesting.
fn classify_xor_string(s: &str) -> Option<StringKind> {
    let lower = s.to_ascii_lowercase();

    for keyword in CREDENTIAL_KEYWORDS {
        if lower.contains(keyword) {
            return Some(StringKind::SuspiciousPath);
        }
    }

    let kind = classify_string(s);

    match kind {
        StringKind::IP | StringKind::IPPort => Some(kind),
        StringKind::Url => Some(kind),
        StringKind::ShellCmd => Some(kind),
        StringKind::SuspiciousPath => Some(kind),
        StringKind::Path => {
            let is_unix_path = s.contains('/')
                && (s.starts_with('/') || s.starts_with("./") || s.starts_with("../"));
            let is_windows_path = s.contains('\\') && s.len() > 3 && s.chars().nth(1) == Some(':');
            if is_unix_path || is_windows_path {
                Some(kind)
            } else {
                None
            }
        }
        StringKind::Registry => Some(kind),
        StringKind::Base64 => Some(kind),
        _ => {
            // Generic fallback: longer strings with spaces that look like natural text
            // This catches user agents, error messages, config values, etc.
            if s.len() >= 30 && s.contains(' ') && looks_like_text(s) {
                Some(StringKind::Const)
            } else {
                None
            }
        }
    }
}

/// Check if a string looks like natural/structured text (not random garbage).
/// Used for generic XOR classification of longer strings with spaces.
fn looks_like_text(s: &str) -> bool {
    let words: Vec<&str> = s.split_whitespace().collect();

    // Need at least 3 words
    if words.len() < 3 {
        return false;
    }

    // Count character types
    let mut alpha = 0usize;
    let mut digit = 0usize;
    let mut space = 0usize;

    for c in s.chars() {
        if c.is_ascii_alphabetic() {
            alpha += 1;
        } else if c.is_ascii_digit() {
            digit += 1;
        } else if c == ' ' {
            space += 1;
        }
    }

    let len = s.len();

    // Must be mostly alphanumeric + spaces (at least 80%)
    let text_chars = alpha + digit + space;
    if text_chars * 100 / len < 80 {
        return false;
    }

    // Alphabetic chars should dominate (at least 50% of non-space)
    let non_space = len - space;
    if non_space > 0 && alpha * 100 / non_space < 50 {
        return false;
    }

    // Reasonable word lengths (average 2-15 chars)
    let avg_word_len = non_space / words.len().max(1);
    if !(2..=15).contains(&avg_word_len) {
        return false;
    }

    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_valid_ip() {
        // Valid C2-like IPs
        assert!(is_valid_ip("192.168.1.1"));
        assert!(is_valid_ip("10.0.0.1"));
        assert!(is_valid_ip("45.33.32.156"));
        assert!(is_valid_ip("185.199.108.153"));

        // Invalid: out of range
        assert!(!is_valid_ip("256.1.1.1"));

        // Invalid: localhost/reserved
        assert!(!is_valid_ip("127.0.0.1"));
        assert!(!is_valid_ip("0.0.0.0"));

        // Invalid: x.0.0.0 pattern
        assert!(!is_valid_ip("1.0.0.0"));

        // Invalid: first octet is 0
        assert!(!is_valid_ip("0.7.2.126"));

        // Invalid: first octet < 10 (likely XOR artifact)
        assert!(!is_valid_ip("4.3.4.32"));

        // Invalid: all same octets (clear XOR artifact)
        assert!(!is_valid_ip("182.182.182.182"));
        assert!(!is_valid_ip("8.8.8.8")); // OK to reject popular DNS
        assert!(!is_valid_ip("1.1.1.1"));

        // Invalid: last octet is 0
        assert!(!is_valid_ip("192.168.1.0"));
    }

    #[test]
    fn test_is_valid_port() {
        assert!(is_valid_port("80"));
        assert!(is_valid_port("443"));
        assert!(!is_valid_port("0"));
        assert!(!is_valid_port("65536"));
    }

    #[test]
    fn test_is_meaningful_string() {
        assert!(is_meaningful_string("http://example.com"));
        assert!(is_meaningful_string("/etc/passwd"));
        assert!(!is_meaningful_string(""));
        assert!(!is_meaningful_string("XYZQWFGH")); // No vowels
    }

    fn make_xor_test_data(plaintext: &[u8], key: u8, offset: usize) -> Vec<u8> {
        let fill_byte = 0x01 ^ key;
        let mut data = vec![fill_byte; 100];
        for (i, b) in plaintext.iter().enumerate() {
            data[offset + i] = b ^ key;
        }
        data
    }

    #[test]
    fn test_xor_url_detection() {
        let plaintext = b"http://evil.com";
        let key: u8 = 0x42;
        let data = make_xor_test_data(plaintext, key, 20);
        let results = extract_xor_strings(&data, 10, false);
        assert!(
            results.iter().any(|r| r.value.contains("http://evil.com")),
            "Results: {:?}",
            results
        );
    }

    #[test]
    fn test_xor_ip_detection() {
        let plaintext = b"192.168.1.100";
        let key: u8 = 0x5A;
        let data = make_xor_test_data(plaintext, key, 30);
        let results = extract_xor_strings(&data, 8, false);
        assert!(
            results.iter().any(|r| r.value.contains("192.168.1.100")),
            "Results: {:?}",
            results
        );
    }

    #[test]
    fn test_xor_ip_port_detection() {
        let plaintext = b"10.0.0.1:8080";
        let key: u8 = 0x3C;
        let data = make_xor_test_data(plaintext, key, 25);
        let results = extract_xor_strings(&data, 8, false);
        assert!(
            results.iter().any(|r| r.value.contains("10.0.0.1:8080")),
            "IP:port should be detected. Results: {:?}",
            results
        );
    }

    #[test]
    fn test_xor_path_detection() {
        let plaintext = b"/etc/passwd";
        let key: u8 = 0xAB;
        let data = make_xor_test_data(plaintext, key, 10);
        let results = extract_xor_strings(&data, 10, false);
        assert!(
            results.iter().any(|r| r.value.contains("/etc/passwd")),
            "Results: {:?}",
            results
        );
    }

    #[test]
    fn test_xor_password_detection() {
        let plaintext = b"password=secret123";
        let key: u8 = 0x77;
        let data = make_xor_test_data(plaintext, key, 20);
        let results = extract_xor_strings(&data, 10, false);
        assert!(
            results.iter().any(|r| r.value.contains("password")),
            "Results: {:?}",
            results
        );
    }

    #[test]
    fn test_no_false_positives_on_random() {
        let data: Vec<u8> = (0..1000).map(|i| ((i * 7 + 13) % 256) as u8).collect();
        let results = extract_xor_strings(&data, 10, false);
        assert!(results.len() < 10);
    }

    #[test]
    fn test_xor_key_0x20_skipped() {
        // Key 0x20 should be skipped - it just flips case
        let plaintext = b"GOROOT OBJECT";
        let key: u8 = 0x20;
        let data = make_xor_test_data(plaintext, key, 20);
        let results = extract_xor_strings(&data, 6, false);
        // Should not find this as it's a false positive
        assert!(
            !results.iter().any(|r| r.value.contains("XOR(0x20)")),
            "Should skip key 0x20. Results: {:?}",
            results
        );
    }

    #[test]
    fn test_xor_hostname_detection() {
        let plaintext = b"evil.malware.com";
        let key: u8 = 0x55;
        let data = make_xor_test_data(plaintext, key, 20);
        let results = extract_xor_strings(&data, 10, false);
        assert!(
            results.iter().any(|r| r.value.contains("evil.malware.com")),
            "Hostname should be detected. Results: {:?}",
            results
        );
    }

    #[test]
    fn test_mozilla_user_agent_detection() {
        // Simulate the actual Go PE binary scenario:
        // - Lots of 0x00/0x01 padding before the Mozilla pattern
        // - XOR key 0x42
        let key: u8 = 0x42;
        let mozilla = b"Mozilla/5.0 (Windows NT 10.0; Win64; x64) Safari/537.36";

        // Create data with padding (0x00 and 0x01 bytes)
        let mut data = vec![0x00; 50];
        data.extend(std::iter::repeat_n(0x01, 20));
        // Add XOR'd Mozilla string
        for b in mozilla {
            data.push(b ^ key);
        }
        // Add trailing padding
        data.extend(std::iter::repeat_n(0x00, 20));

        let results = extract_xor_strings(&data, 10, false);
        assert!(
            results.iter().any(|r| r.value.contains("Mozilla")),
            "Mozilla user agent should be detected. Results: {:?}",
            results
        );
    }
}
