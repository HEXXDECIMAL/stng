//! String classification and validation for XOR-decoded strings.
//!
//! This module contains pure string utility functions used by the XOR extraction
//! pipeline to validate, classify, and clean decoded strings.

use crate::{ExtractedString, StringKind, StringMethod, go::classify_string};
use aho_corasick::AhoCorasick;
use rayon::prelude::*;
use std::collections::HashSet;
use std::sync::OnceLock;
use super::{MAX_AUTO_DETECT_SIZE, MAX_XOR_SCAN_SIZE, SKIP_XOR_KEYS};
use super::key::{calculate_entropy, is_good_xor_key_candidate, score_xor_key_candidate};
use super::scan::extract_custom_xor_strings;

pub(crate) fn trim_consonant_clusters(s: &str) -> String {
    if s.len() < 8 {
        return s.to_string();
    }

    let chars: Vec<char> = s.chars().collect();
    let mut consonant_run = 0;
    let mut trim_pos = None;

    for (i, &c) in chars.iter().enumerate() {
        if c.is_ascii_alphabetic() {
            let is_vowel = matches!(c.to_ascii_lowercase(), 'a' | 'e' | 'i' | 'o' | 'u');
            if is_vowel {
                consonant_run = 0;
            } else {
                consonant_run += 1;
                // If we hit 4+ consonants in a row, mark this as potential trim point
                if consonant_run >= 4 && trim_pos.is_none() {
                    // Trim before the start of this consonant run
                    trim_pos = Some(i - 3);
                }
            }
        } else {
            // Non-letter resets the count
            consonant_run = 0;
        }
    }

    if let Some(pos) = trim_pos {
        // Make sure we're trimming at a reasonable boundary (at least 10 chars into the string)
        if pos >= 10 {
            return chars[..pos].iter().collect();
        }
    }

    s.to_string()
}

/// Clean trailing garbage from locale strings extracted via XOR decoding.
///
/// Locale strings often have trailing garbage after the last valid locale code.
/// This function trims them to prevent overlaps with adjacent strings.
///
/// Examples:
/// - `hy_AM;be_BY;kk_KZ;ru_RU;uk_UA;ffYztZORL` -> `hy_AM;be_BY;kk_KZ;ru_RU;uk_UA;`
pub(crate) fn clean_locale_trailing_garbage(s: &str) -> String {
    // Find the last valid locale separator (';' or ',')
    if let Some(last_sep) = s.rfind([';', ',']) {
        // Include the separator in the result
        let clean_len = last_sep + 1;
        if clean_len < s.len() {
            return s[..clean_len].to_string();
        }
    }

    // No separator found or nothing to trim
    s.to_string()
}

/// Clean trailing garbage from URLs extracted via XOR decoding.
///
/// URLs often have trailing garbage characters that pass printability checks
/// but aren't part of the actual URL. This function trims them to prevent
/// overlaps with adjacent strings.
///
/// Examples:
/// - `http://46.30.191.141n;uJ` -> `http://46.30.191.141`
/// - `https://evil.com/path?foo=barn;X` -> `https://evil.com/path?foo=bar`
pub(crate) fn clean_url_trailing_garbage(url: &str) -> String {
    // For URLs with embedded IPs: trim after the last IP octet
    if let Some(proto_end) = url.find("://") {
        let after_proto = &url[proto_end + 3..];

        // Check if it starts with an IP address
        if after_proto
            .chars()
            .next()
            .is_some_and(|c| c.is_ascii_digit())
        {
            // Find the end of the IP (last digit of last octet)
            let mut ip_end = 0;
            let mut dots = 0;

            for (i, c) in after_proto.chars().enumerate() {
                if c.is_ascii_digit() {
                    ip_end = i + 1;
                } else if c == '.' {
                    dots += 1;
                    if dots > 3 {
                        break; // Too many dots, not a valid IP
                    }
                } else if c == ':' && dots == 3 {
                    // Port number after IP - find end of port
                    let port_start = i + 1;
                    if let Some(port_end_offset) =
                        after_proto[port_start..].find(|c: char| !c.is_ascii_digit())
                    {
                        ip_end = port_start + port_end_offset;
                    } else {
                        ip_end = after_proto.len();
                    }
                    break;
                } else {
                    // Non-IP character
                    break;
                }
            }

            // If we found a valid IP (3 dots), trim after it
            if dots == 3 && ip_end > 0 {
                let clean_len = proto_end + 3 + ip_end;
                if clean_len < url.len() {
                    return url[..clean_len].to_string();
                }
            }
        } else {
            // Domain-based URL: trim after last alphanumeric/slash/common URL chars
            let valid_url_chars: Vec<usize> = after_proto
                .char_indices()
                .filter(|(_, c)| {
                    c.is_alphanumeric()
                        || matches!(c, '/' | '.' | '-' | '_' | '?' | '=' | '&' | '%' | '#' | '+')
                })
                .map(|(i, _)| i)
                .collect();

            if let Some(&last_valid) = valid_url_chars.last() {
                let clean_len = proto_end + 3 + last_valid + 1;
                if clean_len < url.len() {
                    return url[..clean_len].to_string();
                }
            }
        }
    }

    // No cleanup needed or couldn't parse
    url.to_string()
}

/// Expand a multi-byte XOR'd string from a match position.
/// The key cycles from key[0] at the start of the string, not from file offset 0.
/// Auto-detect XOR key by trying candidate strings from the binary.
///
/// For small files (<512KB), tries the last 5 strings (excluding those with _ or starting with "cstr.")
/// as potential XOR keys and returns the one that produces the most valid decoded strings.
///
/// # Arguments
/// * `data` - Binary data to scan
/// * `candidate_strings` - Pre-extracted strings to use as XOR key candidates
/// * `min_length` - Minimum string length for decoded strings
pub(crate) fn auto_detect_xor_key(
    data: &[u8],
    candidate_strings: &[ExtractedString],
    min_length: usize,
) -> Option<(Vec<u8>, String, u64)> {
    // Only auto-detect for small files
    if data.len() > MAX_AUTO_DETECT_SIZE {
        return None;
    }

    // Find candidate XOR keys by quality scoring.
    // Compute entropy once per candidate (shared by qualification check and scoring).
    let mut candidates_with_score: Vec<(u32, u64, &str)> = candidate_strings
        .iter()
        .filter(|s| !s.value.contains('_') && !s.value.starts_with("cstr."))
        .filter_map(|s| {
            let entropy = calculate_entropy(s.value.as_bytes());
            if is_good_xor_key_candidate(&s.value, entropy) {
                Some((score_xor_key_candidate(&s.value, entropy), s.data_offset, s.value.as_str()))
            } else {
                None
            }
        })
        .collect();

    // Sort by score descending (best candidates first)
    candidates_with_score.sort_by(|a, b| {
        b.0.cmp(&a.0) // Score first (descending)
            .then(b.1.cmp(&a.1)) // Then offset (descending - prefer later strings as tiebreaker)
    });

    // Take top candidates instead of just last 5 by offset
    // Try up to 5 best-scored candidates (3-5 is usually sufficient and much faster)
    let candidates: Vec<(u64, &str)> = candidates_with_score
        .iter()
        .take(5)
        .map(|(_, offset, s)| (*offset, *s))
        .collect();

    if candidates.is_empty() {
        return None;
    }

    tracing::debug!(
        "Auto-detecting XOR key from {} best-scored candidates",
        candidates.len()
    );

    for (score, _offset, candidate) in candidates_with_score.iter().take(5) {
        tracing::debug!("  Candidate (score={}): {}", score, candidate);
    }

    // OPTIMIZATION 1: Phase 1 Quick Pre-filter
    // Skip candidates that don't decode killer IOCs in first 32KB - saves time by avoiding full extraction
    let quick_scan_size = std::cmp::min(32768, data.len());
    let quick_data = &data[..quick_scan_size];
    let killer_patterns = [
        "osascript",
        "screencapture",
        "/bin/sh",
        "/bin/bash",
        "2>&1",
        "http://",
        "https://",
        "launchctl",
        "electrum",
        "ethereum",
        "exodus",
    ];

    let mut promising_candidates = Vec::new();
    for (offset, candidate) in &candidates {
        let key = candidate.as_bytes().to_vec();
        let decoded: Vec<u8> = quick_data
            .iter()
            .enumerate()
            .map(|(i, &byte)| byte ^ key[i % key.len()])
            .collect();

        let decoded_str = String::from_utf8_lossy(&decoded);
        if killer_patterns.iter().any(|p| decoded_str.contains(p)) {
            promising_candidates.push((*offset, *candidate));
            tracing::debug!("Phase 1: Candidate '{}' found killer pattern", candidate);
        }
    }

    // Fall back to all candidates if Phase 1 eliminates everything (safety net)
    let candidates_to_test = if promising_candidates.is_empty() {
        tracing::info!(
            "Phase 1: No killer patterns in first 32KB, testing all {} candidates",
            candidates.len()
        );
        candidates
    } else {
        tracing::info!(
            "Phase 1: {} promising candidates (skipped {})",
            promising_candidates.len(),
            candidates.len() - promising_candidates.len()
        );
        promising_candidates
    };

    // OPTIMIZATION 2: Parallel candidate testing
    // Test all promising candidates in parallel for 2-3x speedup on multi-core CPUs
    tracing::info!(
        "Phase 2: Testing {} candidates in parallel",
        candidates_to_test.len()
    );

    let candidate_scores: Vec<(i32, u64, String, Vec<u8>)> = candidates_to_test
        .into_par_iter()
        .filter_map(|(offset, candidate): (u64, &str)| {
            let key = candidate.as_bytes().to_vec();
            let results = extract_custom_xor_strings(data, &key, min_length);

            // Sanity check: if we extracted way too many strings, it's likely noise
            if results.len() > 5000 {
                tracing::debug!(
                    "Rejecting XOR key '{}' - extracted {} strings (> 5000 = likely noise)",
                    candidate,
                    results.len()
                );
                return None;
            }

            // Calculate weighted score based on decoded string quality.
            // Use a set of already-scored values to avoid counting duplicate strings
            // multiple times: real XOR keys decode to diverse content, but false-positive
            // keys (e.g., a library path XOR'd with near-zero code) produce repetitive
            // garbled copies of the key text that would otherwise inflate the score.
            let mut score = 0;
            let mut scored_values: HashSet<String> = HashSet::new();

            for r in &results {
                let value_lower = r.value.to_ascii_lowercase();

                // CRITICAL: Shell commands and redirections (highest priority)
                if value_lower.contains("osascript")
                    || value_lower.contains("screencapture")
                    || value_lower.contains("/bin/sh")
                    || value_lower.contains("/bin/bash")
                    || value_lower.contains("2>&1")
                    || value_lower.contains("<<eod")
                    || value_lower.contains("<<eof")
                {
                    score += 100;
                }

                // Cryptocurrency terms (very high priority) - keywords are already lowercase
                for crypto in CRYPTO_KEYWORDS {
                    if value_lower.contains(crypto) {
                        score += 80;
                        break;
                    }
                }

                // Suspicious paths (very high priority) - only count unique values
                if matches!(r.kind, StringKind::SuspiciousPath)
                    && scored_values.insert(value_lower.clone())
                {
                    score += 75;
                }

                // URLs and network indicators - only count unique values
                if matches!(
                    r.kind,
                    StringKind::Url | StringKind::IP | StringKind::IPPort
                ) && scored_values.insert(value_lower.clone())
                {
                    score += 50;
                }

                // Browser strings - keywords are already lowercase
                for browser in BROWSER_KEYWORDS {
                    if value_lower.contains(browser) {
                        score += 40;
                        break;
                    }
                }

                // Shell commands - only count unique values
                if matches!(r.kind, StringKind::ShellCmd)
                    && scored_values.insert(value_lower.clone())
                {
                    score += 30;
                }

                // Locale strings (en-US, ru-RU pattern)
                if is_locale_string(&r.value) {
                    score += 25;
                }

                // Generic paths (lower priority, only if they match known prefixes)
                if matches!(r.kind, StringKind::Path) && has_known_path_prefix(&r.value) {
                    score += 10;
                }

                // Base64 (low priority)
                if matches!(r.kind, StringKind::Base64) {
                    score += 5;
                }
            }

            tracing::debug!(
                "XOR key candidate '{}': score={} ({} strings)",
                candidate,
                score,
                results.len()
            );

            Some((score, offset, candidate.to_string(), key))
        })
        .collect();

    // Find the best candidate from parallel results
    let mut best_key: Option<(Vec<u8>, String, u64)> = None;
    let mut best_score = 0;

    for (score, offset, candidate, key) in candidate_scores {
        if score > best_score {
            best_score = score;
            best_key = Some((key, candidate, offset));
        }

        // Early termination: if we found a key with very high confidence
        if score > 500 {
            tracing::debug!("High-confidence XOR key found, stopping search");
            break;
        }
    }

    // Require VERY high score to avoid false positives from random XOR keys
    // Any key produces ~85% printable output, so we need EXTREMELY strong evidence
    // Minimum threshold: 300+ (2+ shell commands, multiple high-value IOCs, or clusters of URLs/IPs)
    // This filters out unobfuscated binaries - real XOR'd malware will have explicit
    // command & control URLs, shell commands, or cryptocurrency wallet paths.
    // Threshold is 375 (= 5 unique suspicious paths at 75 pts each). This rejects keys
    // that score only from a handful of garbled path matches (null-byte false positives)
    // while accepting real malware which typically has shell commands (100+ pts) or URLs.
    let min_xor_confidence_threshold = 375;

    tracing::debug!(
        "Best XOR score overall: {} (threshold: {})",
        best_score,
        min_xor_confidence_threshold
    );

    if best_score >= min_xor_confidence_threshold {
        if let Some((ref _key, ref key_str, _)) = best_key {
            tracing::info!(
                "Auto-detected XOR key: '{}' (score: {})",
                key_str,
                best_score
            );
        }
    } else {
        tracing::debug!(
            "No valid XOR key found (best score {} < required {})",
            best_score,
            min_xor_confidence_threshold
        );
        return None;
    }

    best_key
}

/// Extract XOR-encoded strings from binary data.
///
/// Uses Aho-Corasick for efficient single-pass scanning of all XOR'd patterns.
///
/// # Arguments
/// * `data` - Binary data to scan
/// * `min_length` - Minimum string length
/// * `scan_wide` - Whether to scan for UTF-16LE (wide) patterns (use for PE binaries)
pub(crate) fn extract_xor_strings(
    data: &[u8],
    min_length: usize,
    scan_wide: bool,
) -> Vec<ExtractedString> {
    // Skip XOR scanning for very large files - too slow and unlikely to have simple XOR
    if data.len() > MAX_XOR_SCAN_SIZE {
        tracing::debug!(
            "Skipping XOR scan: file size {} MB exceeds {} MB limit",
            data.len() / (1024 * 1024),
            MAX_XOR_SCAN_SIZE / (1024 * 1024)
        );
        return Vec::new();
    }

    let (ac, pattern_info) = if scan_wide {
        &*super::scan::AUTOMATON_WITH_WIDE
    } else {
        &*super::scan::AUTOMATON_ASCII
    };
    let mut results = Vec::new();
    let mut seen: HashSet<(u64, String)> = HashSet::new();

    // Single pass through the data using overlapping matches
    for mat in ac.find_overlapping_iter(data) {
        let mat: aho_corasick::Match = mat;
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
                            value: decoded,
                            data_offset: offset,
                            section: None,
                            method: StringMethod::XorDecode,
                            kind,
                            library: Some(format!("0x{:02X}:16LE", info.key)),
                            fragments: None,
                            ..Default::default()
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
                        value: decoded,
                        data_offset: offset,
                        section: None,
                        method: StringMethod::XorDecode,
                        kind,
                        library: Some(format!("0x{:02X}", info.key)),
                        fragments: None,
                        ..Default::default()
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
pub(crate) fn extract_multikey_xor_strings(
    data: &[u8],
    keys: &[crate::r2::XorKeyInfo],
    min_length: usize,
) -> Vec<ExtractedString> {
    use crate::r2::XorConfidence;
    let mut results = Vec::new();
    let mut seen: HashSet<(u64, String)> = HashSet::new();

    // Only use top 3 high-confidence keys for decryption attempts
    for key_info in keys
        .iter()
        .filter(|k| matches!(k.confidence, XorConfidence::High))
        .take(3)
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
                                value: valid_str.to_string(),
                                data_offset: offset,
                                section: None,
                                method: StringMethod::XorDecode,
                                kind,
                                library: Some(format!("key:{key_preview}")),
                                fragments: None,
                                ..Default::default()
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
pub(crate) fn find_meaningful_substring(s: &str, min_length: usize) -> Option<(&str, usize, usize)> {
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
pub(crate) fn scan_dotted_patterns(
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
                                value: ip,
                                data_offset: offset,
                                section: None,
                                method: StringMethod::XorDecode,
                                kind: StringKind::IP,
                                library: Some(format!("0x{key:02X}")),
                                fragments: None,
                                ..Default::default()
                            });
                        }
                    }
                }

                if let Some((ip_port, start, _end)) = extract_ip_port_at_pos(data, pos, key) {
                    if ip_port.len() >= min_length {
                        let offset = start as u64;
                        if seen.insert((offset, ip_port.clone())) {
                            results.push(ExtractedString {
                                value: ip_port,
                                data_offset: offset,
                                section: None,
                                method: StringMethod::XorDecode,
                                kind: StringKind::IPPort,
                                library: Some(format!("0x{key:02X}")),
                                fragments: None,
                                ..Default::default()
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
                            value: hostname,
                            data_offset: offset,
                            section: None,
                            method: StringMethod::XorDecode,
                            kind: StringKind::Hostname,
                            library: Some(format!("0x{key:02X}")),
                            fragments: None,
                            ..Default::default()
                        });
                    }
                }
            }
        }
    }
}

/// Extract a hostname starting from a dot position.
pub(crate) fn extract_hostname_at_dot(
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
pub(crate) fn expand_xor_string(
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

    // Additional validation for XOR strings: reject strings with unusual punctuation
    if !is_valid_xor_string(&s) || !is_valid_xor_string(trimmed) {
        return None;
    }

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
pub(crate) fn trim_low_entropy(s: &str) -> (&str, usize) {
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
pub(crate) fn expand_xor_wide_string(
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

    // Reject strings with unusual punctuation
    if !is_valid_xor_string(&decoded) {
        return None;
    }

    if is_meaningful_string(&decoded) {
        Some((decoded, start, end))
    } else {
        None
    }
}

/// Try to extract a full IP address starting from a dot position.
pub(crate) fn extract_ip_at_dot(data: &[u8], dot_pos: usize, key: u8) -> Option<(String, usize, usize)> {
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
pub(crate) fn extract_ip_port_at_pos(data: &[u8], dot_pos: usize, key: u8) -> Option<(String, usize, usize)> {
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

pub(crate) fn is_printable_char(b: u8) -> bool {
    // Accept ASCII printable characters
    if b.is_ascii_graphic() || b == b' ' || b == b'\t' {
        return true;
    }
    // Accept UTF-8 continuation bytes (0x80-0xBF) and UTF-8 start bytes (0xC0-0xF7)
    // This allows Unicode text (Russian, Chinese, Arabic, etc.) to pass through
    // Invalid UTF-8 will be caught later by String::from_utf8()
    (0x80..=0xF7).contains(&b)
}

/// Check if a string looks meaningful (not random garbage).
/// This is STRICT for XOR detection - we want high confidence, low false positives.
/// Check if a decoded XOR string is valid (not garbage with unusual punctuation).
/// Returns true if the string passes basic sanity checks.
pub(crate) fn is_valid_xor_string(s: &str) -> bool {
    let lower = s.to_ascii_lowercase();

    // Check for specific malicious indicators (not just any system path)
    let has_shell_command = s.contains("osascript")
        || s.contains("screencapture")
        || s.contains("bash ")
        || s.contains("sh -")
        || s.contains("curl ")
        || s.contains("wget ")
        || s.contains("chmod ")
        || s.contains("python ")
        || s.contains("perl ")
        || s.contains("ruby ")
        || s.contains("/bin/")
        || s.contains("sleep ")
        || s.contains(" rm ")
        || s.contains("rm -")
        || s.contains("echo ")
        || s.contains("kill ")
        || s.contains("ps ")
        || lower.contains("powershell")
        || lower.contains("cmd.exe")
        || lower.contains("xattr");

    let has_suspicious_path = s.contains("Ethereum/keystore")
        || s.contains("/tmp/") && (s.contains(".sh") || s.contains("payload"))
        || s.contains("/etc/passwd")
        || s.contains("/etc/shadow")
        || lower.contains("appdata")
        || lower.contains("programdata")
        || lower.contains("launchagents")
        || lower.contains("launchdaemons");

    let has_suspicious_url = s.contains("://") && !s.contains("apple.com");

    // Check for IP addresses (likely C2 infrastructure) - pattern: N.N.N.N
    let has_ip = s.chars().filter(|&c| c == '.').count() == 3
        && s.split('.')
            .filter(|seg| {
                !seg.is_empty() && seg.chars().all(|c| c.is_ascii_digit()) && seg.len() <= 3
            })
            .count()
            == 4;

    // Check for unicode escape sequences (legitimate obfuscation)
    let has_unicode_escapes = s.contains("\\x") || s.contains("\\u");

    // Check for shell heredoc patterns
    let has_heredoc =
        s.contains("<<") && (s.contains("EOF") || s.contains("EOD") || s.contains("END"));

    // Count truly bad punctuation (control chars and unusual symbols)
    // Allow newlines in heredocs
    let control_chars = s
        .chars()
        .filter(|&c| {
            if has_heredoc && c == '\n' {
                return false;
            }
            matches!(c, '\x00'..='\x1f' | '\x7f')
        })
        .count();

    // If string has SPECIFIC malicious indicators OR encoding, allow them
    // This bypass ensures high-value IOCs pass validation even with unusual chars
    if has_shell_command
        || has_suspicious_path
        || has_suspicious_url
        || has_ip
        || has_unicode_escapes
        || has_heredoc
    {
        // Only reject if mostly control characters (> 30%)
        return control_chars * 3 < s.len();
    }

    // For all other strings, apply strict filtering
    // But allow certain metacharacters in specific contexts
    let has_xml_tags = s.starts_with('<') && s.ends_with('>') && !s.contains(' ');
    let has_shell_metacharacters = s.contains('<') || s.contains('>') || s.contains('|');
    let looks_like_shell = has_shell_metacharacters
        && s.len() >= 15
        && ((s.contains("EOF") || s.contains("END"))
            || (s.contains(">>") || s.contains("<<"))
            || (s.contains("/dev/") && s.contains('>'))
            || (s.contains("2>&1") || s.contains("1>&2")));

    let bad_punct_count = s
        .chars()
        .filter(|&c| {
            // Allow <, > for XML tags or shell commands
            if (has_xml_tags || looks_like_shell) && matches!(c, '<' | '>') {
                return false;
            }
            // Allow | for shell commands
            if looks_like_shell && c == '|' {
                return false;
            }
            matches!(
                c,
                '^' | '~' | '`' | '[' | ']' | '{' | '}' | '<' | '>' | '|' | '\x00'
                    ..='\x1f' | '\x7f' // Control characters
            )
        })
        .count();

    // Count "questionable" punctuation that can appear in valid strings
    let questionable_punct = s
        .chars()
        .filter(|&c| matches!(c, '$' | '#' | '@' | '!' | '"' | '\'' | '\\'))
        .count();

    // Count additional special chars that often indicate garbage (but can be legitimate)
    let additional_special = s
        .chars()
        .filter(|&c| matches!(c, ':' | '+' | '=' | '*' | '&' | '%'))
        .count();

    // Reject if we have ANY bad punctuation characters
    if bad_punct_count > 0 {
        return false;
    }

    // Also reject strings with excessive "questionable" punctuation
    // Allow max 2 questionable punctuation chars, or 20% of string length
    if questionable_punct > 2 && questionable_punct * 5 > s.len() {
        return false;
    }

    // Reject if total special character density is too high (likely garbage)
    let total_special = questionable_punct + additional_special;
    if !s.is_empty() && total_special * 100 / s.len() > 40 {
        return false;
    }

    // Always check meaningfulness for non-IOC strings
    // This catches garbage fragments like " j3/ N1 9-P" that have few special chars
    // but lack linguistic patterns (vowels, word structure, etc.)
    if !is_meaningful_string(s) {
        return false;
    }

    true
}

/// Common English words and computing terms that indicate legitimate text.
/// Used to boost confidence that decoded text is real vs garbage.
const COMMON_WORDS: &[&str] = &[
    // Very common English words (3-5 letters)
    "the",
    "and",
    "for",
    "are",
    "but",
    "not",
    "you",
    "all",
    "can",
    "her",
    "was",
    "one",
    "our",
    "out",
    "day",
    "get",
    "has",
    "him",
    "his",
    "how",
    "man",
    "new",
    "now",
    "old",
    "see",
    "two",
    "way",
    "who",
    "boy",
    "did",
    "its",
    "let",
    "put",
    "say",
    "she",
    "too",
    "use",
    "your",
    "into",
    "just",
    "like",
    "make",
    "many",
    "over",
    "such",
    "take",
    "than",
    "them",
    "then",
    "these",
    "think",
    "through",
    "time",
    "very",
    "when",
    "work",
    "would",
    // System/Path words
    "Users",
    "Library",
    "Application",
    "Support",
    "Local",
    "Storage",
    "AppData",
    "Program",
    "Files",
    "System",
    "Windows",
    "Containers",
    "Cache",
    "Temp",
    "private",
    "public",
    "Desktop",
    "Documents",
    "Downloads",
    "Pictures",
    "Music",
    "Videos",
    // Common file extensions (targets for exfiltration)
    "plist",
    "json",
    "conf",
    "config",
    "sqlite",
    "wallet",
    "keystore",
    "screenshot",
    "Bookmarks",
    "Cookies",
    "History",
    "Preferences",
    // Application names
    "Safari",
    "Chrome",
    "Firefox",
    "Telegram",
    "Discord",
    "Slack",
    // Crypto/Security (exfiltration targets)
    "Wallet",
    "Wallets",
    "Ethereum",
    "Exodus",
    "Electrum",
    "Monero",
    "Bitcoin",
    "password",
    "passwd",
    "token",
    "session",
    "cookie",
    "credential",
    "secret",
];

/// Cached AhoCorasick automaton for COMMON_WORDS (all patterns stored lowercase).
pub(crate) fn get_common_words_automaton() -> &'static AhoCorasick {
    static CACHE: OnceLock<AhoCorasick> = OnceLock::new();
    CACHE.get_or_init(|| {
        let patterns: Vec<String> = COMMON_WORDS
            .iter()
            .map(|w| w.to_ascii_lowercase())
            .collect();
        AhoCorasick::new(&patterns).expect("Failed to build common words automaton")
    })
}

/// Count how many distinct COMMON_WORDS appear in `lower_s` (already lowercased).
/// Stops counting after reaching `limit` to allow early exits in callers.
pub(crate) fn count_common_word_matches(lower_s: &str, limit: usize) -> usize {
    let ac = get_common_words_automaton();
    let mut matched = [false; COMMON_WORDS.len()];
    let mut count = 0;
    for mat in ac.find_overlapping_iter(lower_s) {
        let pid = mat.pattern().as_usize();
        if !matched[pid] {
            matched[pid] = true;
            count += 1;
            if count >= limit {
                break;
            }
        }
    }
    count
}

/// Check if a string looks like well-formed text using linguistic patterns.
/// This recognizes legitimate English/computing text without hardcoded keyword lists.
pub(crate) fn is_meaningful_string(s: &str) -> bool {
    if s.is_empty() {
        return false;
    }

    // Keep byte length for some legacy checks, but use char_count for Unicode correctness
    let len = s.len();
    let char_count = s.chars().count();
    let mut alpha = 0usize;
    let mut digit = 0usize;
    let mut vowel = 0usize;
    let mut upper = 0usize;
    let mut lower = 0usize;
    let mut punct = 0usize;
    let mut spaces = 0usize;
    let mut has_non_ascii = false;

    for c in s.chars() {
        // Support Unicode alphabetic characters (Cyrillic, Chinese, Arabic, etc.)
        if c.is_alphabetic() {
            alpha += 1;
            if !c.is_ascii() {
                has_non_ascii = true;
            }
            // Only track case and vowels for ASCII (English-specific)
            if c.is_ascii_alphabetic() {
                if c.is_ascii_uppercase() {
                    upper += 1;
                } else {
                    lower += 1;
                }
                if matches!(c.to_ascii_lowercase(), 'a' | 'e' | 'i' | 'o' | 'u') {
                    vowel += 1;
                }
            }
        } else if c.is_numeric() {
            digit += 1;
        } else if c.is_ascii_punctuation() {
            punct += 1;
        } else if c == ' ' {
            spaces += 1;
        }
    }

    let alnum = alpha + digit;

    // Must be at least 50% alphanumeric (relaxed from 60% to catch "Bookmarks.plist")
    // Use character count for proper Unicode support
    if char_count > 0 && alnum * 100 / char_count < 50 {
        return false;
    }

    // Check for common file extensions (exfiltration targets)
    let has_file_extension = s.contains(".plist")
        || s.contains(".json")
        || s.contains(".conf")
        || s.contains(".sqlite")
        || s.contains(".jpg")
        || s.contains(".png")
        || s.contains(".txt")
        || s.contains(".log")
        || s.contains(".xml")
        || s.contains(".db")
        || s.contains(".dat")
        || s.contains(".wallet")
        || s.contains(".keystore");

    if has_file_extension {
        // File paths are high value - just check basic quality
        // For non-ASCII text (e.g., Russian folder names), vowel count is 0, so skip that check
        if alpha >= 5 && (vowel > 0 || has_non_ascii) {
            return true;
        }
    }

    // Check if string contains common words (case-insensitive matching via AhoCorasick).
    // We only need to know if count is 0, 1, or ≥2 so we stop scanning at 2.
    let lower_s = s.to_ascii_lowercase();
    let word_matches = count_common_word_matches(&lower_s, 2);

    // Strong signal: 2+ common words = likely legitimate
    if word_matches >= 2 {
        return true;
    }

    // Medium signal: 1 common word + reasonable quality
    if word_matches >= 1 && alpha >= 5 {
        // For non-ASCII text, skip vowel check (vowel is 0 for Russian/Chinese/etc.)
        if has_non_ascii {
            return true;
        }
        let vowel_ratio = if alpha > 0 { vowel * 100 / alpha } else { 0 };
        // Very lenient with common words present
        if vowel_ratio >= 8 {
            return true;
        }
    }

    // Linguistic analysis for strings without known words
    // ONLY apply English-specific checks (vowels, consonants) to ASCII text
    if alpha >= 5 {
        // For non-ASCII text (Russian, Chinese, Arabic, etc.), skip English-specific analysis
        // Just rely on the alphanumeric percentage check above (>=50%)
        if has_non_ascii {
            // Non-ASCII alphabetic text passed the alphanumeric check, accept it
            return true;
        }

        // English-specific analysis for ASCII text
        let vowel_ratio = vowel * 100 / alpha;

        // English text typically has 35-45% vowels
        // Be lenient: accept 12-65%
        if !(12..=65).contains(&vowel_ratio) {
            return false;
        }

        // Check for word-like structure (not random letters)
        // Count consonant clusters (more than 4 consecutive consonants is suspicious)
        let chars: Vec<char> = s.chars().collect();
        let mut max_consonant_run = 0;
        let mut consonant_run = 0;

        for &c in &chars {
            if c.is_ascii_alphabetic()
                && !matches!(c.to_ascii_lowercase(), 'a' | 'e' | 'i' | 'o' | 'u')
            {
                consonant_run += 1;
                max_consonant_run = max_consonant_run.max(consonant_run);
            } else {
                consonant_run = 0;
            }
        }

        // English rarely has >5 consecutive consonants (e.g., "catchphrase" has 4)
        if max_consonant_run > 6 {
            return false;
        }

        // Check case consistency (Title Case, lowercase, UPPERCASE, or camelCase are OK)
        // Random case mixing like "rAnDoM" is suspicious
        if alpha > 8 && upper > 0 && lower > 0 {
            // If we have mixed case, check if it's structured
            let has_spaces_or_separators =
                spaces > 0 || s.contains('/') || s.contains('.') || s.contains('_');

            // Title Case or camelCase with separators is fine
            // Random mixing without structure is bad
            if !has_spaces_or_separators {
                // Check if it's camelCase (starts lowercase, has capitals mid-word)
                let starts_lower = chars[0].is_ascii_lowercase();
                let has_mid_caps = chars
                    .windows(2)
                    .any(|w| w[0].is_ascii_lowercase() && w[1].is_ascii_uppercase());

                if !starts_lower && !has_mid_caps {
                    // Not Title, not camel, not consistent - likely garbage
                    let upper_ratio = upper * 100 / alpha;
                    // Reject if 20-80% uppercase (random mixing)
                    if (20..=80).contains(&upper_ratio) {
                        return false;
                    }
                }
            }
        }

        // Reject all-caps with no punctuation/digits (likely garbage like "ABCDEFGH")
        if upper > 0 && lower == 0 && alpha > 6 && punct == 0 && digit == 0 && spaces == 0 {
            return false;
        }

        // Reject all-lowercase with no vowels (like "bcdfghjk")
        if lower > 0 && upper == 0 && vowel == 0 && alpha > 4 {
            return false;
        }
    }

    // Check character diversity (reject repetitive strings like "aaaaaaa")
    let unique: HashSet<char> = s.chars().collect();
    if unique.len() * 3 < len && len > 10 {
        return false;
    }

    // Reject strings with too many backslashes (path separators are OK, but not excessive)
    let backslash_count = s.chars().filter(|&c| c == '\\').count();
    if backslash_count > 3 && backslash_count * 4 > len {
        return false;
    }

    true
}

pub(crate) fn is_valid_ip(s: &str) -> bool {
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

pub(crate) fn is_valid_port(s: &str) -> bool {
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

/// Well-known suspicious paths that indicate malicious activity.
const SUSPICIOUS_PATHS: &[&str] = &[
    "/Library/Ethereum/keystore",
    "/Library/Application Support/Ethereum",
    "/.ssh/",
    "/.aws/",
    "/.gnupg/",
    "/Library/Keychains/",
    "/Keychain",
    "/wallet.dat",
    "/Library/Cookies",
    // Crypto wallet directories commonly targeted by malware
    "Wallets/Guarda",
    "Wallets/atomic",
    "Wallets/BitPay",
    "Wallets/Ethereum",
    "Wallets/Electrum",
    "Wallets/Electrum-LTC",
    "Wallets/ElectronCash",
    "Wallets/Sparrow",
    "Wallets/Monero",
    "Wallets/Jaxx",
    "Wallets/MyMonero",
    "Wallets/Coinomi",
    "Wallets/Daedalus",
    "Wallets/Wasabi",
    "Wallets/Blockstream",
    "Wallets/",
    "Exodus/exodus.wallet",
    "Exodus/exodus.conf",
    ".electrum/wallets",
    ".electrum-ltc/wallets",
    ".electron-cash/wallets",
    ".sparrow/wallets",
    "Monero/wallets",
    ".walletwasabi/",
    "Neon/storage/userWallet",
    "Daedalus Mainnet/wallets",
    "Blockstream/Green/Wallets",
    "com.bitpay.wallet",
    "/trezor.txt",
    "/specter.txt",
];

/// Trim trailing garbage from extracted strings.
/// This removes characters at the end that don't look like legitimate content.
pub(crate) fn trim_trailing_garbage(s: &str) -> &str {
    // First, check for common shell redirections and terminators that mark natural endpoints
    let natural_endpoints = [
        "2>&1",
        "2>/dev/null",
        ">/dev/null",
        ">&1",
        ">&2",
        " &",
        "EOD",
        "EOF",
    ];

    // Find the last occurrence of any natural endpoint
    let mut natural_end: Option<usize> = None;
    for endpoint in &natural_endpoints {
        if let Some(pos) = s.rfind(endpoint) {
            let candidate_end = pos + endpoint.len();
            natural_end = Some(natural_end.map_or(candidate_end, |prev| prev.max(candidate_end)));
        }
    }

    // If we found a natural endpoint, trim there
    if let Some(end_pos) = natural_end {
        return &s[..end_pos];
    }

    // Check for file extensions as natural endpoints (e.g., .php, .exe, .dll, .so)
    let file_extensions = [
        ".php", ".exe", ".dll", ".so", ".dylib", ".js", ".py", ".rb", ".pl", ".sh", ".html",
        ".xml", ".json", ".txt", ".log", ".conf", ".cfg",
    ];
    for ext in &file_extensions {
        if let Some(pos) = s.rfind(ext) {
            let candidate_end = pos + ext.len();
            natural_end = Some(natural_end.map_or(candidate_end, |prev| prev.max(candidate_end)));
        }
    }

    if let Some(end_pos) = natural_end {
        return &s[..end_pos];
    }

    // Otherwise, work backwards from the end looking for the last legitimate character
    let chars: Vec<char> = s.chars().collect();
    let mut i = chars.len();

    while i > 0 {
        i -= 1;
        let c = chars[i];

        // Stop at clear delimiters
        if c == '"' || c == '\'' || c == ')' || c == ']' || c == '}' || c == '>' {
            return s.char_indices().nth(i + 1).map_or(s, |(pos, _)| &s[..pos]);
        }

        // Stop at alphanumeric followed by whitespace or punctuation that suggests a boundary
        if c.is_ascii_alphanumeric() {
            // Check if the next character (if exists) suggests this is the end
            if i + 1 < chars.len() {
                let next = chars[i + 1];
                // If followed by unusual characters, this might be the real end
                if !next.is_ascii_alphanumeric()
                    && next != '/'
                    && next != '.'
                    && next != '-'
                    && next != '_'
                {
                    return s.char_indices().nth(i + 1).map_or(s, |(pos, _)| &s[..pos]);
                }
            } else {
                // Last character is alphanumeric - keep whole string
                return s;
            }
        }
    }

    s
}


/// Well-known shell commands and tools (for lenient matching with trailing garbage).
const SHELL_COMMANDS: &[&str] = &[
    "screencapture",
    "osascript",
    "curl ",
    "wget ",
    "bash ",
    "sh ",
    "sleep ",
    "rm -rf",
    "python ",
    "perl ",
    "ruby ",
    "powershell",
    "cmd.exe",
    "/bin/sh",
    "/bin/bash",
    "2>&1",
    "<<eod",
    "<<eof",
    ">/dev/null",
];

/// Shell executable paths that should be classified as suspicious.
const SHELL_EXECUTABLE_PATHS: &[&str] = &[
    "/bin/sh",
    "/bin/bash",
    "/bin/zsh",
    "/bin/dash",
    "/usr/bin/bash",
    "/usr/bin/sh",
    "/usr/bin/python",
    "/usr/bin/perl",
    "/usr/bin/ruby",
    "cmd.exe",
    "powershell.exe",
];

/// Cryptocurrency-related terms indicating wallet/keystore access (all lowercase).
const CRYPTO_KEYWORDS: &[&str] = &[
    "ethereum",
    "bitcoin",
    "electrum",
    "wallet",
    "keystore",
    "monero",
    "litecoin",
    "dogecoin",
    "cryptocurrency",
    "mnemonic",
    "seed phrase",
];

/// Browser and application identifiers (all lowercase).
const BROWSER_KEYWORDS: &[&str] = &[
    "safari", "chrome", "firefox", "mozilla", "webkit", "chromium", "opera", "edge",
];

/// Well-known UNIX/macOS/Windows path prefixes.
const KNOWN_PATH_PREFIXES: &[&str] = &[
    // UNIX/Linux common paths
    "/bin/",
    "/usr/bin/",
    "/usr/local/",
    "/etc/",
    "/var/",
    "/tmp/",
    "/dev/",
    "/opt/",
    "/home/",
    "/root/",
    // macOS specific
    "/Library/",
    "/Users/",
    "/Applications/",
    "/System/Library/",
    "/private/",
    // Windows paths
    "C:\\Windows\\",
    "C:\\Program Files\\",
    "C:\\Users\\",
    "C:\\ProgramData\\",
    "C:\\Temp\\",
    "%APPDATA%",
    "%USERPROFILE%",
];

/// Trim obvious garbage from the end of XOR-decoded strings.
/// Check if a string contains locale codes (language_COUNTRY or language-COUNTRY format).
/// These are often used in malware for geofencing/targeting specific regions.
///
/// Common locale patterns:
/// - en_US, en-US (English - United States)
/// - ru_RU, ru-RU (Russian - Russia)
/// - zh_CN, zh-CN (Chinese - China)
/// - Lists: "en_US;fr_FR;de_DE" or "ru_RU;be_BY;kk_KZ"
pub(crate) fn has_multiple_locales(s: &str) -> bool {
    // Common locale codes (top 15 global locales + CIS countries for malware detection)
    const COMMON_LOCALES: &[&str] = &[
        "en_US", "en-US", // English (US)
        "en_GB", "en-GB", // English (UK)
        "zh_CN", "zh-CN", // Chinese (China)
        "es_ES", "es-ES", // Spanish (Spain)
        "es_MX", "es-MX", // Spanish (Mexico)
        "fr_FR", "fr-FR", // French (France)
        "de_DE", "de-DE", // German (Germany)
        "ja_JP", "ja-JP", // Japanese (Japan)
        "pt_BR", "pt-BR", // Portuguese (Brazil)
        "ru_RU", "ru-RU", // Russian (Russia)
        "it_IT", "it-IT", // Italian (Italy)
        "ko_KR", "ko-KR", // Korean (Korea)
        "ar_SA", "ar-SA", // Arabic (Saudi Arabia)
        "hi_IN", "hi-IN", // Hindi (India)
        "tr_TR", "tr-TR", // Turkish (Turkey)
        // CIS countries (common in DPRK malware geofencing)
        "hy_AM", "hy-AM", // Armenian
        "be_BY", "be-BY", // Belarusian
        "kk_KZ", "kk-KZ", // Kazakh
        "uk_UA", "uk-UA", // Ukrainian
        "uz_UZ", "uz-UZ", // Uzbek
    ];

    // Count how many locale codes are present
    let mut locale_count = 0;
    for locale in COMMON_LOCALES {
        if s.contains(locale) {
            locale_count += 1;
            if locale_count >= 2 {
                return true; // Found at least 2 locale codes (likely a geofencing list)
            }
        }
    }

    // Single locale might be legitimate, but lists of locales are suspicious
    false
}

/// Classify an XOR-decoded string. Returns None if it doesn't look interesting.
pub(crate) fn classify_xor_string(s: &str) -> Option<StringKind> {
    // FIRST: Check for high-value IOCs that should bypass strict filtering
    // These are important enough that we want them even if they have unusual chars.
    // Run case-sensitive checks before allocating a lowercase copy.

    // Check for locale strings (common in malware geofencing)
    // Standard format: language_COUNTRY or language-COUNTRY (e.g., en_US, ru-RU, zh_CN)
    // Malware often includes lists like "en_US;fr_FR;de_DE" to check victim's locale
    if has_multiple_locales(s) {
        return Some(StringKind::SuspiciousPath); // Classify as suspicious (indicates geofencing)
    }

    // Check for well-known suspicious paths (even with garbage around them)
    for sus_path in SUSPICIOUS_PATHS {
        if s.contains(sus_path) {
            return Some(StringKind::SuspiciousPath);
        }
    }

    // Defer lowercase allocation until needed for case-insensitive checks.
    let lower = s.to_ascii_lowercase();

    // Check for shell executable paths (before shell commands)
    for exe_path in SHELL_EXECUTABLE_PATHS {
        if lower.contains(exe_path) {
            return Some(StringKind::SuspiciousPath);
        }
    }

    // Check for well-known shell commands (even with trailing garbage)
    for cmd in SHELL_COMMANDS {
        if lower.contains(cmd) {
            return Some(StringKind::ShellCmd);
        }
    }

    // Check for credential keywords
    for keyword in CREDENTIAL_KEYWORDS {
        if lower.contains(keyword) {
            return Some(StringKind::SuspiciousPath);
        }
    }

    // Check for browser/app data exfiltration targets
    let exfil_indicators = [
        "extension settings",
        "local storage",
        "cookies",
        "bookmarks",
        "history",
        "preferences",
        "session",
        "cache",
        "telegram",
        "discord",
        "slack",
        "signal",
        "whatsapp",
        "tdata",
        "desktop folder",
        "documents folder",
    ];

    for indicator in &exfil_indicators {
        if lower.contains(indicator) {
            return Some(StringKind::SuspiciousPath);
        }
    }

    // Quick check for URLs/IPs before strict filtering
    if lower.contains("http://") || lower.contains("https://") || lower.contains("://") {
        // Likely a URL, allow through
        let kind = classify_string(s);
        if matches!(kind, StringKind::Url) {
            return Some(kind);
        }
    }

    // Check for IP addresses (pattern: digits.digits.digits.digits)
    if s.chars().filter(|&c| c == '.').count() == 3 {
        let segments: Vec<&str> = s.split('.').collect();
        if segments.len() == 4
            && segments.iter().all(|seg| {
                !seg.is_empty() && seg.chars().all(|c| c.is_ascii_digit()) && seg.len() <= 3
            })
        {
            // Likely an IP address, allow through
            let kind = classify_string(s);
            if matches!(kind, StringKind::IP | StringKind::IPPort) {
                return Some(kind);
            }
        }
    }

    // SECOND: Check if string looks like well-formed text
    // If it passes linguistic validation, trust it
    if is_meaningful_string(s) {
        // String looks legitimate - classify it
        let kind = classify_string(s);

        // Accept meaningful strings that classify as high-value IOCs
        // NOTE: Const is intentionally excluded - it must pass strict validation below
        // NOTE: Path is intentionally excluded - paths must go through strict validation below
        if matches!(
            kind,
            StringKind::SuspiciousPath
                | StringKind::ShellCmd
                | StringKind::IP
                | StringKind::IPPort
                | StringKind::Url
        ) {
            return Some(kind);
        }
    }

    // SECOND+: Check for encoded data formats directly
    // Base64, hex, and url-encoded strings don't pass linguistic checks but are high-value IOCs.
    // classify_string handles proper format validation (length, charset, structure).
    {
        let kind = classify_string(s);
        if matches!(
            kind,
            StringKind::Base64 | StringKind::HexEncoded | StringKind::UrlEncoded
        ) {
            return Some(kind);
        }
        // XOR decoding may strip trailing '=' padding from base64 (e.g., '=' XOR 0x42 = 0x7F,
        // which is non-printable and gets cut off by the scan). Try re-adding padding.
        let remainder = s.len() % 4;
        if remainder == 2 || remainder == 3 {
            let padding = if remainder == 2 { "==" } else { "=" };
            let padded = format!("{s}{padding}");
            if matches!(classify_string(&padded), StringKind::Base64) {
                return Some(StringKind::Base64);
            }
        }
    }

    // THIRD: For strings that don't pass linguistic checks, apply strict filtering
    if !is_valid_xor_string(s) {
        return None;
    }

    // Classify remaining strings that passed strict validation
    let kind = classify_string(s);

    match kind {
        StringKind::IP
        | StringKind::IPPort
        | StringKind::Url
        | StringKind::SuspiciousPath
        | StringKind::UnicodeEscaped
        | StringKind::HexEncoded
        | StringKind::UrlEncoded
        | StringKind::Registry
        | StringKind::Base64 => Some(kind),
        StringKind::ShellCmd | StringKind::AppleScript => {
            // Reject obvious garbage that starts with backtick but no valid command
            if s.starts_with('`')
                && !s[1..]
                    .trim_start()
                    .chars()
                    .next()
                    .is_some_and(|c| c.is_ascii_alphabetic())
            {
                None
            } else {
                Some(kind)
            }
        }
        StringKind::Path => {
            // STRICT PATH VALIDATION: Only accept paths matching known OS patterns

            // Check for known UNIX/macOS path prefixes
            let has_known_prefix = has_known_path_prefix(s);

            // Check for Windows paths with drive letter
            let is_windows_path = s.len() > 3
                && s.chars().nth(1) == Some(':')
                && s.chars().nth(2) == Some('\\')
                && s.chars()
                    .next()
                    .expect("s is not empty")
                    .is_ascii_alphabetic();

            // Check for relative paths with proper structure
            let is_relative_path = (s.starts_with("./") || s.starts_with("../"))
                && s.matches('/').count() >= 2
                && s.split('/')
                    .filter(|p| !p.is_empty() && *p != "." && *p != "..")
                    .count()
                    >= 1;

            if !has_known_prefix && !is_windows_path && !is_relative_path {
                return None;
            }

            // Reject if path has too many non-path characters
            let bad_chars = s
                .chars()
                .filter(|&c| {
                    !c.is_ascii_alphanumeric()
                        && !matches!(c, '/' | '\\' | '.' | '_' | '-' | ' ' | ':' | '%')
                })
                .count();

            // Reject if > 10% bad characters
            if bad_chars * 10 > s.len() {
                return None;
            }

            // For UNIX paths, ensure they have proper structure
            if s.starts_with('/') {
                let parts: Vec<&str> = s.split('/').filter(|p| !p.is_empty()).collect();

                // Single-level paths (like "/something") need to match known patterns
                if parts.len() == 1 {
                    let name = parts[0];

                    // Check if it matches known single-level paths
                    let known_single_level = [
                        "bin",
                        "etc",
                        "usr",
                        "var",
                        "tmp",
                        "dev",
                        "opt",
                        "home",
                        "root",
                        "Library",
                        "Users",
                        "Applications",
                        "System",
                        "private",
                    ];

                    if !known_single_level.contains(&name) {
                        // For other single-level paths, apply strict validation
                        let has_upper = name.chars().any(|c| c.is_ascii_uppercase());
                        let has_lower = name.chars().any(|c| c.is_ascii_lowercase());
                        let has_digit = name.chars().any(|c| c.is_ascii_digit());

                        // Reject paths with mixed case + digits (garbage pattern)
                        if has_upper && has_lower && has_digit {
                            return None;
                        }

                        // Reject if it alternates between upper/lower too much (gibberish)
                        let mut case_changes = 0;
                        let mut prev_was_upper = false;
                        for c in name.chars().filter(char::is_ascii_alphabetic) {
                            let is_upper = c.is_ascii_uppercase();
                            if prev_was_upper != is_upper {
                                case_changes += 1;
                            }
                            prev_was_upper = is_upper;
                        }
                        // Real paths rarely change case more than 2-3 times
                        if case_changes > 3 {
                            return None;
                        }
                    }
                }

                // Multi-level paths should have reasonable component names
                for part in &parts {
                    // Each component should be mostly alphanumeric
                    let alnum = part.chars().filter(char::is_ascii_alphanumeric).count();
                    if !part.is_empty() && alnum * 100 / part.len() < 60 {
                        return None;
                    }
                }
            }

            Some(kind)
        }
        _ => {
            // Generic fallback for Const and other types
            // Apply additional quality checks to avoid false positives
            // Use character count for proper Unicode support
            let char_count = s.chars().count();

            // Reject strings with too many special characters
            let special_chars = s
                .chars()
                .filter(|&c| {
                    !c.is_alphanumeric() && !c.is_whitespace() && c != '-' && c != '_' && c != '.'
                })
                .count();

            // Reject if > 40% special characters (garbage indicator)
            if char_count > 0 && special_chars * 10 > char_count * 4 {
                return None;
            }

            // Longer strings with spaces should look like natural text
            if char_count >= 30 && s.contains(' ') {
                if looks_like_text(s) {
                    return Some(StringKind::Const);
                }
                return None;
            }

            // Short strings: must be mostly alphanumeric
            // Use character count for proper Unicode support
            let char_count = s.chars().count();
            let alnum = s.chars().filter(|c| c.is_alphanumeric()).count();
            if char_count > 0 && alnum * 10 < char_count * 6 {
                // < 60% alphanumeric = likely garbage
                return None;
            }

            Some(StringKind::Const)
        }
    }
}

/// Check if a string is a locale identifier (e.g., en-US, ru-RU, zh-CN).
pub(crate) fn is_locale_string(s: &str) -> bool {
    let s = s.trim();
    if s.len() < 5 || s.len() > 6 {
        return false;
    }

    let chars: Vec<char> = s.chars().collect();
    if chars.len() < 5 {
        return false;
    }

    // Pattern: 2-3 lowercase + underscore/hyphen + 2-3 uppercase
    // en-US, ru-RU, zh-CN, eng-US, etc.
    let has_separator = chars[2] == '_'
        || chars[2] == '-'
        || (chars.len() == 6 && (chars[3] == '_' || chars[3] == '-'));

    if !has_separator {
        return false;
    }

    let sep_idx = if chars[2] == '_' || chars[2] == '-' {
        2
    } else {
        3
    };

    // Check lowercase before separator
    for &ch in chars.iter().take(sep_idx) {
        if !ch.is_ascii_lowercase() {
            return false;
        }
    }

    // Check uppercase after separator
    for &ch in chars.iter().skip(sep_idx + 1) {
        if !ch.is_ascii_uppercase() {
            return false;
        }
    }

    true
}

/// Check if a path starts with a known OS path prefix.
pub(crate) fn has_known_path_prefix(path: &str) -> bool {
    for prefix in KNOWN_PATH_PREFIXES {
        if path.starts_with(prefix) {
            return true;
        }
    }

    // Also check for relative paths
    // ./ with any name (common for malware: ./malware, ./payload, etc.)
    // ../ needs at least 2 levels
    if let Some(after_dot_slash) = path.strip_prefix("./") {
        // Must have some content after ./
        return !after_dot_slash.is_empty()
            && after_dot_slash
                .chars()
                .next()
                .expect("checked above")
                .is_ascii_alphanumeric();
    }

    if path.starts_with("../") {
        return path.matches('/').count() >= 2; // At least 2 levels
    }

    false
}

/// Check if a string looks like natural/structured text (not random garbage).
/// Used for generic XOR classification of longer strings with spaces.
pub(crate) fn looks_like_text(s: &str) -> bool {
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

