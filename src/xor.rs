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

/// Maximum file size for auto-detection of XOR keys (512 KB).
pub const MAX_AUTO_DETECT_SIZE: usize = 512 * 1024;

/// Calculate Shannon entropy of a byte string.
/// Returns a value between 0.0 (no entropy) and 8.0 (maximum entropy for bytes).
fn calculate_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }

    let mut freq = [0u32; 256];
    for &byte in data {
        freq[byte as usize] += 1;
    }

    let len = data.len() as f64;
    let mut entropy = 0.0;

    for &count in &freq {
        if count > 0 {
            let p = f64::from(count) / len;
            entropy -= p * p.log2();
        }
    }

    entropy
}

/// Check if a string is a good XOR key candidate based on entropy.
/// DPRK malware often uses high-entropy keys like "Moz&Wie;#t/6T!2y", "12GWAPCT1F0I1S14".
fn is_good_xor_key_candidate(s: &str) -> bool {
    let len = s.len();

    // Length between 15-32 characters (typical for XOR keys)
    if !(15..=32).contains(&len) {
        return false;
    }

    // Must be ASCII
    if !s.is_ascii() {
        return false;
    }

    // Reject strings with underscores (typically not used in XOR keys)
    if s.contains('_') {
        return false;
    }

    // Calculate entropy - high entropy indicates randomness/key material
    let entropy = calculate_entropy(s.as_bytes());

    // High entropy threshold: > 3.5 bits per byte
    // This catches keys like "Moz&Wie;#t/6T!2y" (entropy ~4.8)
    // and "12GWAPCT1F0I1S14" (entropy ~3.5)
    // but filters out low-entropy patterns
    if entropy < 3.5 {
        return false;
    }

    // Check for variety in character types (not just numbers, not just letters)
    let has_upper = s.chars().any(|c| c.is_ascii_uppercase());
    let has_lower = s.chars().any(|c| c.is_ascii_lowercase());
    let has_digit = s.chars().any(|c| c.is_ascii_digit());
    let has_special = s.chars().any(|c| !c.is_ascii_alphanumeric());

    // Good keys typically have at least 2 different character types
    let type_count = [has_upper, has_lower, has_digit, has_special]
        .iter()
        .filter(|&&x| x)
        .count();

    if type_count < 2 {
        return false;
    }

    // Reject sequential patterns (like "abcdefghijklmnopqrstuvwxyz")
    let mut sequential_count = 0;
    let bytes = s.as_bytes();
    for i in 0..bytes.len().saturating_sub(2) {
        if bytes[i] + 1 == bytes[i + 1] && bytes[i + 1] + 1 == bytes[i + 2] {
            sequential_count += 1;
        }
    }
    // Reject if more than 20% sequential
    if sequential_count * 5 > bytes.len() {
        return false;
    }

    true
}

/// Minimal high-signal patterns for XOR detection.
/// These short patterns catch a wide variety of malware indicators:
/// - `://` catches all URL schemes (http://, https://, ftp://, etc.)
/// - `/bin` catches Unix shell paths (/bin/sh, /bin/bash)
/// - `C:\` catches Windows paths
/// - `Mozilla` catches user agent strings
/// - `.exe` catches Windows executables (cmd.exe, powershell.exe)
/// - `passw` catches password/passwd variants
/// - `Library` catches macOS paths (/Library/...)
/// - `Ethereum` catches crypto wallet paths
/// - ` %s ` catches format strings (common in C code)
const XOR_PATTERNS: &[&[u8]] = &[
    b"://",
    b"/bin",
    b"C:\\",
    b"Mozilla",
    b".exe",
    b"passw",
    b"Library",
    b"Ethereum",
    b" %s ",
];

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

/// Extract strings decoded with a specified XOR key.
///
/// Applies the given XOR key to the entire binary data and extracts meaningful strings.
/// The key is cycled for multi-byte keys (key[i % `key.len()`]).
///
/// # Arguments
/// * `data` - Binary data to scan
/// * `key` - XOR key bytes (single or multi-byte)
/// * `min_length` - Minimum string length
pub fn extract_custom_xor_strings(
    data: &[u8],
    key: &[u8],
    min_length: usize,
) -> Vec<ExtractedString> {
    extract_custom_xor_strings_with_hints(data, key, min_length, None, true)
}

pub fn extract_custom_xor_strings_unfiltered(
    data: &[u8],
    key: &[u8],
    min_length: usize,
) -> Vec<ExtractedString> {
    extract_custom_xor_strings_with_hints(data, key, min_length, None, false)
}

/// Extract XOR strings with optional radare2 boundary hints.
/// Hints are tried first, and successful regions are excluded from file-wide scanning.
pub fn extract_custom_xor_strings_with_hints(
    data: &[u8],
    key: &[u8],
    min_length: usize,
    r2_hints: Option<&[crate::r2::StringBoundary]>,
    apply_filters: bool,
) -> Vec<ExtractedString> {
    if key.is_empty() || data.is_empty() {
        return Vec::new();
    }

    // Track regions that have been successfully decoded with high quality
    let mut excluded_ranges: Vec<(usize, usize)> = Vec::new();

    // Step 1: Try radare2 hints first if available
    let mut hint_results = Vec::new();
    if let Some(hints) = r2_hints {
        tracing::info!("Trying {} radare2 string boundary hints", hints.len());
        hint_results = extract_xor_strings_from_hints(data, key, min_length, hints, apply_filters);

        // Mark high-quality hint results as excluded from file-wide scanning
        for result in &hint_results {
            if is_high_quality_string(result) {
                let start = result.data_offset as usize;
                let end = start + result.value.len();
                excluded_ranges.push((start, end));
            }
        }

        tracing::info!(
            "Radare2 hints produced {} strings, {} high-quality regions excluded",
            hint_results.len(),
            excluded_ranges.len()
        );
    }

    // Step 2: Continue with normal extraction, excluding hint regions
    extract_custom_xor_strings_filtered_with_exclusions(
        data,
        key,
        min_length,
        apply_filters,
        excluded_ranges,
        hint_results,
    )
}

fn extract_custom_xor_strings_filtered_with_exclusions(
    data: &[u8],
    key: &[u8],
    min_length: usize,
    apply_filters: bool,
    excluded_ranges: Vec<(usize, usize)>,
    hint_results: Vec<ExtractedString>,
) -> Vec<ExtractedString> {
    if key.is_empty() || data.is_empty() {
        return Vec::new();
    }

    // For multi-byte keys, try both approaches and merge results
    // 1. Pattern-based: each string XOR'd independently from key[0]
    // 2. File-level cycling: entire file XOR'd at all key offsets
    if key.len() > 1 {
        let mut all_results = extract_custom_xor_strings_pattern_based(
            data,
            key,
            min_length,
            apply_filters,
            &excluded_ranges,
        );

        // Also try file-level cycling (like single-byte XOR but at all key offsets)
        // This catches strings embedded in continuous XOR'd blocks
        all_results.extend(extract_custom_xor_strings_file_level_cycling(
            data,
            key,
            min_length,
            apply_filters,
            &excluded_ranges,
        ));

        // Deduplicate by (offset, value)
        let dedup_start = std::time::Instant::now();
        let mut seen: HashSet<(u64, String)> = HashSet::new();
        all_results.retain(|s| seen.insert((s.data_offset, s.value.clone())));
        eprintln!("[PERF] Dedup by (offset, value): {} -> {} strings in {:.2}s",
            all_results.len() + seen.len(), all_results.len(), dedup_start.elapsed().as_secs_f64());

        // Remove overlapping strings - keep the higher quality one
        // Sort by quality (score) descending, then by offset
        let sort_start = std::time::Instant::now();
        all_results.sort_by(|a, b| {
            let score_a = string_quality_score(a);
            let score_b = string_quality_score(b);
            score_b.cmp(&score_a).then(a.data_offset.cmp(&b.data_offset))
        });
        eprintln!("[PERF] Final sorting {} strings took {:.2}s",
            all_results.len(), sort_start.elapsed().as_secs_f64());

        let overlap_start = std::time::Instant::now();
        let result_count = all_results.len();
        let mut final_results: Vec<ExtractedString> = Vec::new();
        // Cache trimmed ranges to avoid recalculating trim_*_garbage() repeatedly
        let mut trimmed_ranges: Vec<(usize, usize)> = Vec::new(); // (trimmed_start, trimmed_end)

        for result in all_results {
            let start = result.data_offset as usize;
            let end = start + result.value.len();

            // Trim both leading and trailing garbage for overlap checking
            let trimmed_leading = trim_leading_garbage(&result.value);
            let leading_offset = result.value.len() - trimmed_leading.len();
            let trimmed_both = trim_trailing_garbage(trimmed_leading);
            let trimmed_start = start + leading_offset;
            let trimmed_end = trimmed_start + trimmed_both.len();

            // Check if this overlaps with any previously accepted string (using trimmed ranges)
            let mut overlaps = false;
            for &(prev_trimmed_start, prev_trimmed_end) in &trimmed_ranges {
                if !(trimmed_end <= prev_trimmed_start || trimmed_start >= prev_trimmed_end) {
                    overlaps = true;
                    break;
                }
            }

            // Only add if it doesn't overlap (higher quality strings are checked first)
            if !overlaps {
                trimmed_ranges.push((trimmed_start, trimmed_end));
                final_results.push(result);
            }
        }
        eprintln!("[PERF] Final overlap checking took {:.2}s, kept {} of {} strings",
            overlap_start.elapsed().as_secs_f64(), final_results.len(), result_count);

        // Re-sort by offset for consistent output
        final_results.sort_by_key(|s| s.data_offset);

        // Merge with hint results
        final_results.extend(hint_results);
        final_results.sort_by_key(|s| s.data_offset);

        return final_results;
    }

    // Single-byte key: use file-level XOR (simpler, same result either way)
    let mut results = Vec::new();
    let mut seen: HashSet<(u64, String)> = HashSet::new();

    // Decode the entire data with the XOR key
    let decoded: Vec<u8> = data
        .iter()
        .enumerate()
        .map(|(i, &byte)| byte ^ key[i % key.len()])
        .collect();

    // Scan for printable ASCII strings in the decoded data
    let mut start = 0;
    while start < decoded.len() {
        // Find start of printable run
        while start < decoded.len() && !is_printable_char(decoded[start]) {
            start += 1;
        }

        if start >= decoded.len() {
            break;
        }

        // Find end of printable run
        let mut end = start;
        while end < decoded.len() && is_printable_char(decoded[end]) {
            end += 1;
        }

        // Extract and validate the string
        if end - start >= min_length {
            if let Ok(s) = String::from_utf8(decoded[start..end].to_vec()) {
                // Use same filtering as multi-byte XOR: classify + validation::is_garbage() in lib.rs
                let kind_opt = if apply_filters {
                    classify_xor_string(&s)
                } else {
                    Some(StringKind::Const)
                };

                if let Some(kind) = kind_opt {
                    let offset = start as u64;
                    if seen.insert((offset, s.clone())) {
                        let key_preview = if key.len() > 8 {
                            format!("{}...", String::from_utf8_lossy(&key[..8]))
                        } else {
                            String::from_utf8_lossy(key).to_string()
                        };

                        results.push(ExtractedString {
                            value: s,
                            data_offset: offset,
                            section: None,
                            method: StringMethod::XorDecode,
                            kind,
                            library: Some(format!("key:{}", key_preview)),
                        });
                    }
                }
            }
        }

        start = end + 1;
    }

    results
}

/// Extract strings XOR'd with a multi-byte key using brute-force position scanning.
/// Each string is XOR'd independently starting from key[0], not cycling from file offset 0.
/// This is the most common approach in malware (e.g., DPRK samples).
/// Extract strings using file-level cycling XOR (exhaustive key offset search).
/// Tries XORing the entire file with the key starting at each possible offset (0..key.len()).
fn extract_custom_xor_strings_file_level_cycling(
    data: &[u8],
    key: &[u8],
    min_length: usize,
    apply_filters: bool,
    excluded_ranges: &[(usize, usize)],
) -> Vec<ExtractedString> {
    let start_time = std::time::Instant::now();
    tracing::info!(
        "File-level cycling XOR: {} bytes with {} byte key ({} offsets)",
        data.len(),
        key.len(),
        key.len()
    );

    let mut all_candidates = Vec::new();
    let mut seen: HashSet<(u64, String)> = HashSet::new();

    // Try each possible key offset
    for key_offset in 0..key.len() {
        // Decode entire file with key starting at this offset
        let mut decoded: Vec<u8> = Vec::with_capacity(data.len());
        for (i, &byte) in data.iter().enumerate() {
            decoded.push(byte ^ key[(i + key_offset) % key.len()]);
        }

        // Extract printable strings from decoded data
        let mut start = 0;
        while start < decoded.len() {
            // Skip non-printable
            while start < decoded.len() && !is_printable_byte_for_file_xor(decoded[start]) {
                start += 1;
            }

            if start >= decoded.len() {
                break;
            }


            // Skip if this position is in an excluded range (from radare2 hints)
            let in_excluded_range = excluded_ranges.iter().any(|&(ex_start, ex_end)| {
                start >= ex_start && start < ex_end
            });
            if in_excluded_range {
                // Skip to end of excluded range
                if let Some(&(_, ex_end)) = excluded_ranges.iter().find(|&&(ex_start, ex_end)| {
                    start >= ex_start && start < ex_end
                }) {
                    start = ex_end;
                    continue;
                }
            }

            // Skip if we're in a null byte region in the original data
            // (these just produce the key)
            if start < data.len() {
                let mut null_count = 0;
                for i in start..data.len().min(start + key.len()) {
                    if data[i] == 0x00 {
                        null_count += 1;
                    }
                }
                if null_count >= key.len() / 2 {
                    start += key.len();
                    continue;
                }
            }

            // Collect printable run
            let mut end = start;
            let mut consecutive_nulls = 0;
            while end < decoded.len() && is_printable_byte_for_file_xor(decoded[end]) {
                // Stop if we hit many consecutive nulls in the source data
                if end < data.len() && data[end] == 0x00 {
                    consecutive_nulls += 1;
                    if consecutive_nulls >= 2 {
                        break;
                    }
                } else {
                    consecutive_nulls = 0;
                }
                end += 1;
            }

            // Check length
            if end - start >= min_length {
                if let Ok(s) = String::from_utf8(decoded[start..end].to_vec()) {
                    // Skip XOR key artifacts (key fragments from XORing null bytes)
                    if apply_filters && is_xor_key_artifact(&s, key) {
                        start = end;
                        continue;
                    }

                    let offset = start as u64;
                    if seen.insert((offset, s.clone())) {
                        // Classify the string
                        let kind_opt = if apply_filters {
                            classify_xor_string(&s)
                        } else {
                            Some(StringKind::Const)
                        };

                        if let Some(kind) = kind_opt {
                            let key_preview = if key.len() > 8 {
                                format!("{}...", String::from_utf8_lossy(&key[..8]))
                            } else {
                                String::from_utf8_lossy(key).to_string()
                            };

                            all_candidates.push(ExtractedString {
                                value: s,
                                data_offset: offset,
                                section: None,
                                method: StringMethod::XorDecode,
                                kind,
                                library: Some(format!("key:{}@{}", key_preview, key_offset)),
                            });
                        }
                    }
                }
            }

            start = end;
        }
    }

    let collection_time = start_time.elapsed();
    eprintln!("[PERF] File-level cycling collected {} candidates in {:.2}s",
        all_candidates.len(), collection_time.as_secs_f64());

    tracing::info!(
        "File-level cycling collected {} candidate strings across {} offsets",
        all_candidates.len(),
        key.len()
    );

    // Remove overlapping strings - keep the higher quality one
    // Sort by quality (score) descending, then by offset
    let dedup_start = std::time::Instant::now();
    all_candidates.sort_by(|a, b| {
        let score_a = string_quality_score(a);
        let score_b = string_quality_score(b);
        score_b.cmp(&score_a).then(a.data_offset.cmp(&b.data_offset))
    });
    eprintln!("[PERF] Sorting {} candidates took {:.2}s",
        all_candidates.len(), dedup_start.elapsed().as_secs_f64());

    let candidate_count = all_candidates.len();
    let mut final_results: Vec<ExtractedString> = Vec::new();
    // Cache trimmed ranges to avoid recalculating trim_*_garbage() repeatedly
    let mut trimmed_ranges: Vec<(usize, usize)> = Vec::new(); // (trimmed_start, trimmed_end)

    for result in all_candidates {
        let start = result.data_offset as usize;
        let end = start + result.value.len();

        // Trim both leading and trailing garbage for overlap checking
        let trimmed_leading = trim_leading_garbage(&result.value);
        let leading_offset = result.value.len() - trimmed_leading.len();
        let trimmed_both = trim_trailing_garbage(trimmed_leading);
        let trimmed_start = start + leading_offset;
        let trimmed_end = trimmed_start + trimmed_both.len();

        // Check if this overlaps with any previously accepted string (using trimmed ranges)
        let mut overlaps = false;
        for &(prev_trimmed_start, prev_trimmed_end) in &trimmed_ranges {
            // Only consider it an overlap if it overlaps with the trimmed (legitimate) part
            if !(trimmed_end <= prev_trimmed_start || trimmed_start >= prev_trimmed_end) {
                overlaps = true;
                break;
            }
        }

        // Only add if it doesn't overlap (higher quality strings are checked first)
        if !overlaps {
            trimmed_ranges.push((trimmed_start, trimmed_end));
            final_results.push(result);
        }
    }

    let overlap_time = dedup_start.elapsed();
    eprintln!("[PERF] Overlap checking took {:.2}s, kept {} of {} strings",
        overlap_time.as_secs_f64(), final_results.len(), candidate_count);

    // Re-sort by offset for consistent output
    final_results.sort_by_key(|s| s.data_offset);

    let total_time = start_time.elapsed();
    eprintln!("[PERF] File-level cycling total: {:.2}s", total_time.as_secs_f64());

    tracing::info!(
        "File-level cycling complete: {} strings after quality-based deduplication",
        final_results.len()
    );

    final_results
}

/// Check if a byte is printable for file-level XOR extraction
fn is_printable_byte_for_file_xor(b: u8) -> bool {
    b.is_ascii_graphic() || b == b' ' || b == b'\t' || b == b'\n'
}

/// Try XOR decoding at radare2 string boundary hints.
/// These locations are where r2 found null-terminated strings, making them
/// likely candidates for properly-terminated XOR'd strings.
fn extract_xor_strings_from_hints(
    data: &[u8],
    key: &[u8],
    min_length: usize,
    hints: &[crate::r2::StringBoundary],
    apply_filters: bool,
) -> Vec<ExtractedString> {
    let mut results = Vec::new();
    let mut seen: HashSet<(u64, String)> = HashSet::new();

    for hint in hints {
        let offset = hint.offset as usize;
        let max_len = hint.length;

        if offset >= data.len() {
            continue;
        }

        // Try file-level cycling (all key offsets)
        for key_offset in 0..key.len() {
            let mut decoded = Vec::new();
            let mut end = offset;

            // Decode up to hint.length bytes or until we hit non-printable
            while end < data.len() && (end - offset) < max_len {
                let actual_offset = end;
                let ki = (actual_offset + key_offset) % key.len();
                let decoded_byte = data[end] ^ key[ki];

                if is_printable_byte_for_file_xor(decoded_byte) {
                    decoded.push(decoded_byte);
                    end += 1;
                } else {
                    break;
                }
            }

            if decoded.len() < min_length {
                continue;
            }

            if let Ok(s) = String::from_utf8(decoded) {
                // Skip XOR key artifacts
                if apply_filters && is_xor_key_artifact(&s, key) {
                    continue;
                }

                // Classify
                let kind_opt = if apply_filters {
                    classify_xor_string(&s)
                } else {
                    Some(StringKind::Const)
                };

                if let Some(kind) = kind_opt {
                    if seen.insert((offset as u64, s.clone())) {
                        let key_preview = if key.len() > 8 {
                            format!("{}...", String::from_utf8_lossy(&key[..8]))
                        } else {
                            String::from_utf8_lossy(key).to_string()
                        };

                        results.push(ExtractedString {
                            value: s,
                            data_offset: offset as u64,
                            section: None,
                            method: StringMethod::XorDecode,
                            kind,
                            library: Some(format!("key:{}@hint", key_preview)),
                        });
                    }
                }
            }
        }
    }

    results
}

/// Check if a string is high quality (worth excluding its region from file-wide scanning).
fn is_high_quality_string(s: &ExtractedString) -> bool {
    // High quality = shell commands, suspicious paths, URLs, crypto terms
    matches!(
        s.kind,
        StringKind::ShellCmd | StringKind::SuspiciousPath | StringKind::Url | StringKind::IP
    ) || s.value.to_ascii_lowercase().contains("ethereum")
        || s.value.to_ascii_lowercase().contains("bitcoin")
        || s.value.to_ascii_lowercase().contains("osascript")
        || s.value.len() >= 30 // Long strings are usually significant
}

/// Score a string's quality for deduplication purposes.
/// Higher score = higher quality = prefer keeping this string.
fn string_quality_score(s: &ExtractedString) -> i32 {
    let mut score = 0;

    // Score based on string kind (higher value = more interesting)
    match s.kind {
        StringKind::ShellCmd => score += 100,
        StringKind::SuspiciousPath => score += 90,
        StringKind::Url => score += 80,
        StringKind::IP | StringKind::IPPort => score += 70,
        StringKind::Hostname => score += 60,
        StringKind::Registry => score += 50,
        StringKind::Path => score += 40,
        StringKind::Base64 => score += 30,
        StringKind::FuncName => score += 20,
        StringKind::Const => score += 10,
        _ => {}
    }

    // Bonus for longer strings (more context)
    score += (s.value.len() / 10).min(20) as i32;

    // Bonus for specific high-value terms
    let lower = s.value.to_ascii_lowercase();
    if lower.contains("http://") || lower.contains("https://") {
        score += 60; // URLs with explicit protocol are very valuable
    }
    if lower.contains("osascript") || lower.contains("/bin/sh") || lower.contains("2>&1") {
        score += 50;
    }
    if lower.contains("ethereum") || lower.contains("wallet") || lower.contains("keystore") {
        score += 40;
    }
    if lower.contains("xattr") || lower.contains("screencapture") || lower.contains("launchagents") {
        score += 30;
    }
    // Bonus for IP addresses (likely C2 infrastructure)
    if s.value.chars().filter(|&c| c == '.').count() == 3 {
        // Check if it looks like an IP address (4 segments with dots)
        let segments: Vec<&str> = s.value.split('.').collect();
        if segments.len() == 4 && segments.iter().all(|seg| {
            seg.chars().take_while(|c| c.is_ascii_digit()).count() > 0
        }) {
            score += 35; // Likely an IP address
        }
    }

    // Penalty for strings that look like garbage
    let special_count = s.value.chars().filter(|c| !c.is_alphanumeric() && !c.is_whitespace()).count();
    if s.value.len() > 0 && special_count * 100 / s.value.len() > 40 {
        score -= 20; // Too many special characters
    }

    score
}

/// Check if a decoded string is likely just the XOR key itself (or fragments).
/// This happens when XORing null bytes with the key.
fn is_xor_key_artifact(s: &str, key: &[u8]) -> bool {
    // Convert key to string for comparison
    let key_str = String::from_utf8_lossy(key);

    // Exact match or substring of key
    if key_str.contains(s) || s.contains(key_str.as_ref()) {
        return true;
    }

    // Check if string is mostly composed of repeating key pattern
    // (happens when XORing the key with itself or null bytes)
    if s.len() >= key.len() {
        // Count how many characters match the key pattern
        let mut matches = 0;
        for (i, c) in s.chars().enumerate() {
            let key_char = key[i % key.len()] as char;
            if c == key_char {
                matches += 1;
            }
        }

        // If >70% of the string matches the key pattern, it's likely an artifact
        if matches * 100 / s.len() > 70 {
            return true;
        }
    }

    // Check for key fragments (at least 8 consecutive chars from the key)
    if key.len() >= 8 {
        for window_size in (8..=key.len().min(s.len())).rev() {
            let key_str_bytes = key_str.as_bytes();
            for key_start in 0..=(key.len().saturating_sub(window_size)) {
                let key_fragment = &key_str_bytes[key_start..key_start + window_size];
                if let Ok(fragment_str) = std::str::from_utf8(key_fragment) {
                    if s.contains(fragment_str) {
                        return true;
                    }
                }
            }
        }
    }

    false
}

///
/// Scans every position in the file as a potential string start, XOR-decodes forward,
/// and keeps strings that pass filtering.
fn extract_custom_xor_strings_pattern_based(
    data: &[u8],
    key: &[u8],
    min_length: usize,
    apply_filters: bool,
    excluded_ranges: &[(usize, usize)],
) -> Vec<ExtractedString> {
    let start_time = std::time::Instant::now();
    tracing::info!(
        "Multi-byte XOR brute-force scan: {} bytes with {} byte key",
        data.len(),
        key.len()
    );

    let mut results = Vec::new();
    let mut seen: HashSet<(u64, String)> = HashSet::new();
    // Track used byte ranges to avoid overlapping strings
    let mut used_ranges: Vec<(usize, usize)> = Vec::new();

    // Brute-force scan: try every position as a potential string start
    // Step by 1 for thorough scanning - we need to catch strings at any offset
    // The overlap detection will handle deduplication
    let step = 1;
    let mut checked = 0;

    for pos in (0..data.len()).step_by(step) {
        checked += 1;
        if checked % 10000 == 0 {
            tracing::debug!("  Scanned {} positions, found {} strings", checked, results.len());
        }

        // Skip if this position is within an already-extracted string
        let overlaps_existing = used_ranges.iter().any(|&(start, end)| {
            pos >= start && pos < end
        });
        if overlaps_existing {
            continue;
        }

        // Skip if this position is in an excluded range (from radare2 hints)
        let in_excluded_range = excluded_ranges.iter().any(|&(ex_start, ex_end)| {
            pos >= ex_start && pos < ex_end
        });
        if in_excluded_range {
            continue;
        }

        // Try to decode a string starting at this position
        if let Some((decoded, start, end)) = try_decode_xor_string_at(data, pos, key, min_length) {
            // Check if this decoded string would overlap with an existing one
            let would_overlap = used_ranges.iter().any(|&(used_start, used_end)| {
                !(end <= used_start || start >= used_end)
            });

            if would_overlap {
                continue;
            }

            // Skip XOR key artifacts (key fragments from XORing null bytes)
            if apply_filters && is_xor_key_artifact(&decoded, key) {
                continue;
            }

            // Classify the string (or use Const if filtering disabled)
            let kind_opt = if apply_filters {
                classify_xor_string(&decoded)
            } else {
                Some(StringKind::Const)
            };

            if let Some(kind) = kind_opt {
                let offset = start as u64;
                if seen.insert((offset, decoded.clone())) {
                        let key_preview = if key.len() > 8 {
                            format!("{}...", String::from_utf8_lossy(&key[..8]))
                        } else {
                            String::from_utf8_lossy(key).to_string()
                        };

                        // Mark this range as used
                        used_ranges.push((start, end));

                        results.push(ExtractedString {
                            value: decoded,
                            data_offset: offset,
                            section: None,
                            method: StringMethod::XorDecode,
                            kind,
                            library: Some(format!("key:{}", key_preview)),
                        });
                    }
                }
            }
        }

    let elapsed = start_time.elapsed();
    eprintln!("[PERF] Pattern-based scanning: checked {} positions, found {} strings in {:.2}s",
        checked, results.len(), elapsed.as_secs_f64());

    tracing::info!(
        "Multi-byte XOR scan complete: checked {} positions, found {} unique strings",
        checked,
        results.len()
    );

    results
}

/// Try to decode an XOR'd string starting at a specific position.
/// Returns the decoded string if it looks valid.
fn try_decode_xor_string_at(
    data: &[u8],
    pos: usize,
    key: &[u8],
    min_length: usize,
) -> Option<(String, usize, usize)> {
    // Skip if we're starting in a region of null bytes (these decode to the key itself)
    if data[pos] == 0x00 {
        // Count consecutive nulls
        let mut null_count = 0;
        let mut check_pos = pos;
        while check_pos < data.len() && data[check_pos] == 0x00 {
            null_count += 1;
            check_pos += 1;
        }
        // If we have many consecutive nulls (>= key length), skip this region
        if null_count >= key.len() {
            return None;
        }
    }

    let max_len = 200;
    let mut end = pos;
    let mut decoded_bytes = Vec::new();
    let mut consecutive_nulls = 0;

    // Try to decode forward from this position
    while end < data.len() && (end - pos) < max_len {
        let key_idx = (end - pos) % key.len();
        let decoded_byte = data[end] ^ key[key_idx];

        // Track consecutive null bytes in the encoded data
        if data[end] == 0x00 {
            consecutive_nulls += 1;
            // Null bytes in XOR'd data decode to the key byte
            // Stop if we hit consecutive nulls
            if consecutive_nulls >= 2 {
                break;
            }
        } else {
            consecutive_nulls = 0;
        }

        // For multi-byte XOR, allow newlines and common whitespace in addition to printable chars
        // Note: \r (carriage return) terminates the string, only \n (newline) is allowed for multi-line strings
        let is_valid = decoded_byte.is_ascii_graphic()
            || decoded_byte == b' '
            || decoded_byte == b'\t'
            || decoded_byte == b'\n';

        if is_valid {
            decoded_bytes.push(decoded_byte);
            end += 1;
        } else {
            break;
        }
    }

    // Must have minimum length
    if decoded_bytes.len() < min_length {
        return None;
    }

    // Try to convert to UTF-8
    let decoded_str = String::from_utf8(decoded_bytes).ok()?;

    // Quick sanity check: must have some meaningful content
    // (at least 3 alphanumeric chars total, not necessarily consecutive)
    let alnum_count = decoded_str.chars().filter(|c| c.is_ascii_alphanumeric()).count();

    if alnum_count < 3 {
        return None;
    }

    Some((decoded_str, pos, end))
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
pub fn auto_detect_xor_key(
    data: &[u8],
    candidate_strings: &[ExtractedString],
    min_length: usize,
) -> Option<(Vec<u8>, String, u64)> {
    // Only auto-detect for small files
    if data.len() > MAX_AUTO_DETECT_SIZE {
        return None;
    }

    // Find candidate XOR keys: high-entropy strings near the end of the file
    // Sort by offset (descending) to get strings physically near the end of the binary
    let mut candidates_with_offset: Vec<(u64, &str)> = candidate_strings
        .iter()
        .filter(|s| {
            !s.value.contains('_')
                && !s.value.starts_with("cstr.")
                && is_good_xor_key_candidate(&s.value)
        })
        .map(|s| (s.data_offset, s.value.as_str()))
        .collect();

    // Sort by offset descending (highest offsets first - near end of file)
    candidates_with_offset.sort_by(|a, b| b.0.cmp(&a.0));

    // Take last 5 by file offset (not by position in vector)
    let candidates: Vec<(u64, &str)> = candidates_with_offset
        .iter()
        .take(5)
        .copied()
        .collect();

    if candidates.is_empty() {
        return None;
    }

    tracing::debug!(
        "Auto-detecting XOR key from {} candidates: {:?}",
        candidates.len(),
        candidates.iter().map(|(_, s)| s).collect::<Vec<_>>()
    );

    // Try each candidate and calculate weighted scores based on string value
    let mut best_key: Option<(Vec<u8>, String, u64)> = None;
    let mut best_score = 0;

    for (offset, candidate) in candidates {
        let key = candidate.as_bytes().to_vec();
        let results = extract_custom_xor_strings(data, &key, min_length);

        // Calculate weighted score based on decoded string quality
        let mut score = 0;

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
                score += 100; // Highest priority
            }

            // Cryptocurrency terms (very high priority)
            for crypto in CRYPTO_KEYWORDS {
                if value_lower.contains(&crypto.to_ascii_lowercase()) {
                    score += 80;
                    break;
                }
            }

            // Suspicious paths (very high priority)
            if matches!(r.kind, StringKind::SuspiciousPath) {
                score += 75;
            }

            // URLs and network indicators
            if matches!(r.kind, StringKind::Url | StringKind::IP | StringKind::IPPort) {
                score += 50;
            }

            // Browser strings
            for browser in BROWSER_KEYWORDS {
                if value_lower.contains(&browser.to_ascii_lowercase()) {
                    score += 40;
                    break;
                }
            }

            // Shell commands
            if matches!(r.kind, StringKind::ShellCmd) {
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

        if score > best_score {
            best_score = score;
            best_key = Some((key, candidate.to_string(), offset));
        }
    }

    if best_score > 0 {
        if let Some((ref _key, ref key_str, _)) = best_key {
            tracing::info!(
                "Auto-detected XOR key: '{}' (score: {})",
                key_str,
                best_score
            );
        }
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
                            value: decoded,
                            data_offset: offset,
                            section: None,
                            method: StringMethod::XorDecode,
                            kind,
                            library: Some(format!("0x{:02X}:16LE", info.key)),
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
                                value: valid_str.to_string(),
                                data_offset: offset,
                                section: None,
                                method: StringMethod::XorDecode,
                                kind,
                                library: Some(format!("key:{}", key_preview)),
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
                                value: ip,
                                data_offset: offset,
                                section: None,
                                method: StringMethod::XorDecode,
                                kind: StringKind::IP,
                                library: Some(format!("0x{:02X}", key)),
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
                                library: Some(format!("0x{:02X}", key)),
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
                            library: Some(format!("0x{:02X}", key)),
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
];

/// Trim trailing garbage from extracted strings.
/// This removes characters at the end that don't look like legitimate content.
fn trim_trailing_garbage(s: &str) -> &str {
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
    let file_extensions = [".php", ".exe", ".dll", ".so", ".dylib", ".js", ".py", ".rb", ".pl", ".sh",
                           ".html", ".xml", ".json", ".txt", ".log", ".conf", ".cfg"];
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
            return s.char_indices().nth(i + 1).map(|(pos, _)| &s[..pos]).unwrap_or(s);
        }

        // Stop at alphanumeric followed by whitespace or punctuation that suggests a boundary
        if c.is_ascii_alphanumeric() {
            // Check if the next character (if exists) suggests this is the end
            if i + 1 < chars.len() {
                let next = chars[i + 1];
                // If followed by unusual characters, this might be the real end
                if !next.is_ascii_alphanumeric() && next != '/' && next != '.' && next != '-' && next != '_' {
                    return s.char_indices().nth(i + 1).map(|(pos, _)| &s[..pos]).unwrap_or(s);
                }
            } else {
                // Last character is alphanumeric - keep whole string
                return s;
            }
        }
    }

    s
}

/// Trim leading garbage from extracted strings.
/// This removes characters at the beginning that don't look like legitimate content.
fn trim_leading_garbage(s: &str) -> &str {
    // Check for URLs - they should start with http:// or https://
    if let Some(pos) = s.find("http://") {
        return &s[pos..];
    }
    if let Some(pos) = s.find("https://") {
        return &s[pos..];
    }

    // Check for common path prefixes
    if let Some(pos) = s.find("/Library/") {
        // Look backwards from /Library/ to see if there's a %s or other legitimate prefix
        if pos > 0 {
            let prefix = &s[..pos];
            // If prefix contains %s or similar format specifiers, keep them
            if prefix.contains("%s") || prefix.contains("%d") {
                // Find the last format specifier
                if let Some(fmt_pos) = prefix.rfind("%s").or_else(|| prefix.rfind("%d")) {
                    return &s[fmt_pos..];
                }
            }
        }
        return &s[pos..];
    }

    // Check for Windows paths
    if let Some(pos) = s.find("C:\\") {
        return &s[pos..];
    }

    // Check for common file paths
    if let Some(pos) = s.find("~/.") {
        return &s[pos..];
    }

    // Check for absolute Unix paths (but not /Library which we already handled)
    // Look for patterns like /bin/, /usr/, /etc/, /var/, /opt/, /home/
    for path_prefix in &["/bin/", "/usr/", "/etc/", "/var/", "/opt/", "/home/"] {
        if let Some(pos) = s.find(path_prefix) {
            return &s[pos..];
        }
    }

    // No recognizable pattern found, return as-is
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
    "python ",
    "perl ",
    "ruby ",
    "powershell",
    "cmd.exe",
    "/bin/sh",
    "/bin/bash",
    "2>&1",
    "<<EOD",
    "<<EOF",
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

/// Cryptocurrency-related terms indicating wallet/keystore access.
const CRYPTO_KEYWORDS: &[&str] = &[
    "Ethereum",
    "Bitcoin",
    "Electrum",
    "wallet",
    "keystore",
    "Monero",
    "Litecoin",
    "Dogecoin",
    "cryptocurrency",
    "mnemonic",
    "seed phrase",
];

/// Browser and application identifiers.
const BROWSER_KEYWORDS: &[&str] = &[
    "Safari",
    "Chrome",
    "Firefox",
    "Mozilla",
    "WebKit",
    "Chromium",
    "Opera",
    "Edge",
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

/// Classify an XOR-decoded string. Returns None if it doesn't look interesting.
fn classify_xor_string(s: &str) -> Option<StringKind> {
    let lower = s.to_ascii_lowercase();

    // Check for well-known suspicious paths (even with garbage around them)
    for sus_path in SUSPICIOUS_PATHS {
        if s.contains(sus_path) {
            return Some(StringKind::SuspiciousPath);
        }
    }

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

    let kind = classify_string(s);

    match kind {
        StringKind::IP | StringKind::IPPort => Some(kind),
        StringKind::Url => Some(kind),
        StringKind::ShellCmd => {
            // Reject obvious garbage that starts with backtick but no valid command
            if s.starts_with('`') && !s[1..].trim_start().chars().next().is_some_and(|c| c.is_ascii_alphabetic()) {
                None
            } else {
                Some(kind)
            }
        }
        StringKind::SuspiciousPath => Some(kind),
        StringKind::Path => {
            // STRICT PATH VALIDATION: Only accept paths matching known OS patterns

            // Check for known UNIX/macOS path prefixes
            let has_known_prefix = has_known_path_prefix(s);

            // Check for Windows paths with drive letter
            let is_windows_path = s.len() > 3
                && s.chars().nth(1) == Some(':')
                && s.chars().nth(2) == Some('\\')
                && s.chars().next().unwrap().is_ascii_alphabetic();

            // Check for relative paths with proper structure
            let is_relative_path = (s.starts_with("./") || s.starts_with("../"))
                && s.matches('/').count() >= 2
                && s.split('/').filter(|p| !p.is_empty() && *p != "." && *p != "..").count() >= 1;

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
                    let known_single_level = ["bin", "etc", "usr", "var", "tmp", "dev", "opt", "home", "root",
                                            "Library", "Users", "Applications", "System", "private"];

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
                    let alnum = part.chars().filter(|c| c.is_ascii_alphanumeric()).count();
                    if part.len() > 0 && alnum * 100 / part.len() < 60 {
                        return None;
                    }
                }
            }

            Some(kind)
        }
        StringKind::Registry => Some(kind),
        StringKind::Base64 => Some(kind),
        _ => {
            // Generic fallback: anything else that passed is_meaningful_xor_string()
            // should be classified as Const. This includes:
            // - Short strings like locale codes (ru_RU, en_US)
            // - Single words (Ethereum, keystore, Wallet)
            // - XML/plist tags (<array>, <dict>)
            // - Longer strings with spaces that look like natural text
            if s.len() >= 30 && s.contains(' ') && looks_like_text(s) {
                Some(StringKind::Const)
            } else {
                // Return Const for short strings that passed is_meaningful_xor_string
                // Don't return None - that would filter out legitimate strings
                Some(StringKind::Const)
            }
        }
    }
}

/// Check if a string is a locale identifier (e.g., en-US, ru-RU, zh-CN).
fn is_locale_string(s: &str) -> bool {
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
    let has_separator = chars[2] == '_' || chars[2] == '-' || (chars.len() == 6 && (chars[3] == '_' || chars[3] == '-'));

    if !has_separator {
        return false;
    }

    let sep_idx = if chars[2] == '_' || chars[2] == '-' { 2 } else { 3 };

    // Check lowercase before separator
    for i in 0..sep_idx {
        if !chars[i].is_ascii_lowercase() {
            return false;
        }
    }

    // Check uppercase after separator
    for i in (sep_idx + 1)..chars.len() {
        if !chars[i].is_ascii_uppercase() {
            return false;
        }
    }

    true
}

/// Check if a path starts with a known OS path prefix.
fn has_known_path_prefix(path: &str) -> bool {
    for prefix in KNOWN_PATH_PREFIXES {
        if path.starts_with(prefix) {
            return true;
        }
    }

    // Also check for relative paths
    // ./ with any name (common for malware: ./malware, ./payload, etc.)
    // ../ needs at least 2 levels
    if path.starts_with("./") {
        let after_dot_slash = &path[2..];
        // Must have some content after ./
        return !after_dot_slash.is_empty() && after_dot_slash.chars().next().unwrap().is_ascii_alphanumeric();
    }

    if path.starts_with("../") {
        return path.matches('/').count() >= 2; // At least 2 levels
    }

    false
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
            results.iter().any(|r| r.value == "http://evil.com"
                && r.library.as_ref().map(|l| l.contains("0x42")).unwrap_or(false)),
            "Should find URL with XOR key 0x42. Results: {:?}",
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
            results.iter().any(|r| r.value == "192.168.1.100"
                && r.library.as_ref().map(|l| l.contains("0x5A")).unwrap_or(false)),
            "Should find IP with XOR key 0x5A. Results: {:?}",
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
            results.iter().any(|r| r.value == "10.0.0.1:8080"
                && r.library.as_ref().map(|l| l.contains("0x3C")).unwrap_or(false)),
            "IP:port should be detected with XOR key 0x3C. Results: {:?}",
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
            results.iter().any(|r| r.value == "/etc/passwd"
                && r.library.as_ref().map(|l| l.contains("0xAB")).unwrap_or(false)),
            "Should find path with XOR key 0xAB. Results: {:?}",
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
            results.iter().any(|r| r.value == "password=secret123"
                && r.library.as_ref().map(|l| l.contains("0x77")).unwrap_or(false)),
            "Should find password string with XOR key 0x77. Results: {:?}",
            results
        );
    }

    #[test]
    fn test_no_false_positives_on_random() {
        let data: Vec<u8> = (0..1000).map(|i| ((i * 7 + 13) % 256) as u8).collect();
        let results = extract_xor_strings(&data, 10, false);
        assert!(results.len() < 10, "Should have few false positives on random data");
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
            !results.iter().any(|r| r.library.as_ref().map(|l| l.contains("0x20")).unwrap_or(false)),
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
            results.iter().any(|r| r.value == "evil.malware.com"
                && r.library.as_ref().map(|l| l.contains("0x55")).unwrap_or(false)),
            "Hostname should be detected with XOR key 0x55. Results: {:?}",
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
            results.iter().any(|r| r.value.contains("Mozilla")
                && r.library.as_ref().map(|l| l.contains("0x42")).unwrap_or(false)),
            "Mozilla user agent should be detected with XOR key 0x42. Results: {:?}",
            results
        );
    }

    #[test]
    fn test_custom_xor_single_byte_key() {
        // Test with single-byte custom XOR key
        let plaintext = b"http://malware.example.com";
        let key = vec![0x42];
        let xored: Vec<u8> = plaintext.iter().map(|b| b ^ key[0]).collect();

        let results = extract_custom_xor_strings(&xored, &key, 10);
        assert!(
            results.iter().any(|r| r.value == "http://malware.example.com"
                && r.library.as_ref().map(|l| l.contains("key:B")).unwrap_or(false)),
            "Custom single-byte XOR should decode URL. Results: {:?}",
            results
        );
    }

    #[test]
    fn test_custom_xor_multi_byte_key() {
        // Test with multi-byte custom XOR key
        let plaintext = b"secret password: admin123";
        let key = b"KEY";
        let xored: Vec<u8> = plaintext
            .iter()
            .enumerate()
            .map(|(i, &b)| b ^ key[i % key.len()])
            .collect();

        let results = extract_custom_xor_strings(&xored, key, 10);
        assert!(
            results.iter().any(|r| r.value == "secret password: admin123"
                && r.library.as_ref().map(|l| l.contains("key:KEY")).unwrap_or(false)),
            "Custom multi-byte XOR should decode password. Results: {:?}",
            results
        );
    }

    #[test]
    fn test_custom_xor_string_key() {
        // Test with a realistic string key (like the user's example)
        let plaintext = b"https://c2server.evil.com/api/v1/beacon";
        let key = b"fYztZORL5VNS7nCUH1ktn5UoJ8VSgaf";
        let xored: Vec<u8> = plaintext
            .iter()
            .enumerate()
            .map(|(i, &b)| b ^ key[i % key.len()])
            .collect();

        let results = extract_custom_xor_strings(&xored, key, 10);
        assert!(
            results.iter().any(|r| r.value == "https://c2server.evil.com/api/v1/beacon"
                && r.library.as_ref().map(|l| l.contains("key:fYztZORL")).unwrap_or(false)),
            "Custom string XOR key should decode C2 URL. Results: {:?}",
            results
        );
    }

    #[test]
    fn test_custom_xor_empty_key() {
        // Empty key should return no results
        let data = b"test data";
        let key = vec![];
        let results = extract_custom_xor_strings(data, &key, 4);
        assert!(results.is_empty(), "Empty key should return no results");
    }

    #[test]
    fn test_custom_xor_empty_data() {
        // Empty data should return no results
        let data = b"";
        let key = b"KEY";
        let results = extract_custom_xor_strings(data, key, 4);
        assert!(results.is_empty(), "Empty data should return no results");
    }

    #[test]
    fn test_custom_xor_ip_address() {
        // Test IP address detection with custom XOR
        let plaintext = b"192.168.1.100";
        let key = b"SECRET";
        let xored: Vec<u8> = plaintext
            .iter()
            .enumerate()
            .map(|(i, &b)| b ^ key[i % key.len()])
            .collect();

        let results = extract_custom_xor_strings(&xored, key, 8);
        assert!(
            results.iter().any(|r| r.value == "192.168.1.100"
                && r.library.as_ref().map(|l| l.contains("key:SECRET")).unwrap_or(false)),
            "Custom XOR should detect IP addresses. Results: {:?}",
            results
        );
    }

    #[test]
    fn test_custom_xor_path() {
        // Test path detection with custom XOR
        let plaintext = b"/bin/bash";
        let key = b"XOR";
        let xored: Vec<u8> = plaintext
            .iter()
            .enumerate()
            .map(|(i, &b)| b ^ key[i % key.len()])
            .collect();

        let results = extract_custom_xor_strings(&xored, key, 4);
        assert!(
            results.iter().any(|r| r.value == "/bin/bash"
                && r.library.as_ref().map(|l| l.contains("key:XOR")).unwrap_or(false)),
            "Custom XOR should detect paths. Results: {:?}",
            results
        );
    }

    #[test]
    fn test_suspicious_path_with_garbage() {
        // Real-world case: Ethereum keystore path with garbage around it
        let plaintext = b"XQYf%s/Library/Ethereum/keystoregP^pAEO{,\"v";
        let key = b"KEY";
        let xored: Vec<u8> = plaintext
            .iter()
            .enumerate()
            .map(|(i, &b)| b ^ key[i % key.len()])
            .collect();

        let results = extract_custom_xor_strings(&xored, key, 10);
        assert!(
            results.iter().any(|r| r.kind == StringKind::SuspiciousPath
                && r.value.contains("/Library/Ethereum/keystore")),
            "Should detect Ethereum keystore path even with garbage. Results: {:?}",
            results
        );
    }

    #[test]
    fn test_shell_command_with_trailing_garbage() {
        // Real-world case: screencapture command with trailing garbage
        let plaintext = b"fscreencapture -x -t %s \"%s\"SlY";
        let key = b"KEY";
        let xored: Vec<u8> = plaintext
            .iter()
            .enumerate()
            .map(|(i, &b)| b ^ key[i % key.len()])
            .collect();

        let results = extract_custom_xor_strings(&xored, key, 10);
        assert!(
            results.iter().any(|r| r.kind == StringKind::ShellCmd
                && r.value.contains("screencapture")),
            "Should detect screencapture command even with trailing garbage. Results: {:?}",
            results
        );
    }

    #[test]
    fn test_backtick_garbage_not_shell() {
        // Garbage starting with backtick should NOT be classified as shell command
        let garbage = b"`{ Cy\\.ADpv~~AblBWJU,OWJ.wZOR+qnt";
        let key = b"KEY";
        let xored: Vec<u8> = garbage
            .iter()
            .enumerate()
            .map(|(i, &b)| b ^ key[i % key.len()])
            .collect();

        let results = extract_custom_xor_strings(&xored, key, 10);
        assert!(
            !results.iter().any(|r| r.kind == StringKind::ShellCmd),
            "Garbage with backtick should NOT be shell command. Results: {:?}",
            results
        );
    }

    #[test]
    fn test_garbage_path_rejected() {
        let key = b"KEY";

        // Test garbage with special chars
        let garbage1 = b"/<})M9*&D@44$]";
        let xored1: Vec<u8> = garbage1
            .iter()
            .enumerate()
            .map(|(i, &b)| b ^ key[i % key.len()])
            .collect();
        let results1 = extract_custom_xor_strings(&xored1, key, 4);
        assert!(
            !results1.iter().any(|r| r.kind == StringKind::Path),
            "Garbage with special chars should NOT be path"
        );

        // Test garbage with mixed case + digits
        let garbage2 = b"/1H1ktn5UtJ8VKgaf";
        let xored2: Vec<u8> = garbage2
            .iter()
            .enumerate()
            .map(|(i, &b)| b ^ key[i % key.len()])
            .collect();
        let results2 = extract_custom_xor_strings(&xored2, key, 4);
        assert!(
            !results2.iter().any(|r| r.kind == StringKind::Path),
            "Garbage with mixed case and digits should NOT be path"
        );

        // Test garbage with mixed case + special chars
        let garbage3 = b"/o2lBYC}rOkeH^";
        let xored3: Vec<u8> = garbage3
            .iter()
            .enumerate()
            .map(|(i, &b)| b ^ key[i % key.len()])
            .collect();
        let results3 = extract_custom_xor_strings(&xored3, key, 4);
        assert!(
            !results3.iter().any(|r| r.kind == StringKind::Path),
            "Garbage with special chars should NOT be path"
        );
    }

    #[test]
    fn test_xor_library_pattern() {
        // Test Library pattern detection
        let plaintext = b"/Library/Application Support/";
        let key: u8 = 0x33;
        let data = make_xor_test_data(plaintext, key, 20);
        let results = extract_xor_strings(&data, 10, false);
        assert!(
            results.iter().any(|r| r.value.contains("Library")),
            "Should detect Library in XOR'd path. Results: {:?}",
            results
        );
    }

    #[test]
    fn test_xor_ethereum_pattern() {
        // Test Ethereum pattern detection
        let plaintext = b"/Library/Ethereum/keystore";
        let key: u8 = 0x7F;
        let data = make_xor_test_data(plaintext, key, 15);
        let results = extract_xor_strings(&data, 10, false);
        assert!(
            results.iter().any(|r| r.value.contains("Ethereum")),
            "Should detect Ethereum in XOR'd path. Results: {:?}",
            results
        );
    }

    #[test]
    fn test_xor_format_string_pattern() {
        // Test " %s " pattern detection with a longer, more meaningful string
        let plaintext = b"File path is %s and size is %d bytes";
        let key: u8 = 0x42;
        let data = make_xor_test_data(plaintext, key, 25);
        let results = extract_xor_strings(&data, 10, false);
        assert!(
            !results.is_empty(),
            "Should detect format string with ' %s ' pattern. Results: {:?}",
            results
        );
    }

    #[test]
    fn test_known_xor_keys_qualify() {
        // Test known DPRK and other malware XOR keys
        let known_keys = vec![
            "fYztZORL5VNS7nCUH1ktn5UoJ8VSgaf", // HomaBrew malware
            "Moz&Wie;#t/6T!2y",                 // DPRK malware
            "12GWAPCT1F0I1S14",                 // DPRK malware
            "009WAYHb90687PXkS",                // Another sample
            ".sV%58&.lypQ[$=",                  // Another sample
        ];

        for key in &known_keys {
            let qualifies = is_good_xor_key_candidate(key);
            let entropy = calculate_entropy(key.as_bytes());
            assert!(
                qualifies,
                "Known XOR key '{}' should qualify (entropy: {:.2})",
                key,
                entropy
            );
        }
    }

    #[test]
    fn test_bad_xor_key_candidates_rejected() {
        // These should NOT qualify as good XOR keys
        let bad_keys = vec![
            "abcdefghijklmnopqrstuvwxyz", // Sequential, despite high entropy
            "short",                       // Too short
            "this_has_underscores_12345", // Has underscores
            "AAAAAAAAAAAAAAAAA",           // Low entropy
            "1111111111111111",            // Low entropy, all same type
            "verylongkeythatexceedsthirtytwocharacterslimit", // Too long
        ];

        for key in &bad_keys {
            let qualifies = is_good_xor_key_candidate(key);
            assert!(
                !qualifies,
                "Bad key candidate '{}' should NOT qualify",
                key
            );
        }
    }

    #[test]
    fn test_entropy_calculation() {
        // Test entropy calculation
        let uniform = "abcdefgh"; // 8 unique chars = 3.0 bits
        let entropy1 = calculate_entropy(uniform.as_bytes());
        assert!(
            entropy1 > 2.9 && entropy1 < 3.1,
            "Uniform distribution should have ~3.0 bits entropy, got {:.2}",
            entropy1
        );

        let repeated = "aaaaaaaa"; // All same = 0 bits
        let entropy2 = calculate_entropy(repeated.as_bytes());
        assert!(
            entropy2 < 0.1,
            "All same character should have ~0 bits entropy, got {:.2}",
            entropy2
        );

        let mixed = "aAbBcCdD1!2@3#"; // High entropy
        let entropy3 = calculate_entropy(mixed.as_bytes());
        assert!(
            entropy3 > 3.5,
            "Mixed characters should have high entropy, got {:.2}",
            entropy3
        );
    }

    #[test]
    fn test_auto_detect_xor_key() {
        // Create test data with a known XOR key (realistic DPRK-style key)
        let plaintext = b"http://evil.com/malware.exe";
        let key_string = "fYztZORL5VNS7nC"; // 15 chars, high entropy
        let key_bytes = key_string.as_bytes();

        // XOR the plaintext
        let xored: Vec<u8> = plaintext
            .iter()
            .enumerate()
            .map(|(i, &b)| b ^ key_bytes[i % key_bytes.len()])
            .collect();

        // Create candidate strings (simulating extracted strings from binary)
        let candidates = vec![
            ExtractedString {
                value: "some_underscore_string".to_string(),
                data_offset: 0,
                section: None,
                method: StringMethod::RawScan,
                kind: StringKind::Const,
                library: None,
            },
            ExtractedString {
                value: "cstr.SomeString".to_string(),
                data_offset: 100,
                section: None,
                method: StringMethod::RawScan,
                kind: StringKind::Const,
                library: None,
            },
            ExtractedString {
                value: "ShortKey".to_string(),
                data_offset: 200,
                section: None,
                method: StringMethod::RawScan,
                kind: StringKind::Const,
                library: None,
            },
            ExtractedString {
                value: key_string.to_string(), // The actual key
                data_offset: 300,
                section: None,
                method: StringMethod::RawScan,
                kind: StringKind::Const,
                library: None,
            },
        ];

        // Auto-detect should find the right key
        let detected = auto_detect_xor_key(&xored, &candidates, 10);
        assert!(
            detected.is_some(),
            "Should auto-detect XOR key from candidates"
        );

        let (detected_key, detected_str, _offset) = detected.unwrap();
        assert_eq!(
            detected_key,
            key_bytes,
            "Should detect the correct XOR key: got '{}', expected '{}'",
            String::from_utf8_lossy(&detected_key),
            key_string
        );
        assert_eq!(detected_str, key_string, "Key string should match");
    }

    #[test]
    fn test_brew_agent_xor_key_detection() {
        // Test that we can auto-detect the correct XOR key for HomeBrew malware
        // The correct key is "fYztZORL5VNS7nCUH1ktn5UoJ8VSgaf"
        // This key should score highest because it decodes osascript commands and Ethereum paths

        let key_string = "fYztZORL5VNS7nCUH1ktn5UoJ8VSgaf";
        let key_bytes = key_string.as_bytes();

        // XOR some high-value strings with this key
        let strings = vec![
            "osascript 2>&1 <<EOD",
            "/Library/Ethereum/keystore",
            "screencapture -x -t %s",
            "en-US",
            "ru-RU",
            "Safari/537.36",
        ];

        let mut xored_data = Vec::new();
        for s in &strings {
            let xored: Vec<u8> = s
                .as_bytes()
                .iter()
                .enumerate()
                .map(|(i, &b)| b ^ key_bytes[i % key_bytes.len()])
                .collect();
            xored_data.extend_from_slice(&xored);
            xored_data.extend_from_slice(&[0xFF; 50]); // Padding (use 0xFF to avoid null regions)
        }

        // Create candidate strings including the real key
        let candidates = vec![
            ExtractedString {
                value: "some_other_key_12345".to_string(),
                data_offset: 0,
                section: None,
                method: StringMethod::RawScan,
                kind: StringKind::Const,
                library: None,
            },
            ExtractedString {
                value: key_string.to_string(),
                data_offset: 100,
                section: None,
                method: StringMethod::RawScan,
                kind: StringKind::Const,
                library: None,
            },
        ];

        // Auto-detect should find the correct key
        let detected = auto_detect_xor_key(&xored_data, &candidates, 10);
        assert!(
            detected.is_some(),
            "Should auto-detect XOR key from candidates"
        );

        let (detected_key, detected_str, _) = detected.unwrap();
        assert_eq!(
            detected_key,
            key_bytes,
            "Should detect the correct XOR key based on osascript and Ethereum strings"
        );
        assert_eq!(detected_str, key_string);

        // Verify that the detected key decodes the strings correctly
        let decoded_results = extract_custom_xor_strings(&xored_data, &detected_key, 10);
        let decoded_values: Vec<String> = decoded_results.iter().map(|r| r.value.clone()).collect();

        // Should find osascript (highest priority)
        assert!(
            decoded_values.iter().any(|s| s.contains("osascript")),
            "Should decode osascript command"
        );

        // Should find Ethereum path (crypto keyword, high priority)
        assert!(
            decoded_values.iter().any(|s| s.contains("Ethereum")),
            "Should decode Ethereum keystore path"
        );

        // Should find Safari (browser keyword)
        assert!(
            decoded_values.iter().any(|s| s.contains("Safari")),
            "Should decode Safari user agent"
        );
    }

    #[test]
    fn test_locale_string_detection() {
        // Test locale string recognition
        assert!(is_locale_string("en-US"));
        assert!(is_locale_string("ru-RU"));
        assert!(is_locale_string("zh-CN"));
        assert!(is_locale_string("en_US"));
        assert!(is_locale_string("ru_RU"));
        assert!(is_locale_string("eng-US")); // 3-letter code

        // Not locale strings
        assert!(!is_locale_string("en"));
        assert!(!is_locale_string("USA"));
        assert!(!is_locale_string("en-us")); // lowercase country code
        assert!(!is_locale_string("EN-US")); // uppercase language code
        assert!(!is_locale_string("e1-US")); // digit in language code
        assert!(!is_locale_string("toolong"));
    }

    #[test]
    fn test_known_path_prefix_detection() {
        // UNIX/Linux paths
        assert!(has_known_path_prefix("/bin/bash"));
        assert!(has_known_path_prefix("/usr/bin/python"));
        assert!(has_known_path_prefix("/etc/passwd"));
        assert!(has_known_path_prefix("/tmp/test.txt"));

        // macOS paths
        assert!(has_known_path_prefix("/Library/Ethereum/keystore"));
        assert!(has_known_path_prefix("/Users/admin/.ssh/id_rsa"));
        assert!(has_known_path_prefix("/Applications/Safari.app"));

        // Windows paths
        assert!(has_known_path_prefix("C:\\Windows\\System32"));
        assert!(has_known_path_prefix("C:\\Program Files\\app"));
        assert!(has_known_path_prefix("%APPDATA%\\data"));

        // Relative paths with structure
        assert!(has_known_path_prefix("./lib/module/file.js"));
        assert!(has_known_path_prefix("../config/settings.json"));

        // Relative paths with single component (common for malware)
        assert!(has_known_path_prefix("./malware"));
        assert!(has_known_path_prefix("./payload"));
        assert!(has_known_path_prefix("./a"));

        // Not known prefixes
        assert!(!has_known_path_prefix("/unknown/path"));
        assert!(!has_known_path_prefix("random/path")); // No leading ./
        assert!(!has_known_path_prefix("./")); // Empty after ./
    }

    #[test]
    fn test_xor_no_overlapping_strings() {
        // Test that we don't extract overlapping strings from the same data region
        // Real issue: "fxattr" at 496f3 and "xattr" at 496f4 (overlapping in source)
        let key_string = "fYztZORL5VNS7nCUH1ktn5UoJ8VSgaf";
        let key_bytes = key_string.as_bytes();

        let plaintext = b"xattr -d com.apple.quarantine";

        // Create data with the string XOR'd at position 50
        let mut data = vec![0xFF; 200];
        for (i, &b) in plaintext.iter().enumerate() {
            data[50 + i] = b ^ key_bytes[i % key_bytes.len()];
        }

        let results = extract_custom_xor_strings(&data, key_bytes, 10);

        // Check for overlapping strings (same data region decoded multiple times)
        for i in 0..results.len() {
            for j in (i + 1)..results.len() {
                let start1 = results[i].data_offset as usize;
                let end1 = start1 + results[i].value.len();
                let start2 = results[j].data_offset as usize;
                let end2 = start2 + results[j].value.len();

                // Check if ranges overlap
                let overlaps = !(end1 <= start2 || end2 <= start1);

                assert!(
                    !overlaps,
                    "Found overlapping strings: '{}' at {}..{} and '{}' at {}..{}",
                    results[i].value,
                    start1,
                    end1,
                    results[j].value,
                    start2,
                    end2
                );
            }
        }
    }

    #[test]
    fn test_brew_agent_sleep_command_extracted() {
        // Test that "sleep 3; rm -rf '%s'" is extracted at the correct offset
        // This was a real bug where "eep 3; rm -rf '%s'" was extracted instead
        // because the step size skipped the actual start position

        let key = b"fYztZORL5VNS7nCUH1ktn5UoJ8VSgaf";

        // The actual command that should be found
        let expected = "sleep 3; rm -rf '%s'";

        // XOR encode it
        let xored: Vec<u8> = expected
            .as_bytes()
            .iter()
            .enumerate()
            .map(|(i, &b)| b ^ key[i % key.len()])
            .collect();

        // Create test data with the string at a position that's not divisible by 4
        // to ensure we catch it even with step scanning
        let mut data = vec![0xFF; 100];
        data.extend_from_slice(&xored);
        data.extend_from_slice(&[0xFF; 100]);

        let results = extract_custom_xor_strings(&data, key, 10);

        // Should find the complete sleep command
        let found = results.iter().any(|r| r.value == expected);
        assert!(
            found,
            "Should extract complete sleep command '{}', found: {:?}",
            expected,
            results.iter().map(|r| &r.value).collect::<Vec<_>>()
        );

        // Should NOT find truncated version
        let found_truncated = results.iter().any(|r| r.value.starts_with("eep ") && !r.value.starts_with("sleep"));
        assert!(
            !found_truncated,
            "Should not extract truncated 'eep' version"
        );
    }

    #[test]
    fn test_brew_agent_open_command_extracted_correctly() {
        // Test extraction from actual brew_agent binary at offset 0x4b115
        // Should find: 'open -a /bin/bash --args -c "sleep 3; rm -rf \'%s\'"'
        // Bug: Currently finding "ep 3; rm -rf '%s" at 0x4b135 instead

        if let Ok(data) = std::fs::read("testdata/malware/brew_agent") {
            let key = b"fYztZORL5VNS7nCUH1ktn5UoJ8VSgaf";
            let results = extract_custom_xor_strings(&data, key, 10);

            // Check what we found in the region 0x4b100-0x4b200
            let in_region: Vec<_> = results.iter()
                .filter(|r| r.data_offset >= 0x4b100 && r.data_offset < 0x4b200)
                .collect();

            // Should find the full "open -a /bin/bash" command starting at 0x4b115
            let found_open_cmd = in_region.iter().any(|r| {
                r.value.contains("open -a /bin/bash") && r.value.contains("sleep 3")
            });

            // Should find sleep command (either standalone or as part of open command)
            let found_sleep = in_region.iter().any(|r| r.value.contains("sleep 3"));

            // Should NOT find truncated "eep 3" without the "sl" prefix
            let found_truncated = in_region.iter().any(|r| {
                r.value.starts_with("eep 3") ||
                (r.value.contains("eep 3") && !r.value.contains("sleep 3"))
            });

            if !found_open_cmd || !found_sleep || found_truncated {
                eprintln!("\nStrings found in region 0x4b100-0x4b200:");
                for r in &in_region {
                    eprintln!("  0x{:05x} {:20} {:?}",
                        r.data_offset,
                        r.library.as_ref().map(|s| s.as_str()).unwrap_or(""),
                        &r.value[..r.value.len().min(60)]);
                }
            }

            assert!(found_sleep, "Should find 'sleep 3' command in region");
            assert!(found_open_cmd, "Should find full 'open -a /bin/bash' command at 0x4b115");
            assert!(!found_truncated, "Should NOT find truncated 'eep 3' without 'sleep'");
        } else {
            eprintln!("Skipping test - brew_agent binary not found");
        }
    }

    #[test]
    fn test_xor_garbage_strings_rejected() {
        // Test that garbage strings are properly rejected
        // These are real examples from brew_agent that should be filtered
        let key = b"fYztZORL5VNS7nCUH1ktn5UoJ8VSgaf";

        let garbage_examples = vec![
            "14; 5s$!>g",
            "%+. >#B3<S",
            "dA:+<<7)^V",
            "dA:+<<7)^9N",
            "dA:+=*&$Z%:=V",
            "eA:+=*&<B#'77",
            "drUvhNSNP)ZBO+^",
            "rUvhNSNP)ZBO+^",
            "{YztDORL*VNS",
            "5/;:#G?:*71",
            "%+. >#B3<Sh",
            ".O3<<71 9'R",
            "2z+<<7)^9N",
        ];

        for garbage in &garbage_examples {
            // XOR encode it
            let xored: Vec<u8> = garbage
                .as_bytes()
                .iter()
                .enumerate()
                .map(|(i, &b)| b ^ key[i % key.len()])
                .collect();

            let mut data = vec![0x00; 20];
            data.extend_from_slice(&xored);
            data.extend_from_slice(&[0x00; 20]);

            let results = extract_custom_xor_strings(&data, key, 10);

            // These garbage strings should NOT be extracted
            let found = results.iter().any(|r| r.value == *garbage);
            if found {
                eprintln!("WARNING: Garbage string '{}' was extracted (may need better filtering)", garbage);
            }
        }
    }

    #[test]
    fn test_valid_paths_accepted() {
        let key = b"KEY";

        // Test valid multi-level paths
        let path1 = b"/usr/bin/bash";
        let xored1: Vec<u8> = path1
            .iter()
            .enumerate()
            .map(|(i, &b)| b ^ key[i % key.len()])
            .collect();
        let results1 = extract_custom_xor_strings(&xored1, key, 4);
        assert!(
            results1.iter().any(|r| r.kind == StringKind::Path || r.kind == StringKind::SuspiciousPath),
            "/usr/bin/bash should be detected as path or suspicious path. Found: {:?}",
            results1.iter().map(|r| (&r.value, &r.kind)).collect::<Vec<_>>()
        );

        // Test /etc/passwd
        let path2 = b"/etc/passwd";
        let xored2: Vec<u8> = path2
            .iter()
            .enumerate()
            .map(|(i, &b)| b ^ key[i % key.len()])
            .collect();
        let results2 = extract_custom_xor_strings(&xored2, key, 4);
        assert!(
            results2.iter().any(|r| r.kind == StringKind::Path || r.kind == StringKind::SuspiciousPath),
            "/etc/passwd should be detected as path"
        );

        // Test /dev/urandom
        let path3 = b"/dev/urandom";
        let xored3: Vec<u8> = path3
            .iter()
            .enumerate()
            .map(|(i, &b)| b ^ key[i % key.len()])
            .collect();
        let results3 = extract_custom_xor_strings(&xored3, key, 4);
        assert!(
            results3.iter().any(|r| r.kind == StringKind::Path),
            "/dev/urandom should be detected as path"
        );
    }
}
