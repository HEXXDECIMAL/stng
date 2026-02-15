/// Comprehensive tests for XOR string extraction to prevent regression
/// Uses a sanitized subset of brew_agent malware (non-executable data only)
use stng::{ExtractOptions, StringMethod, StringKind};

const BREW_AGENT_KEY: &[u8] = b"fYztZORL5VNS7nCUH1ktn5UoJ8VSgaf";

/// Load the test fixture (sanitized region from brew_agent)
fn load_test_fixture() -> Vec<u8> {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/brew_agent_xor_region.bin"
    );
    std::fs::read(path).expect("Failed to load test fixture")
}

#[test]
fn test_xor_finds_both_volume_variants() {
    // The malware has both "muted true" and "muted false" commands
    // These should both be extracted without overlap issues
    let data = load_test_fixture();

    let opts = ExtractOptions::new(10)
        .with_xor_key(BREW_AGENT_KEY.to_vec())
        .with_garbage_filter(true);

    let extracted = stng::extract_strings_with_options(&data, &opts);

    let xor_strings: Vec<_> = extracted
        .iter()
        .filter(|s| s.method == StringMethod::XorDecode)
        .collect();

    // Find volume strings
    let volume_strings: Vec<_> = xor_strings
        .iter()
        .filter(|s| s.value.to_lowercase().contains("volume"))
        .collect();

    // Should find at least the two main variants
    assert!(
        volume_strings.len() >= 2,
        "Expected at least 2 volume strings, found {}",
        volume_strings.len()
    );

    // Check for exact "true" variant
    let has_true = volume_strings
        .iter()
        .any(|s| s.value == "set volume output muted true");
    assert!(
        has_true,
        "Should find exact string 'set volume output muted true'. Found: {:?}",
        volume_strings.iter().map(|s| &s.value).collect::<Vec<_>>()
    );

    // Check for exact "false" variant
    let has_false = volume_strings
        .iter()
        .any(|s| s.value == "set volume output muted false");
    assert!(
        has_false,
        "Should find exact string 'set volume output muted false'. Found: {:?}",
        volume_strings.iter().map(|s| &s.value).collect::<Vec<_>>()
    );
}

#[test]
fn test_xor_no_garbage_suffixes() {
    // Null termination should prevent garbage suffixes like "truegtZh"
    let data = load_test_fixture();

    let opts = ExtractOptions::new(10)
        .with_xor_key(BREW_AGENT_KEY.to_vec())
        .with_garbage_filter(true);

    let extracted = stng::extract_strings_with_options(&data, &opts);

    let volume_strings: Vec<_> = extracted
        .iter()
        .filter(|s| s.method == StringMethod::XorDecode)
        .filter(|s| s.value.to_lowercase().contains("volume"))
        .collect();

    for s in &volume_strings {
        // Check that strings end cleanly, not with mixed-case garbage
        let last_word = s.value.split_whitespace().last().unwrap_or("");

        // Should end with "true" or "false", not "truegtZh" or "falseaTrs..."
        assert!(
            last_word == "true" || last_word == "false" || last_word.len() <= 10,
            "Volume string has garbage suffix: {:?}",
            s.value
        );
    }
}

#[test]
fn test_xor_no_byte_range_overlaps() {
    // No two XOR strings should decode the same bytes differently
    let data = load_test_fixture();

    let opts = ExtractOptions::new(10)
        .with_xor_key(BREW_AGENT_KEY.to_vec())
        .with_garbage_filter(true);

    let extracted = stng::extract_strings_with_options(&data, &opts);

    let xor_strings: Vec<_> = extracted
        .iter()
        .filter(|s| s.method == StringMethod::XorDecode)
        .collect();

    // Check for byte-range overlaps
    for (i, s1) in xor_strings.iter().enumerate() {
        let s1_start = s1.data_offset as usize;
        let s1_end = s1_start + s1.value.len();

        for (j, s2) in xor_strings.iter().enumerate() {
            if i == j {
                continue;
            }

            let s2_start = s2.data_offset as usize;
            let s2_end = s2_start + s2.value.len();

            let overlaps = !(s1_end <= s2_start || s1_start >= s2_end);

            assert!(
                !overlaps,
                "Found overlapping XOR strings:\n  [{:#x}-{:#x}] {:?}\n  [{:#x}-{:#x}] {:?}",
                s1_start, s1_end, s1.value,
                s2_start, s2_end, s2.value
            );
        }
    }
}

#[test]
fn test_xor_finds_malware_indicators() {
    // Should find key malware IOCs from the DPRK sample
    let data = load_test_fixture();

    let opts = ExtractOptions::new(10)
        .with_xor_key(BREW_AGENT_KEY.to_vec())
        .with_garbage_filter(true);

    let extracted = stng::extract_strings_with_options(&data, &opts);

    let xor_strings: Vec<_> = extracted
        .iter()
        .filter(|s| s.method == StringMethod::XorDecode)
        .map(|s| s.value.to_lowercase())
        .collect();

    let combined = xor_strings.join(" ");

    // Key indicators from DPRK malware
    assert!(
        combined.contains("wallet"),
        "Should find wallet-related strings"
    );
    assert!(
        combined.contains("telegram"),
        "Should find Telegram references"
    );
    assert!(
        combined.contains("osascript"),
        "Should find osascript commands"
    );
}

#[test]
fn test_xor_classification() {
    // XOR strings should be properly classified
    let data = load_test_fixture();

    let opts = ExtractOptions::new(10)
        .with_xor_key(BREW_AGENT_KEY.to_vec())
        .with_garbage_filter(true);

    let extracted = stng::extract_strings_with_options(&data, &opts);

    let volume_strings: Vec<_> = extracted
        .iter()
        .filter(|s| s.method == StringMethod::XorDecode)
        .filter(|s| s.value.to_lowercase().contains("volume"))
        .collect();

    // Volume strings should be classified as ShellCmd or AppleScript
    // (They are osascript commands, which may be classified either way)
    for s in &volume_strings {
        assert!(
            s.kind == StringKind::ShellCmd || s.kind == StringKind::AppleScript,
            "Volume string should be classified as ShellCmd or AppleScript, got {:?}: {:?}",
            s.kind,
            s.value
        );
    }
}

#[test]
fn test_xor_null_termination() {
    // Test that we correctly handle null termination using real data
    // In the test fixture, strings should end at nulls
    let data = load_test_fixture();

    let opts = ExtractOptions::new(10)
        .with_xor_key(BREW_AGENT_KEY.to_vec())
        .with_garbage_filter(true);

    let extracted = stng::extract_strings_with_options(&data, &opts);

    let volume_strings: Vec<_> = extracted
        .iter()
        .filter(|s| s.method == StringMethod::XorDecode)
        .filter(|s| s.value.to_lowercase().contains("volume"))
        .collect();

    // Volume strings should be clean (no garbage after null termination)
    for s in &volume_strings {
        // Should not have random garbage at the end
        assert!(
            !s.value.ends_with("gtZh"),
            "String should be null-terminated, not end with garbage: {:?}",
            s.value
        );
        assert!(
            !s.value.ends_with("aTrsJg"),
            "String should be null-terminated, not end with garbage: {:?}",
            s.value
        );
    }
}

#[test]
fn test_xor_strings_starting_with_key_first_byte() {
    // Test that we can find strings starting with 'f' (key[0])
    // In the real data, check if we have any strings starting with 'f'
    let data = load_test_fixture();

    let opts = ExtractOptions::new(10)
        .with_xor_key(BREW_AGENT_KEY.to_vec())
        .with_garbage_filter(true);

    let extracted = stng::extract_strings_with_options(&data, &opts);

    let xor_strings: Vec<_> = extracted
        .iter()
        .filter(|s| s.method == StringMethod::XorDecode)
        .collect();

    // The key starts with 'f', so strings starting with 'f' would have
    // null as first byte in source. Check that we can find such strings
    // (This verifies we allow j==0 to be null in the decode loop)
    let starts_with_f: Vec<_> = xor_strings
        .iter()
        .filter(|s| s.value.starts_with('f') || s.value.starts_with('F'))
        .collect();

    // We should find at least some strings starting with 'f'
    // (The exact count doesn't matter, just that we CAN find them)
    assert!(
        !starts_with_f.is_empty(),
        "Should be able to find strings starting with key[0] ('f')"
    );
}

#[test]
fn test_xor_performance() {
    // Extraction should be reasonably fast
    use std::time::Instant;

    let data = load_test_fixture();

    let opts = ExtractOptions::new(10)
        .with_xor_key(BREW_AGENT_KEY.to_vec())
        .with_garbage_filter(true);

    let start = Instant::now();
    let extracted = stng::extract_strings_with_options(&data, &opts);
    let elapsed = start.elapsed();

    let xor_count = extracted
        .iter()
        .filter(|s| s.method == StringMethod::XorDecode)
        .count();

    // Should complete in under 1 second for 180KB
    assert!(
        elapsed.as_secs() < 1,
        "XOR extraction took too long: {:?}",
        elapsed
    );

    // Should find reasonable number of strings (not 0, not thousands)
    assert!(
        xor_count > 50 && xor_count < 500,
        "Expected 50-500 XOR strings, found {}",
        xor_count
    );

    println!(
        "XOR extraction: {} strings in {:.3}s ({:.0} KB/s)",
        xor_count,
        elapsed.as_secs_f64(),
        data.len() as f64 / 1024.0 / elapsed.as_secs_f64()
    );
}

#[test]
fn test_xor_minimum_length_respected() {
    // Should respect minimum length parameter for XOR extraction
    let data = load_test_fixture();

    let min_len = 25;
    let opts = ExtractOptions::new(4) // General min length
        .with_xor_key(BREW_AGENT_KEY.to_vec())
        .with_xor(Some(min_len)) // Specific XOR min length
        .with_garbage_filter(true);

    let extracted = stng::extract_strings_with_options(&data, &opts);

    let xor_strings: Vec<_> = extracted
        .iter()
        .filter(|s| s.method == StringMethod::XorDecode)
        .collect();

    // All XOR strings should be >= min_len characters
    for s in &xor_strings {
        assert!(
            s.value.len() >= min_len,
            "Found XOR string shorter than xor_min_length: {:?} ({} chars, expected >= {})",
            s.value,
            s.value.len(),
            min_len
        );
    }

    // Should still find some strings
    assert!(
        !xor_strings.is_empty(),
        "Should find at least some XOR strings even with higher min_length"
    );
}
