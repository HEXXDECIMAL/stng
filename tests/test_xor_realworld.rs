/// Real-world test for multi-byte XOR extraction using actual malware sample
use stng::{ExtractOptions, StringMethod};

#[test]
fn test_xor_brew_agent_malware() {
    // Test against real DPRK malware sample
    let sample_path = "testdata/xor/brew_agent_xor_sample";

    // Skip if sample doesn't exist
    if !std::path::Path::new(sample_path).exists() {
        eprintln!("Skipping - malware sample not found at {}", sample_path);
        return;
    }

    let data = std::fs::read(sample_path).expect("Failed to read malware sample");
    let key = b"fYztZORL5VNS7nCUH1ktn5UoJ8VSgaf";

    let opts = ExtractOptions::new(10)
        .with_xor_key(key.to_vec())
        .with_garbage_filter(false);

    let extracted = stng::extract_strings_with_options(&data, &opts);

    let xor_strings: Vec<&str> = extracted
        .iter()
        .filter(|s| s.method == StringMethod::XorDecode)
        .map(|s| s.value.as_str())
        .collect();

    println!("Found {} XOR-decoded strings", xor_strings.len());

    // Test 1: osascript command (shell execution)
    assert!(
        xor_strings.iter().any(|s| s.contains("osascript")),
        "Should find osascript shell command"
    );

    // Test 2: locale strings (ru_RU indicates Russian targeting)
    assert!(
        xor_strings.iter().any(|s| s.contains("ru_RU") || s.contains("hy_AM")),
        "Should find locale strings (ru_RU or hy_AM)"
    );

    // Test 3: Multi-line AppleScript
    assert!(
        xor_strings.iter().any(|s| s.contains("POSIX file") && s.contains('\n')),
        "Should find multi-line AppleScript with newlines"
    );

    // Test 4: Safari/browser targeting
    assert!(
        xor_strings.iter().any(|s| s.to_lowercase().contains("safari") || s.to_lowercase().contains("cookies")),
        "Should find browser targeting strings"
    );

    // Test 5: Cryptocurrency wallet targeting
    assert!(
        xor_strings.iter().any(|s| s.contains("Ethereum") || s.contains("keystore")),
        "Should find crypto wallet targeting"
    );

    // Verify we're finding a reasonable number of strings
    assert!(
        xor_strings.len() >= 10,
        "Should find at least 10 XOR-decoded strings, found {}",
        xor_strings.len()
    );

    println!("✓ All malware analysis checks passed");
}

#[test]
fn test_xor_display_multiline() {
    // Verify that multi-line XOR strings are properly decoded
    let sample_path = "testdata/xor/brew_agent_xor_sample";

    if !std::path::Path::new(sample_path).exists() {
        return;
    }

    let data = std::fs::read(sample_path).unwrap();
    let key = b"fYztZORL5VNS7nCUH1ktn5UoJ8VSgaf";

    let opts = ExtractOptions::new(10)
        .with_xor_key(key.to_vec())
        .with_garbage_filter(false);

    let extracted = stng::extract_strings_with_options(&data, &opts);

    // Find a multi-line string
    let multiline = extracted
        .iter()
        .filter(|s| s.method == StringMethod::XorDecode)
        .find(|s| s.value.contains('\n') && s.value.len() > 50);

    assert!(multiline.is_some(), "Should find at least one multi-line XOR string");

    let s = multiline.unwrap();
    let lines: Vec<&str> = s.value.lines().collect();

    assert!(
        lines.len() >= 2,
        "Multi-line string should have at least 2 lines, found {}",
        lines.len()
    );

    println!("✓ Found multi-line XOR string with {} lines", lines.len());
}
