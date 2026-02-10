use std::fs;

fn main() {
    let sample_path = "testdata/malware/brew_agent";
    let data = fs::read(sample_path).expect("Failed to read");

    // First, extract strings normally to see what we get
    println!("Step 1: Extract strings normally");
    let opts = stng::ExtractOptions::new(10);
    let strings = stng::extract_strings_with_options(&data, &opts);

    println!("  Total strings: {}", strings.len());

    // Find candidate keys
    println!("\nStep 2: Look for XOR key candidates (15-32 chars, high entropy)");
    let candidates: Vec<_> = strings.iter()
        .filter(|s| {
            let len = s.value.len();
            len >= 15 && len <= 32 && s.value.is_ascii()
        })
        .map(|s| {
            let entropy = calculate_entropy(s.value.as_bytes());
            (entropy, s.value.as_str(), s.data_offset)
        })
        .filter(|(e, _, _)| *e >= 3.5)
        .collect();

    println!("  Found {} candidates", candidates.len());
    for (entropy, val, offset) in candidates.iter().take(10) {
        let (upper, lower, digit, special) = count_char_types(val);
        println!("    [0x{:06x}] {} (entropy: {:.2}, len: {}, upper: {}, lower: {}, digit: {}, special: {})",
                 offset, val, entropy, val.len(), upper, lower, digit, special);
    }

    // Now look specifically for the known key
    println!("\nStep 3: Look for the known key");
    let key = "fYztZORL5VNS7nCUH1ktn5UoJ8VSgaf";
    let found_key = strings.iter().find(|s| s.value == key);

    if let Some(s) = found_key {
        let entropy = calculate_entropy(s.value.as_bytes());
        let (upper, lower, digit, special) = count_char_types(&s.value);
        println!("  ✓ Found key at 0x{:06x}", s.data_offset);
        println!("    Entropy: {:.2}", entropy);
        println!("    Char types: upper={}, lower={}, digit={}, special={}", upper, lower, digit, special);

        // Check if it passes is_good_xor_key_candidate checks
        println!("\n  Checking is_good_xor_key_candidate() filters:");
        println!("    Length 15-32? {}", (15..=32).contains(&s.value.len()));
        println!("    ASCII? {}", s.value.is_ascii());
        println!("    No underscores? {}", !s.value.contains('_'));
        println!("    Entropy >= 3.5? {}", entropy >= 3.5);
        println!("    Type count >= 2? {}", (upper > 0 as usize) as usize + (lower > 0 as usize) as usize + (digit > 0 as usize) as usize + (special > 0 as usize) as usize >= 2);
    } else {
        println!("  ✗ Key not found");
    }

    // Now check how many strings would be decoded with the correct key
    println!("\nStep 4: Try decoding with the correct key");
    let key_bytes = b"fYztZORL5VNS7nCUH1ktn5UoJ8VSgaf";
    let decoded = stng::xor::extract_custom_xor_strings(
        &data,
        &key_bytes.to_vec(),
        10,
    );

    println!("  Decoded {} strings with the correct key", decoded.len());

    // Look for critical indicators
    let has_osascript = decoded.iter().any(|s| s.value.contains("osascript"));
    let has_c2 = decoded.iter().any(|s| s.value.contains("46.30.191"));
    let has_electrum = decoded.iter().any(|s| s.value.contains("electrum"));

    println!("  Critical indicators:");
    println!("    osascript? {}", if has_osascript { "✓" } else { "✗" });
    println!("    C2 URL? {}", if has_c2 { "✓" } else { "✗" });
    println!("    electrum? {}", if has_electrum { "✓" } else { "✗" });
}

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

fn count_char_types(s: &str) -> (usize, usize, usize, usize) {
    let mut upper = 0;
    let mut lower = 0;
    let mut digit = 0;
    let mut special = 0;

    for c in s.chars() {
        if c.is_ascii_uppercase() {
            upper = 1;
        } else if c.is_ascii_lowercase() {
            lower = 1;
        } else if c.is_ascii_digit() {
            digit = 1;
        } else if !c.is_ascii_alphanumeric() {
            special = 1;
        }
    }

    (upper, lower, digit, special)
}
