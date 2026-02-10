use std::fs;

fn main() {
    let sample_path = "testdata/malware/brew_agent";
    let data = fs::read(sample_path).expect("Failed to read");

    // Extract strings WITHOUT XOR scanning
    let opts = stng::ExtractOptions::new(10);
    let extracted = stng::extract_strings_with_options(&data, &opts);

    println!("Total strings extracted: {}\n", extracted.len());

    // Look for the XOR key
    let key = "fYztZORL5VNS7nCUH1ktn5UoJ8VSgaf";
    let key_found = extracted.iter().find(|s| s.value == key);

    if let Some(s) = key_found {
        println!("✓ XOR key found in extracted strings!");
        println!("  Value: {}", s.value);
        println!("  Kind: {:?}", s.kind);
        println!("  Method: {:?}", s.method);
        println!("  Offset: 0x{:x}", s.data_offset);
    } else {
        println!("✗ XOR key NOT in extracted strings\n");

        // Show all strings sorted by offset to see what's near 0x235ad
        let mut nearby: Vec<_> = extracted.iter()
            .filter(|s| s.data_offset >= 0x230a0 && s.data_offset <= 0x24000)
            .collect();
        nearby.sort_by_key(|s| s.data_offset);

        println!("Strings in the range 0x230a0-0x24000:");
        for s in nearby.iter().take(20) {
            println!("  [0x{:06x}] {} ({})", s.data_offset, s.value, s.value.len());
        }
    }

    // Look for high-entropy strings that might be confused with the key
    println!("\nSearching for strings that look like XOR keys (15-32 chars, high entropy):");
    let mut high_entropy: Vec<_> = extracted.iter()
        .filter(|s| s.value.len() >= 15 && s.value.len() <= 32 && s.value.is_ascii())
        .map(|s| {
            let entropy = calculate_entropy(s.value.as_bytes());
            (entropy, s)
        })
        .filter(|(e, _)| *e >= 3.5)
        .collect();

    high_entropy.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap_or(std::cmp::Ordering::Equal));

    for (entropy, s) in high_entropy.iter().take(20) {
        println!("  [0x{:06x}] {} (entropy: {:.2}, len: {})",
                 s.data_offset, s.value, entropy, s.value.len());
    }
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
