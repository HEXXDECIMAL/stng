use std::fs;

fn main() {
    let sample_path = "testdata/malware/brew_agent";
    let data = fs::read(sample_path).expect("Failed to read");
    
    // Extract all strings normally (no XOR key provided)
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
        println!("✗ XOR key NOT in extracted strings");
        
        // Check if it's in there with different length
        let partial_matches: Vec<_> = extracted.iter()
            .filter(|s| s.value.contains("fYztZORL") || s.value.contains("VSgaf"))
            .collect();
        
        if !partial_matches.is_empty() {
            println!("\n  Partial matches found:");
            for s in partial_matches.iter().take(5) {
                println!("    - {}", s.value);
            }
        }
    }
    
    // Look for high-entropy strings that might be confused with the key
    println!("\nSearching for strings that look like XOR keys (15-32 chars, high entropy):");
    for s in &extracted {
        if s.value.len() >= 15 && s.value.len() <= 32 && s.value.is_ascii() {
            let entropy = calculate_entropy(s.value.as_bytes());
            if entropy >= 3.5 {
                println!("  [0x{:x}] {} (entropy: {:.2})", s.data_offset, s.value, entropy);
            }
        }
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
