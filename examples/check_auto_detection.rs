use std::fs;

fn main() {
    let sample_path = "testdata/malware/brew_agent";
    let data = fs::read(sample_path).expect("Failed to read");

    // Extract with XOR auto-detection enabled
    let opts = stng::ExtractOptions::new(10)
        .with_xor(Some(10))
        .with_garbage_filter(true);

    println!("Extracting with XOR auto-detection enabled...");
    let extracted = stng::extract_strings_with_options(&data, &opts);

    println!("Total strings extracted: {}\n", extracted.len());

    // Count strings by method
    let mut by_method = std::collections::HashMap::new();
    for s in &extracted {
        *by_method.entry(format!("{:?}", s.method)).or_insert(0) += 1;
    }

    println!("Strings by method:");
    let mut methods: Vec<_> = by_method.iter().collect();
    methods.sort();
    for (method, count) in methods {
        println!("  {}: {}", method, count);
    }

    // Look for XOR decoded strings
    let xor_strings: Vec<_> = extracted.iter()
        .filter(|s| s.method == stng::StringMethod::XorDecode)
        .collect();

    println!("\nXOR-decoded strings found: {}", xor_strings.len());

    if !xor_strings.is_empty() {
        println!("\nFirst 10 XOR-decoded strings:");
        for (i, s) in xor_strings.iter().take(10).enumerate() {
            println!("  [{}] {}", i, s.value);
        }
    }

    // Look for critical indicators
    let has_osascript = xor_strings.iter().any(|s| s.value.contains("osascript"));
    let has_c2 = xor_strings.iter().any(|s| s.value.contains("46.30.191") || s.value.contains("http://"));
    let has_electrum = xor_strings.iter().any(|s| s.value.contains("electrum"));

    println!("\nCritical indicators found:");
    println!("  osascript: {}", if has_osascript { "✓" } else { "✗" });
    println!("  C2 URL: {}", if has_c2 { "✓" } else { "✗" });
    println!("  electrum: {}", if has_electrum { "✓" } else { "✗" });

    // Look for XorKey strings
    let xor_keys: Vec<_> = extracted.iter()
        .filter(|s| s.kind == stng::StringKind::XorKey)
        .collect();

    if !xor_keys.is_empty() {
        println!("\nXOR keys detected:");
        for s in xor_keys {
            println!("  {} (offset 0x{:x})", s.value, s.data_offset);
        }
    }
}
