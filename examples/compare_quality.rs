use std::fs;

fn main() {
    let sample_path = "testdata/xor/brew_agent_xor_sample";
    let data = fs::read(sample_path).expect("Failed to read malware sample");
    let key = b"fYztZORL5VNS7nCUH1ktn5UoJ8VSgaf";

    let opts = stng::ExtractOptions::new(10)
        .with_xor_key(key.to_vec())
        .with_garbage_filter(false);

    let extracted = stng::extract_strings_with_options(&data, &opts);

    let xor_strings: Vec<_> = extracted
        .iter()
        .filter(|s| s.method == stng::StringMethod::XorDecode)
        .collect();

    println!("=== STRING QUALITY ANALYSIS ===");
    println!("Total strings: {}\n", xor_strings.len());

    // Define quality categories
    let mut high_quality = Vec::new(); // Real-looking paths, commands, URLs
    let mut medium_quality = Vec::new(); // Mixed alphanumeric
    let mut low_quality = Vec::new(); // Mostly special chars/noise

    for s in &xor_strings {
        let value = &s.value;
        let alnum_count = value.chars().filter(|c| c.is_alphanumeric()).count();
        let alnum_ratio = alnum_count as f64 / value.len() as f64;

        // High quality: paths, URLs, commands with real content
        if value.contains("/")
            || value.contains("http")
            || value.contains("://")
            || value.contains("Library")
            || value.contains("Containers")
            || value.contains("launchctl")
            || value.contains("bash")
            || value.contains("osascript")
            || value.contains("open")
            || alnum_ratio > 0.7
        {
            high_quality.push(s);
        } else if alnum_ratio > 0.4 {
            medium_quality.push(s);
        } else {
            low_quality.push(s);
        }
    }

    println!("High quality (likely real): {}", high_quality.len());
    println!("Medium quality (mixed): {}", medium_quality.len());
    println!("Low quality (mostly noise): {}", low_quality.len());
    println!();

    // Show samples
    println!("Sample HIGH quality strings:");
    for (i, s) in high_quality.iter().take(15).enumerate() {
        let display = if s.value.len() > 70 {
            format!("{}...", &s.value[..70])
        } else {
            s.value.clone()
        };
        println!("  [{}] {}", i, display);
    }

    println!("\nSample LOW quality strings:");
    for (i, s) in low_quality.iter().take(15).enumerate() {
        println!("  [{}] {}", i, s.value);
    }

    // Count by string kind
    println!("\n=== BY STRING KIND ===");
    let mut kinds = std::collections::HashMap::new();
    for s in &xor_strings {
        *kinds.entry(format!("{:?}", s.kind)).or_insert(0) += 1;
    }
    let mut kinds_vec: Vec<_> = kinds.into_iter().collect();
    kinds_vec.sort_by(|a, b| b.1.cmp(&a.1));
    for (kind, count) in kinds_vec.iter().take(10) {
        println!("  {}: {}", kind, count);
    }
}
