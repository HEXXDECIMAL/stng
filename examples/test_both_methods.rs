use std::fs;

fn main() {
    let sample_path = "testdata/xor/brew_agent_xor_sample";
    let data = fs::read(sample_path).expect("Failed to read malware sample");
    let key = b"fYztZORL5VNS7nCUH1ktn5UoJ8VSgaf";

    let opts = stng::ExtractOptions::new(10)
        .with_xor_key(key.to_vec())
        .with_garbage_filter(false);

    let extracted = stng::extract_strings_with_options(&data, &opts);

    let xor_strings: Vec<&str> = extracted
        .iter()
        .filter(|s| s.method == stng::StringMethod::XorDecode)
        .map(|s| s.value.as_str())
        .collect();

    println!("=== BOTH METHODS TEST ===");
    println!("Found {} XOR-decoded strings\n", xor_strings.len());

    // Test for test_xor_application_paths expectations
    println!("=== APPLICATION PATHS TEST ===");

    let has_browser = xor_strings
        .iter()
        .any(|s| (s.contains("Safari") || s.contains("Chrome")) && s.contains("Library"));
    println!(
        "Browser path: {}",
        if has_browser {
            "✓ FOUND"
        } else {
            "✗ MISSING"
        }
    );

    // Show what Safari/Chrome strings we have
    println!("\nSafari/Chrome strings:");
    for s in &xor_strings {
        if (s.contains("Safari") || s.contains("Chrome")) {
            println!("  - {}", s);
        }
    }

    // Show Library strings
    println!("\nLibrary strings with Safari or Chrome:");
    for s in &xor_strings {
        if s.contains("Library") && (s.contains("Safari") || s.contains("Chrome")) {
            println!("  ✓ {}", s);
        }
    }
}
