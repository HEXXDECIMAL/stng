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

    println!("=== FINDING MISSING STRINGS ===\n");

    // test_xor_application_paths failures
    println!("test_xor_application_paths expects:");

    let has_browser = xor_strings
        .iter()
        .any(|s| (s.contains("Safari") || s.contains("Chrome")) && s.contains("Library"));
    println!(
        "  Safari/Chrome + Library: {}",
        if has_browser { "✓" } else { "✗ MISSING" }
    );
    if !has_browser {
        println!("    Strings with Safari/Chrome:");
        for s in &xor_strings {
            if s.contains("Safari") || s.contains("Chrome") {
                println!("      - {}", s);
            }
        }
    }

    // test_xor_shell_commands failures
    println!("\ntest_xor_shell_commands expects:");

    let has_launchctl = xor_strings.iter().any(|s| {
        (s.contains("launchctl") || s.contains("aunchctl"))
            && s.contains("load -w")
            && s.contains("2>&1")
    });
    println!(
        "  launchctl + 'load -w' + '2>&1': {}",
        if has_launchctl { "✓" } else { "✗ MISSING" }
    );
    if !has_launchctl {
        println!("    Strings with launchctl:");
        for s in &xor_strings {
            if s.contains("launchctl") || s.contains("load") {
                println!("      - {}", s);
            }
        }
    }

    // test_xor_url_extraction failures
    println!("\ntest_xor_url_extraction expects:");

    let has_ip_url = xor_strings
        .iter()
        .any(|s| s.contains("http://46.30.191.141") || s.contains("46.30.191.141"));
    println!(
        "  URL with 46.30.191.141: {}",
        if has_ip_url { "✓" } else { "✗ MISSING" }
    );
    if !has_ip_url {
        println!("    Strings with 46.30 or http://:");
        for s in &xor_strings {
            if s.contains("46.30") || (s.contains("http://") && s.len() > 15) {
                println!("      - {}", s);
            }
        }
    }
}
