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

    println!("=== CYCLING-ONLY TEST ===");
    println!("Found {} XOR-decoded strings\n", xor_strings.len());

    // Test for test_xor_application_paths expectations
    println!("=== APPLICATION PATHS TEST ===");

    let has_bitpay = xor_strings
        .iter()
        .any(|s| s.contains("bitpay") && s.contains("wallet"));
    println!(
        "BitPay wallet: {}",
        if has_bitpay {
            "✓ FOUND"
        } else {
            "✗ MISSING"
        }
    );

    let has_telegram = xor_strings
        .iter()
        .any(|s| s.contains("Telegram") && (s.contains("tdata") || s.contains("Desktop")));
    println!(
        "Telegram path: {}",
        if has_telegram {
            "✓ FOUND"
        } else {
            "✗ MISSING"
        }
    );

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

    let has_discord = xor_strings
        .iter()
        .any(|s| s.contains("discord") && s.contains("Local Storage"));
    println!(
        "Discord path: {}",
        if has_discord {
            "✓ FOUND"
        } else {
            "✗ MISSING"
        }
    );

    // Test for test_xor_shell_commands expectations
    println!("\n=== SHELL COMMANDS TEST ===");

    let has_launchctl = xor_strings.iter().any(|s| {
        (s.contains("launchctl") || s.contains("aunchctl"))
            && s.contains("load -w")
            && s.contains("2>&1")
    });
    println!(
        "launchctl command: {}",
        if has_launchctl {
            "✓ FOUND"
        } else {
            "✗ MISSING"
        }
    );

    let has_sleep_cmd = xor_strings
        .iter()
        .any(|s| s.contains("sleep") && (s.contains("/bin/bash") || s.contains("bash")));
    println!(
        "sleep command: {}",
        if has_sleep_cmd {
            "✓ FOUND"
        } else {
            "✗ MISSING"
        }
    );

    // Test for test_xor_url_extraction expectations
    println!("\n=== URL EXTRACTION TEST ===");

    let has_ip_url = xor_strings
        .iter()
        .any(|s| s.contains("http://46.30.191.141") || s.contains("46.30.191.141"));
    println!(
        "C2 URL (46.30.191.141): {}",
        if has_ip_url {
            "✓ FOUND"
        } else {
            "✗ MISSING"
        }
    );

    // Print all strings for inspection
    println!("\n=== ALL XOR STRINGS ({}) ===", xor_strings.len());
    for (i, s) in xor_strings.iter().enumerate() {
        let display = if s.len() > 80 {
            format!("{}...", &s[..80])
        } else {
            s.to_string()
        };
        println!("[{:2}] {}", i, display);
    }
}
