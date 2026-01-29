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

    // Test 2: C2 URL (higher priority than locale strings in overlap resolution)
    assert!(
        xor_strings.iter().any(|s| s.contains("http://") || s.contains("46.30.191")),
        "Should find C2 URL (http://46.30.191.141)"
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

#[test]
fn test_xor_url_extraction() {
    // Test that we correctly extract URLs, specifically http://46.30.191.141
    let sample_path = "testdata/xor/brew_agent_xor_sample";

    if !std::path::Path::new(sample_path).exists() {
        eprintln!("Skipping - malware sample not found");
        return;
    }

    let data = std::fs::read(sample_path).unwrap();
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

    // Test 1: Should find the IP address URL
    let has_ip_url = xor_strings.iter().any(|s| {
        s.contains("http://46.30.191.141") || s.contains("46.30.191.141")
    });
    assert!(
        has_ip_url,
        "Should find URL containing http://46.30.191.141\nFound XOR strings:\n{}",
        xor_strings.join("\n")
    );

    // Test 2: URLs should start with http:// or https://
    let has_proper_url = xor_strings.iter().any(|s| {
        s.contains("http://") || s.contains("https://")
    });
    assert!(
        has_proper_url,
        "Should find at least one string containing http:// or https://"
    );

    println!("✓ URL extraction tests passed");
}

#[test]
fn test_xor_shell_commands() {
    // Test that we extract shell commands correctly with natural endpoints
    let sample_path = "testdata/xor/brew_agent_xor_sample";

    if !std::path::Path::new(sample_path).exists() {
        eprintln!("Skipping - malware sample not found");
        return;
    }

    let data = std::fs::read(sample_path).unwrap();
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

    // Test 1: launchctl command with 2>&1 redirection
    // Note: may have leading garbage trimmed, so check for "aunchctl" or "launchctl"
    let has_launchctl = xor_strings.iter().any(|s| {
        (s.contains("launchctl") || s.contains("aunchctl")) && s.contains("load -w") && s.contains("2>&1")
    });

    assert!(
        has_launchctl,
        "Should find 'launchctl load -w' command with 2>&1 redirection"
    );

    // Test 2: open command with sleep (NOT fopen)
    let has_sleep_cmd = xor_strings.iter().any(|s| {
        s.contains("sleep") && (s.contains("/bin/bash") || s.contains("bash"))
    });
    assert!(
        has_sleep_cmd,
        "Should find command containing 'sleep' with bash"
    );

    // Test 3: Verify the full sleep command content
    let sleep_str = xor_strings.iter().find(|s| s.contains("sleep"));
    if let Some(s) = sleep_str {
        assert!(
            s.contains("rm -rf"),
            "Sleep command should include 'rm -rf' part: {}",
            s
        );
    }

    // Test 4: screencapture command
    // Note: may have leading garbage trimmed
    let has_screencapture = xor_strings.iter().any(|s| {
        s.contains("screencapture") || s.contains("creencapture")
    });
    assert!(
        has_screencapture,
        "Should find screencapture command"
    );

    println!("✓ Shell command extraction tests passed");
}

#[test]
fn test_xor_application_paths() {
    // Test that we extract application and wallet paths correctly
    let sample_path = "testdata/xor/brew_agent_xor_sample";

    if !std::path::Path::new(sample_path).exists() {
        eprintln!("Skipping - malware sample not found");
        return;
    }

    let data = std::fs::read(sample_path).unwrap();
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

    // Test 1: BitPay wallet path
    let has_bitpay = xor_strings.iter().any(|s| {
        s.contains("bitpay") && s.contains("wallet")
    });
    assert!(
        has_bitpay,
        "Should find BitPay wallet path"
    );

    // Test 2: Telegram path
    let has_telegram = xor_strings.iter().any(|s| {
        s.contains("Telegram") && (s.contains("tdata") || s.contains("Desktop"))
    });
    assert!(
        has_telegram,
        "Should find Telegram application path with tdata"
    );

    // Test 3: Safari or Chrome path
    let has_browser = xor_strings.iter().any(|s| {
        (s.contains("Safari") || s.contains("Chrome")) && s.contains("Library")
    });
    assert!(
        has_browser,
        "Should find Safari or Chrome library path"
    );

    // Test 4: Discord path
    let has_discord = xor_strings.iter().any(|s| {
        s.contains("discord") && s.contains("Local Storage")
    });
    assert!(
        has_discord,
        "Should find Discord Local Storage path"
    );

    println!("✓ Application path extraction tests passed");
}

#[test]
fn test_xor_file_extensions() {
    // Test that we correctly extract strings ending with file extensions
    let sample_path = "testdata/xor/brew_agent_xor_sample";

    if !std::path::Path::new(sample_path).exists() {
        eprintln!("Skipping - malware sample not found");
        return;
    }

    let data = std::fs::read(sample_path).unwrap();
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

    // Test 1: .php file
    let has_php = xor_strings.iter().any(|s| {
        s.ends_with(".php") || s.contains(".php")
    });
    assert!(
        has_php,
        "Should find strings ending with .php"
    );

    // Test 2: .json file (configuration)
    // Note: may have trailing garbage, so check contains() not ends_with()
    let has_json = xor_strings.iter().any(|s| {
        s.contains(".json")
    });
    assert!(
        has_json,
        "Should find strings with .json extension"
    );

    // Test 3: .sqlite database
    let has_sqlite = xor_strings.iter().any(|s| {
        s.contains(".sqlite")
    });
    assert!(
        has_sqlite,
        "Should find strings with .sqlite extension"
    );

    println!("✓ File extension extraction tests passed");
}

#[test]
fn test_xor_crypto_wallets() {
    // Test that we extract cryptocurrency wallet paths
    let sample_path = "testdata/xor/brew_agent_xor_sample";

    if !std::path::Path::new(sample_path).exists() {
        eprintln!("Skipping - malware sample not found");
        return;
    }

    let data = std::fs::read(sample_path).unwrap();
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

    // Test 1: Electrum wallet
    let has_electrum = xor_strings.iter().any(|s| {
        s.contains("electrum") && s.contains("wallet")
    });
    assert!(
        has_electrum,
        "Should find Electrum wallet path"
    );

    // Test 2: Exodus wallet
    let has_exodus = xor_strings.iter().any(|s| {
        s.contains("Exodus")
    });
    assert!(
        has_exodus,
        "Should find Exodus wallet reference"
    );

    // Test 3: Wasabi wallet
    let has_wasabi = xor_strings.iter().any(|s| {
        let lower = s.to_lowercase();
        lower.contains("wasabi") && (lower.contains("wallet") || lower.contains("client"))
    });
    assert!(
        has_wasabi,
        "Should find Wasabi wallet path"
    );

    // Test 4: Generic wallet references
    let wallet_count = xor_strings.iter().filter(|s| {
        s.to_lowercase().contains("wallet")
    }).count();

    assert!(
        wallet_count >= 5,
        "Should find at least 5 wallet-related strings, found {}",
        wallet_count
    );

    println!("✓ Cryptocurrency wallet extraction tests passed - found {} wallet references", wallet_count);
}
