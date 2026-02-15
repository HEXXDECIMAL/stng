// Debug why the multiline AppleScript string is being filtered out
use std::fs;

fn main() {
    let data = fs::read("/Users/t/data/dissect/malware/macho/2026.homabrews_org/brew_agent")
        .expect("Failed to read malware sample");

    // This is the exact multiline string from offset 0x220f1
    let multiline_applescript = "?2ftell application \"Finder\"\nset desktopFolder to path to desktop folder\nset documentsFolder to path to documents folder\nset srcFiles to every file of desktopFolder whose name extension is in %s\nset docsFiles to every file of documentsFolder whose name extension is in %s\nset allFiles to srcFiles &";

    println!("=== Testing the actual multiline AppleScript string ===");
    println!("Length: {} bytes", multiline_applescript.len());
    println!("First 100 chars: '{}'", multiline_applescript.chars().take(100).collect::<String>());
    println!();

    // Test classify_xor_string
    println!("Testing classify_xor_string:");
    let classified = classify_test(multiline_applescript);
    println!("  Result: {}", if classified { "Some(ShellCmd)" } else { "None" });
    println!();

    // Test is_garbage (simplified version from validation.rs)
    println!("Testing is_garbage:");
    let is_garb = is_garbage_test(multiline_applescript);
    println!("  Result: {}", is_garb);
    println!();

    if !classified {
        println!("🔴 ISSUE: classify_xor_string returns None!");
        println!("   The string will be excluded during XOR extraction when apply_filters=true");
    } else if is_garb {
        println!("🔴 ISSUE: is_garbage returns true!");
        println!("   The string will be filtered out at the garbage filter stage");
    } else {
        println!("✅ Both checks pass - the string should be kept!");
        println!("   But we know it's being filtered out, so the bug is elsewhere...");
    }
}

fn classify_test(s: &str) -> bool {
    let lower = s.to_ascii_lowercase();

    let applescript_indicators = [
        "set ", "tell application", "path to desktop", "path to documents",
        "every file of", "whose name extension", "posix file", "end tell",
        "do shell script", "display dialog", "choose file", "choose folder",
    ];

    for indicator in &applescript_indicators {
        if lower.contains(indicator) {
            println!("    ✓ Matched indicator: '{}'", indicator);
            return true;
        }
    }

    println!("    ✗ No match");
    false
}

fn is_garbage_test(s: &str) -> bool {
    let trimmed = s.trim();
    let len = trimmed.len();

    // Fast path from validation.rs lines 21-44
    if trimmed.len() >= 12 {
        let bytes = trimmed.as_bytes();
        let first = bytes[0];

        if bytes.iter().all(|&b| b == first) {
            println!("    Rejected: all same character");
            return true;
        }

        if first.is_ascii_alphabetic() {
            let simple_chars = bytes
                .iter()
                .filter(|&&b| {
                    b.is_ascii_alphanumeric()
                        || b == b' '
                        || b == b'_'
                        || b == b'-'
                        || b == b'.'
                        || b == b'/'
                })
                .count();
            let percentage = simple_chars * 100 / bytes.len();
            println!("    Simple chars: {}/{} = {}%", simple_chars, bytes.len(), percentage);
            if percentage >= 80 {
                println!("    ✓ Fast path PASS (>=80% simple chars)");
                return false;
            }
        } else {
            println!("    First char '{}' (0x{:02x}) is not alphabetic", first as char, first);
        }
    }

    // Would continue with more checks...
    println!("    Continuing with full garbage analysis (assuming passes)");
    false
}
