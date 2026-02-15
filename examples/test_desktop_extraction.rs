// Test direct extraction of desktopFolder strings
use stng::ExtractOptions;
use std::fs;

fn main() {
    let data = fs::read("/Users/t/data/dissect/malware/macho/2026.homabrews_org/brew_agent")
        .expect("Failed to read malware sample");
    let key = b"fYztZORL5VNS7nCUH1ktn5UoJ8VSgaf";

    println!("=== With filtering (garbage_filter=true) ===");
    let opts_filtered = ExtractOptions::new(10)
        .with_xor_key(key.to_vec())
        .with_garbage_filter(true);

    let results_filtered = stng::extract_strings_with_options(&data, &opts_filtered);

    println!("Total strings extracted: {}", results_filtered.len());
    let xor_strings: Vec<_> = results_filtered.iter()
        .filter(|s| s.method == stng::StringMethod::XorDecode)
        .collect();
    println!("  XOR strings: {}", xor_strings.len());

    let desktop_strings: Vec<_> = results_filtered.iter()
        .filter(|s| s.value.to_lowercase().contains("desktop"))
        .collect();

    println!("Found {} strings containing 'desktop':", desktop_strings.len());
    for s in &desktop_strings {
        println!("  0x{:x} {:?}: {}", s.data_offset, s.kind, s.value);
    }

    println!("\n=== Without filtering (garbage_filter=false) ===");
    let opts_unfiltered = ExtractOptions::new(10)
        .with_xor_key(key.to_vec())
        .with_garbage_filter(false);

    let results_unfiltered = stng::extract_strings_with_options(&data, &opts_unfiltered);

    println!("Total strings extracted: {}", results_unfiltered.len());
    let xor_strings_unf: Vec<_> = results_unfiltered.iter()
        .filter(|s| s.method == stng::StringMethod::XorDecode)
        .collect();
    println!("  XOR strings: {}", xor_strings_unf.len());

    let desktop_strings_unf: Vec<_> = results_unfiltered.iter()
        .filter(|s| s.value.to_lowercase().contains("desktop"))
        .collect();

    println!("Found {} strings containing 'desktop':", desktop_strings_unf.len());
    for s in &desktop_strings_unf {
        println!("  0x{:x} {:?}: {}", s.data_offset, s.kind, s.value);
    }

    // Check specific offset
    println!("\n=== Checking offset 0x220f1 (start of multiline string) ===");
    let at_220f1: Vec<_> = results_unfiltered.iter()
        .filter(|s| s.data_offset == 0x220f1)
        .collect();

    if at_220f1.is_empty() {
        println!("NO STRINGS FOUND at offset 0x220f1 in unfiltered results!");
    } else {
        for s in &at_220f1 {
            println!("  Unfiltered: 0x{:x} {:?}", s.data_offset, s.kind);
            println!("  Length: {} bytes", s.value.len());
            println!("  First 100 chars: '{}'", s.value.chars().take(100).collect::<String>());
            println!("  Contains 'desktopFolder': {}", s.value.contains("desktopFolder"));
        }
    }

    let at_220f1_filt: Vec<_> = results_filtered.iter()
        .filter(|s| s.data_offset == 0x220f1)
        .collect();

    if at_220f1_filt.is_empty() {
        println!("NO STRINGS FOUND at offset 0x220f1 in filtered results!");
        println!("   → This is the BUG! The multiline AppleScript should be here.");
    } else {
        for s in &at_220f1_filt {
            println!("  Filtered: 0x{:x} {:?}: '{}'", s.data_offset, s.kind, s.value);
        }
    }

    println!("\n=== ALL unfiltered XOR strings from 0x22000 to 0x22300 ===");
    let range_strings: Vec<_> = results_unfiltered.iter()
        .filter(|s| s.data_offset >= 0x22000 && s.data_offset < 0x22300 && s.method == stng::StringMethod::XorDecode)
        .collect();
    println!("Found {} strings in range:", range_strings.len());
    for s in range_strings {
        let preview = if s.value.len() > 60 {
            format!("{}...", s.value.chars().take(60).collect::<String>())
        } else {
            s.value.clone()
        };
        println!("  0x{:x} {:?}: {}", s.data_offset, s.kind, preview);
    }
}
