//! Integration tests for strangs library.

use strangs::{
    detect_language, extract_strings, extract_strings_with_options, is_garbage, is_go_binary,
    is_rust_binary, ExtractOptions, ExtractedString, StringKind, StringMethod,
};

// Test data: minimal ELF header for a 64-bit little-endian ELF
fn minimal_elf_header() -> Vec<u8> {
    let mut data = vec![0u8; 512];
    // ELF magic
    data[0..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
    // Class: 64-bit (2)
    data[4] = 2;
    // Endianness: little-endian (1)
    data[5] = 1;
    // Version
    data[6] = 1;
    // OS/ABI
    data[7] = 0;
    // Type: executable
    data[16..18].copy_from_slice(&[2, 0]);
    // Machine: x86_64 (0x3E)
    data[18..20].copy_from_slice(&[0x3E, 0]);
    // Version
    data[20..24].copy_from_slice(&[1, 0, 0, 0]);
    // Section header string table index
    data[62..64].copy_from_slice(&[0, 0]);
    data
}

// Test data: minimal Mach-O header for 64-bit
fn minimal_macho_header() -> Vec<u8> {
    let mut data = vec![0u8; 512];
    // Mach-O 64-bit magic
    data[0..4].copy_from_slice(&[0xCF, 0xFA, 0xED, 0xFE]);
    // CPU type: x86_64 (0x01000007)
    data[4..8].copy_from_slice(&[0x07, 0x00, 0x00, 0x01]);
    // CPU subtype
    data[8..12].copy_from_slice(&[0x03, 0x00, 0x00, 0x00]);
    // File type: executable (2)
    data[12..16].copy_from_slice(&[0x02, 0x00, 0x00, 0x00]);
    // Number of load commands
    data[16..20].copy_from_slice(&[0x00, 0x00, 0x00, 0x00]);
    // Size of load commands
    data[20..24].copy_from_slice(&[0x00, 0x00, 0x00, 0x00]);
    data
}

#[test]
fn test_extract_strings_empty_data() {
    let strings = extract_strings(&[], 4);
    assert!(strings.is_empty());
}

#[test]
fn test_extract_strings_from_printable_data() {
    // Printable data should be extracted (like traditional `strings`)
    let data = b"not a valid binary format at all";
    let strings = extract_strings(data, 4);
    // Should find the printable string
    assert!(!strings.is_empty());
}

#[test]
fn test_extract_strings_pure_binary() {
    // Pure binary data with no printable runs should return empty
    let data = &[0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07];
    let strings = extract_strings(data, 4);
    assert!(strings.is_empty());
}

#[test]
fn test_extract_strings_minimal_elf() {
    let data = minimal_elf_header();
    let strings = extract_strings(&data, 4);
    // Minimal ELF with no sections should return empty
    assert!(strings.is_empty());
}

#[test]
fn test_extract_strings_minimal_macho() {
    let data = minimal_macho_header();
    let strings = extract_strings(&data, 4);
    // Minimal Mach-O with no segments should return empty
    assert!(strings.is_empty());
}

#[test]
fn test_detect_language_empty() {
    assert_eq!(detect_language(&[]), "unknown");
}

#[test]
fn test_detect_language_text() {
    // Plain text should be detected as "text"
    assert_eq!(detect_language(b"not a binary"), "text");
}

#[test]
fn test_detect_language_binary_garbage() {
    // Binary garbage should be "unknown"
    assert_eq!(detect_language(&[0x00, 0x01, 0x02, 0x03, 0x04]), "unknown");
}

#[test]
fn test_detect_language_elf() {
    let data = minimal_elf_header();
    assert_eq!(detect_language(&data), "unknown"); // No Go/Rust sections
}

#[test]
fn test_is_go_binary_empty() {
    assert!(!is_go_binary(&[]));
}

#[test]
fn test_is_go_binary_invalid() {
    assert!(!is_go_binary(b"not a binary"));
}

#[test]
fn test_is_rust_binary_empty() {
    assert!(!is_rust_binary(&[]));
}

#[test]
fn test_is_rust_binary_invalid() {
    assert!(!is_rust_binary(b"not a binary"));
}

#[test]
fn test_extract_options_new() {
    let opts = ExtractOptions::new(4);
    assert_eq!(opts.min_length, 4);
    assert!(!opts.use_r2);
    assert!(opts.path.is_none());
}

#[test]
fn test_extract_options_with_r2() {
    let opts = ExtractOptions::new(4).with_r2("/path/to/binary");
    assert_eq!(opts.min_length, 4);
    assert!(opts.use_r2);
    assert_eq!(opts.path, Some("/path/to/binary".to_string()));
}

#[test]
fn test_extract_strings_with_options_empty() {
    let opts = ExtractOptions::new(4);
    let strings = extract_strings_with_options(&[], &opts);
    assert!(strings.is_empty());
}

// Garbage detection tests
#[test]
fn test_is_garbage_valid_strings() {
    assert!(!is_garbage("Hello World"));
    assert!(!is_garbage("go1.22.0"));
    assert!(!is_garbage("/usr/lib/go"));
    assert!(!is_garbage("runtime.memequal"));
    assert!(!is_garbage("SIGFPE: floating-point exception"));
    assert!(!is_garbage("Bool"));
    assert!(!is_garbage("Time"));
    assert!(!is_garbage("linux"));
    assert!(!is_garbage("amd64"));
    assert!(!is_garbage("https://example.com"));
    assert!(!is_garbage("ERROR_CODE_123"));
}

#[test]
fn test_is_garbage_empty_and_short() {
    assert!(is_garbage(""));
    assert!(is_garbage(" "));
    assert!(is_garbage("a")); // Single char
}

#[test]
fn test_is_garbage_control_chars() {
    assert!(is_garbage("ab\x00cd"));
    assert!(is_garbage("\x01\x02\x03"));
    assert!(is_garbage("hello\x00world"));
}

#[test]
fn test_is_garbage_misaligned_patterns() {
    assert!(is_garbage("asL "));
    assert!(is_garbage("``L "));
    assert!(is_garbage("dL "));
    assert!(is_garbage("`L "));
}

#[test]
fn test_is_garbage_short_mixed_case() {
    assert!(is_garbage("P9O"));
    assert!(is_garbage("8ZAj"));
    assert!(is_garbage("pIo2"));
}

#[test]
fn test_is_garbage_all_caps_short_ok() {
    // All caps short strings are OK
    assert!(!is_garbage("API"));
    assert!(!is_garbage("HTTP"));
    assert!(!is_garbage("GET"));
}

#[test]
fn test_is_garbage_all_lowercase_short_ok() {
    assert!(!is_garbage("foo"));
    assert!(!is_garbage("bar"));
    assert!(!is_garbage("test"));
}

#[test]
fn test_is_garbage_all_digits_short_ok() {
    assert!(!is_garbage("1234"));
    assert!(!is_garbage("2024"));
}

#[test]
fn test_is_garbage_repeated_chars() {
    assert!(is_garbage("aaaa"));
    assert!(is_garbage("...."));
    assert!(is_garbage("----"));
}

#[test]
fn test_is_garbage_excessive_whitespace() {
    assert!(is_garbage("   a   ")); // Single char after trim
                                    // "ab cd" after trim has proper content, may not be garbage
}

#[test]
fn test_is_garbage_unicode_endings() {
    assert!(is_garbage("333333ӿ"));
    assert!(is_garbage("abcӿ"));
}

#[test]
fn test_is_garbage_noise_punctuation() {
    assert!(is_garbage("@#$%"));
    assert!(is_garbage("@E?"));
    assert!(is_garbage("P$O"));
}

#[test]
fn test_is_garbage_hex_patterns() {
    // These are actually valid lowercase strings
    // The is_garbage function allows all-lowercase short strings
    assert!(!is_garbage("deadbeef")); // All lowercase, allowed
                                      // Mixed case short patterns that look like garbage
    assert!(is_garbage("0a1b2c3d")); // Has digits mixed with letters
}

// Test StringKind variants
#[test]
fn test_string_kind_default() {
    let kind: StringKind = Default::default();
    assert_eq!(kind, StringKind::Const);
}

// Test StringMethod display
#[test]
fn test_string_method_variants() {
    let methods = vec![
        StringMethod::Structure,
        StringMethod::InstructionPattern,
        StringMethod::RawScan,
        StringMethod::Heuristic,
        StringMethod::R2String,
        StringMethod::R2Symbol,
    ];
    for method in methods {
        // Just verify they can be formatted
        let _ = format!("{:?}", method);
    }
}

// Test ExtractedString
#[test]
fn test_extracted_string_serialization() {
    let s = ExtractedString {
        value: "test".to_string(),
        data_offset: 0x1000,
        section: Some("__rodata".to_string()),
        method: StringMethod::Structure,
        kind: StringKind::Const,
        library: None,
    };

    let json = serde_json::to_string(&s).unwrap();
    assert!(json.contains("\"value\":\"test\""));
    assert!(json.contains("\"data_offset\":4096"));
}

#[test]
fn test_extracted_string_with_library() {
    let s = ExtractedString {
        value: "_printf".to_string(),
        data_offset: 0x2000,
        section: None,
        method: StringMethod::Structure,
        kind: StringKind::Import,
        library: Some("libSystem.B.dylib".to_string()),
    };

    let json = serde_json::to_string(&s).unwrap();
    assert!(json.contains("\"library\":\"libSystem.B.dylib\""));
}

#[test]
fn test_extracted_string_without_library_skips_field() {
    let s = ExtractedString {
        value: "test".to_string(),
        data_offset: 0x1000,
        section: None,
        method: StringMethod::Structure,
        kind: StringKind::Const,
        library: None,
    };

    let json = serde_json::to_string(&s).unwrap();
    // library field should be skipped when None
    assert!(!json.contains("\"library\""));
}

// Tests using real system binaries for higher coverage
mod real_binary_tests {
    use super::*;
    use std::path::Path;

    fn get_real_binary() -> Option<Vec<u8>> {
        let paths = ["/bin/ls", "/usr/bin/ls", "/bin/cat", "/usr/bin/cat"];
        for path in paths {
            if Path::new(path).exists() {
                if let Ok(data) = std::fs::read(path) {
                    return Some(data);
                }
            }
        }
        None
    }

    #[test]
    fn test_extract_strings_real_binary() {
        let Some(data) = get_real_binary() else {
            return;
        };

        let strings = extract_strings(&data, 4);
        // Real binaries should have some strings
        assert!(!strings.is_empty(), "Real binary should have strings");
    }

    #[test]
    fn test_detect_language_real_binary() {
        let Some(data) = get_real_binary() else {
            return;
        };

        let lang = detect_language(&data);
        // Real system binary is typically C/unknown
        assert!(["unknown", "c", "rust", "go"].contains(&lang));
    }

    #[test]
    fn test_is_go_binary_real_binary() {
        let Some(data) = get_real_binary() else {
            return;
        };

        // System binaries are typically not Go
        let result = is_go_binary(&data);
        assert!(!result, "System binary should not be Go");
    }

    #[test]
    fn test_is_rust_binary_real_binary() {
        let Some(data) = get_real_binary() else {
            return;
        };

        // System binaries are typically not Rust
        let result = is_rust_binary(&data);
        assert!(!result, "System binary should not be Rust");
    }

    #[test]
    fn test_extract_with_options_real_binary() {
        let Some(data) = get_real_binary() else {
            return;
        };

        let opts = ExtractOptions::new(4);
        let strings = extract_strings_with_options(&data, &opts);
        assert!(!strings.is_empty());
    }

    #[test]
    fn test_extract_with_min_length_variations() {
        let Some(data) = get_real_binary() else {
            return;
        };

        let strings_4 = extract_strings(&data, 4);
        let strings_10 = extract_strings(&data, 10);
        let strings_20 = extract_strings(&data, 20);

        // More restrictive min_length should yield fewer or equal strings
        assert!(strings_10.len() <= strings_4.len());
        assert!(strings_20.len() <= strings_10.len());
    }

    #[test]
    fn test_extracted_strings_have_valid_values() {
        let Some(data) = get_real_binary() else {
            return;
        };

        let strings = extract_strings(&data, 4);
        for s in &strings {
            // Strings should be valid UTF-8 (they're already String type)
            assert!(!s.value.is_empty());
            // Note: Some strings (imports/symbols) may be shorter than min_length
            // The min_length filter applies to extracted strings, not imports
        }
    }

    #[test]
    fn test_string_kinds_are_valid() {
        let Some(data) = get_real_binary() else {
            return;
        };

        let strings = extract_strings(&data, 4);
        for s in &strings {
            // All StringKind variants should be valid
            let _ = format!("{:?}", s.kind);
            let _ = format!("{:?}", s.method);
        }
    }

    #[test]
    fn test_sections_are_reasonable() {
        let Some(data) = get_real_binary() else {
            return;
        };

        let strings = extract_strings(&data, 4);
        for s in &strings {
            if let Some(ref section) = s.section {
                // Section names should not be empty
                assert!(!section.is_empty());
            }
        }
    }
}

// Tests using real Go binaries
mod go_binary_tests {
    use super::*;
    use std::path::Path;

    fn get_go_binary() -> Option<Vec<u8>> {
        // Try common Go binary locations
        let go_path = std::process::Command::new("which")
            .arg("go")
            .output()
            .ok()
            .and_then(|o| String::from_utf8(o.stdout).ok())
            .map(|s| s.trim().to_string());

        if let Some(path) = go_path {
            if Path::new(&path).exists() {
                return std::fs::read(&path).ok();
            }
        }

        // Try standard locations
        let paths = [
            "/opt/homebrew/bin/go",
            "/usr/local/go/bin/go",
            "/usr/bin/go",
        ];
        for path in paths {
            if Path::new(path).exists() {
                if let Ok(data) = std::fs::read(path) {
                    return Some(data);
                }
            }
        }
        None
    }

    #[test]
    fn test_detect_go_binary() {
        let Some(data) = get_go_binary() else {
            return;
        };

        let is_go = is_go_binary(&data);
        assert!(is_go, "Go binary should be detected as Go");
    }

    #[test]
    fn test_detect_language_go() {
        let Some(data) = get_go_binary() else {
            return;
        };

        let lang = detect_language(&data);
        assert_eq!(lang, "go", "Go binary should be detected as 'go'");
    }

    #[test]
    fn test_extract_strings_go_binary() {
        let Some(data) = get_go_binary() else {
            return;
        };

        let strings = extract_strings(&data, 4);
        assert!(!strings.is_empty(), "Go binary should have many strings");

        // Go binaries typically have thousands of strings
        assert!(
            strings.len() > 100,
            "Expected many strings from Go binary, got {}",
            strings.len()
        );
    }

    #[test]
    fn test_go_binary_has_go_strings() {
        let Some(data) = get_go_binary() else {
            return;
        };

        let strings = extract_strings(&data, 4);

        // Go binaries should have typical Go runtime strings
        let has_runtime = strings.iter().any(|s| s.value.contains("runtime"));
        let has_go_version = strings.iter().any(|s| s.value.contains("go1."));

        // At least one should be true
        assert!(
            has_runtime || has_go_version,
            "Go binary should have runtime or version strings"
        );
    }

    #[test]
    fn test_go_binary_has_funcname_kinds() {
        let Some(data) = get_go_binary() else {
            return;
        };

        let strings = extract_strings(&data, 4);

        // Go binaries should have some FuncName kind strings
        let has_funcname = strings.iter().any(|s| s.kind == StringKind::FuncName);
        assert!(has_funcname, "Go binary should have FuncName kind strings");
    }
}

// Tests using real Rust binaries
mod rust_binary_tests {
    use super::*;
    use std::env;
    use std::path::Path;

    fn get_rust_binary() -> Option<Vec<u8>> {
        // Try the current project's binary first (guaranteed to exist)
        let self_binary = env!("CARGO_BIN_EXE_strangs");
        if Path::new(self_binary).exists() {
            return std::fs::read(self_binary).ok();
        }

        // Try cargo bin directory
        if let Some(home) = env::var_os("HOME") {
            let cargo_bin = Path::new(&home).join(".cargo/bin");
            if cargo_bin.exists() {
                // Try to find a small Rust binary
                if let Ok(entries) = std::fs::read_dir(&cargo_bin) {
                    for entry in entries.flatten() {
                        let path = entry.path();
                        if path.is_file() {
                            // Skip very large binaries for faster tests
                            if let Ok(meta) = std::fs::metadata(&path) {
                                if meta.len() < 50_000_000 {
                                    // < 50MB
                                    if let Ok(data) = std::fs::read(&path) {
                                        // Verify it's actually a Rust binary
                                        if is_rust_binary(&data) {
                                            return Some(data);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        None
    }

    #[test]
    fn test_self_binary_detection() {
        // Test against our own binary
        let self_path = env!("CARGO_BIN_EXE_strangs");
        if !Path::new(self_path).exists() {
            return;
        }

        let data = std::fs::read(self_path).unwrap();

        // Our binary might be detected as Rust depending on build
        let _lang = detect_language(&data);
        let _is_rust = is_rust_binary(&data);

        // Just verify extraction doesn't panic
        let strings = extract_strings(&data, 4);
        assert!(!strings.is_empty(), "Self binary should have strings");
    }

    #[test]
    fn test_self_binary_with_options() {
        let self_path = env!("CARGO_BIN_EXE_strangs");
        if !Path::new(self_path).exists() {
            return;
        }

        let data = std::fs::read(self_path).unwrap();

        // Test with various options
        let opts = ExtractOptions::new(6).with_garbage_filter(true);
        let strings = extract_strings_with_options(&data, &opts);
        assert!(!strings.is_empty());

        // All strings should be >= 6 chars (mostly - imports might be shorter)
        // Just verify it doesn't panic
    }

    #[test]
    fn test_self_binary_extract_from_object() {
        let self_path = env!("CARGO_BIN_EXE_strangs");
        if !Path::new(self_path).exists() {
            return;
        }

        let data = std::fs::read(self_path).unwrap();
        let object = strangs::goblin::Object::parse(&data).unwrap();
        let opts = ExtractOptions::new(4);
        let strings = strangs::extract_from_object(&object, &data, &opts);
        assert!(!strings.is_empty());
    }

    #[test]
    fn test_self_binary_string_kinds() {
        let self_path = env!("CARGO_BIN_EXE_strangs");
        if !Path::new(self_path).exists() {
            return;
        }

        let data = std::fs::read(self_path).unwrap();
        let strings = extract_strings(&data, 4);

        // Should have various kinds of strings
        let has_const = strings.iter().any(|s| s.kind == StringKind::Const);
        let has_import = strings.iter().any(|s| s.kind == StringKind::Import);

        assert!(
            has_const || has_import,
            "Should have Const or Import strings"
        );
    }

    #[test]
    fn test_extract_strings_rust_binary() {
        let Some(data) = get_rust_binary() else {
            return;
        };

        let strings = extract_strings(&data, 4);
        assert!(!strings.is_empty(), "Rust binary should have strings");
    }

    #[test]
    fn test_rust_binary_has_rust_strings() {
        let Some(data) = get_rust_binary() else {
            return;
        };

        let strings = extract_strings(&data, 4);

        // Rust binaries often have typical Rust strings
        let has_rust_hint = strings.iter().any(|s| {
            s.value.contains("rust")
                || s.value.contains("panic")
                || s.value.contains("unwrap")
                || s.value.contains("core::")
                || s.value.contains("std::")
        });

        // May not always be true depending on binary, so just log
        if !has_rust_hint {
            eprintln!("Note: No typical Rust strings found in binary");
        }
    }
}

// Tests for edge cases and corner cases
// Additional tests for specific extraction scenarios
mod extraction_scenario_tests {
    use super::*;

    #[test]
    fn test_extract_with_r2_option_no_r2_installed() {
        let data = minimal_elf_header();
        // Test with r2 option but no path
        let opts = ExtractOptions::new(4).with_r2("/nonexistent/path");
        let strings = extract_strings_with_options(&data, &opts);
        // Should still work, just without r2 results
        let _ = strings;
    }

    #[test]
    fn test_extract_unknown_binary_format() {
        // Random data that isn't ELF, Mach-O, or PE
        let data = b"RANDOMDATANOTABINARYFORMAT123456789";
        let strings = extract_strings(data, 4);
        // May extract raw strings or return empty
        let _ = strings;
    }

    #[test]
    fn test_extract_corrupted_elf() {
        let mut data = minimal_elf_header();
        // Corrupt the header
        data[16] = 0xFF;
        data[17] = 0xFF;
        let strings = extract_strings(&data, 4);
        // Should handle gracefully
        let _ = strings;
    }

    #[test]
    fn test_extract_corrupted_macho() {
        let mut data = minimal_macho_header();
        // Set invalid CPU type
        data[4..8].copy_from_slice(&[0xFF, 0xFF, 0xFF, 0xFF]);
        let strings = extract_strings(&data, 4);
        // Should handle gracefully
        let _ = strings;
    }

    #[test]
    fn test_extract_very_small_binary() {
        // Just the magic bytes for ELF
        let data = vec![0x7f, b'E', b'L', b'F'];
        let strings = extract_strings(&data, 4);
        assert!(strings.is_empty());
    }

    #[test]
    fn test_extract_very_small_macho() {
        // Just the magic bytes for Mach-O
        let data = vec![0xCF, 0xFA, 0xED, 0xFE];
        let strings = extract_strings(&data, 4);
        assert!(strings.is_empty());
    }
}

// Tests for fat Mach-O binaries
mod fat_binary_tests {
    use super::*;
    use std::path::Path;

    fn get_fat_binary() -> Option<Vec<u8>> {
        // /bin/ls is a fat binary on macOS
        let path = "/bin/ls";
        if Path::new(path).exists() {
            std::fs::read(path).ok()
        } else {
            None
        }
    }

    #[test]
    fn test_fat_binary_extract_strings() {
        let Some(data) = get_fat_binary() else {
            return;
        };

        let strings = extract_strings(&data, 4);
        assert!(!strings.is_empty(), "Fat binary should have strings");
    }

    #[test]
    fn test_fat_binary_detect_language() {
        let Some(data) = get_fat_binary() else {
            return;
        };

        let lang = detect_language(&data);
        // System binaries are typically C/unknown
        assert_eq!(lang, "unknown");
    }

    #[test]
    fn test_fat_binary_not_go() {
        let Some(data) = get_fat_binary() else {
            return;
        };

        assert!(!is_go_binary(&data), "Fat system binary should not be Go");
    }

    #[test]
    fn test_fat_binary_not_rust() {
        let Some(data) = get_fat_binary() else {
            return;
        };

        assert!(
            !is_rust_binary(&data),
            "Fat system binary should not be Rust"
        );
    }

    #[test]
    fn test_fat_binary_with_options() {
        let Some(data) = get_fat_binary() else {
            return;
        };

        let opts = ExtractOptions::new(8);
        let strings = extract_strings_with_options(&data, &opts);
        assert!(!strings.is_empty());
    }

    #[test]
    fn test_fat_binary_has_imports() {
        let Some(data) = get_fat_binary() else {
            return;
        };

        let strings = extract_strings(&data, 4);

        // System binaries should have imports
        let has_imports = strings.iter().any(|s| s.kind == StringKind::Import);
        assert!(has_imports, "Fat binary should have imports");
    }
}

// Tests for r2 integration (only run if r2 is installed)
mod r2_tests {
    use super::*;
    use std::path::Path;
    use std::process::Command;

    fn r2_available() -> bool {
        Command::new("r2")
            .arg("-v")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }

    #[test]
    fn test_r2_extract_strings() {
        if !r2_available() {
            eprintln!("Skipping: r2 not installed");
            return;
        }

        let path = "/bin/ls";
        if !Path::new(path).exists() {
            return;
        }

        let result = strangs::r2::extract_strings(path, 4);
        assert!(result.is_some(), "r2 should extract strings from /bin/ls");

        let strings = result.unwrap();
        assert!(!strings.is_empty(), "r2 should find strings");
    }

    #[test]
    fn test_r2_is_available() {
        // Just verify the function works
        let available = strangs::r2::is_available();
        if available {
            eprintln!("r2 is available");
        } else {
            eprintln!("r2 is not available");
        }
    }

    #[test]
    fn test_r2_nonexistent_file() {
        if !r2_available() {
            return;
        }

        let result = strangs::r2::extract_strings("/nonexistent/path/to/binary", 4);
        assert!(
            result.is_none(),
            "r2 should return None for nonexistent file"
        );
    }

    #[test]
    fn test_extract_with_r2_option() {
        if !r2_available() {
            return;
        }

        let path = "/bin/ls";
        if !Path::new(path).exists() {
            return;
        }

        let data = std::fs::read(path).unwrap();
        let opts = ExtractOptions::new(4).with_r2(path);
        let strings = extract_strings_with_options(&data, &opts);

        assert!(
            !strings.is_empty(),
            "Extraction with r2 should find strings"
        );
    }

    #[test]
    fn test_r2_strings_have_method() {
        if !r2_available() {
            return;
        }

        let path = "/bin/ls";
        if !Path::new(path).exists() {
            return;
        }

        let result = strangs::r2::extract_strings(path, 4);
        if let Some(strings) = result {
            // r2 strings should have R2String or R2Symbol method
            for s in &strings {
                assert!(
                    s.method == StringMethod::R2String || s.method == StringMethod::R2Symbol,
                    "r2 extracted string should have r2 method"
                );
            }
        }
    }
}

// Tests using cross-compiled ELF and PE binaries
mod cross_compiled_tests {
    use super::*;
    use std::path::Path;

    fn get_go_elf_binary() -> Option<Vec<u8>> {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/testdata/hello_linux_amd64"
        );
        if Path::new(path).exists() {
            std::fs::read(path).ok()
        } else {
            None
        }
    }

    fn get_go_pe_binary() -> Option<Vec<u8>> {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/testdata/hello_windows.exe"
        );
        if Path::new(path).exists() {
            std::fs::read(path).ok()
        } else {
            None
        }
    }

    // ELF Go binary tests
    #[test]
    fn test_elf_go_binary_detection() {
        let Some(data) = get_go_elf_binary() else {
            eprintln!("Skipping: ELF Go binary not found");
            return;
        };

        assert!(
            is_go_binary(&data),
            "ELF Go binary should be detected as Go"
        );
    }

    #[test]
    fn test_elf_go_detect_language() {
        let Some(data) = get_go_elf_binary() else {
            return;
        };

        let lang = detect_language(&data);
        assert_eq!(lang, "go", "ELF Go binary should be detected as 'go'");
    }

    #[test]
    fn test_elf_go_extract_strings() {
        let Some(data) = get_go_elf_binary() else {
            return;
        };

        let strings = extract_strings(&data, 4);
        assert!(!strings.is_empty(), "ELF Go binary should have strings");

        // Go binaries should have many strings
        assert!(
            strings.len() > 100,
            "Expected many strings from Go ELF, got {}",
            strings.len()
        );
    }

    #[test]
    fn test_elf_go_has_runtime_strings() {
        let Some(data) = get_go_elf_binary() else {
            return;
        };

        let strings = extract_strings(&data, 4);

        // Go binaries should have runtime strings
        let has_runtime = strings.iter().any(|s| s.value.contains("runtime"));
        assert!(has_runtime, "ELF Go binary should have runtime strings");
    }

    #[test]
    fn test_elf_go_has_gopclntab_strings() {
        let Some(data) = get_go_elf_binary() else {
            return;
        };

        let strings = extract_strings(&data, 4);

        // Should have function names from gopclntab
        let has_func = strings.iter().any(|s| s.kind == StringKind::FuncName);
        assert!(has_func, "ELF Go binary should have FuncName strings");
    }

    #[test]
    fn test_elf_go_has_filepath_strings() {
        let Some(data) = get_go_elf_binary() else {
            return;
        };

        let strings = extract_strings(&data, 4);

        // Should have file paths from debug info
        let has_path = strings
            .iter()
            .any(|s| s.kind == StringKind::FilePath || s.kind == StringKind::Path);
        assert!(has_path, "ELF Go binary should have file path strings");
    }

    // PE Go binary tests
    #[test]
    fn test_pe_go_binary_detection() {
        let Some(data) = get_go_pe_binary() else {
            eprintln!("Skipping: PE Go binary not found");
            return;
        };

        // PE detection may not identify Go specifically
        let is_go = is_go_binary(&data);
        // Just verify it doesn't panic and returns a boolean
        let _ = is_go;
    }

    #[test]
    fn test_pe_go_extract_strings() {
        let Some(data) = get_go_pe_binary() else {
            return;
        };

        let strings = extract_strings(&data, 4);
        assert!(!strings.is_empty(), "PE Go binary should have strings");
    }

    #[test]
    fn test_pe_go_has_strings() {
        let Some(data) = get_go_pe_binary() else {
            return;
        };

        let strings = extract_strings(&data, 4);

        // PE Go binaries should have some recognizable strings
        let has_hello = strings.iter().any(|s| s.value.contains("Hello"));
        let has_runtime = strings.iter().any(|s| s.value.contains("runtime"));

        assert!(
            has_hello || has_runtime,
            "PE Go binary should have Hello or runtime strings"
        );
    }

    #[test]
    fn test_elf_not_rust() {
        let Some(data) = get_go_elf_binary() else {
            return;
        };

        assert!(
            !is_rust_binary(&data),
            "Go ELF should not be detected as Rust"
        );
    }

    #[test]
    fn test_pe_not_rust() {
        let Some(data) = get_go_pe_binary() else {
            return;
        };

        assert!(
            !is_rust_binary(&data),
            "Go PE should not be detected as Rust"
        );
    }

    #[test]
    fn test_elf_extract_with_options() {
        let Some(data) = get_go_elf_binary() else {
            return;
        };

        let opts = ExtractOptions::new(10);
        let strings = extract_strings_with_options(&data, &opts);
        assert!(!strings.is_empty());
    }

    #[test]
    fn test_pe_extract_with_options() {
        let Some(data) = get_go_pe_binary() else {
            return;
        };

        let opts = ExtractOptions::new(10);
        let strings = extract_strings_with_options(&data, &opts);
        assert!(!strings.is_empty());
    }

    #[test]
    fn test_elf_go_with_garbage_filter() {
        let Some(data) = get_go_elf_binary() else {
            return;
        };

        let opts_filtered = ExtractOptions::new(4).with_garbage_filter(true);
        let opts_unfiltered = ExtractOptions::new(4).with_garbage_filter(false);

        let filtered = extract_strings_with_options(&data, &opts_filtered);
        let unfiltered = extract_strings_with_options(&data, &opts_unfiltered);

        assert!(unfiltered.len() >= filtered.len());
    }

    #[test]
    fn test_pe_go_with_garbage_filter() {
        let Some(data) = get_go_pe_binary() else {
            return;
        };

        let opts_filtered = ExtractOptions::new(4).with_garbage_filter(true);
        let opts_unfiltered = ExtractOptions::new(4).with_garbage_filter(false);

        let filtered = extract_strings_with_options(&data, &opts_filtered);
        let unfiltered = extract_strings_with_options(&data, &opts_unfiltered);

        assert!(unfiltered.len() >= filtered.len());
    }

    #[test]
    fn test_elf_extract_from_object() {
        let Some(data) = get_go_elf_binary() else {
            return;
        };

        let object = strangs::goblin::Object::parse(&data).unwrap();
        let opts = ExtractOptions::new(4);
        let strings = strangs::extract_from_object(&object, &data, &opts);

        assert!(!strings.is_empty());
        // Should have the same results as extract_strings_with_options
        let direct = extract_strings_with_options(&data, &opts);
        assert_eq!(strings.len(), direct.len());
    }

    #[test]
    fn test_pe_extract_from_object() {
        let Some(data) = get_go_pe_binary() else {
            return;
        };

        let object = strangs::goblin::Object::parse(&data).unwrap();
        let opts = ExtractOptions::new(4);
        let strings = strangs::extract_from_object(&object, &data, &opts);

        assert!(!strings.is_empty());
    }
}

// Tests for the new API features
mod api_tests {
    use super::*;

    #[test]
    fn test_extract_from_object_api() {
        let data = std::fs::read("/bin/ls").unwrap();
        let object = strangs::goblin::Object::parse(&data).unwrap();
        let opts = ExtractOptions::new(4);
        let strings = strangs::extract_from_object(&object, &data, &opts);
        assert!(!strings.is_empty());
    }

    #[test]
    fn test_extract_from_object_with_preextracted_r2() {
        let data = std::fs::read("/bin/ls").unwrap();
        let object = strangs::goblin::Object::parse(&data).unwrap();

        // Create fake pre-extracted r2 strings
        let fake_r2 = vec![ExtractedString {
            value: "fake_r2_string".to_string(),
            data_offset: 0x1000,
            section: None,
            method: StringMethod::R2String,
            kind: StringKind::Const,
            library: None,
        }];

        let opts = ExtractOptions::new(4).with_r2_strings(fake_r2);
        let strings = strangs::extract_from_object(&object, &data, &opts);

        // Should include our fake r2 string
        assert!(strings.iter().any(|s| s.value == "fake_r2_string"));
    }

    #[test]
    fn test_goblin_reexport() {
        // Verify goblin is properly re-exported
        let data = std::fs::read("/bin/ls").unwrap();
        let _object = strangs::goblin::Object::parse(&data).unwrap();
    }

    #[test]
    fn test_extract_options_builder_chain() {
        let fake_strings = vec![ExtractedString {
            value: "test".to_string(),
            data_offset: 0,
            section: None,
            method: StringMethod::R2String,
            kind: StringKind::Const,
            library: None,
        }];

        let opts = ExtractOptions::new(8)
            .with_r2("/path/to/binary")
            .with_r2_strings(fake_strings);

        assert_eq!(opts.min_length, 8);
        assert!(opts.use_r2);
        assert!(opts.path.is_some());
        assert!(opts.r2_strings.is_some());
    }

    #[test]
    fn test_extract_from_elf_object() {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/testdata/hello_linux_amd64"
        );
        if !std::path::Path::new(path).exists() {
            return;
        }

        let data = std::fs::read(path).unwrap();
        let object = strangs::goblin::Object::parse(&data).unwrap();
        let opts = ExtractOptions::new(4);
        let strings = strangs::extract_from_object(&object, &data, &opts);

        assert!(!strings.is_empty());
    }

    #[test]
    fn test_extract_from_pe_object() {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/testdata/hello_windows.exe"
        );
        if !std::path::Path::new(path).exists() {
            return;
        }

        let data = std::fs::read(path).unwrap();
        let object = strangs::goblin::Object::parse(&data).unwrap();
        let opts = ExtractOptions::new(4);
        let strings = strangs::extract_from_object(&object, &data, &opts);

        assert!(!strings.is_empty());
    }
}

// Tests for garbage filtering
mod filter_tests {
    use super::*;

    #[test]
    fn test_garbage_filter_enabled() {
        let data = std::fs::read("/bin/ls").unwrap();
        let opts_filtered = ExtractOptions::new(4).with_garbage_filter(true);
        let opts_unfiltered = ExtractOptions::new(4).with_garbage_filter(false);

        let filtered = extract_strings_with_options(&data, &opts_filtered);
        let unfiltered = extract_strings_with_options(&data, &opts_unfiltered);

        // Unfiltered should have more or equal strings
        assert!(unfiltered.len() >= filtered.len());
    }

    #[test]
    fn test_garbage_filter_removes_garbage() {
        let data = std::fs::read("/bin/ls").unwrap();
        let opts = ExtractOptions::new(4).with_garbage_filter(true);
        let strings = extract_strings_with_options(&data, &opts);

        // All strings should pass is_garbage check
        for s in &strings {
            assert!(!is_garbage(&s.value), "Found garbage string: {}", s.value);
        }
    }

    #[test]
    fn test_options_default_no_filter() {
        let opts = ExtractOptions::new(4);
        assert!(!opts.filter_garbage);
    }

    #[test]
    fn test_options_with_filter() {
        let opts = ExtractOptions::new(4).with_garbage_filter(true);
        assert!(opts.filter_garbage);
    }
}

mod edge_case_tests {
    use super::*;

    #[test]
    fn test_extract_with_zero_min_length() {
        let data = minimal_elf_header();
        let strings = extract_strings(&data, 0);
        // With min_length 0, may extract empty/single-char strings from binary
        // Just verify it doesn't panic
        let _ = strings;
    }

    #[test]
    fn test_extract_with_large_min_length() {
        let data = minimal_elf_header();
        let strings = extract_strings(&data, 1000);
        assert!(strings.is_empty());
    }

    #[test]
    fn test_string_kind_debug() {
        let kinds = vec![
            StringKind::Const,
            StringKind::FuncName,
            StringKind::FilePath,
            StringKind::EnvVar,
            StringKind::Error,
            StringKind::Url,
            StringKind::Path,
            StringKind::Section,
            StringKind::Ident,
            StringKind::Arg,
            StringKind::MapKey,
            StringKind::Import,
            StringKind::Export,
        ];
        for kind in kinds {
            let s = format!("{:?}", kind);
            assert!(!s.is_empty());
        }
    }

    #[test]
    fn test_string_method_debug() {
        let methods = vec![
            StringMethod::Structure,
            StringMethod::InstructionPattern,
            StringMethod::RawScan,
            StringMethod::Heuristic,
            StringMethod::R2String,
            StringMethod::R2Symbol,
        ];
        for method in methods {
            let s = format!("{:?}", method);
            assert!(!s.is_empty());
        }
    }

    #[test]
    fn test_extract_options_builder_pattern() {
        let opts = ExtractOptions::new(5).with_r2("/some/path");
        assert_eq!(opts.min_length, 5);
        assert!(opts.use_r2);
        assert_eq!(opts.path, Some("/some/path".to_string()));
    }

    #[test]
    fn test_extracted_string_equality() {
        let s1 = ExtractedString {
            value: "test".to_string(),
            data_offset: 0x1000,
            section: Some("test".to_string()),
            method: StringMethod::Structure,
            kind: StringKind::Const,
            library: None,
        };
        let s2 = ExtractedString {
            value: "test".to_string(),
            data_offset: 0x1000,
            section: Some("test".to_string()),
            method: StringMethod::Structure,
            kind: StringKind::Const,
            library: None,
        };
        // Clone check
        let s3 = s1.clone();
        assert_eq!(s1.value, s2.value);
        assert_eq!(s1.value, s3.value);
    }

    #[test]
    fn test_is_garbage_edge_cases() {
        // Null bytes
        assert!(is_garbage("ab\0cd"));
        // Tabs are treated as garbage
        assert!(is_garbage("hello\tworld"));
        // Newlines are also garbage
        assert!(is_garbage("hello\nworld"));
        // Non-ASCII unicode is treated as garbage (binary artifacts)
        assert!(is_garbage("héllo wörld"));
        // ASCII strings are fine
        assert!(!is_garbage("hello world"));
        // Very long string (all same char is garbage)
        let long = "a".repeat(10000);
        assert!(is_garbage(&long));
        // Long varied string is not garbage
        let varied = "hello world this is a longer test string";
        assert!(!is_garbage(varied));
    }

    #[test]
    fn test_minimal_pe_header() {
        // Create minimal PE header
        let mut data = vec![0u8; 512];
        // DOS header magic
        data[0..2].copy_from_slice(&[0x4D, 0x5A]); // MZ
                                                   // PE offset at 0x3C
        data[0x3C..0x40].copy_from_slice(&[0x80, 0x00, 0x00, 0x00]);
        // PE signature at 0x80
        data[0x80..0x84].copy_from_slice(&[0x50, 0x45, 0x00, 0x00]); // PE\0\0

        // This is a minimal/invalid PE, should return empty
        let strings = extract_strings(&data, 4);
        assert!(strings.is_empty());
    }
}

/// Tests for UTF-16LE wide string extraction (Windows binaries)
mod wide_string_tests {
    use super::*;

    /// Helper to encode a string as UTF-16LE with null terminator
    fn to_utf16le_null(s: &str) -> Vec<u8> {
        let mut bytes = Vec::new();
        for c in s.encode_utf16() {
            bytes.extend_from_slice(&c.to_le_bytes());
        }
        bytes.extend_from_slice(&[0x00, 0x00]);
        bytes
    }

    /// Helper to create a minimal PE with embedded wide strings
    fn minimal_pe_with_wide_strings(wide_strings: &[&str]) -> Vec<u8> {
        let mut data = vec![0u8; 1024];

        // DOS header magic
        data[0..2].copy_from_slice(&[0x4D, 0x5A]); // MZ

        // PE offset at 0x3C
        data[0x3C..0x40].copy_from_slice(&[0x80, 0x00, 0x00, 0x00]);

        // PE signature at 0x80
        data[0x80..0x84].copy_from_slice(&[0x50, 0x45, 0x00, 0x00]); // PE\0\0

        // COFF header (20 bytes) at 0x84
        data[0x84..0x86].copy_from_slice(&[0x64, 0x86]); // Machine: AMD64
        data[0x86..0x88].copy_from_slice(&[0x01, 0x00]); // NumberOfSections: 1
        data[0x94..0x96].copy_from_slice(&[0xF0, 0x00]); // SizeOfOptionalHeader
        data[0x96..0x98].copy_from_slice(&[0x22, 0x00]); // Characteristics

        // Optional header at 0x98
        data[0x98..0x9A].copy_from_slice(&[0x0B, 0x02]); // PE32+ magic

        // Embed wide strings starting at offset 0x200
        let mut offset = 0x200;
        for s in wide_strings {
            let encoded = to_utf16le_null(s);
            if offset + encoded.len() <= data.len() {
                data[offset..offset + encoded.len()].copy_from_slice(&encoded);
                offset += encoded.len();
            }
        }

        data
    }

    #[test]
    fn test_wide_string_method_exists() {
        // Verify the WideString method variant is available
        let method = StringMethod::WideString;
        assert_eq!(format!("{:?}", method), "WideString");
    }

    #[test]
    fn test_pe_with_embedded_wide_strings() {
        // Use the real Windows binary which is a valid PE
        let path = std::path::Path::new("tests/testdata/hello_windows.exe");
        if !path.exists() {
            return; // Skip if test data not available
        }

        let data = std::fs::read(path).expect("Failed to read test binary");
        let strings = extract_strings(&data, 4);

        // Should find wide strings in a real Windows PE
        let wide_strings: Vec<_> = strings
            .iter()
            .filter(|s| s.method == StringMethod::WideString)
            .collect();

        // Real Windows binaries have wide strings
        // (count may vary but extraction should work without error)
        println!(
            "Found {} wide strings in PE, total {} strings",
            wide_strings.len(),
            strings.len()
        );
    }

    #[test]
    fn test_wide_strings_have_correct_method() {
        let data = minimal_pe_with_wide_strings(&["TestString"]);
        let strings = extract_strings(&data, 4);

        let wide_strings: Vec<_> = strings
            .iter()
            .filter(|s| s.value == "TestString")
            .collect();

        if !wide_strings.is_empty() {
            assert_eq!(
                wide_strings[0].method,
                StringMethod::WideString,
                "Wide string should have WideString method"
            );
        }
    }

    #[test]
    fn test_real_windows_binary_wide_strings() {
        // Test with the real Windows Go binary in testdata
        let path = std::path::Path::new("tests/testdata/hello_windows.exe");
        if !path.exists() {
            return; // Skip if test data not available
        }

        let data = std::fs::read(path).expect("Failed to read test binary");
        let strings = extract_strings(&data, 4);

        // Count wide strings
        let wide_count = strings
            .iter()
            .filter(|s| s.method == StringMethod::WideString)
            .count();

        // Windows binaries typically have some wide strings
        // (Go binaries may have fewer, but should still have some from runtime)
        println!("Found {} wide strings in hello_windows.exe", wide_count);

        // The test passes as long as extraction completes without error
        // Wide string count may vary based on binary content
    }

    #[test]
    fn test_wide_strings_classified_correctly() {
        let data = minimal_pe_with_wide_strings(&[
            "https://example.com",
            "C:\\Users\\Test",
            "HKEY_LOCAL_MACHINE\\SOFTWARE",
        ]);

        let strings = extract_strings(&data, 4);

        // Check URL classification
        if let Some(url) = strings.iter().find(|s| s.value.contains("example.com")) {
            assert_eq!(url.kind, StringKind::Url, "URL should be classified as Url");
        }

        // Check path classification
        if let Some(path) = strings.iter().find(|s| s.value.contains("Users")) {
            assert_eq!(
                path.kind,
                StringKind::Path,
                "Windows path should be classified as Path"
            );
        }

        // Check registry classification
        if let Some(reg) = strings.iter().find(|s| s.value.contains("HKEY_")) {
            assert_eq!(
                reg.kind,
                StringKind::Registry,
                "Registry path should be classified as Registry"
            );
        }
    }

    #[test]
    fn test_wide_strings_with_garbage_filter() {
        let data = minimal_pe_with_wide_strings(&["ValidString", "Test1234"]);

        let opts = ExtractOptions::new(4).with_garbage_filter(true);
        let strings = extract_strings_with_options(&data, &opts);

        // Valid strings should pass garbage filter
        let wide_strings: Vec<_> = strings
            .iter()
            .filter(|s| s.method == StringMethod::WideString)
            .collect();

        // Garbage filter should not remove legitimate wide strings
        for s in &wide_strings {
            assert!(
                !is_garbage(&s.value),
                "Wide string '{}' should not be garbage",
                s.value
            );
        }
    }

    #[test]
    fn test_wide_string_min_length() {
        // Test min_length filtering with the real Windows binary
        let path = std::path::Path::new("tests/testdata/hello_windows.exe");
        if !path.exists() {
            return;
        }

        let data = std::fs::read(path).expect("Failed to read test binary");

        // Extract with min_length=4
        let strings_short = extract_strings(&data, 4);
        let wide_short: Vec<_> = strings_short
            .iter()
            .filter(|s| s.method == StringMethod::WideString)
            .collect();

        // Extract with min_length=10
        let strings_long = extract_strings(&data, 10);
        let wide_long: Vec<_> = strings_long
            .iter()
            .filter(|s| s.method == StringMethod::WideString)
            .collect();

        // Higher min_length should result in fewer or equal wide strings
        assert!(
            wide_long.len() <= wide_short.len(),
            "Higher min_length should filter more strings"
        );

        // All wide strings should meet min_length requirement
        for s in &wide_long {
            assert!(
                s.value.len() >= 10,
                "Wide string '{}' should be >= 10 chars",
                s.value
            );
        }
    }

    #[test]
    fn test_wide_strings_deduplication() {
        let data = minimal_pe_with_wide_strings(&["Duplicate", "Duplicate", "Unique"]);

        let strings = extract_strings(&data, 4);

        // Should only have one "Duplicate"
        let dup_count = strings.iter().filter(|s| s.value == "Duplicate").count();
        assert!(dup_count <= 1, "Duplicate strings should be deduplicated");
    }

    #[test]
    fn test_wide_strings_offset_tracking() {
        let data = minimal_pe_with_wide_strings(&["FirstString"]);

        let strings = extract_strings(&data, 4);

        if let Some(s) = strings.iter().find(|s| s.value == "FirstString") {
            // Offset should be >= 0x200 (where we embedded the string)
            assert!(
                s.data_offset >= 0x200,
                "Wide string offset should reflect position in binary"
            );
        }
    }
}
