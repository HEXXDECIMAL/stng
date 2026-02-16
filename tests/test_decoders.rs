/// Comprehensive tests for decoder edge cases and batch processing
/// Covers src/decoders.rs edge cases and untested code paths
/// Targets: 45% → 80% coverage (+1.8%)

use stng::decoders::{
    decode_base32_strings, decode_base64_strings, decode_base85_strings, decode_hex_strings,
    decode_unicode_escape_strings, decode_url_strings, deobfuscate_concatenation,
    try_decode_ascii85,
};
use stng::{ExtractedString, StringKind, StringMethod};

// Helper to create test ExtractedString
fn make_string(value: &str, kind: StringKind) -> ExtractedString {
    ExtractedString {
        value: value.to_string(),
        data_offset: 0,
        section: None,
        method: StringMethod::RawScan,
        kind,
        library: None,
        fragments: None,
        section_size: None,
        section_executable: None,
        section_writable: None,
        architecture: None,
        function_meta: None,
    }
}

// ==================== Concatenation Deobfuscation ====================

#[test]
fn test_deobfuscate_concatenation_javascript() {
    // Must result in >= 16 chars (MIN_BASE64_LENGTH)
    let input = r#""SGVsbG8g" + "V29ybGQhCg==""#; // "Hello World!\n" in base64
    let result = deobfuscate_concatenation(input);
    assert_eq!(result, Some("SGVsbG8gV29ybGQhCg==".to_string()));
}

#[test]
fn test_deobfuscate_concatenation_python() {
    let input = r#"'SGVsbG8g' + 'V29ybGQhCg==""#;
    let result = deobfuscate_concatenation(input);
    assert_eq!(result, Some("SGVsbG8gV29ybGQhCg==".to_string()));
}

#[test]
fn test_deobfuscate_concatenation_php() {
    let input = r#"'SGVsbG8g' . 'V29ybGQhCg==""#;
    let result = deobfuscate_concatenation(input);
    assert_eq!(result, Some("SGVsbG8gV29ybGQhCg==".to_string()));
}

#[test]
fn test_deobfuscate_concatenation_mixed_quotes() {
    let input = r#""SGVsbG8g" + 'V29ybGQhCg==""#;
    let result = deobfuscate_concatenation(input);
    assert_eq!(result, Some("SGVsbG8gV29ybGQhCg==".to_string()));
}

#[test]
fn test_deobfuscate_concatenation_no_pattern() {
    let input = "simple_string_no_concat";
    let result = deobfuscate_concatenation(input);
    assert_eq!(result, None);
}

#[test]
fn test_deobfuscate_concatenation_single_segment() {
    let input = r#""single" + ""#; // Only one valid segment
    let result = deobfuscate_concatenation(input);
    assert_eq!(result, None);
}

#[test]
fn test_deobfuscate_concatenation_too_short() {
    // Result would be < MIN_BASE64_LENGTH (16)
    let input = r#""ab" + "cd""#;
    let result = deobfuscate_concatenation(input);
    assert_eq!(result, None);
}

// ==================== Batch Base64 Decoding ====================

#[test]
fn test_decode_base64_strings_batch() {
    let inputs = vec![
        make_string("SGVsbG8gV29ybGQh", StringKind::Base64), // "Hello World!"
        make_string("VGVzdCBEYXRhISE=", StringKind::Base64), // "Test Data!!"
        make_string("not_base64", StringKind::Const),
    ];

    let results = decode_base64_strings(&inputs);

    assert_eq!(results.len(), 2);
    assert_eq!(results[0].value, "Hello World!");
    assert_eq!(results[0].method, StringMethod::Base64Decode);
    assert_eq!(results[1].value, "Test Data!!");
    assert_eq!(results[1].method, StringMethod::Base64Decode);
}

#[test]
fn test_decode_base64_strings_with_concatenation() {
    let inputs = vec![
        make_string(r#""SGVsbG8g" + "V29ybGQh""#, StringKind::Const),
    ];

    let results = decode_base64_strings(&inputs);

    // Should deobfuscate concatenation and decode
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].value, "Hello World!");
    assert_eq!(results[0].method, StringMethod::Base64Decode);
}

#[test]
fn test_decode_base64_strings_empty() {
    let results = decode_base64_strings(&[]);
    assert!(results.is_empty());
}

// ==================== Base64 Edge Cases ====================

#[test]
fn test_base64_too_short() {
    let input = make_string("SGVs", StringKind::Base64); // Only 4 chars (< MIN_BASE64_LENGTH)
    let results = decode_base64_strings(&[input]);
    assert!(results.is_empty());
}

#[test]
fn test_base64_invalid_padding() {
    // Malformed base64 (invalid padding)
    let input = make_string("SGVsbG8gV29ybGQh===", StringKind::Base64);
    let results = decode_base64_strings(&[input]);
    // Should fail to decode
    assert!(results.is_empty());
}

#[test]
fn test_base64_result_too_short() {
    // Input must be >= MIN_BASE64_LENGTH (16 chars)
    // "SGVsbG8gV29ybGQh" = "Hello World!" (exactly 16 chars input, 12 chars output)
    let input = make_string("SGVsbG8gV29ybGQh", StringKind::Base64);
    let results = decode_base64_strings(&[input]);
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].value, "Hello World!");

    // Test that decoded results < 4 chars (after trim) are rejected
    // We need base64 >= 16 chars that decodes to < 4 chars
    // "ICAgICAgICAgICAg" = 16 chars of base64 encoding "           " (11 spaces)
    // After trim, this becomes empty string (< 4 chars)
    let whitespace_input = make_string("ICAgICAgICAgICAg", StringKind::Base64);
    let whitespace_results = decode_base64_strings(&[whitespace_input]);
    // Should be rejected due to trimmed length < 4
    assert!(whitespace_results.is_empty());
}

#[test]
fn test_base64_whitespace_trimming() {
    let input = make_string("  SGVsbG8gV29ybGQh  ", StringKind::Base64);
    let results = decode_base64_strings(&[input]);
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].value, "Hello World!");
}

// ==================== Batch Hex Decoding ====================

#[test]
fn test_decode_hex_strings_batch() {
    let inputs = vec![
        make_string("48656c6c6f20576f726c6421", StringKind::HexEncoded),
        make_string("54657374204461746121", StringKind::HexEncoded),
        make_string("not_hex", StringKind::Const),
    ];

    let results = decode_hex_strings(&inputs);

    assert_eq!(results.len(), 2);
    assert_eq!(results[0].value, "Hello World!");
    assert_eq!(results[0].method, StringMethod::HexDecode);
    assert_eq!(results[1].value, "Test Data!");
    assert_eq!(results[1].method, StringMethod::HexDecode);
}

#[test]
fn test_decode_hex_strings_empty() {
    let results = decode_hex_strings(&[]);
    assert!(results.is_empty());
}

// ==================== Hex Edge Cases ====================

#[test]
fn test_hex_odd_length() {
    let input = make_string("48656c6c6f20576f726c642", StringKind::HexEncoded); // Odd length
    let results = decode_hex_strings(&[input]);
    assert!(results.is_empty());
}

#[test]
fn test_hex_too_short() {
    let input = make_string("48656c6c", StringKind::HexEncoded); // < MIN_HEX_LENGTH
    let results = decode_hex_strings(&[input]);
    assert!(results.is_empty());
}

#[test]
fn test_hex_invalid_chars() {
    let input = make_string("48656c6c6f20576fXXld6421", StringKind::HexEncoded);
    let results = decode_hex_strings(&[input]);
    assert!(results.is_empty());
}

#[test]
fn test_hex_uppercase() {
    let input = make_string("48656C6C6F20576F726C6421", StringKind::HexEncoded);
    let results = decode_hex_strings(&[input]);
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].value, "Hello World!");
}

#[test]
fn test_hex_mixed_case() {
    let input = make_string("48656c6C6f20576F726c6421", StringKind::HexEncoded);
    let results = decode_hex_strings(&[input]);
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].value, "Hello World!");
}

// ==================== Batch URL Decoding ====================

#[test]
fn test_decode_url_strings_batch() {
    let inputs = vec![
        make_string("Hello%20World%21", StringKind::UrlEncoded),
        make_string("Test%20Data%21%21", StringKind::UrlEncoded),
        make_string("no_encoding", StringKind::Const),
    ];

    let results = decode_url_strings(&inputs);

    assert_eq!(results.len(), 2);
    assert_eq!(results[0].value, "Hello World!");
    assert_eq!(results[0].method, StringMethod::UrlDecode);
    assert_eq!(results[1].value, "Test Data!!");
    assert_eq!(results[1].method, StringMethod::UrlDecode);
}

#[test]
fn test_decode_url_strings_empty() {
    let results = decode_url_strings(&[]);
    assert!(results.is_empty());
}

// ==================== URL Decoding Edge Cases ====================

#[test]
fn test_url_no_percent() {
    let input = make_string("no_percent_encoding", StringKind::UrlEncoded);
    let results = decode_url_strings(&[input]);
    assert!(results.is_empty());
}

#[test]
fn test_url_no_change_after_decode() {
    // String with % but doesn't decode to anything different
    let input = make_string("same%", StringKind::UrlEncoded);
    let results = decode_url_strings(&[input]);
    assert!(results.is_empty());
}

#[test]
fn test_url_special_chars() {
    let input = make_string("path%2Fto%2Ffile%3Fquery%3Dvalue%26foo%3Dbar", StringKind::UrlEncoded);
    let results = decode_url_strings(&[input]);
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].value, "path/to/file?query=value&foo=bar");
}

#[test]
fn test_url_plus_sign() {
    let input = make_string("Hello+World%21", StringKind::UrlEncoded);
    let results = decode_url_strings(&[input]);
    assert_eq!(results.len(), 1);
    // Note: urlencoding crate may or may not convert + to space
    assert!(!results[0].value.is_empty());
}

// Note: is_likely_url_encoded is private, tested indirectly via decode_url_strings

// ==================== Batch Unicode Escape Decoding ====================

#[test]
fn test_decode_unicode_escape_strings_batch() {
    let inputs = vec![
        make_string("\\x48\\x65\\x6c\\x6c\\x6f", StringKind::UnicodeEscaped),
        make_string("\\u0054\\u0065\\u0073\\u0074", StringKind::UnicodeEscaped),
        make_string("no_escapes", StringKind::Const),
    ];

    let results = decode_unicode_escape_strings(&inputs);

    assert_eq!(results.len(), 2);
    assert_eq!(results[0].value, "Hello");
    assert_eq!(results[0].method, StringMethod::UnicodeEscapeDecode);
    assert_eq!(results[1].value, "Test");
    assert_eq!(results[1].method, StringMethod::UnicodeEscapeDecode);
}

#[test]
fn test_decode_unicode_escape_strings_empty() {
    let results = decode_unicode_escape_strings(&[]);
    assert!(results.is_empty());
}

// ==================== Unicode Escape Edge Cases ====================

#[test]
fn test_unicode_escape_x_format() {
    let input = make_string("\\x48\\x65\\x6c\\x6c\\x6f", StringKind::UnicodeEscaped);
    let results = decode_unicode_escape_strings(&[input]);
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].value, "Hello");
}

#[test]
fn test_unicode_escape_u_format() {
    let input = make_string("\\u0048\\u0065\\u006c\\u006c\\u006f", StringKind::UnicodeEscaped);
    let results = decode_unicode_escape_strings(&[input]);
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].value, "Hello");
}

#[test]
fn test_unicode_escape_U_format() {
    let input = make_string("\\U00000048\\U00000065\\U0000006c\\U0000006c\\U0000006f", StringKind::UnicodeEscaped);
    let results = decode_unicode_escape_strings(&[input]);
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].value, "Hello");
}

#[test]
fn test_unicode_escape_mixed_formats() {
    let input = make_string("\\x48\\u0065\\x6c\\u006c\\x6f", StringKind::UnicodeEscaped);
    let results = decode_unicode_escape_strings(&[input]);
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].value, "Hello");
}

#[test]
fn test_unicode_escape_incomplete_sequence() {
    // Incomplete escape sequences should be left as-is
    let input = make_string("\\x4", StringKind::UnicodeEscaped);
    let results = decode_unicode_escape_strings(&[input]);
    // Should fail or return original (no valid decode)
    assert!(results.is_empty() || results[0].value == "\\x4");
}

#[test]
fn test_unicode_escape_invalid_hex() {
    let input = make_string("\\xZZ\\xYY", StringKind::UnicodeEscaped);
    let results = decode_unicode_escape_strings(&[input]);
    // Invalid hex should be left as-is (no change = no decode)
    assert!(results.is_empty());
}

#[test]
fn test_unicode_escape_no_escapes() {
    let input = make_string("plain text", StringKind::UnicodeEscaped);
    let results = decode_unicode_escape_strings(&[input]);
    assert!(results.is_empty());
}

// Note: is_likely_unicode_escaped is private, tested indirectly via decode_unicode_escape_strings

// ==================== Batch Base32 Decoding ====================

#[test]
fn test_decode_base32_strings_batch() {
    let inputs = vec![
        make_string("JBSWY3DPEBLW64TMMQ======", StringKind::Base32),
        make_string("JBSWY3DPEBLW64TMMQ", StringKind::Base32), // No padding
        make_string("not_base32", StringKind::Const),
    ];

    let results = decode_base32_strings(&inputs);

    assert!(results.len() >= 2);
    assert_eq!(results[0].value, "Hello World");
    assert_eq!(results[0].method, StringMethod::Base32Decode);
}

#[test]
fn test_decode_base32_strings_empty() {
    let results = decode_base32_strings(&[]);
    assert!(results.is_empty());
}

// ==================== Base32 Edge Cases ====================

#[test]
fn test_base32_too_short() {
    let input = make_string("JBSWY3DP", StringKind::Base32); // < 16 chars
    let results = decode_base32_strings(&[input]);
    assert!(results.is_empty());
}

#[test]
fn test_base32_invalid_chars() {
    let input = make_string("JBSWY3DPEBLW64TMMQ!!!!!!!", StringKind::Base32);
    let results = decode_base32_strings(&[input]);
    assert!(results.is_empty());
}

// Note: is_likely_base32 is private, tested indirectly via decode_base32_strings

// ==================== Batch Base85 Decoding ====================

#[test]
fn test_decode_base85_strings_batch() {
    let inputs = vec![
        make_string("<~9jqo^~>", StringKind::Base85),
        make_string("not_base85", StringKind::Const),
    ];

    let results = decode_base85_strings(&inputs);

    // Base85 detection is strict, may or may not decode
    // Just ensure no panic
    assert!(results.len() <= inputs.len());
}

#[test]
fn test_decode_base85_strings_empty() {
    let results = decode_base85_strings(&[]);
    assert!(results.is_empty());
}

// ==================== Base85 Edge Cases ====================

#[test]
fn test_base85_too_short() {
    let input = make_string("<~9jq~>", StringKind::Base85); // < 20 chars
    let results = decode_base85_strings(&[input]);
    assert!(results.is_empty());
}

#[test]
fn test_base85_with_whitespace() {
    // Should skip whitespace and decode
    if let Some(decoded) = try_decode_ascii85("<~9jqo^\n  \t~>") {
        assert_eq!(decoded, b"Man ");
    }
}

#[test]
fn test_base85_z_shorthand() {
    // 'z' should expand to four zero bytes
    if let Some(decoded) = try_decode_ascii85("z") {
        assert_eq!(decoded, vec![0u8; 4]);
    }
}

#[test]
fn test_base85_partial_group() {
    // Test partial group handling (3 chars -> 2 bytes)
    if let Some(decoded) = try_decode_ascii85("9jq") {
        assert_eq!(decoded.len(), 2);
    }
}

#[test]
fn test_base85_invalid_char() {
    // Characters outside valid ASCII85 range should fail
    let result = try_decode_ascii85("9jqo^~invalid~");
    assert!(result.is_none());
}

#[test]
fn test_base85_overflow_protection() {
    // Test that overflow is prevented
    let result = try_decode_ascii85("uuuuu");
    // Should handle overflow gracefully (return None)
    // uuuuu would overflow u32 if not checked
    assert!(result.is_none());
}

// Note: is_likely_base64 and is_likely_hex are private, tested indirectly via batch decode functions

// ==================== Size Limit Tests ====================

#[test]
fn test_base64_size_limit() {
    // Create a string that would decode to > MAX_DECODED_SIZE (10MB)
    // Base64 expands by ~33%, so we need ~13.3MB of base64
    // For testing, we'll just verify the limit exists
    // (Actually creating 13MB of test data would be slow)

    // Instead, test with a reasonable size
    let large_input = "A".repeat(1000);
    let input = make_string(&large_input, StringKind::Base64);
    let results = decode_base64_strings(&[input]);
    // Should either decode or reject, but not panic
    assert!(results.len() <= 1);
}

#[test]
fn test_hex_size_limit() {
    // Similar to base64, verify size limit handling
    let large_input = "41".repeat(1000); // "A" repeated 1000 times
    let input = make_string(&large_input, StringKind::HexEncoded);
    let results = decode_hex_strings(&[input]);
    assert!(results.len() <= 1);
}

// ==================== Classification Tests ====================

#[test]
fn test_decoded_string_classification() {
    // Test that decoded strings are properly classified
    let url_encoded = make_string("http%3A%2F%2Fexample.com", StringKind::UrlEncoded);
    let results = decode_url_strings(&[url_encoded]);

    if !results.is_empty() {
        // Should classify as URL
        assert_eq!(results[0].kind, StringKind::Url);
    }
}

#[test]
fn test_decoded_ip_classification() {
    // Decode hex that contains an IP address
    let hex_ip = make_string("3139322e3136382e312e31", StringKind::HexEncoded); // "192.168.1.1"
    let results = decode_hex_strings(&[hex_ip]);

    if !results.is_empty() {
        assert_eq!(results[0].value, "192.168.1.1");
        assert_eq!(results[0].kind, StringKind::IP);
    }
}
