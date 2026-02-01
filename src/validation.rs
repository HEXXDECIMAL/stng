//! String validation utilities.
//!
//! Functions for validating and filtering string candidates to remove garbage
//! and low-quality strings.

/// Determines if a string appears to be garbage/noise rather than meaningful content.
///
/// This heuristic detects common patterns of misaligned reads and low-value strings:
/// - Short strings with non-alphanumeric characters
/// - Strings ending with backtick + letter + spaces (misaligned Go data)
/// - Strings with very low alphanumeric ratio
/// - Strings that are mostly whitespace padding
/// - Strings with embedded null or control characters
pub fn is_garbage(s: &str) -> bool {
    // Normalize: trim whitespace first
    let trimmed = s.trim();

    // Fast path: longer strings with normal patterns are rarely garbage
    // This avoids expensive analysis for the common case
    if trimmed.len() >= 12 {
        let bytes = trimmed.as_bytes();
        let first = bytes[0];
        // Quick check for all-same-character strings (garbage)
        if bytes.iter().all(|&b| b == first) {
            return true;
        }
        // If it starts with a letter and has mostly alphanumeric + common punctuation, skip full analysis
        if first.is_ascii_alphabetic() {
            let simple_chars = bytes.iter().filter(|&&b| {
                b.is_ascii_alphanumeric() || b == b' ' || b == b'_' || b == b'-' || b == b'.' || b == b'/'
            }).count();
            if simple_chars * 100 / bytes.len() >= 80 {
                return false;
            }
        }
    }

    // Special case: Shell command patterns (check before control char rejection)
    // These often have garbage bytes before/after but are still valuable
    // Examples: "osascript", "bash", "sh ", "/bin/", "2>&1", "<<EOD"
    if trimmed.contains("osascript")
        || trimmed.contains("bash")
        || trimmed.contains("/bin/sh")
        || trimmed.contains("/bin/bash")
        || trimmed.contains("2>&1")
        || trimmed.contains("<<")  // heredocs: <<EOD, <<EOF, <<END, etc.
        || trimmed.contains("2>/dev/null")
        || trimmed.contains("2>")
        || (trimmed.contains(" sh ") || trimmed.starts_with("sh ") || trimmed.ends_with(" sh"))
    {
        // BUT: if the string is mostly gibberish (too many special chars), reject it
        let special_count = trimmed.chars().filter(|c| !c.is_alphanumeric() && !c.is_whitespace()).count();
        let alnum_count = trimmed.chars().filter(|c| c.is_alphanumeric()).count();

        // Real shell commands should have reasonable alphanumeric content
        // Reject if <40% alphanumeric or if special chars dominate
        if alnum_count * 100 / trimmed.len() < 40 || special_count > alnum_count {
            // Continue to normal garbage checks
        } else {
            return false; // Shell commands are NOT garbage
        }
    }

    // Check for control characters in non-trailing-newline portion
    let check_control = s.trim_end_matches('\n');
    for c in check_control.chars() {
        if c.is_control() {
            return true;
        }
    }
    let len = trimmed.len();

    // Empty or whitespace-only
    if len == 0 {
        return true;
    }

    // Single characters are almost always garbage from raw scans
    if len == 1 {
        return true;
    }

    // Special case: locale strings (en_US, zh_CN, etc.)
    // Format: 2-3 lowercase letters + underscore + 2-3 uppercase letters
    if len == 5 || len == 6 {
        let chars: Vec<char> = trimmed.chars().collect();
        if chars.len() >= 5 {
            let has_locale_pattern = (chars[0].is_ascii_lowercase()
                && chars[1].is_ascii_lowercase()
                && chars[2] == '_'
                && chars[3].is_ascii_uppercase()
                && chars[4].is_ascii_uppercase())
                || (chars.len() == 6
                    && chars[0].is_ascii_lowercase()
                    && chars[1].is_ascii_lowercase()
                    && chars[2].is_ascii_lowercase()
                    && chars[3] == '_'
                    && chars[4].is_ascii_uppercase()
                    && chars[5].is_ascii_uppercase());
            if has_locale_pattern {
                return false; // Locale strings are NOT garbage
            }
        }
    }

    // Special case: XML/plist tags (<array>, <dict>, <key>, etc.)
    if trimmed.starts_with('<') && trimmed.ends_with('>') && len >= 3 {
        let inner = &trimmed[1..trimmed.len() - 1];
        // Valid XML tag if inner content is alphanumeric (possibly with / for closing tags)
        let is_valid_tag = inner.chars().all(|c| c.is_alphanumeric() || c == '/');
        if is_valid_tag && !inner.is_empty() {
            return false; // XML tags are NOT garbage
        }
    }

    // Special case: Shell command patterns with redirections and heredocs
    // Examples: "osascript 2>&1 <<EOD", "command 2>/dev/null", "cmd > output.txt"
    if trimmed.contains("2>&1")  // stderr redirect to stdout
        || trimmed.contains("2>")  // stderr redirect to file
        || trimmed.contains("<<")  // heredoc
        || (trimmed.contains('>') && trimmed.split_whitespace().count() >= 2)  // redirect with spaces
    {
        // Check if it looks like a command (has alphanumeric content)
        let alnum_count = trimmed.chars().filter(|c| c.is_alphanumeric()).count();
        if alnum_count >= 3 {
            return false; // Shell commands with redirections are NOT garbage
        }
    }

    // Single-pass character counting
    let mut upper = 0usize;
    let mut lower = 0usize;
    let mut digit = 0usize;
    let mut alpha = 0usize;
    let mut whitespace = 0usize;
    let mut noise_punct = 0usize;
    let mut open_parens = 0usize;
    let mut close_parens = 0usize;
    let mut quotes = 0usize;
    let mut special = 0usize;
    let mut hex_only = 0usize;
    let mut ascii_count = 0usize;
    let mut alternations = 0usize;
    let mut prev_is_digit: Option<bool> = None;
    let mut first_char: Option<char> = None;
    let mut all_same = true;
    let mut last_char = '\0';
    let mut has_non_hex_letter = false;

    for c in trimmed.chars() {
        // Track first/last and uniformity
        if first_char.is_none() {
            first_char = Some(c);
        } else if all_same && Some(c) != first_char {
            all_same = false;
        }
        last_char = c;

        // ASCII check
        if c.is_ascii() {
            ascii_count += 1;
        }

        // Character type counting
        if c.is_ascii_uppercase() {
            upper += 1;
            alpha += 1;
            if !c.is_ascii_hexdigit() {
                has_non_hex_letter = true;
            }
            hex_only += 1;
            // Alternation tracking
            if prev_is_digit == Some(true) {
                alternations += 1;
            }
            prev_is_digit = Some(false);
        } else if c.is_ascii_lowercase() {
            lower += 1;
            alpha += 1;
            if !c.is_ascii_hexdigit() {
                has_non_hex_letter = true;
            }
            hex_only += 1;
            if prev_is_digit == Some(true) {
                alternations += 1;
            }
            prev_is_digit = Some(false);
        } else if c.is_ascii_digit() {
            digit += 1;
            hex_only += 1;
            if prev_is_digit == Some(false) {
                alternations += 1;
            }
            prev_is_digit = Some(true);
        } else if c.is_alphabetic() {
            // Non-ASCII alphabetic
            alpha += 1;
            if prev_is_digit == Some(true) {
                alternations += 1;
            }
            prev_is_digit = Some(false);
        } else if c.is_whitespace() {
            whitespace += 1;
        } else {
            // Punctuation/special characters
            match c {
                '#' | '@' | '?' | '>' | '<' | '|' | '\\' | '^' | '`' | '~' | '$' | '+' | '&'
                | '*' | '=' | ';' | ':' | '!' | ',' => noise_punct += 1,
                '(' | '[' | '{' => open_parens += 1,
                ')' | ']' | '}' => close_parens += 1,
                '"' | '\'' => quotes += 1,
                _ => {}
            }
            if !c.is_alphanumeric() && !c.is_whitespace() {
                special += 1;
            }
        }
    }

    let alphanumeric = alpha + digit;
    let first_char = trimmed.chars().next().unwrap_or(' ');

    // Very short strings (2-6 chars) that look like random binary data
    if (2..=6).contains(&len) {
        let is_all_upper = upper == len;
        let is_all_lower = lower == len;
        let is_all_digit = digit == len;
        // Allow identifier-like patterns: leading digit(s) + uppercase only (e.g., "8BIM", "3DES", "2D")
        // Digits must be at the START only, not interspersed (reject "9N2A", "0YI0")
        let is_digit_upper_id = first_char.is_ascii_digit()
            && upper > 0
            && lower == 0
            && special == 0
            && trimmed
                .chars()
                .skip_while(char::is_ascii_digit)
                .all(|c| c.is_ascii_uppercase());
        // Allow PascalCase words: leading uppercase + rest lowercase, no digits (e.g., "Bool", "Exif", "Time")
        let is_pascal_case =
            first_char.is_ascii_uppercase() && upper == 1 && lower > 0 && digit == 0;
        // Allow camelCase words: leading lowercase + one uppercase NOT at end, no digits (e.g., "someWord")
        // Reject patterns like "phbS" (uppercase at end) or "gnzUrs" (too short to verify)
        // camelCase needs at least 7 chars to be recognizable (e.g., "myValue")
        let last_char = trimmed.chars().last().unwrap_or(' ');
        let is_camel_case = len >= 7
            && first_char.is_ascii_lowercase()
            && upper == 1
            && digit == 0
            && !last_char.is_ascii_uppercase();
        // Allow lowercase + trailing digits (e.g., "amd64", "utf8", "sha256")
        // Must start with lowercase, not digit (reject "8oz1")
        let is_lower_with_suffix = first_char.is_ascii_lowercase()
            && lower > 0
            && upper == 0
            && digit > 0
            && last_char.is_ascii_digit();

        if !(is_all_upper
            || is_all_lower
            || is_all_digit
            || is_digit_upper_id
            || is_pascal_case
            || is_camel_case
            || is_lower_with_suffix)
        {
            // Mixed case with digits in short strings is usually garbage
            if digit > 0 && (upper > 0 || lower > 0) {
                return true;
            }
            // Irregular mixed case patterns are usually garbage from compressed data
            // (e.g., "zVQO", "IKfB", "phbS", "OsVLJ", "HQIld")
            if upper > 0 && lower > 0 {
                return true;
            }
            // Short strings with internal whitespace are garbage (e.g., "VW N", "5c 9")
            if whitespace > 0 {
                return true;
            }
        }
    }

    // Short strings with noise punctuation are garbage (expanded range for compressed data)
    if len <= 10 && noise_punct > 0 {
        return true;
    }

    // Strings with trailing spaces after short content often indicate misaligned reads
    if s.ends_with(' ') && len < 10 && alphanumeric < 4 {
        return true;
    }

    // Pattern: ends with backtick + single letter + optional spaces (Go misaligned reads)
    let bytes = trimmed.as_bytes();
    if len >= 2 {
        if let Some(idx) = bytes.iter().rposition(|&b| b.is_ascii_alphabetic()) {
            if idx > 0 && bytes[idx - 1] == b'`' {
                return true;
            }
        }
    }

    // Very short strings with special chars are usually garbage
    if len <= 4 && alphanumeric < len / 2 {
        return true;
    }

    // Short strings with unbalanced or unusual punctuation patterns
    if len <= 8 && (open_parens != close_parens || quotes == 1) {
        return true;
    }

    // Short strings that look like misaligned binary
    if len <= 6 {
        if upper > 0 && special > 0 && alpha == upper {
            return true;
        }
        // Short strings with special chars are usually garbage, BUT:
        // - Filenames with single '.' (e.g., "a.out", "d.exe", "lib.so") are OK
        // - Section/path prefixes starting with '.' (e.g., ".text", ".data", ".init") are OK
        if special > 0 && len <= 5 {
            // Count dots
            let dot_count = trimmed.chars().filter(|&c| c == '.').count();
            // If it's ONLY dots as special chars, it might be a filename or section name
            if dot_count == special {
                // Single dot in the middle (filename: "d.exe", "a.out")
                // OR starts with dot (section name: ".text", ".data", ".bss")
                let is_filename_pattern = (dot_count == 1
                    && !trimmed.starts_with('.')
                    && !trimmed.ends_with('.'))
                    || trimmed.starts_with('.');
                if is_filename_pattern && alphanumeric > 0 {
                    // Not garbage - looks like a filename or section name
                } else {
                    return true;
                }
            } else {
                // Has other special chars besides dots - likely garbage
                return true;
            }
        }
    }

    // Medium-length strings (5-10 chars) with mixed case and digits are usually noise
    // from compressed data (e.g., "fprzTR8", "J=22KJT", "V1rN:R")
    // Exclude legitimate patterns like version strings, dates, paths
    if (5..=10).contains(&len) && digit > 0 && upper > 0 && lower > 0 {
        // Allow patterns that look like versions (go1.22, v1.0) or dates
        let looks_like_version = trimmed.starts_with("go")
            || trimmed.starts_with('v')
            || trimmed.starts_with('V')
            || trimmed.contains('.');
        if !looks_like_version {
            return true;
        }
    }

    // Short strings (5-8 chars) with all uppercase + digits but irregular pattern
    // are usually garbage (e.g., "55LYE", "0GZF")
    if (5..=8).contains(&len) && digit > 0 && alpha == upper && lower == 0 && special == 0 {
        // Allow patterns like "HTTP2", "UTF8" where digit is at the end
        let last_char = trimmed.chars().last().unwrap_or(' ');
        let first_char = trimmed.chars().next().unwrap_or(' ');
        if first_char.is_ascii_digit() || (!last_char.is_ascii_digit() && digit > 0) {
            return true;
        }
    }

    // Strings that are mostly non-alphanumeric
    if len >= 4 && alphanumeric == 0 {
        return true;
    }

    // Alternating digit-letter patterns
    if len >= 6 && digit > 0 && alpha > 0 && alternations >= 4 && alternations * 2 >= len {
        return true;
    }

    // Very low ratio of alphanumeric characters
    if len > 6 && alphanumeric * 100 / len < 30 {
        return true;
    }

    // Strings that look like random hex/binary data
    if len >= 8
        && !has_non_hex_letter
        && hex_only == len
        && digit > 0
        && alpha > 0
        && !trimmed.contains('.')
        && !trimmed.starts_with("0x")
    {
        return true;
    }

    // Single repeated character
    if len >= 4 && all_same {
        return true;
    }

    // Strings with excessive whitespace relative to content
    if whitespace > 0 && whitespace * 3 > len {
        return true;
    }

    // Short strings with non-ASCII characters are often misaligned reads
    let non_ascii_count = len - ascii_count;
    if non_ascii_count > 0 && len < 20 && non_ascii_count * 5 > ascii_count {
        return true;
    }

    // Short strings ending with unusual unicode are suspicious
    if !last_char.is_ascii() && len < 15 && alphanumeric < len / 2 {
        return true;
    }

    // Character class contiguous region analysis
    // Legitimate strings have longer runs of the same character class (lowercase, uppercase, digits)
    // Garbage strings alternate chaotically between classes
    if len >= 6 {
        // Define character classes for each character
        #[derive(PartialEq, Eq, Clone, Copy)]
        enum CharClass {
            Upper,
            Lower,
            Digit,
            Special,
            Whitespace,
        }

        let char_classes: Vec<CharClass> = trimmed
            .chars()
            .map(|c| {
                if c.is_ascii_uppercase() {
                    CharClass::Upper
                } else if c.is_ascii_lowercase() {
                    CharClass::Lower
                } else if c.is_ascii_digit() {
                    CharClass::Digit
                } else if c.is_whitespace() {
                    CharClass::Whitespace
                } else {
                    CharClass::Special
                }
            })
            .collect();

        // Count transitions and track run lengths
        let mut transitions = 0;
        let mut run_lengths: Vec<usize> = Vec::new();
        let mut current_run_length = 1;

        for i in 1..char_classes.len() {
            if char_classes[i] == char_classes[i - 1] {
                current_run_length += 1;
            } else {
                transitions += 1;
                run_lengths.push(current_run_length);
                current_run_length = 1;
            }
        }
        run_lengths.push(current_run_length); // Don't forget the last run

        // Calculate average run length
        let total_run_chars: usize = run_lengths.iter().sum();
        let avg_run_length = if run_lengths.is_empty() {
            0.0
        } else {
            total_run_chars as f32 / run_lengths.len() as f32
        };

        // Check if string is dominated by one character class (>70%)
        // Include special characters in the check - strings with mostly special chars
        // are often legitimate (like shell commands, format strings, etc.)
        let max_class_count = upper.max(lower).max(digit).max(special);
        let is_mostly_one_class = max_class_count * 100 / len > 70;

        // Check for structured patterns that naturally have many transitions
        // These should be exempt from alternation checks
        // Paths need more than just a slash - require alphanumeric content and reasonable structure
        // Also reject if too many special characters (real paths are usually <20% special)
        // AND require mostly lowercase (real paths are typically lowercase)
        let looks_like_path = (trimmed.contains('/') || trimmed.contains('\\'))
            && alphanumeric >= 3
            && special * 100 / len <= 30
            && (alphanumeric == 0 || lower * 100 / alphanumeric >= 40)  // At least 40% of alphanumeric chars are lowercase
            && (trimmed.starts_with('/')
                || trimmed.starts_with('\\')
                || trimmed.contains("/.")
                || trimmed.contains("\\.")
                || trimmed.split(&['/', '\\'][..]).filter(|s| !s.is_empty()).count() >= 2);
        let looks_like_url = trimmed.contains("://") || trimmed.contains("http");
        // Domains should have reasonable structure: mostly alphanumeric, dots, hyphens, underscores
        // Reject if too many special characters (real domains have <20% special)
        let looks_like_domain = trimmed.contains('.')
            && trimmed.split('.').filter(|s| !s.is_empty()).count() >= 2
            && special * 100 / len <= 20;
        let looks_like_version = (trimmed.starts_with("go")
            || trimmed.starts_with('v')
            || trimmed.starts_with('V'))
            && trimmed.contains('.')
            && digit > 0;
        // Base64 strings have uniform character distribution but many transitions
        // They only contain [A-Za-z0-9+/=] and often end with =
        let looks_like_base64 = len >= 16
            && upper > 0
            && lower > 0
            && trimmed
                .chars()
                .all(|c| c.is_alphanumeric() || c == '+' || c == '/' || c == '=');
        // Format strings contain % followed by format specifiers (s, d, f, x, v, etc.)
        let looks_like_format_string = trimmed.contains("%s")
            || trimmed.contains("%d")
            || trimmed.contains("%f")
            || trimmed.contains("%x")
            || trimmed.contains("%v")
            || trimmed.contains("%p")
            || trimmed.contains("%c")
            || trimmed.contains("%u");
        let is_structured_pattern = looks_like_path
            || looks_like_url
            || looks_like_domain
            || looks_like_version
            || looks_like_base64
            || looks_like_format_string;

        // Reject strings with excessive alternation and short runs
        // Exception: strings dominated by one class (like all-uppercase acronyms)
        // Exception: structured patterns (paths, URLs, domains, versions)
        if !is_mostly_one_class && !is_structured_pattern {
            // Too many transitions relative to length (>60% of positions are transitions)
            if transitions * 100 / len > 60 {
                return true;
            }

            // Very short average run length indicates random alternation
            // Avg run length < 2.0 means mostly 1-char runs (chaotic alternation)
            if avg_run_length < 2.0 && len >= 8 {
                return true;
            }

            // For shorter strings (6-7 chars), be even stricter
            if len <= 7 && avg_run_length < 1.5 && transitions >= 4 {
                return true;
            }
        } else if is_structured_pattern && avg_run_length < 2.0 && len >= 10 {
            // Even "structured" patterns shouldn't be TOO chaotic
            // Reject if very short runs (< 2.0) in strings ≥10 chars
            // This catches garbage that looks like paths/domains but has random alternation
            // EXCEPTION: Don't apply this check to recognized structured patterns since they naturally create short runs
            // (e.g., "/usr/lib/go" has runs: /, usr, /, lib, /, go = avg 1.83)
            // (e.g., "Photoshop 3.0" has runs: P, hotoshop, space, 3, ., 0 = avg 2.17)
            // (e.g., "VGhpcyBpcyBhIHNlY3JldCBtZXNzYWdl" = avg 1.78, typical for base64)
            // (e.g., "Error: %s at line %d" = avg 1.54, typical for format strings)
            // Only reject if VERY chaotic (< 2.0) AND not a recognized structured pattern
            if !looks_like_path
                && !looks_like_domain
                && !looks_like_version
                && !looks_like_base64
                && !looks_like_format_string
                && !looks_like_url {
                return true;
            }
        }
    }

    false
}

/// Check if a byte sequence looks like valid UTF-8 with reasonable content.
#[allow(dead_code)]
pub fn is_valid_string(bytes: &[u8], min_length: usize) -> bool {
    if bytes.len() < min_length {
        return false;
    }

    std::str::from_utf8(bytes).is_ok_and(|s| {
        // Check printability
        let printable = s
            .chars()
            .filter(|c| c.is_ascii_graphic() || c.is_ascii_whitespace())
            .count();
        printable * 2 >= s.len()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_valid_string_basic() {
        assert!(is_valid_string(b"Hello World", 4));
    }

    #[test]
    fn test_is_valid_string_too_short() {
        assert!(!is_valid_string(b"Hi", 4));
    }

    #[test]
    fn test_is_valid_string_non_printable() {
        assert!(!is_valid_string(b"\x01\x02\x03\x04", 4));
    }

    #[test]
    fn test_is_valid_string_mixed() {
        // More than 50% printable should pass
        assert!(is_valid_string(b"abcd\x01", 4));
    }

    #[test]
    fn test_is_garbage_valid_strings() {
        // Valid strings should NOT be garbage
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
    fn test_is_garbage_jpeg_metadata() {
        // JPEG/image metadata strings should NOT be garbage
        assert!(!is_garbage("JFIF"));
        assert!(!is_garbage("Photoshop 3.0"));
        assert!(!is_garbage("8BIM")); // Photoshop resource marker
        assert!(!is_garbage("Exif"));
        assert!(!is_garbage("cph/3c13276u.tif"));
        assert!(!is_garbage("1998:12:15 13:03:34"));
        assert!(!is_garbage("Library of Congress"));
        // JPEG quantization table character sequence
        assert!(!is_garbage("%&'()*456789:CDEFGHIJSTUVWXYZcdefghijstuvwxyz"));
    }

    #[test]
    fn test_is_garbage_misaligned_go_reads() {
        // Misaligned Go data patterns should be garbage
        assert!(is_garbage("asL "));
        assert!(is_garbage("``L "));
        assert!(is_garbage("dL "));
        assert!(is_garbage("7aL "));
        assert!(is_garbage("`L "));
        assert!(is_garbage("D`L  "));
        assert!(is_garbage("~dL  "));
        assert!(is_garbage("#uL  "));
        assert!(is_garbage("gkL     @M"));
    }

    #[test]
    fn test_is_garbage_short_binary_patterns() {
        // Short strings that look like misaligned binary data
        assert!(is_garbage("PuO#"));
        assert!(is_garbage("P9O"));
        assert!(is_garbage("8ZAj"));
        assert!(is_garbage("pIo2"));
        assert!(is_garbage("PIO2"));
        assert!(is_garbage("@E?"));
        assert!(is_garbage("P$O"));
        assert!(is_garbage("0Y/("));
        assert!(is_garbage("UoV#"));
        assert!(is_garbage("1j2`1r2l1128"));
        // JPEG/binary compressed data patterns
        assert!(is_garbage("Gi4r"));
        assert!(is_garbage("Uim0"));
        assert!(is_garbage("Ilu4"));
        assert!(is_garbage("cwZd"));
        // More compressed data patterns with interspersed digits
        assert!(is_garbage("9N2A")); // digits interspersed with letters
        assert!(is_garbage("0YI0")); // digits interspersed with letters
        assert!(is_garbage("8oz1")); // leading digit + lowercase (not valid pattern)
        assert!(is_garbage("gnzUrs")); // short mixed case
                                       // Note: "3OEP" looks like "8BIM" (digit + uppercase), can't distinguish without whitelist
                                       // Short strings with internal spaces
        assert!(is_garbage("5c 9"));
        assert!(is_garbage("VW N"));
        // But all-uppercase, all-lowercase, or all-numeric are OK
        assert!(!is_garbage("PFO"));
        assert!(!is_garbage("API"));
        assert!(!is_garbage("foo"));
        assert!(!is_garbage("1234"));
    }

    #[test]
    fn test_is_garbage_short_nonalpha() {
        // Short strings with mostly non-alphanumeric
        assert!(is_garbage("@#$%"));
        assert!(is_garbage("!!!"));
        assert!(is_garbage("   "));
        assert!(is_garbage(""));
    }

    #[test]
    fn test_is_garbage_repeated_chars() {
        // Single repeated characters
        assert!(is_garbage("aaaa"));
        assert!(is_garbage("...."));
        assert!(is_garbage("----"));
    }

    #[test]
    fn test_is_garbage_unicode_endings() {
        // Short strings with non-ASCII unicode at the end
        assert!(is_garbage("333333ӿ"));
        assert!(is_garbage("abcӿ"));
    }

    #[test]
    fn test_is_garbage_control_chars() {
        // Strings with control characters
        assert!(is_garbage("ab\x00cd"));
        assert!(is_garbage("\x01\x02\x03"));
    }

    #[test]
    fn test_is_garbage_single_char() {
        assert!(is_garbage("a"));
        assert!(is_garbage("X"));
        assert!(is_garbage("1"));
    }

    #[test]
    fn test_is_garbage_alternating_pattern() {
        // Alternating digit-letter patterns
        assert!(is_garbage("1a2b3c4d5e"));
    }

    #[test]
    fn test_is_garbage_low_alphanum_ratio() {
        // Less than 30% alphanumeric for strings > 6 chars
        assert!(is_garbage("....!!!!"));
    }

    #[test]
    fn test_is_garbage_unbalanced_parens() {
        assert!(is_garbage("ab(cd"));
        assert!(is_garbage("ab[cd"));
    }

    #[test]
    fn test_is_garbage_single_quote() {
        assert!(is_garbage("ab'cd"));
    }

    #[test]
    fn test_is_garbage_trailing_newline_ok() {
        // Trailing newline should not trigger control char detection
        assert!(!is_garbage("hello world\n"));
    }

    #[test]
    fn test_is_garbage_short_strings_with_dots() {
        // Short strings with dots should not be automatically marked as garbage
        // These are common in filenames and section names
        assert!(!is_garbage("d.exe"), "d.exe should not be garbage");
        assert!(!is_garbage(".blah"), ".blah should not be garbage");
        assert!(!is_garbage("a.out"), "a.out should not be garbage");
        assert!(!is_garbage("lib.so"), "lib.so should not be garbage");

        // Section names specifically (starts with dot)
        assert!(!is_garbage(".text"), ".text should not be garbage");
        assert!(!is_garbage(".data"), ".data should not be garbage");
        assert!(!is_garbage(".bss"), ".bss should not be garbage");
    }

    #[test]
    fn test_is_garbage_base64_strings() {
        // Base64 strings should NOT be garbage
        assert!(!is_garbage("VGhpcyBpcyBhIHNlY3JldCBtZXNzYWdl"));
        assert!(!is_garbage("SGVsbG8gV29ybGQh"));
        assert!(!is_garbage("YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXo="));
    }

    #[test]
    fn test_is_garbage_xor_malware_samples() {
        // Real garbage strings from XOR-decoded malware (brew_agent sample)
        // These have chaotic character class alternation and should be filtered
        // Note: Some strings with specific patterns (e.g., short with limited special chars)
        // may not be caught by all heuristics, but the majority should be filtered
        let garbage_strings = vec![
            "v*\\^R--E:y4)@O",
            "ZFI7% eE;*\\Y",
            "Z(9uE(/S_B>7/c",
            "#LUU2!FN}v.VDH!#T:y40]P\"L,JSy',E[H\"5/c",
            "#L_G90_<\"J8KFy!!SCy>+FH}v.LXJ",
            "\\?UuC%3YeO9,[<\"J8KFy!!SCy' ]Z",
            "H>@uO*)T:y40]P\"L,JSy4%R\\I%(/c",
            "G$M*y'5RVy2$\\E\"Y(KLI6- eE\"7Cc",
            "P_T1*]Q}v.LXJ",
            "F?T*y'5RVy2$\\E\"Z(MEV0@",
            "IC#*_H}v.LXJ",
            "\\?UuU()SNy17JY\"H!U*y!8IN&",
            "[(\\uG(, eC/,[<\"O.UEU!@",
            "Z(9u@'/PC@>)J<\"O+U_U,@",
            "\\>Q*y\"'ENUW",
            "\\A21\\<\"O!VIMD",
            "\\J8&D<\"O\"IOHD",
            "F.R*y\"/P_HW",
            "[(\\*y\"2EUV2+/c",
            "\\R2)C<\"O9\\FJ+@",
            "@9\\*y#%T_H!Ep[",
            "]C# AJ}v*\\^N+3TTG: /c",
            "^OR,/SNH6(J<\"N(MZQ1)D:y0",
        ];

        for s in &garbage_strings {
            assert!(
                is_garbage(s),
                "XOR garbage string should be filtered: {:?}",
                s
            );
        }
    }
}
