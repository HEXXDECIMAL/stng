//! Common types and utilities for language-aware string extraction.

use serde::Serialize;

/// Represents a string structure found in binary (pointer + length pair).
#[derive(Debug, Clone)]
pub struct StringStruct {
    /// Offset in the section where this structure was found
    #[allow(dead_code)]
    pub struct_offset: u64,
    /// Virtual address of the string data
    pub ptr: u64,
    /// Length of the string
    pub len: u64,
}

/// An extracted string with metadata.
#[derive(Debug, Clone, Serialize)]
pub struct ExtractedString {
    /// The string value
    pub value: String,
    /// Offset in the binary where the string data is located
    pub data_offset: u64,
    /// Section name where the string was found
    pub section: Option<String>,
    /// How the string was found
    #[allow(dead_code)]
    pub method: StringMethod,
    /// Semantic kind of the string
    pub kind: StringKind,
    /// Source library for imports (e.g., "libSystem.B.dylib")
    #[serde(skip_serializing_if = "Option::is_none")]
    pub library: Option<String>,
}

/// Method used to extract the string.
///
/// Indicates the extraction technique, which affects confidence and context.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
pub enum StringMethod {
    /// Found via pointer+length structure analysis
    Structure,
    /// Found via instruction pattern analysis (inline literals)
    InstructionPattern,
    /// Found via traditional null-terminated/ASCII scan (fallback)
    RawScan,
    /// Found via heuristic pattern matching (Rust packed strings)
    Heuristic,
    /// Found via radare2 string analysis (iz command)
    R2String,
    /// Found via radare2 symbol analysis (is command)
    R2Symbol,
    /// Found via UTF-16LE wide string scan (Windows)
    WideString,
    /// Found via XOR decoding (single-byte key)
    XorDecode,
    /// Found in Mach-O code signature (entitlements)
    CodeSignature,
}

/// Semantic kind of the extracted string.
///
/// Classifies strings by their purpose and security relevance.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Default)]
pub enum StringKind {
    /// Generic string constant
    #[default]
    Const,
    /// Function or method name
    FuncName,
    /// Source file path
    FilePath,
    /// Map/dictionary key
    MapKey,
    /// Error message
    Error,
    /// Environment variable name
    EnvVar,
    /// URL or URI
    Url,
    /// File system path
    Path,
    /// Function argument (inline literal)
    Arg,
    /// Identifier (variable, type name, etc.)
    Ident,
    /// Low-value garbage string (misaligned reads, noise)
    Garbage,
    /// Binary segment/section name (__TEXT, .rodata, etc.)
    Section,
    /// Imported symbol from external library
    Import,
    /// Exported symbol
    Export,
    // Security-focused classifications
    /// IP address (v4 or v6)
    IP,
    /// IP:port or host:port combination
    IPPort,
    /// Hostname (domain name like evil.com)
    Hostname,
    /// Shell command (pipes, redirects, common commands)
    ShellCmd,
    /// Suspicious path (hidden dirs, rootkit locations, persistence)
    SuspiciousPath,
    /// Windows registry path
    Registry,
    /// Base64-encoded data
    Base64,
    /// Overlay/appended data after ELF/PE boundary (ASCII/UTF-8)
    Overlay,
    /// Overlay data in UTF-16LE encoding (common in malware configs)
    OverlayWide,
    /// macOS entitlement from code signature
    Entitlement,
    /// Application/service identifier from entitlements
    AppId,
    /// Raw entitlements XML plist from Mach-O code signature
    EntitlementsXml,
    /// XOR encryption key (detected or provided)
    XorKey,
}

/// Severity level for security-focused output.
///
/// Used to prioritize and highlight critical findings in security analysis.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Severity {
    /// Critical IOCs: IPs, URLs, shell commands, suspicious paths
    High = 0,
    /// Important context: paths, env vars, imports
    Medium = 1,
    /// Supporting info: function names, exports
    Low = 2,
    /// Default: constants, identifiers
    Info = 3,
}

impl StringKind {
    /// Get the severity level for this kind
    pub fn severity(&self) -> Severity {
        match self {
            StringKind::IP
            | StringKind::IPPort
            | StringKind::Hostname
            | StringKind::Url
            | StringKind::ShellCmd
            | StringKind::SuspiciousPath
            | StringKind::Base64
            | StringKind::Overlay
            | StringKind::OverlayWide
            | StringKind::Entitlement
            | StringKind::AppId
            | StringKind::XorKey => Severity::High,

            StringKind::Path
            | StringKind::FilePath
            | StringKind::Import
            | StringKind::EnvVar
            | StringKind::Registry
            | StringKind::Error
            | StringKind::EntitlementsXml => Severity::Medium,

            StringKind::FuncName | StringKind::Export => Severity::Low,

            _ => Severity::Info,
        }
    }

    /// Get short display name for the kind
    pub fn short_name(&self) -> &'static str {
        match self {
            StringKind::Const => "-",
            StringKind::FuncName => "func",
            StringKind::FilePath => "file",
            StringKind::MapKey => "key",
            StringKind::Error => "error",
            StringKind::EnvVar => "env",
            StringKind::Url => "url",
            StringKind::Path => "path",
            StringKind::Arg => "arg",
            StringKind::Ident => "ident",
            StringKind::Garbage => "garbage",
            StringKind::Section => "section",
            StringKind::Import => "import",
            StringKind::Export => "export",
            StringKind::IP => "ip",
            StringKind::IPPort => "ip:port",
            StringKind::Hostname => "host",
            StringKind::ShellCmd => "shell",
            StringKind::SuspiciousPath => "sus",
            StringKind::Registry => "registry",
            StringKind::Base64 => "base64",
            StringKind::Overlay => "overlay",
            StringKind::OverlayWide => "overlay:16LE",
            StringKind::Entitlement => "entitlement",
            StringKind::AppId => "appid",
            StringKind::EntitlementsXml => "entitlements",
            StringKind::XorKey => "xor_key",
        }
    }
}

/// Binary information needed for string extraction.
#[derive(Debug, Clone, Copy)]
pub struct BinaryInfo {
    pub is_64bit: bool,
    pub is_little_endian: bool,
    pub ptr_size: usize,
}

impl BinaryInfo {
    #[allow(dead_code)]
    pub fn new_64bit_le() -> Self {
        Self {
            is_64bit: true,
            is_little_endian: true,
            ptr_size: 8,
        }
    }

    #[allow(dead_code)]
    pub fn new_32bit_le() -> Self {
        Self {
            is_64bit: false,
            is_little_endian: true,
            ptr_size: 4,
        }
    }

    #[allow(dead_code)]
    pub fn new_64bit_be() -> Self {
        Self {
            is_64bit: true,
            is_little_endian: false,
            ptr_size: 8,
        }
    }

    #[allow(dead_code)]
    pub fn new_32bit_be() -> Self {
        Self {
            is_64bit: false,
            is_little_endian: false,
            ptr_size: 4,
        }
    }

    /// Create `BinaryInfo` from ELF header information
    pub fn from_elf(is_64bit: bool, is_little_endian: bool) -> Self {
        Self {
            is_64bit,
            is_little_endian,
            ptr_size: if is_64bit { 8 } else { 4 },
        }
    }

    /// Create `BinaryInfo` from Mach-O (always little-endian on modern systems)
    pub fn from_macho(is_64bit: bool) -> Self {
        Self {
            is_64bit,
            is_little_endian: true, // All modern Mach-O is LE
            ptr_size: if is_64bit { 8 } else { 4 },
        }
    }

    /// Create `BinaryInfo` from PE (always little-endian)
    pub fn from_pe(is_64bit: bool) -> Self {
        Self {
            is_64bit,
            is_little_endian: true, // PE is always LE
            ptr_size: if is_64bit { 8 } else { 4 },
        }
    }
}

/// Information about trailing/overlay data appended after the binary structure.
///
/// Overlay data is commonly used by malware to hide payloads or configuration.
/// This struct identifies data appended beyond the normal ELF/PE structure boundaries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OverlayInfo {
    /// Offset where the overlay data begins
    pub start_offset: u64,
    /// Size of the overlay data in bytes
    pub size: u64,
}

/// Find pointer+length structures that point into a data blob.
///
/// This scans section data looking for consecutive pointer+length pairs
/// where the pointer falls within the target blob's address range.
///
/// # Arguments
///
/// * `section_data` - Raw bytes of the section to scan
/// * `section_addr` - Virtual address of the section
/// * `blob_addr` - Virtual address of the target data blob
/// * `blob_size` - Size of the target data blob in bytes
/// * `info` - Binary architecture information
///
/// # Returns
///
/// A vector of string structures found, each representing a potential string reference.
pub fn find_string_structures(
    section_data: &[u8],
    section_addr: u64,
    blob_addr: u64,
    blob_size: u64,
    info: &BinaryInfo,
) -> Vec<StringStruct> {
    // Fast path for 64-bit little-endian (most common case)
    if info.is_64bit && info.is_little_endian {
        return find_string_structures_64le(section_data, section_addr, blob_addr, blob_size);
    }

    // Generic path for other architectures
    find_string_structures_generic(section_data, section_addr, blob_addr, blob_size, info)
}

/// Specialized fast path for 64-bit little-endian (no runtime checks in loop)
#[inline(always)]
fn find_string_structures_64le(
    section_data: &[u8],
    section_addr: u64,
    blob_addr: u64,
    blob_size: u64,
) -> Vec<StringStruct> {
    let mut structs = Vec::new();
    let blob_end = blob_addr + blob_size;

    if section_data.len() < 16 {
        return structs;
    }

    let mut i = 0;
    let end = section_data.len() - 15;

    while i < end {
        // Direct LE reads without runtime endianness checks
        // SAFETY: We checked i < end where end = section_data.len() - 15, so we have 16 bytes
        let ptr = u64::from_le_bytes(
            section_data[i..i + 8]
                .try_into()
                .expect("slice bounds checked above"),
        );
        let len = u64::from_le_bytes(
            section_data[i + 8..i + 16]
                .try_into()
                .expect("slice bounds checked above"),
        );

        if ptr >= blob_addr
            && ptr < blob_end
            && len > 0
            && len < 1024 * 1024
            && ptr + len <= blob_end
        {
            structs.push(StringStruct {
                struct_offset: section_addr + i as u64,
                ptr,
                len,
            });
        }
        i += 8;
    }

    structs
}

/// Generic path for non-64-bit-LE architectures
fn find_string_structures_generic(
    section_data: &[u8],
    section_addr: u64,
    blob_addr: u64,
    blob_size: u64,
    info: &BinaryInfo,
) -> Vec<StringStruct> {
    let mut structs = Vec::new();
    let struct_size = info.ptr_size * 2;

    if section_data.len() < struct_size {
        return structs;
    }

    for i in (0..=section_data.len() - struct_size).step_by(info.ptr_size) {
        // SAFETY: Loop ensures we have struct_size bytes available at position i
        let (ptr, len) = if info.is_64bit && info.is_little_endian {
            let ptr = u64::from_le_bytes(
                section_data[i..i + 8]
                    .try_into()
                    .expect("bounds checked in loop"),
            );
            let len = u64::from_le_bytes(
                section_data[i + 8..i + 16]
                    .try_into()
                    .expect("bounds checked in loop"),
            );
            (ptr, len)
        } else if info.is_64bit {
            let ptr = u64::from_be_bytes(
                section_data[i..i + 8]
                    .try_into()
                    .expect("bounds checked in loop"),
            );
            let len = u64::from_be_bytes(
                section_data[i + 8..i + 16]
                    .try_into()
                    .expect("bounds checked in loop"),
            );
            (ptr, len)
        } else if info.is_little_endian {
            let ptr = u64::from(u32::from_le_bytes(
                section_data[i..i + 4]
                    .try_into()
                    .expect("bounds checked in loop"),
            ));
            let len = u64::from(u32::from_le_bytes(
                section_data[i + 4..i + 8]
                    .try_into()
                    .expect("bounds checked in loop"),
            ));
            (ptr, len)
        } else {
            let ptr = u64::from(u32::from_be_bytes(
                section_data[i..i + 4]
                    .try_into()
                    .expect("bounds checked in loop"),
            ));
            let len = u64::from(u32::from_be_bytes(
                section_data[i + 4..i + 8]
                    .try_into()
                    .expect("bounds checked in loop"),
            ));
            (ptr, len)
        };

        // Check if this looks like a valid string structure
        if ptr >= blob_addr
            && ptr < blob_addr + blob_size
            && len > 0
            && len < 1024 * 1024 // Max 1MB string
            && ptr + len <= blob_addr + blob_size
        {
            structs.push(StringStruct {
                struct_offset: section_addr + i as u64,
                ptr,
                len,
            });
        }
    }

    structs
}

/// Extract strings from a data blob using string structures as boundaries.
///
/// Uses the pointer and length information from string structures to precisely
/// extract string data, avoiding concatenation issues common in packed string sections.
///
/// # Arguments
///
/// * `blob` - Raw bytes of the data blob containing string data
/// * `blob_addr` - Virtual address of the blob
/// * `structs` - String structures pointing into the blob
/// * `section_name` - Optional section name for metadata
/// * `classify_fn` - Function to classify each extracted string
///
/// # Type Parameters
///
/// * `F` - Closure that takes a string slice and returns its `StringKind`
///
/// # Returns
///
/// A vector of extracted strings with metadata.
pub fn extract_from_structures<F>(
    blob: &[u8],
    blob_addr: u64,
    structs: &[StringStruct],
    section_name: Option<&str>,
    classify_fn: F,
) -> Vec<ExtractedString>
where
    F: Fn(&str) -> StringKind,
{
    let mut result = Vec::with_capacity(structs.len() / 2);

    for s in structs {
        if s.ptr < blob_addr {
            continue;
        }

        let offset = (s.ptr - blob_addr) as usize;
        let end = offset + s.len as usize;

        if end > blob.len() {
            continue;
        }

        let bytes = &blob[offset..end];

        // Fast ASCII printability check before UTF-8 validation
        let printable_count = bytes
            .iter()
            .filter(|&&b| b.is_ascii_graphic() || b.is_ascii_whitespace())
            .count();

        if printable_count * 2 < bytes.len() {
            continue;
        }

        // Validate UTF-8
        if let Ok(string) = std::str::from_utf8(bytes) {
            let trimmed = string.trim();
            if trimmed.is_empty() {
                continue;
            }
            result.push(ExtractedString {
                value: trimmed.to_string(),
                data_offset: s.ptr,
                section: section_name.map(std::string::ToString::to_string),
                method: StringMethod::Structure,
                kind: classify_fn(trimmed),
                library: None,
            });
        }
    }

    result
}

/// Determines if a string appears to be garbage/noise rather than meaningful content.
///
/// This heuristic detects common patterns of misaligned reads and low-value strings:
/// - Short strings with non-alphanumeric characters
/// - Strings ending with backtick + letter + spaces (misaligned Go data)
/// - Strings with very low alphanumeric ratio
/// - Strings that are mostly whitespace padding
/// - Strings with embedded null or control characters
pub fn is_garbage(s: &str) -> bool {
    // Check for control characters in non-trailing-newline portion
    let check_control = s.trim_end_matches('\n');
    for c in check_control.chars() {
        if c.is_control() {
            return true;
        }
    }

    // Normalize: trim whitespace
    let trimmed = s.trim();
    let len = trimmed.len();

    // Empty or whitespace-only
    if len == 0 {
        return true;
    }

    // Single characters are almost always garbage from raw scans
    if len == 1 {
        return true;
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
            if dot_count == special as usize {
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

    false
}

/// Check if a byte sequence looks like valid UTF-8 with reasonable content.
#[allow(dead_code)]
pub fn is_valid_string(bytes: &[u8], min_length: usize) -> bool {
    if bytes.len() < min_length {
        return false;
    }

    match std::str::from_utf8(bytes) {
        Ok(s) => {
            // Check printability
            let printable = s
                .chars()
                .filter(|c| c.is_ascii_graphic() || c.is_ascii_whitespace())
                .count();
            printable * 2 >= s.len()
        }
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_binary_info_64bit_le() {
        let info = BinaryInfo::new_64bit_le();
        assert!(info.is_64bit);
        assert!(info.is_little_endian);
        assert_eq!(info.ptr_size, 8);
    }

    #[test]
    fn test_binary_info_32bit_le() {
        let info = BinaryInfo::new_32bit_le();
        assert!(!info.is_64bit);
        assert!(info.is_little_endian);
        assert_eq!(info.ptr_size, 4);
    }

    #[test]
    fn test_find_string_structures_64bit_le() {
        let info = BinaryInfo::new_64bit_le();

        // Create section with one valid string structure
        // ptr = 0x1000, len = 5
        let mut section_data = vec![0u8; 32];
        section_data[0..8].copy_from_slice(&0x1000u64.to_le_bytes());
        section_data[8..16].copy_from_slice(&5u64.to_le_bytes());

        let structs = find_string_structures(
            &section_data,
            0x2000, // section_addr
            0x1000, // blob_addr
            0x100,  // blob_size
            &info,
        );

        assert_eq!(structs.len(), 1);
        assert_eq!(structs[0].ptr, 0x1000);
        assert_eq!(structs[0].len, 5);
        assert_eq!(structs[0].struct_offset, 0x2000);
    }

    #[test]
    fn test_extract_from_structures_basic() {
        let blob = b"HelloWorld";
        let structs = vec![
            StringStruct {
                struct_offset: 0,
                ptr: 0x1000,
                len: 5,
            },
            StringStruct {
                struct_offset: 16,
                ptr: 0x1005,
                len: 5,
            },
        ];

        let strings =
            extract_from_structures(blob, 0x1000, &structs, Some("test"), |_| StringKind::Const);

        assert_eq!(strings.len(), 2);
        assert_eq!(strings[0].value, "Hello");
        assert_eq!(strings[1].value, "World");
        assert_eq!(strings[0].method, StringMethod::Structure);
    }

    #[test]
    fn test_is_valid_string_basic() {
        assert!(is_valid_string(b"Hello World", 4));
    }

    #[test]
    fn test_is_valid_string_too_short() {
        assert!(!is_valid_string(b"Hi", 4));
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
    fn test_binary_info_64bit_be() {
        let info = BinaryInfo::new_64bit_be();
        assert!(info.is_64bit);
        assert!(!info.is_little_endian);
        assert_eq!(info.ptr_size, 8);
    }

    #[test]
    fn test_binary_info_32bit_be() {
        let info = BinaryInfo::new_32bit_be();
        assert!(!info.is_64bit);
        assert!(!info.is_little_endian);
        assert_eq!(info.ptr_size, 4);
    }

    #[test]
    fn test_binary_info_from_elf() {
        let info64 = BinaryInfo::from_elf(true, true);
        assert!(info64.is_64bit);
        assert!(info64.is_little_endian);
        assert_eq!(info64.ptr_size, 8);

        let info32 = BinaryInfo::from_elf(false, false);
        assert!(!info32.is_64bit);
        assert!(!info32.is_little_endian);
        assert_eq!(info32.ptr_size, 4);
    }

    #[test]
    fn test_binary_info_from_macho() {
        let info64 = BinaryInfo::from_macho(true);
        assert!(info64.is_64bit);
        assert!(info64.is_little_endian); // Mach-O always LE
        assert_eq!(info64.ptr_size, 8);

        let info32 = BinaryInfo::from_macho(false);
        assert!(!info32.is_64bit);
        assert!(info32.is_little_endian);
        assert_eq!(info32.ptr_size, 4);
    }

    #[test]
    fn test_binary_info_from_pe() {
        let info64 = BinaryInfo::from_pe(true);
        assert!(info64.is_64bit);
        assert!(info64.is_little_endian); // PE always LE
        assert_eq!(info64.ptr_size, 8);

        let info32 = BinaryInfo::from_pe(false);
        assert!(!info32.is_64bit);
        assert!(info32.is_little_endian);
        assert_eq!(info32.ptr_size, 4);
    }

    #[test]
    fn test_find_string_structures_empty() {
        let info = BinaryInfo::new_64bit_le();
        let structs = find_string_structures(&[], 0x2000, 0x1000, 0x100, &info);
        assert!(structs.is_empty());
    }

    #[test]
    fn test_find_string_structures_too_short() {
        let info = BinaryInfo::new_64bit_le();
        let section_data = vec![0u8; 8]; // Only 8 bytes, need 16 for struct
        let structs = find_string_structures(&section_data, 0x2000, 0x1000, 0x100, &info);
        assert!(structs.is_empty());
    }

    #[test]
    fn test_find_string_structures_32bit() {
        let info = BinaryInfo::new_32bit_le();

        let mut section_data = vec![0u8; 16];
        section_data[0..4].copy_from_slice(&0x1000u32.to_le_bytes());
        section_data[4..8].copy_from_slice(&5u32.to_le_bytes());

        let structs = find_string_structures(&section_data, 0x2000, 0x1000, 0x100, &info);

        assert_eq!(structs.len(), 1);
        assert_eq!(structs[0].ptr, 0x1000);
        assert_eq!(structs[0].len, 5);
    }

    #[test]
    fn test_find_string_structures_big_endian() {
        let info = BinaryInfo::new_64bit_be();

        let mut section_data = vec![0u8; 32];
        section_data[0..8].copy_from_slice(&0x1000u64.to_be_bytes());
        section_data[8..16].copy_from_slice(&5u64.to_be_bytes());

        let structs = find_string_structures(&section_data, 0x2000, 0x1000, 0x100, &info);

        assert_eq!(structs.len(), 1);
        assert_eq!(structs[0].ptr, 0x1000);
        assert_eq!(structs[0].len, 5);
    }

    #[test]
    fn test_find_string_structures_32bit_be() {
        let info = BinaryInfo::new_32bit_be();

        let mut section_data = vec![0u8; 16];
        section_data[0..4].copy_from_slice(&0x1000u32.to_be_bytes());
        section_data[4..8].copy_from_slice(&5u32.to_be_bytes());

        let structs = find_string_structures(&section_data, 0x2000, 0x1000, 0x100, &info);

        assert_eq!(structs.len(), 1);
    }

    #[test]
    fn test_extract_from_structures_invalid_utf8() {
        let blob = &[0xFF, 0xFE, 0xFD, 0xFC, 0xFB];
        let structs = vec![StringStruct {
            struct_offset: 0,
            ptr: 0x1000,
            len: 5,
        }];

        let strings = extract_from_structures(blob, 0x1000, &structs, None, |_| StringKind::Const);

        // Invalid UTF-8 should be skipped
        assert!(strings.is_empty());
    }

    #[test]
    fn test_extract_from_structures_mostly_non_printable() {
        let blob = b"\x01\x02\x03\x04\x05";
        let structs = vec![StringStruct {
            struct_offset: 0,
            ptr: 0x1000,
            len: 5,
        }];

        let strings = extract_from_structures(blob, 0x1000, &structs, None, |_| StringKind::Const);

        // Mostly non-printable should be skipped
        assert!(strings.is_empty());
    }

    #[test]
    fn test_extract_from_structures_ptr_out_of_range() {
        let blob = b"Hello";
        let structs = vec![StringStruct {
            struct_offset: 0,
            ptr: 0x5000, // Out of range
            len: 5,
        }];

        let strings = extract_from_structures(blob, 0x1000, &structs, None, |_| StringKind::Const);

        assert!(strings.is_empty());
    }

    #[test]
    fn test_extract_from_structures_len_overflow() {
        let blob = b"Hello";
        let structs = vec![StringStruct {
            struct_offset: 0,
            ptr: 0x1000,
            len: 100, // Longer than blob
        }];

        let strings = extract_from_structures(blob, 0x1000, &structs, None, |_| StringKind::Const);

        assert!(strings.is_empty());
    }

    #[test]
    fn test_extract_from_structures_with_section_name() {
        let blob = b"Hello";
        let structs = vec![StringStruct {
            struct_offset: 0,
            ptr: 0x1000,
            len: 5,
        }];

        let strings = extract_from_structures(blob, 0x1000, &structs, Some(".rodata"), |_| {
            StringKind::Const
        });

        assert_eq!(strings.len(), 1);
        assert_eq!(strings[0].section, Some(".rodata".to_string()));
    }

    #[test]
    fn test_extract_from_structures_classification() {
        let blob = b"/usr/bin";
        let structs = vec![StringStruct {
            struct_offset: 0,
            ptr: 0x1000,
            len: 8,
        }];

        let strings = extract_from_structures(blob, 0x1000, &structs, None, |s| {
            if s.starts_with('/') {
                StringKind::Path
            } else {
                StringKind::Const
            }
        });

        assert_eq!(strings.len(), 1);
        assert_eq!(strings[0].kind, StringKind::Path);
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
    fn test_string_kind_equality() {
        assert_eq!(StringKind::Const, StringKind::Const);
        assert_ne!(StringKind::Const, StringKind::Import);
        assert_ne!(StringKind::Import, StringKind::Export);
    }

    #[test]
    fn test_string_method_equality() {
        assert_eq!(StringMethod::Structure, StringMethod::Structure);
        assert_ne!(StringMethod::Structure, StringMethod::RawScan);
    }

    #[test]
    fn test_extracted_string_clone() {
        let s = ExtractedString {
            value: "test".to_string(),
            data_offset: 100,
            section: Some("section".to_string()),
            method: StringMethod::Structure,
            kind: StringKind::Const,
            library: Some("lib".to_string()),
        };

        let cloned = s.clone();
        assert_eq!(s.value, cloned.value);
        assert_eq!(s.data_offset, cloned.data_offset);
        assert_eq!(s.section, cloned.section);
        assert_eq!(s.library, cloned.library);
    }

    #[test]
    fn test_string_struct_clone() {
        let s = StringStruct {
            struct_offset: 100,
            ptr: 200,
            len: 10,
        };

        let cloned = s.clone();
        assert_eq!(s.struct_offset, cloned.struct_offset);
        assert_eq!(s.ptr, cloned.ptr);
        assert_eq!(s.len, cloned.len);
    }
}
