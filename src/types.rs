//! Core types for string extraction.
//!
//! This module defines the fundamental data structures used throughout
//! the string extraction process.

use serde::Serialize;

/// Represents a string structure found in binary (pointer + length pair).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct StringStruct {
    /// Offset in the section where this structure was found
    #[allow(dead_code)]
    pub struct_offset: u64,
    /// Virtual address of the string data
    pub ptr: u64,
    /// Length of the string
    pub len: u64,
}

/// Represents a fragment of a multi-part string (e.g., stack strings from multiple instructions)
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct StringFragment {
    /// File offset where this fragment's data is located
    pub offset: u64,
    /// Length of this fragment in bytes
    pub length: usize,
    /// The specific instruction flavor (e.g., "movabs", "`stack_array`")
    #[serde(skip_serializing_if = "Option::is_none")]
    pub flavor: Option<String>,
}

/// An extracted string with metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
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
    /// For multi-part strings (`StackString`), tracks all source fragments
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub fragments: Option<Vec<StringFragment>>,
    /// For Section strings, stores size and type metadata
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub section_size: Option<u64>,
    /// For Section strings, whether the section is executable
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub section_executable: Option<bool>,
    /// For Section strings, whether the section is writable
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub section_writable: Option<bool>,
}

impl Default for ExtractedString {
    fn default() -> Self {
        ExtractedString {
            value: String::new(),
            data_offset: 0,
            section: None,
            method: StringMethod::RawScan,
            kind: StringKind::Const,
            library: None,
            fragments: None,
            section_size: None,
            section_executable: None,
            section_writable: None,
        }
    }
}

impl ExtractedString {
    /// Get formatted section metadata if this is a section string
    pub fn section_metadata_str(&self) -> Option<String> {
        if self.kind != StringKind::Section {
            return None;
        }

        let size = self.section_size?;
        let is_exec = self.section_executable.unwrap_or(false);
        let is_write = self.section_writable.unwrap_or(false);

        // Format size
        let size_str = if size < 1024 {
            format!("{}b", size)
        } else if size < 1024 * 1024 {
            format!("{:.1}kb", size as f64 / 1024.0)
        } else {
            format!("{:.1}mb", size as f64 / (1024.0 * 1024.0))
        };

        // Format type
        let type_str = match (is_exec, is_write) {
            (true, true) => "TEXT+DATA",
            (true, false) => "TEXT",
            (false, true) => "DATA",
            (false, false) => "DATA",
        };

        Some(format!("({}, {})", size_str, type_str))
    }
}

/// Method used to extract the string.
///
/// Indicates the extraction technique, which affects confidence and context.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[non_exhaustive]
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
    /// Found via base64 decoding
    Base64Decode,
    /// Found via hex decoding
    HexDecode,
    /// Found via URL decoding
    UrlDecode,
    /// Found via unicode escape decoding (\xHH, \uHHHH, \UHHHHHHHH)
    UnicodeEscapeDecode,
    /// Found via base32 decoding
    Base32Decode,
    /// Found via base85 decoding (ASCII85/Z85)
    Base85Decode,
    /// Found via stack string construction analysis (immediate values)
    StackString,
    /// Found in Mach-O code signature (entitlements)
    CodeSignature,
}

/// Semantic kind of the extracted string.
///
/// Classifies strings by their purpose and security relevance.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Default)]
#[non_exhaustive]
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
    /// Hex-encoded ASCII data (each byte as two hex chars)
    HexEncoded,
    /// Unicode escape sequences (\xXX, \uXXXX format)
    UnicodeEscaped,
    /// URL-encoded data (%XX format)
    UrlEncoded,
    /// Base32-encoded data
    Base32,
    /// Base58-encoded data (Bitcoin/cryptocurrency)
    Base58,
    /// Base85-encoded data (ASCII85/Z85)
    Base85,
    /// Overlay/appended data after ELF/PE boundary (ASCII/UTF-8)
    Overlay,
    // Cryptocurrency and ransomware IOCs
    /// Cryptocurrency wallet address (Bitcoin, Ethereum, Monero, etc.)
    CryptoWallet,
    /// Cryptocurrency mining pool URL or stratum address
    MiningPool,
    /// Email address (often used in ransomware contact info)
    Email,
    /// Tor/Onion address (.onion domain)
    TorAddress,
    /// CTF competition flag (CTF{...}, flag{...}, etc.)
    CTFFlag,
    /// SQL injection payload
    SQLInjection,
    /// XSS (Cross-Site Scripting) payload
    XSSPayload,
    /// Command injection pattern
    CommandInjection,
    /// JWT (JSON Web Token)
    JWT,
    /// API key or secret (AWS, GitHub, Stripe, etc.)
    APIKey,
    /// Windows mutex or synchronization object name
    Mutex,
    /// GUID (Globally Unique Identifier)
    GUID,
    /// Ransomware-related string (ransom note, file extension, etc.)
    RansomNote,
    /// LDAP/Active Directory distinguished name
    LDAPPath,
    /// Overlay data in UTF-16LE encoding (common in malware configs)
    OverlayWide,
    /// Stack-constructed string (common in malware)
    StackString,
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
            | StringKind::HexEncoded
            | StringKind::UnicodeEscaped
            | StringKind::UrlEncoded
            | StringKind::Base32
            | StringKind::Base58
            | StringKind::Base85
            | StringKind::Overlay
            | StringKind::OverlayWide
            | StringKind::StackString
            | StringKind::Entitlement
            | StringKind::AppId
            | StringKind::XorKey
            | StringKind::CryptoWallet
            | StringKind::MiningPool
            | StringKind::Email
            | StringKind::TorAddress
            | StringKind::CTFFlag
            | StringKind::SQLInjection
            | StringKind::XSSPayload
            | StringKind::CommandInjection
            | StringKind::JWT
            | StringKind::APIKey
            | StringKind::Mutex
            | StringKind::GUID
            | StringKind::RansomNote
            | StringKind::LDAPPath => Severity::High,

            StringKind::Path
            | StringKind::FilePath
            | StringKind::Import
            | StringKind::EnvVar
            | StringKind::Registry
            | StringKind::Error
            | StringKind::Section
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
            StringKind::HexEncoded => "hex",
            StringKind::UnicodeEscaped => "unicode",
            StringKind::UrlEncoded => "urlenc",
            StringKind::Base32 => "base32",
            StringKind::Base58 => "base58",
            StringKind::Base85 => "base85",
            StringKind::Overlay => "overlay",
            StringKind::OverlayWide => "overlay:16LE",
            StringKind::StackString => "stack",
            StringKind::Entitlement => "entitlement",
            StringKind::AppId => "appid",
            StringKind::EntitlementsXml => "entitlements",
            StringKind::XorKey => "xor_key",
            StringKind::CryptoWallet => "crypto",
            StringKind::MiningPool => "miner",
            StringKind::Email => "email",
            StringKind::TorAddress => "tor",
            StringKind::CTFFlag => "ctf_flag",
            StringKind::SQLInjection => "sqli",
            StringKind::XSSPayload => "xss",
            StringKind::CommandInjection => "cmdi",
            StringKind::JWT => "jwt",
            StringKind::APIKey => "api_key",
            StringKind::Mutex => "mutex",
            StringKind::GUID => "guid",
            StringKind::RansomNote => "ransom",
            StringKind::LDAPPath => "ldap",
        }
    }
}

/// Binary information needed for string extraction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
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
            fragments: None,
            section_size: None,
            section_executable: None,
            section_writable: None,
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
