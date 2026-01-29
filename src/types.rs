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
    /// Overlay/appended data after ELF/PE boundary (ASCII/UTF-8)
    Overlay,
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
            | StringKind::Overlay
            | StringKind::OverlayWide
            | StringKind::StackString
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
            StringKind::StackString => "stack",
            StringKind::Entitlement => "entitlement",
            StringKind::AppId => "appid",
            StringKind::EntitlementsXml => "entitlements",
            StringKind::XorKey => "xor_key",
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
