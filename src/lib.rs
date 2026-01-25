//! # strangs - Language-aware string extraction
//!
//! This library provides language-aware string extraction for Go and Rust binaries.
//! Unlike traditional `strings(1)`, it understands how these languages store strings
//! internally (pointer + length pairs, NOT null-terminated) and can properly extract
//! individual strings from packed string data.
//!
//! ## Background
//!
//! Both Go and Rust use "fat pointer" representations for strings:
//! - Go: `string` is `{ptr: *byte, len: int}` (16 bytes on 64-bit)
//! - Rust: `&str` is `{ptr: *u8, len: usize}` (16 bytes on 64-bit)
//! - Rust: `String` is `{ptr: *u8, len: usize, cap: usize}` (24 bytes on 64-bit)
//!
//! Because strings aren't null-terminated, they're often packed together
//! in the binary without separators. Traditional string extraction tools
//! concatenate them into garbage blobs.
//!
//! This module finds the pointer+length structures and uses them to
//! extract strings with precise boundaries.
//!
//! ## Usage
//!
//! ```no_run
//! use strangs::extract_strings;
//!
//! let data = std::fs::read("my_binary").unwrap();
//! let strings = extract_strings(&data, 4);
//!
//! for s in strings {
//!     println!("{}: {}", s.data_offset, s.value);
//! }
//! ```

mod common;
mod go;
mod instr;
pub mod r2;
mod rust;

pub use common::{is_garbage, BinaryInfo, ExtractedString, StringKind, StringMethod, StringStruct};

use std::collections::HashSet;
pub use go::GoStringExtractor;
pub use rust::RustStringExtractor;

// Re-export goblin so library clients can parse binaries themselves
pub use goblin;
use goblin::mach::MachO;
use goblin::Object;

/// Collect segment and section names from a Mach-O binary.
fn collect_macho_segments(macho: &MachO) -> Vec<String> {
    let mut segments = Vec::new();
    for seg in &macho.segments {
        if let Ok(name) = seg.name() {
            segments.push(name.to_string());
        }
        if let Ok(sections) = seg.sections() {
            for (sec, _) in sections {
                if let Ok(name) = sec.name() {
                    segments.push(name.to_string());
                }
            }
        }
    }
    segments
}

/// Collect section names from an ELF binary.
fn collect_elf_segments(elf: &goblin::elf::Elf) -> Vec<String> {
    elf.section_headers
        .iter()
        .filter_map(|sh| elf.shdr_strtab.get_at(sh.sh_name).map(|s| s.to_string()))
        .collect()
}

/// Helper to check if a Mach-O binary has Go sections.
fn macho_has_go_sections(macho: &MachO) -> bool {
    macho.segments.iter().any(|seg| {
        seg.sections().is_ok_and(|secs| {
            secs.iter().any(|(sec, _)| {
                let name = sec.name().unwrap_or("");
                name == "__gopclntab" || name == "__go_buildinfo"
            })
        })
    })
}

/// Check if a binary is a Go binary by looking for Go-specific sections.
pub fn is_go_binary(data: &[u8]) -> bool {
    match Object::parse(data) {
        Ok(Object::Mach(goblin::mach::Mach::Binary(macho))) => macho_has_go_sections(&macho),
        Ok(Object::Mach(goblin::mach::Mach::Fat(_))) => false,
        Ok(Object::Elf(elf)) => elf.section_headers.iter().any(|sh| {
            let name = elf.shdr_strtab.get_at(sh.sh_name).unwrap_or("");
            name == ".gopclntab" || name == ".go.buildinfo"
        }),
        Ok(Object::PE(_pe)) => false,
        _ => false,
    }
}

/// Check if a binary is a Rust binary.
pub fn is_rust_binary(data: &[u8]) -> bool {
    match Object::parse(data) {
        Ok(Object::Mach(goblin::mach::Mach::Binary(macho))) => macho_is_rust(&macho),
        Ok(Object::Elf(elf)) => elf.section_headers.iter().any(|sh| {
            let name = elf.shdr_strtab.get_at(sh.sh_name).unwrap_or("");
            name.contains("rust") || name == ".rustc"
        }),
        _ => false,
    }
}

/// Check if a Mach-O binary appears to be a Rust binary.
fn macho_is_rust(macho: &MachO) -> bool {
    macho.segments.iter().any(|seg| {
        seg.sections().is_ok_and(|secs| {
            secs.iter().any(|(sec, _)| {
                let name = sec.name().unwrap_or("");
                name.contains("rust")
            })
        })
    })
}

/// Extract imports from a Mach-O binary.
fn extract_macho_imports(macho: &MachO, min_length: usize) -> Vec<ExtractedString> {
    let mut strings = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();

    // Extract imports with their source library
    if let Ok(imports) = macho.imports() {
        for import in imports {
            if import.name.len() >= min_length && seen.insert(import.name.to_string()) {
                // Strip the leading path from dylib, e.g., "/usr/lib/libSystem.B.dylib" -> "libSystem.B.dylib"
                let lib = import.dylib.rsplit('/').next().unwrap_or(import.dylib);
                strings.push(ExtractedString {
                    value: import.name.to_string(),
                    data_offset: import.address,
                    section: None,
                    method: StringMethod::Structure,
                    kind: StringKind::Import,
                    library: Some(lib.to_string()),
                });
            }
        }
    }

    // Extract exports
    if let Ok(exports) = macho.exports() {
        for export in exports {
            if export.name.len() >= min_length && seen.insert(export.name.to_string()) {
                strings.push(ExtractedString {
                    value: export.name.to_string(),
                    data_offset: export.offset,
                    section: None,
                    method: StringMethod::Structure,
                    kind: StringKind::Export,
                    library: None,
                });
            }
        }
    }

    strings
}

/// Extract imports from an ELF binary.
fn extract_elf_imports(elf: &goblin::elf::Elf, min_length: usize) -> Vec<ExtractedString> {
    let mut strings = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();

    // Extract dynamic symbols (imports/exports)
    for sym in &elf.dynsyms {
        let name = match elf.dynstrtab.get_at(sym.st_name) {
            Some(n) if n.len() >= min_length => n,
            _ => continue,
        };

        if !seen.insert(name.to_string()) {
            continue;
        }

        // UNDEF symbols with non-zero st_value or GLOBAL binding are imports
        // GLOBAL/WEAK symbols with defined section are exports
        let (kind, library) = if sym.st_shndx == 0 {
            // Undefined - this is an import
            // Try to find the library from verneed
            let lib = elf.verneed.iter()
                .flat_map(|v| v.iter())
                .find(|vn| {
                    vn.iter().any(|aux| {
                        elf.dynstrtab.get_at(aux.vna_name) == Some(name)
                    })
                })
                .and_then(|vn| elf.dynstrtab.get_at(vn.vn_file))
                .map(|s| s.to_string());
            (StringKind::Import, lib)
        } else if sym.st_bind() == goblin::elf::sym::STB_GLOBAL
            || sym.st_bind() == goblin::elf::sym::STB_WEAK {
            // Defined global/weak symbol - this is an export
            (StringKind::Export, None)
        } else {
            continue;
        };

        strings.push(ExtractedString {
            value: name.to_string(),
            data_offset: sym.st_value,
            section: None,
            method: StringMethod::Structure,
            kind,
            library,
        });
    }

    strings
}

/// Options for string extraction.
#[derive(Debug, Clone, Default)]
pub struct ExtractOptions {
    /// Minimum string length to extract
    pub min_length: usize,
    /// Use radare2 for extraction (if available). Default: false for library use.
    pub use_r2: bool,
    /// Path to the binary file (required if use_r2 is true)
    pub path: Option<String>,
    /// Pre-extracted strings from radare2 (allows clients to run r2 themselves)
    pub r2_strings: Option<Vec<ExtractedString>>,
    /// Filter out garbage strings (default: false for library, true for CLI)
    pub filter_garbage: bool,
}

impl ExtractOptions {
    pub fn new(min_length: usize) -> Self {
        Self {
            min_length,
            use_r2: false,
            path: None,
            r2_strings: None,
            filter_garbage: false,
        }
    }

    pub fn with_r2(mut self, path: &str) -> Self {
        self.use_r2 = true;
        self.path = Some(path.to_string());
        self
    }

    /// Provide pre-extracted r2 strings instead of running r2 internally.
    /// This allows library clients to run r2 themselves and pass the results.
    pub fn with_r2_strings(mut self, strings: Vec<ExtractedString>) -> Self {
        self.r2_strings = Some(strings);
        self
    }

    /// Enable garbage filtering to remove noise strings.
    /// Default is false for library use to give clients full control.
    pub fn with_garbage_filter(mut self, enable: bool) -> Self {
        self.filter_garbage = enable;
        self
    }
}

/// Detect binary type and extract strings using appropriate language-aware extractor.
///
/// This is the main entry point for string extraction. It automatically detects
/// whether the binary is Go or Rust and uses the appropriate extractor.
///
/// # Arguments
///
/// * `data` - The raw binary data
/// * `min_length` - Minimum string length to extract
///
/// # Returns
///
/// A vector of extracted strings with metadata about where they were found.
pub fn extract_strings(data: &[u8], min_length: usize) -> Vec<ExtractedString> {
    extract_strings_with_options(data, &ExtractOptions::new(min_length))
}

/// Extract strings with additional options.
///
/// This allows specifying whether to use radare2 for extraction.
pub fn extract_strings_with_options(data: &[u8], opts: &ExtractOptions) -> Vec<ExtractedString> {
    match Object::parse(data) {
        Ok(object) => extract_from_object(&object, data, opts),
        Err(_) => {
            // Unknown format - use r2 if available, otherwise raw scan
            let mut strings = Vec::new();
            if let Some(r2_strings) = get_r2_strings(opts) {
                strings.extend(r2_strings);
            }
            if strings.is_empty() && !data.is_empty() {
                strings.extend(extract_raw_strings(data, opts.min_length, None, &[]));
            }
            strings
        }
    }
}

/// Helper to get r2 strings from options (pre-extracted or by running r2)
fn get_r2_strings(opts: &ExtractOptions) -> Option<Vec<ExtractedString>> {
    // Use pre-extracted r2 strings if provided
    if let Some(ref r2_strings) = opts.r2_strings {
        return Some(r2_strings.clone());
    }
    // Otherwise run r2 if enabled
    if opts.use_r2 {
        if let Some(ref path) = opts.path {
            return r2::extract_strings(path, opts.min_length);
        }
    }
    None
}

/// Extract strings from a pre-parsed goblin Object.
///
/// This allows library clients who have already parsed the binary with goblin
/// to avoid re-parsing. Useful when integrating with tools that use goblin directly.
///
/// # Arguments
///
/// * `object` - A pre-parsed goblin Object
/// * `data` - The raw binary data (needed for string extraction)
/// * `opts` - Extraction options
///
/// # Example
///
/// ```no_run
/// use strangs::{extract_from_object, ExtractOptions, goblin};
///
/// let data = std::fs::read("my_binary").unwrap();
/// let object = goblin::Object::parse(&data).unwrap();
/// let opts = ExtractOptions::new(4);
/// let strings = extract_from_object(&object, &data, &opts);
/// ```
pub fn extract_from_object(object: &Object, data: &[u8], opts: &ExtractOptions) -> Vec<ExtractedString> {
    let min_length = opts.min_length;
    let mut strings = Vec::new();

    match object {
        Object::Mach(goblin::mach::Mach::Binary(macho)) => {
            let segments = collect_macho_segments(macho);
            if macho_has_go_sections(macho) {
                let extractor = GoStringExtractor::new(min_length);
                strings.extend(extractor.extract_macho(macho, data));
            } else if macho_is_rust(macho) {
                let extractor = RustStringExtractor::new(min_length);
                strings.extend(extractor.extract_macho(macho, data));
            } else {
                // Unknown Mach-O - use r2 if available
                if let Some(r2_strings) = get_r2_strings(opts) {
                    strings.extend(r2_strings);
                }
                // Also do raw scan to catch anything r2 missed
                let extractor = RustStringExtractor::new(min_length);
                let rust_strings = extractor.extract_macho(macho, data);
                if rust_strings.is_empty() {
                    strings.extend(extract_raw_strings(data, min_length, None, &segments));
                } else {
                    strings.extend(rust_strings);
                }
            }
            // Add imports/exports, upgrading existing strings
            let imports = extract_macho_imports(macho, min_length);
            let import_map: std::collections::HashMap<&str, (&StringKind, Option<&str>)> = imports
                .iter()
                .map(|s| (s.value.as_str(), (&s.kind, s.library.as_deref())))
                .collect();
            for s in strings.iter_mut() {
                if let Some(&(kind, lib)) = import_map.get(s.value.as_str()) {
                    s.kind = kind.clone();
                    s.library = lib.map(|l| l.to_string());
                }
            }
            let seen: HashSet<String> = strings.iter().map(|s| s.value.clone()).collect();
            for s in imports {
                if !seen.contains(&s.value) {
                    strings.push(s);
                }
            }
        }
        Object::Mach(goblin::mach::Mach::Fat(fat)) => {
            // Fat binary - check for Go/Rust first
            let mut is_go = false;
            let mut is_rust = false;
            let mut segments = Vec::new();
            let mut first_macho: Option<MachO> = None;
            for arch_result in fat.into_iter() {
                if let Ok(goblin::mach::SingleArch::MachO(macho)) = arch_result {
                    segments = collect_macho_segments(&macho);
                    if macho_has_go_sections(&macho) {
                        is_go = true;
                        let extractor = GoStringExtractor::new(min_length);
                        strings.extend(extractor.extract_macho(&macho, data));
                    } else if macho_is_rust(&macho) {
                        is_rust = true;
                        let extractor = RustStringExtractor::new(min_length);
                        strings.extend(extractor.extract_macho(&macho, data));
                    }
                    first_macho = Some(macho);
                    break;
                }
            }
            // For non-Go/non-Rust fat binaries, use r2 if available + raw scan
            if !is_go && !is_rust {
                if let Some(r2_strings) = get_r2_strings(opts) {
                    strings.extend(r2_strings);
                }
                // Also do raw scan to catch anything r2 missed
                strings.extend(extract_raw_strings(data, min_length, None, &segments));
            }
            // Add imports/exports from first architecture, upgrading existing strings
            if let Some(ref macho) = first_macho {
                let imports = extract_macho_imports(macho, min_length);
                // Build a map of import values to their library info
                let import_map: std::collections::HashMap<&str, (&StringKind, Option<&str>)> = imports
                    .iter()
                    .map(|s| (s.value.as_str(), (&s.kind, s.library.as_deref())))
                    .collect();
                // Update existing strings that are actually imports
                for s in strings.iter_mut() {
                    if let Some(&(kind, lib)) = import_map.get(s.value.as_str()) {
                        s.kind = kind.clone();
                        s.library = lib.map(|l| l.to_string());
                    }
                }
                // Add new imports that weren't found before
                let seen: HashSet<String> = strings.iter().map(|s| s.value.clone()).collect();
                for s in imports {
                    if !seen.contains(&s.value) {
                        strings.push(s);
                    }
                }
            }
        }
        Object::Elf(elf) => {
            let segments = collect_elf_segments(elf);

            // Check for Go sections
            let has_go = elf.section_headers.iter().any(|sh| {
                let name = elf.shdr_strtab.get_at(sh.sh_name).unwrap_or("");
                name == ".gopclntab" || name == ".go.buildinfo"
            });

            // Check for Rust (presence of rust metadata or panic strings)
            let has_rust = elf.section_headers.iter().any(|sh| {
                let name = elf.shdr_strtab.get_at(sh.sh_name).unwrap_or("");
                name.contains("rust") || name == ".rustc"
            });

            if has_go {
                let extractor = GoStringExtractor::new(min_length);
                strings.extend(extractor.extract_elf(elf, data));
            } else if has_rust {
                let extractor = RustStringExtractor::new(min_length);
                strings.extend(extractor.extract_elf(elf, data));
            } else {
                // Unknown ELF - use r2 if available + raw scan
                if let Some(r2_strings) = get_r2_strings(opts) {
                    strings.extend(r2_strings);
                }
                // Also do raw scan to catch anything r2 missed
                let extractor = RustStringExtractor::new(min_length);
                let rust_strings = extractor.extract_elf(elf, data);
                if rust_strings.is_empty() {
                    strings.extend(extract_raw_strings(data, min_length, None, &segments));
                } else {
                    strings.extend(rust_strings);
                }
            }
            // Add imports/exports from dynamic symbols, upgrading existing strings
            let imports = extract_elf_imports(elf, min_length);
            let import_map: std::collections::HashMap<&str, (&StringKind, Option<&str>)> = imports
                .iter()
                .map(|s| (s.value.as_str(), (&s.kind, s.library.as_deref())))
                .collect();
            for s in strings.iter_mut() {
                if let Some(&(kind, lib)) = import_map.get(s.value.as_str()) {
                    s.kind = kind.clone();
                    s.library = lib.map(|l| l.to_string());
                }
            }
            let seen: HashSet<String> = strings.iter().map(|s| s.value.clone()).collect();
            for s in imports {
                if !seen.contains(&s.value) {
                    strings.push(s);
                }
            }
        }
        Object::PE(pe) => {
            // Collect PE section names
            let segments: Vec<String> = pe.sections.iter().map(|sec| {
                String::from_utf8_lossy(&sec.name).trim_end_matches('\0').to_string()
            }).collect();

            // Check for Go by looking for go.buildinfo or runtime.main
            let has_go = pe.sections.iter().any(|sec| {
                let name = String::from_utf8_lossy(&sec.name);
                name.contains("go") || name.contains(".rdata")
            });

            if has_go {
                let extractor = GoStringExtractor::new(min_length);
                strings.extend(extractor.extract_pe(pe, data));
            } else {
                // Unknown PE - use r2 if available
                if let Some(r2_strings) = get_r2_strings(opts) {
                    strings.extend(r2_strings);
                }
                if strings.is_empty() {
                    strings.extend(extract_raw_strings(data, min_length, None, &segments));
                }
            }
        }
        _ => {
            // Unknown format - use r2 if available, otherwise raw scan
            if let Some(r2_strings) = get_r2_strings(opts) {
                strings.extend(r2_strings);
            }
            if strings.is_empty() && !data.is_empty() {
                strings.extend(extract_raw_strings(data, min_length, None, &[]));
            }
        }
    }

    // Apply garbage filter if enabled
    if opts.filter_garbage {
        strings.retain(|s| !common::is_garbage(&s.value));
    }

    strings
}

/// Extract raw null-terminated strings from binary data (fallback for unknown binaries).
fn extract_raw_strings(
    data: &[u8],
    min_length: usize,
    section: Option<String>,
    segment_names: &[String],
) -> Vec<ExtractedString> {
    // Build a set of known segment/section names for quick lookup
    let segment_names: HashSet<&str> = segment_names.iter().map(|s| s.as_str()).collect();

    let mut strings = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();
    let mut current = Vec::new();
    let mut start_offset = 0usize;

    for (i, &byte) in data.iter().enumerate() {
        if byte == 0 {
            if current.len() >= min_length {
                if let Ok(s) = std::str::from_utf8(&current) {
                    let trimmed = s.trim();
                    if !trimmed.is_empty() && !seen.contains(trimmed) {
                        seen.insert(trimmed.to_string());

                        // Check if this string matches a known segment/section name
                        let kind = if segment_names.contains(trimmed) {
                            StringKind::Section
                        } else {
                            go::classify_string(trimmed)
                        };

                        strings.push(ExtractedString {
                            value: trimmed.to_string(),
                            data_offset: start_offset as u64,
                            section: section.clone(),
                            method: StringMethod::RawScan,
                            kind,
                            library: None,
                        });
                    }
                }
            }
            current.clear();
        } else if byte.is_ascii_graphic() || byte.is_ascii_whitespace() {
            if current.is_empty() {
                start_offset = i;
            }
            current.push(byte);
        } else {
            current.clear();
        }
    }

    strings
}

/// Detect the language of a binary.
///
/// Returns "go", "rust", or "unknown".
pub fn detect_language(data: &[u8]) -> &'static str {
    if is_go_binary(data) {
        "go"
    } else if is_rust_binary(data) {
        "rust"
    } else {
        "unknown"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_strings_empty_data() {
        let strings = extract_strings(&[], 4);
        assert!(strings.is_empty());
    }

    #[test]
    fn test_extract_strings_invalid_binary() {
        let data = b"not a valid binary format";
        let strings = extract_strings(data, 4);
        assert!(strings.is_empty());
    }

    #[test]
    fn test_detect_language_empty() {
        assert_eq!(detect_language(&[]), "unknown");
    }

    #[test]
    fn test_detect_language_invalid() {
        assert_eq!(detect_language(b"not a binary"), "unknown");
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
        let opts = ExtractOptions::new(8).with_r2("/path/to/binary");
        assert_eq!(opts.min_length, 8);
        assert!(opts.use_r2);
        assert_eq!(opts.path, Some("/path/to/binary".to_string()));
    }

    #[test]
    fn test_extract_options_default() {
        let opts = ExtractOptions::default();
        assert_eq!(opts.min_length, 0);
        assert!(!opts.use_r2);
        assert!(opts.path.is_none());
    }

    #[test]
    fn test_extract_strings_with_options_empty() {
        let opts = ExtractOptions::new(4);
        let strings = extract_strings_with_options(&[], &opts);
        assert!(strings.is_empty());
    }

    #[test]
    fn test_extract_strings_with_min_length() {
        let strings1 = extract_strings(&[], 1);
        let strings2 = extract_strings(&[], 100);
        assert!(strings1.is_empty());
        assert!(strings2.is_empty());
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

    // Helper to create minimal ELF header
    fn minimal_elf() -> Vec<u8> {
        let mut data = vec![0u8; 64];
        data[0..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
        data[4] = 2; // 64-bit
        data[5] = 1; // little endian
        data[6] = 1; // version
        data
    }

    // Helper to create minimal Mach-O header
    fn minimal_macho() -> Vec<u8> {
        let mut data = vec![0u8; 32];
        data[0..4].copy_from_slice(&[0xCF, 0xFA, 0xED, 0xFE]); // 64-bit magic
        data[4..8].copy_from_slice(&[0x07, 0x00, 0x00, 0x01]); // x86_64
        data
    }

    #[test]
    fn test_is_go_binary_minimal_elf() {
        let data = minimal_elf();
        assert!(!is_go_binary(&data)); // No Go sections
    }

    #[test]
    fn test_is_rust_binary_minimal_elf() {
        let data = minimal_elf();
        assert!(!is_rust_binary(&data)); // No Rust sections
    }

    #[test]
    fn test_is_go_binary_minimal_macho() {
        let data = minimal_macho();
        assert!(!is_go_binary(&data)); // No Go sections
    }

    #[test]
    fn test_is_rust_binary_minimal_macho() {
        let data = minimal_macho();
        assert!(!is_rust_binary(&data)); // No Rust sections
    }

    #[test]
    fn test_detect_language_minimal_elf() {
        let data = minimal_elf();
        assert_eq!(detect_language(&data), "unknown");
    }

    #[test]
    fn test_detect_language_minimal_macho() {
        let data = minimal_macho();
        assert_eq!(detect_language(&data), "unknown");
    }

    #[test]
    fn test_extract_strings_minimal_elf() {
        let data = minimal_elf();
        let strings = extract_strings(&data, 4);
        assert!(strings.is_empty());
    }

    #[test]
    fn test_extract_strings_minimal_macho() {
        let data = minimal_macho();
        let strings = extract_strings(&data, 4);
        assert!(strings.is_empty());
    }

    #[test]
    fn test_extract_raw_strings_basic() {
        let data = b"Hello\0World\0foo\0";
        let strings = extract_raw_strings(data, 4, None, &[]);

        assert_eq!(strings.len(), 2);
        assert!(strings.iter().any(|s| s.value == "Hello"));
        assert!(strings.iter().any(|s| s.value == "World"));
    }

    #[test]
    fn test_extract_raw_strings_with_section() {
        let data = b"Hello\0World\0";
        let strings = extract_raw_strings(data, 4, Some(".rodata".to_string()), &[]);

        assert!(strings.iter().all(|s| s.section == Some(".rodata".to_string())));
    }

    #[test]
    fn test_extract_raw_strings_segment_detection() {
        let segment_names = vec!["__TEXT".to_string(), "__DATA".to_string()];
        let data = b"__TEXT\0Hello\0__DATA\0";
        let strings = extract_raw_strings(data, 4, None, &segment_names);

        // __TEXT and __DATA should be classified as Section
        let text = strings.iter().find(|s| s.value == "__TEXT").unwrap();
        assert_eq!(text.kind, StringKind::Section);

        let data_section = strings.iter().find(|s| s.value == "__DATA").unwrap();
        assert_eq!(data_section.kind, StringKind::Section);

        // Hello should not be Section
        let hello = strings.iter().find(|s| s.value == "Hello").unwrap();
        assert_ne!(hello.kind, StringKind::Section);
    }

    #[test]
    fn test_extract_raw_strings_deduplication() {
        let data = b"Hello\0Hello\0World\0";
        let strings = extract_raw_strings(data, 4, None, &[]);

        assert_eq!(strings.iter().filter(|s| s.value == "Hello").count(), 1);
    }

    #[test]
    fn test_extract_raw_strings_min_length() {
        let data = b"Hi\0Hey\0Hello\0";
        let strings = extract_raw_strings(data, 4, None, &[]);

        // Only "Hello" (5 chars) should pass
        assert_eq!(strings.len(), 1);
        assert_eq!(strings[0].value, "Hello");
    }

    #[test]
    fn test_extract_raw_strings_whitespace_trimming() {
        let data = b"  Hello  \0  World  \0";
        let strings = extract_raw_strings(data, 4, None, &[]);

        assert!(strings.iter().any(|s| s.value == "Hello"));
        assert!(strings.iter().any(|s| s.value == "World"));
    }

    #[test]
    fn test_extract_raw_strings_non_printable() {
        let data = b"Hello\x01World\0";
        let strings = extract_raw_strings(data, 4, None, &[]);

        // Non-printable byte breaks the string
        assert!(strings.iter().any(|s| s.value == "World"));
    }

    #[test]
    fn test_extract_raw_strings_classification() {
        let data = b"https://example.com\0/usr/bin\0PATH\0hello world\0";
        let strings = extract_raw_strings(data, 4, None, &[]);

        let url = strings.iter().find(|s| s.value.contains("example")).unwrap();
        assert_eq!(url.kind, StringKind::Url);

        let path = strings.iter().find(|s| s.value == "/usr/bin").unwrap();
        assert_eq!(path.kind, StringKind::Path);

        let env = strings.iter().find(|s| s.value == "PATH").unwrap();
        assert_eq!(env.kind, StringKind::EnvVar);
    }

    #[test]
    fn test_collect_macho_segments_minimal() {
        let data = minimal_macho();
        if let Ok(goblin::Object::Mach(goblin::mach::Mach::Binary(macho))) =
            goblin::Object::parse(&data)
        {
            let segments = collect_macho_segments(&macho);
            // Minimal Mach-O has no segments
            assert!(segments.is_empty());
        }
    }

    #[test]
    fn test_collect_elf_segments_minimal() {
        let data = minimal_elf();
        if let Ok(goblin::Object::Elf(elf)) = goblin::Object::parse(&data) {
            let segments = collect_elf_segments(&elf);
            // Minimal ELF has no sections
            assert!(segments.is_empty());
        }
    }

    #[test]
    fn test_extract_macho_imports_minimal() {
        let data = minimal_macho();
        if let Ok(goblin::Object::Mach(goblin::mach::Mach::Binary(macho))) =
            goblin::Object::parse(&data)
        {
            let imports = extract_macho_imports(&macho, 4);
            // Minimal Mach-O has no imports
            assert!(imports.is_empty());
        }
    }

    #[test]
    fn test_extract_elf_imports_minimal() {
        let data = minimal_elf();
        if let Ok(goblin::Object::Elf(elf)) = goblin::Object::parse(&data) {
            let imports = extract_elf_imports(&elf, 4);
            // Minimal ELF has no dynamic symbols
            assert!(imports.is_empty());
        }
    }

    #[test]
    fn test_extract_options_with_r2_strings() {
        let fake_r2_strings = vec![
            ExtractedString {
                value: "test_string".to_string(),
                data_offset: 0x1000,
                section: None,
                method: StringMethod::R2String,
                kind: StringKind::Const,
                library: None,
            },
        ];
        let opts = ExtractOptions::new(4).with_r2_strings(fake_r2_strings.clone());
        assert!(opts.r2_strings.is_some());
        assert_eq!(opts.r2_strings.unwrap().len(), 1);
    }

    #[test]
    fn test_get_r2_strings_preextracted() {
        let fake_r2_strings = vec![
            ExtractedString {
                value: "preextracted".to_string(),
                data_offset: 0x2000,
                section: Some(".text".to_string()),
                method: StringMethod::R2String,
                kind: StringKind::FuncName,
                library: None,
            },
        ];
        let opts = ExtractOptions::new(4).with_r2_strings(fake_r2_strings);
        let result = get_r2_strings(&opts);
        assert!(result.is_some());
        assert_eq!(result.unwrap()[0].value, "preextracted");
    }

    #[test]
    fn test_get_r2_strings_none() {
        let opts = ExtractOptions::new(4);
        let result = get_r2_strings(&opts);
        assert!(result.is_none());
    }

    #[test]
    fn test_extract_from_object_macho() {
        let data = minimal_macho();
        if let Ok(object) = goblin::Object::parse(&data) {
            let opts = ExtractOptions::new(4);
            let strings = extract_from_object(&object, &data, &opts);
            // Minimal Mach-O should return empty
            assert!(strings.is_empty());
        }
    }

    #[test]
    fn test_extract_from_object_elf() {
        let data = minimal_elf();
        if let Ok(object) = goblin::Object::parse(&data) {
            let opts = ExtractOptions::new(4);
            let strings = extract_from_object(&object, &data, &opts);
            // Minimal ELF should return empty
            assert!(strings.is_empty());
        }
    }

    #[test]
    fn test_extract_from_object_with_r2_strings() {
        let data = minimal_macho();
        if let Ok(object) = goblin::Object::parse(&data) {
            let fake_r2_strings = vec![
                ExtractedString {
                    value: "from_r2".to_string(),
                    data_offset: 0x3000,
                    section: None,
                    method: StringMethod::R2String,
                    kind: StringKind::Const,
                    library: None,
                },
            ];
            let opts = ExtractOptions::new(4).with_r2_strings(fake_r2_strings);
            let strings = extract_from_object(&object, &data, &opts);
            // Should include the pre-extracted r2 string
            assert!(strings.iter().any(|s| s.value == "from_r2"));
        }
    }
}
