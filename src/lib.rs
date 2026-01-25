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
}

impl ExtractOptions {
    pub fn new(min_length: usize) -> Self {
        Self {
            min_length,
            use_r2: false,
            path: None,
        }
    }

    pub fn with_r2(mut self, path: &str) -> Self {
        self.use_r2 = true;
        self.path = Some(path.to_string());
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
    let min_length = opts.min_length;
    let mut strings = Vec::new();

    match Object::parse(data) {
        Ok(Object::Mach(goblin::mach::Mach::Binary(macho))) => {
            let segments = collect_macho_segments(&macho);
            if macho_has_go_sections(&macho) {
                let extractor = GoStringExtractor::new(min_length);
                strings.extend(extractor.extract_macho(&macho, data));
            } else if macho_is_rust(&macho) {
                let extractor = RustStringExtractor::new(min_length);
                strings.extend(extractor.extract_macho(&macho, data));
            } else {
                // Unknown Mach-O - use r2 if enabled, then merge with raw scan
                if opts.use_r2 {
                    if let Some(path) = &opts.path {
                        if let Some(r2_strings) = r2::extract_strings(path, min_length) {
                            strings.extend(r2_strings);
                        }
                    }
                }
                // Also do raw scan to catch anything r2 missed
                let extractor = RustStringExtractor::new(min_length);
                let rust_strings = extractor.extract_macho(&macho, data);
                if rust_strings.is_empty() {
                    strings.extend(extract_raw_strings(data, min_length, None, &segments));
                } else {
                    strings.extend(rust_strings);
                }
            }
            // Add imports/exports, upgrading existing strings
            let imports = extract_macho_imports(&macho, min_length);
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
        Ok(Object::Mach(goblin::mach::Mach::Fat(fat))) => {
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
            // For non-Go/non-Rust fat binaries, use r2 if enabled + raw scan
            if !is_go && !is_rust {
                if opts.use_r2 {
                    if let Some(path) = &opts.path {
                        if let Some(r2_strings) = r2::extract_strings(path, min_length) {
                            strings.extend(r2_strings);
                        }
                    }
                }
                // Also do raw scan to catch anything r2 missed
                strings.extend(extract_raw_strings(data, min_length, None, &segments));
            }
            // Add imports/exports from first architecture, upgrading existing strings
            if let Some(macho) = first_macho {
                let imports = extract_macho_imports(&macho, min_length);
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
        Ok(Object::Elf(elf)) => {
            let segments = collect_elf_segments(&elf);

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
                strings.extend(extractor.extract_elf(&elf, data));
            } else if has_rust {
                let extractor = RustStringExtractor::new(min_length);
                strings.extend(extractor.extract_elf(&elf, data));
            } else {
                // Unknown ELF - use r2 if enabled + raw scan
                if opts.use_r2 {
                    if let Some(path) = &opts.path {
                        if let Some(r2_strings) = r2::extract_strings(path, min_length) {
                            strings.extend(r2_strings);
                        }
                    }
                }
                // Also do raw scan to catch anything r2 missed
                let extractor = RustStringExtractor::new(min_length);
                let rust_strings = extractor.extract_elf(&elf, data);
                if rust_strings.is_empty() {
                    strings.extend(extract_raw_strings(data, min_length, None, &segments));
                } else {
                    strings.extend(rust_strings);
                }
            }
            // Add imports/exports from dynamic symbols, upgrading existing strings
            let imports = extract_elf_imports(&elf, min_length);
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
        Ok(Object::PE(pe)) => {
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
                strings.extend(extractor.extract_pe(&pe, data));
            } else {
                // Unknown PE - use r2 if enabled
                if opts.use_r2 {
                    if let Some(path) = &opts.path {
                        if let Some(r2_strings) = r2::extract_strings(path, min_length) {
                            strings.extend(r2_strings);
                        }
                    }
                }
                if strings.is_empty() {
                    strings.extend(extract_raw_strings(data, min_length, None, &segments));
                }
            }
        }
        _ => {
            // Unknown format - use r2 if enabled, otherwise raw scan
            if opts.use_r2 {
                if let Some(path) = &opts.path {
                    if let Some(r2_strings) = r2::extract_strings(path, min_length) {
                        strings.extend(r2_strings);
                    }
                }
            }
            if strings.is_empty() && !data.is_empty() {
                strings.extend(extract_raw_strings(data, min_length, None, &[]));
            }
        }
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
}
