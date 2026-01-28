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
pub mod xor;

pub use common::{
    is_garbage, BinaryInfo, ExtractedString, OverlayInfo, Severity, StringKind, StringMethod,
    StringStruct,
};

pub use go::GoStringExtractor;
use memchr::memchr_iter;
pub use rust::RustStringExtractor;
use std::collections::HashSet;

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

/// Find the section name containing an address in a Mach-O binary.
fn find_macho_section(macho: &MachO, addr: u64) -> Option<String> {
    for seg in &macho.segments {
        for (sec, _) in seg.sections().ok()?.iter() {
            let start = sec.addr;
            let end = start + sec.size;
            if addr >= start && addr < end {
                return Some(sec.name().ok()?.to_string());
            }
        }
    }
    None
}

/// Convert virtual address to file offset for Mach-O binaries.
fn macho_vaddr_to_file_offset(macho: &MachO, vaddr: u64) -> u64 {
    for seg in &macho.segments {
        let vm_start = seg.vmaddr;
        let vm_end = vm_start + seg.vmsize;

        if vaddr >= vm_start && vaddr < vm_end {
            // file_offset = (virtual_address - segment_vmaddr) + segment_fileoff
            return (vaddr - vm_start) + seg.fileoff;
        }
    }

    // If not found in any segment, return the vaddr as-is
    vaddr
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
                let section = find_macho_section(macho, import.address);
                // Convert virtual address to file offset
                let file_offset = macho_vaddr_to_file_offset(macho, import.address);
                strings.push(ExtractedString {
                    value: import.name.to_string(),
                    data_offset: file_offset,
                    section,
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
                // Convert virtual address to file offset
                let file_offset = macho_vaddr_to_file_offset(macho, export.offset);
                let section = find_macho_section(macho, export.offset);
                strings.push(ExtractedString {
                    value: export.name.to_string(),
                    data_offset: file_offset,
                    section,
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
            let lib = elf
                .verneed
                .iter()
                .flat_map(|v| v.iter())
                .find(|vn| {
                    vn.iter()
                        .any(|aux| elf.dynstrtab.get_at(aux.vna_name) == Some(name))
                })
                .and_then(|vn| elf.dynstrtab.get_at(vn.vn_file))
                .map(|s| s.to_string());
            (StringKind::Import, lib)
        } else if sym.st_bind() == goblin::elf::sym::STB_GLOBAL
            || sym.st_bind() == goblin::elf::sym::STB_WEAK
        {
            // Defined global/weak symbol - this is an export
            (StringKind::Export, None)
        } else {
            continue;
        };

        // Look up the actual section name from the section index
        let section = if sym.st_shndx > 0 && sym.st_shndx < elf.section_headers.len() {
            elf.shdr_strtab
                .get_at(elf.section_headers[sym.st_shndx].sh_name)
                .map(|s| s.to_string())
        } else {
            None
        };
        strings.push(ExtractedString {
            value: name.to_string(),
            data_offset: sym.st_value,
            section,
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
    /// Enable XOR string detection (single-byte keys). Default: false.
    pub xor_scan: bool,
    /// Minimum length for XOR-decoded strings (default: 10).
    pub xor_min_length: usize,
    /// Enable advanced multi-byte XOR scanning with radare2/rizin (slow). Default: false.
    pub xorscan: bool,
}

impl ExtractOptions {
    pub fn new(min_length: usize) -> Self {
        Self {
            min_length,
            use_r2: false,
            path: None,
            r2_strings: None,
            filter_garbage: false,
            xor_scan: false,
            xor_min_length: xor::DEFAULT_XOR_MIN_LENGTH,
            xorscan: false,
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

    /// Enable XOR string detection with optional custom minimum length.
    /// This scans for strings obfuscated with single-byte XOR keys (0x01-0xFF).
    /// Default minimum length is 10 characters.
    pub fn with_xor(mut self, min_length: Option<usize>) -> Self {
        self.xor_scan = true;
        if let Some(len) = min_length {
            self.xor_min_length = len;
        }
        self
    }

    /// Enable advanced multi-byte XOR scanning with radare2/rizin.
    /// This is slower but can detect complex multi-byte XOR obfuscation.
    /// Requires radare2 or rizin to be installed.
    pub fn with_xorscan(mut self, enable: bool) -> Self {
        self.xorscan = enable;
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

            // Check if this looks like a PE (MZ header) even if goblin failed to parse
            let is_pe = data.len() >= 2 && data[0] == 0x4D && data[1] == 0x5A;

            // Extract wide strings for PE-like files (common in Windows binaries)
            if is_pe && !data.is_empty() {
                strings.extend(extract_wide_strings(data, opts.min_length, None, &[]));
            }

            // Raw scan for all unknown formats
            if !data.is_empty() {
                strings.extend(extract_raw_strings(data, opts.min_length, None, &[]));
            }

            // XOR string detection (if enabled)
            if opts.xor_scan && !data.is_empty() {
                strings.extend(xor::extract_xor_strings(data, opts.xor_min_length, is_pe));

                // Multi-byte XOR detection using radare2-detected keys (only if --xorscan)
                if opts.xorscan {
                    if let Some(ref path) = opts.path {
                        tracing::debug!(
                            "Multi-byte XOR: analyzing {} candidate strings",
                            strings.len()
                        );
                        // Use already extracted strings as XOR key candidates
                        let xor_keys = r2::verify_xor_keys(path, &strings);
                        tracing::debug!("Multi-byte XOR: found {} potential keys", xor_keys.len());
                        if !xor_keys.is_empty() {
                            let decoded = xor::extract_multikey_xor_strings(
                                data,
                                &xor_keys,
                                opts.xor_min_length,
                            );
                            tracing::debug!("Multi-byte XOR: decoded {} strings", decoded.len());
                            strings.extend(decoded);
                        } else {
                            tracing::debug!("Multi-byte XOR: no high-confidence keys found");
                        }
                    } else {
                        tracing::debug!("Multi-byte XOR: path not provided, skipping");
                    }
                }
            }

            // Apply garbage filter if enabled (but never filter entitlements XML)
            if opts.filter_garbage {
                strings.retain(|s| {
                    s.kind == StringKind::EntitlementsXml || !common::is_garbage(&s.value)
                });
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
pub fn extract_from_object(
    object: &Object,
    data: &[u8],
    opts: &ExtractOptions,
) -> Vec<ExtractedString> {
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
                    s.kind = *kind;
                    s.library = lib.map(|l| l.to_string());
                }
            }
            let seen: HashSet<&str> = strings.iter().map(|s| s.value.as_str()).collect();
            let new_imports: Vec<_> = imports
                .into_iter()
                .filter(|s| !seen.contains(s.value.as_str()))
                .collect();
            strings.extend(new_imports);

            // Extract entitlements as raw XML for inline display
            let entitlements = extract_macho_entitlements(macho, data, min_length);

            // Remove strings that overlap with entitlement XML ranges
            for ent in &entitlements {
                if ent.kind == StringKind::EntitlementsXml {
                    let ent_start = ent.data_offset;
                    let ent_end = ent_start + ent.value.len() as u64;
                    strings.retain(|s| {
                        // Keep strings that don't overlap with the entitlement range
                        let s_start = s.data_offset;
                        let s_end = s_start + s.value.len() as u64;
                        // No overlap if string ends before entitlement starts or starts after entitlement ends
                        s_end <= ent_start || s_start >= ent_end
                    });
                }
            }

            strings.extend(entitlements);
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
                let import_map: std::collections::HashMap<&str, (&StringKind, Option<&str>)> =
                    imports
                        .iter()
                        .map(|s| (s.value.as_str(), (&s.kind, s.library.as_deref())))
                        .collect();
                // Update existing strings that are actually imports
                for s in strings.iter_mut() {
                    if let Some(&(kind, lib)) = import_map.get(s.value.as_str()) {
                        s.kind = *kind;
                        s.library = lib.map(|l| l.to_string());
                    }
                }
                // Add new imports that weren't found before
                let seen: HashSet<&str> = strings.iter().map(|s| s.value.as_str()).collect();
                let new_imports: Vec<_> = imports
                    .into_iter()
                    .filter(|s| !seen.contains(s.value.as_str()))
                    .collect();
                strings.extend(new_imports);

                // Extract entitlements as raw XML for inline display
                let entitlements = extract_macho_entitlements(macho, data, min_length);

                // Remove strings that overlap with entitlement XML ranges
                for ent in &entitlements {
                    if ent.kind == StringKind::EntitlementsXml {
                        let ent_start = ent.data_offset;
                        let ent_end = ent_start + ent.value.len() as u64;
                        strings.retain(|s| {
                            // Keep strings that don't overlap with the entitlement range
                            let s_start = s.data_offset;
                            let s_end = s_start + s.value.len() as u64;
                            // No overlap if string ends before entitlement starts or starts after entitlement ends
                            s_end <= ent_start || s_start >= ent_end
                        });
                    }
                }

                strings.extend(entitlements);
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
                    s.kind = *kind;
                    s.library = lib.map(|l| l.to_string());
                }
            }
            let seen: HashSet<&str> = strings.iter().map(|s| s.value.as_str()).collect();
            let new_imports: Vec<_> = imports
                .into_iter()
                .filter(|s| !seen.contains(s.value.as_str()))
                .collect();
            strings.extend(new_imports);

            // Extract overlay/appended data (common malware technique)
            strings.extend(extract_overlay_strings(data, min_length));
        }
        Object::PE(pe) => {
            // Collect PE section names
            let segments: Vec<String> = pe
                .sections
                .iter()
                .map(|sec| {
                    String::from_utf8_lossy(&sec.name)
                        .trim_end_matches('\0')
                        .to_string()
                })
                .collect();

            // Check for Go by looking for go.buildinfo section specifically
            let has_go = pe.sections.iter().any(|sec| {
                let name = String::from_utf8_lossy(&sec.name);
                name.contains("go.buildinfo") || name.contains("gopclntab")
            });

            if has_go {
                let extractor = GoStringExtractor::new(min_length);
                strings.extend(extractor.extract_pe(pe, data));
            }

            // Use r2 if available
            if let Some(r2_strings) = get_r2_strings(opts) {
                strings.extend(r2_strings);
            }

            // Extract UTF-16LE wide strings (common in Windows binaries)
            strings.extend(extract_wide_strings(data, min_length, None, &segments));

            // Raw scan for PE (catches strings missed by structure extraction)
            strings.extend(extract_raw_strings(data, min_length, None, &segments));

            // Extract overlay/appended data (common malware technique)
            strings.extend(extract_overlay_strings(data, min_length));
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

    // XOR string detection (if enabled)
    if opts.xor_scan && !data.is_empty() {
        let is_pe = matches!(object, Object::PE(_));
        strings.extend(xor::extract_xor_strings(data, opts.xor_min_length, is_pe));

        // Multi-byte XOR detection using radare2-detected keys (only if --xorscan)
        if opts.xorscan {
            if let Some(ref path) = opts.path {
                tracing::debug!(
                    "Multi-byte XOR: path={}, analyzing {} candidate strings",
                    path,
                    strings.len()
                );
                let xor_keys = r2::verify_xor_keys(path, &strings);
                tracing::debug!("Multi-byte XOR: found {} potential keys", xor_keys.len());
                if !xor_keys.is_empty() {
                    tracing::debug!(
                        "Multi-byte XOR: attempting decryption with {} keys",
                        xor_keys.len()
                    );
                    let decoded =
                        xor::extract_multikey_xor_strings(data, &xor_keys, opts.xor_min_length);
                    tracing::debug!("Multi-byte XOR: decoded {} strings", decoded.len());
                    strings.extend(decoded);
                } else {
                    tracing::debug!("Multi-byte XOR: no high-confidence keys found");
                }
            } else {
                tracing::debug!("Multi-byte XOR: path not provided, skipping");
            }
        }
    }

    // Apply garbage filter if enabled (but never filter entitlements XML)
    if opts.filter_garbage {
        strings.retain(|s| s.kind == StringKind::EntitlementsXml || !common::is_garbage(&s.value));
    }

    strings
}

/// Extract strings from a pre-parsed Mach-O binary.
///
/// This allows library clients who have already parsed the binary to avoid re-parsing.
pub fn extract_from_macho(
    macho: &MachO,
    data: &[u8],
    opts: &ExtractOptions,
) -> Vec<ExtractedString> {
    let min_length = opts.min_length;
    let mut strings = Vec::new();
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

    // Add imports/exports
    let imports = extract_macho_imports(macho, min_length);
    let import_map: std::collections::HashMap<&str, (&StringKind, Option<&str>)> = imports
        .iter()
        .map(|s| (s.value.as_str(), (&s.kind, s.library.as_deref())))
        .collect();
    for s in strings.iter_mut() {
        if let Some(&(kind, lib)) = import_map.get(s.value.as_str()) {
            s.kind = *kind;
            s.library = lib.map(|l| l.to_string());
        }
    }
    let seen: HashSet<&str> = strings.iter().map(|s| s.value.as_str()).collect();
    let new_imports: Vec<_> = imports
        .into_iter()
        .filter(|s| !seen.contains(s.value.as_str()))
        .collect();
    strings.extend(new_imports);

    // Extract entitlements as raw XML for inline display
    let entitlements = extract_macho_entitlements(macho, data, min_length);

    // Remove strings that overlap with entitlement XML ranges
    for ent in &entitlements {
        if ent.kind == StringKind::EntitlementsXml {
            let ent_start = ent.data_offset;
            let ent_end = ent_start + ent.value.len() as u64;
            strings.retain(|s| {
                // Keep strings that don't overlap with the entitlement range
                let s_start = s.data_offset;
                let s_end = s_start + s.value.len() as u64;
                // No overlap if string ends before entitlement starts or starts after entitlement ends
                s_end <= ent_start || s_start >= ent_end
            });
        }
    }

    strings.extend(entitlements);

    // Apply garbage filter if enabled (but never filter entitlements XML)
    if opts.filter_garbage {
        strings.retain(|s| s.kind == StringKind::EntitlementsXml || !common::is_garbage(&s.value));
    }

    strings
}

/// Extract entitlements XML from Mach-O code signature.
///
/// Returns the raw XML plist from LC_CODE_SIGNATURE if present.
#[allow(dead_code)]
pub fn extract_macho_entitlements_xml(data: &[u8]) -> Option<String> {
    use goblin::mach::load_command::CommandVariant;
    use goblin::Object;

    let macho = match Object::parse(data) {
        Ok(Object::Mach(goblin::mach::Mach::Binary(m))) => m,
        _ => return None,
    };

    // Find LC_CODE_SIGNATURE load command
    for cmd in &macho.load_commands {
        if let CommandVariant::CodeSignature(ref cs) = cmd.command {
            let offset = cs.dataoff as usize;
            let size = cs.datasize as usize;

            if offset + size > data.len() {
                continue;
            }

            let cs_data = &data[offset..offset + size];

            // Look for XML plist (starts with <?xml)
            if let Some(xml_start) = find_subsequence(cs_data, b"<?xml") {
                let xml_data = &cs_data[xml_start..];

                // Find end of plist
                if let Some(plist_end) = find_subsequence(xml_data, b"</plist>") {
                    let xml_content = &xml_data[..plist_end + 8]; // include </plist>

                    if let Ok(xml_str) = String::from_utf8(xml_content.to_vec()) {
                        return Some(xml_str);
                    }
                }
            }
        }
    }

    None
}

/// Extract entitlements from Mach-O code signature as raw XML.
///
/// Returns the full XML plist as a single string for inline display.
fn extract_macho_entitlements(
    macho: &MachO,
    data: &[u8],
    _min_length: usize,
) -> Vec<ExtractedString> {
    use goblin::mach::load_command::CommandVariant;

    let mut entitlements = Vec::new();

    // Find LC_CODE_SIGNATURE load command
    for cmd in &macho.load_commands {
        if let CommandVariant::CodeSignature(ref cs) = cmd.command {
            let offset = cs.dataoff as usize;
            let size = cs.datasize as usize;

            if offset + size > data.len() {
                continue;
            }

            let cs_data = &data[offset..offset + size];

            // Look for XML plist (starts with <?xml)
            if let Some(xml_start) = find_subsequence(cs_data, b"<?xml") {
                let xml_data = &cs_data[xml_start..];

                // Find end of plist
                if let Some(plist_end) = find_subsequence(xml_data, b"</plist>") {
                    let xml_content = &xml_data[..plist_end + 8]; // include </plist>

                    if let Ok(xml_str) = String::from_utf8(xml_content.to_vec()) {
                        entitlements.push(ExtractedString {
                            value: xml_str,
                            data_offset: (offset + xml_start) as u64,
                            section: Some("__LINKEDIT".to_string()),
                            method: StringMethod::CodeSignature,
                            kind: StringKind::EntitlementsXml,
                            library: None,
                        });
                    }
                }
            }
        }
    }

    entitlements
}

/// Simple XML parser to extract entitlement key strings from plist.
///
/// Extracts text between <key> and </key> tags.
#[allow(dead_code)]
fn parse_entitlement_keys(xml: &[u8], base_offset: u64, min_length: usize) -> Vec<ExtractedString> {
    let mut keys = Vec::new();
    let xml_str = String::from_utf8_lossy(xml);

    // Simple regex-free parser: find <key>...</key> patterns
    let mut offset = 0;
    while let Some(key_start) = xml_str[offset..].find("<key>") {
        let key_content_start = offset + key_start + 5; // after "<key>"
        if let Some(key_end_pos) = xml_str[key_content_start..].find("</key>") {
            let key_value = &xml_str[key_content_start..key_content_start + key_end_pos];

            if key_value.len() >= min_length {
                keys.push(ExtractedString {
                    value: key_value.to_string(),
                    data_offset: base_offset + key_content_start as u64,
                    section: Some("__LINKEDIT".to_string()),
                    method: StringMethod::CodeSignature,
                    kind: StringKind::Entitlement,
                    library: None,
                });
            }

            offset = key_content_start + key_end_pos + 6; // after "</key>"
        } else {
            break;
        }
    }

    // Also extract <string>...</string> values (app IDs, paths, etc.)
    let mut offset = 0;
    while let Some(str_start) = xml_str[offset..].find("<string>") {
        let str_content_start = offset + str_start + 8; // after "<string>"
        if let Some(str_end_pos) = xml_str[str_content_start..].find("</string>") {
            let str_value = &xml_str[str_content_start..str_content_start + str_end_pos];

            if str_value.len() >= min_length {
                keys.push(ExtractedString {
                    value: str_value.to_string(),
                    data_offset: base_offset + str_content_start as u64,
                    section: Some("__LINKEDIT".to_string()),
                    method: StringMethod::CodeSignature,
                    kind: StringKind::AppId,
                    library: None,
                });
            }

            offset = str_content_start + str_end_pos + 9; // after "</string>"
        } else {
            break;
        }
    }

    keys
}

/// Find a byte subsequence within a slice.
fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() {
        return Some(0);
    }
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

/// Extract strings from a pre-parsed ELF binary.
///
/// This allows library clients who have already parsed the binary to avoid re-parsing.
pub fn extract_from_elf(
    elf: &goblin::elf::Elf,
    data: &[u8],
    opts: &ExtractOptions,
) -> Vec<ExtractedString> {
    let min_length = opts.min_length;
    let mut strings = Vec::new();
    let segments = collect_elf_segments(elf);

    // Check for Go sections
    let has_go = elf.section_headers.iter().any(|sh| {
        let name = elf.shdr_strtab.get_at(sh.sh_name).unwrap_or("");
        name == ".gopclntab" || name == ".go.buildinfo"
    });

    // Check for Rust
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
        let extractor = RustStringExtractor::new(min_length);
        let rust_strings = extractor.extract_elf(elf, data);
        if rust_strings.is_empty() {
            strings.extend(extract_raw_strings(data, min_length, None, &segments));
        } else {
            strings.extend(rust_strings);
        }
    }

    // Add imports/exports
    let imports = extract_elf_imports(elf, min_length);
    let import_map: std::collections::HashMap<&str, (&StringKind, Option<&str>)> = imports
        .iter()
        .map(|s| (s.value.as_str(), (&s.kind, s.library.as_deref())))
        .collect();
    for s in strings.iter_mut() {
        if let Some(&(kind, lib)) = import_map.get(s.value.as_str()) {
            s.kind = *kind;
            s.library = lib.map(|l| l.to_string());
        }
    }
    let seen: HashSet<&str> = strings.iter().map(|s| s.value.as_str()).collect();
    let new_imports: Vec<_> = imports
        .into_iter()
        .filter(|s| !seen.contains(s.value.as_str()))
        .collect();
    strings.extend(new_imports);

    // Extract overlay/appended data (common malware technique)
    strings.extend(extract_overlay_strings(data, min_length));

    // Apply garbage filter if enabled (but never filter entitlements XML)
    if opts.filter_garbage {
        strings.retain(|s| s.kind == StringKind::EntitlementsXml || !common::is_garbage(&s.value));
    }

    strings
}

/// Extract strings from a pre-parsed PE binary.
///
/// This allows library clients who have already parsed the binary to avoid re-parsing.
pub fn extract_from_pe(
    pe: &goblin::pe::PE,
    data: &[u8],
    opts: &ExtractOptions,
) -> Vec<ExtractedString> {
    let min_length = opts.min_length;
    let mut strings = Vec::new();

    // Collect PE section names
    let segments: Vec<String> = pe
        .sections
        .iter()
        .map(|sec| {
            String::from_utf8_lossy(&sec.name)
                .trim_end_matches('\0')
                .to_string()
        })
        .collect();

    // Check for Go
    let has_go = pe.sections.iter().any(|sec| {
        let name = String::from_utf8_lossy(&sec.name);
        name.contains("go") || name.contains(".rdata")
    });

    if has_go {
        let extractor = GoStringExtractor::new(min_length);
        strings.extend(extractor.extract_pe(pe, data));
    }

    // Use r2 if available
    if let Some(r2_strings) = get_r2_strings(opts) {
        strings.extend(r2_strings);
    }

    // Extract UTF-16LE wide strings (common in Windows binaries)
    strings.extend(extract_wide_strings(data, min_length, None, &segments));

    // Also do raw scan for PE (always, since structure extraction may miss many strings)
    if !data.is_empty() {
        strings.extend(extract_raw_strings(data, min_length, None, &segments));
    }

    // Apply garbage filter if enabled (but never filter entitlements XML)
    if opts.filter_garbage {
        strings.retain(|s| s.kind == StringKind::EntitlementsXml || !common::is_garbage(&s.value));
    }

    strings
}

/// Extract raw strings from binary data (fallback for unknown binaries).
///
/// Uses two strategies:
/// 1. Null-terminated strings (traditional approach)
/// 2. Printable character runs (like traditional `strings` command)
fn extract_raw_strings(
    data: &[u8],
    min_length: usize,
    section: Option<String>,
    segment_names: &[String],
) -> Vec<ExtractedString> {
    // Build a set of known segment/section names for quick lookup
    let segment_names_set: HashSet<&str> = segment_names.iter().map(|s| s.as_str()).collect();

    let mut strings = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();

    // Strategy 1: Null-terminated strings
    let mut prev_end = 0usize;
    for null_pos in memchr_iter(0, data) {
        let chunk = &data[prev_end..null_pos];
        let chunk_start = prev_end;
        prev_end = null_pos + 1;

        if chunk.len() < min_length {
            continue;
        }

        // Find the last contiguous printable run that ends at the chunk boundary
        let mut run_start = None;
        for (i, &b) in chunk.iter().enumerate() {
            if b.is_ascii_graphic() || b.is_ascii_whitespace() {
                if run_start.is_none() {
                    run_start = Some(i);
                }
            } else {
                run_start = None;
            }
        }

        let Some(start) = run_start else { continue };
        let candidate = &chunk[start..];

        if candidate.len() < min_length {
            continue;
        }

        if let Ok(s) = std::str::from_utf8(candidate) {
            let trimmed = s.trim();
            if trimmed.len() >= min_length && !trimmed.is_empty() && !seen.contains(trimmed) {
                let kind = if segment_names_set.contains(trimmed) {
                    StringKind::Section
                } else {
                    go::classify_string(trimmed)
                };

                seen.insert(trimmed.to_string());
                strings.push(ExtractedString {
                    value: trimmed.to_string(),
                    data_offset: (chunk_start + start) as u64,
                    section: section.clone(),
                    method: StringMethod::RawScan,
                    kind,
                    library: None,
                });
            }
        }
    }

    // Strategy 2: Printable character runs (like traditional `strings`)
    // This catches strings that aren't null-terminated (common in JPEG, PDF, etc.)
    extract_printable_runs(
        data,
        min_length,
        &section,
        &segment_names_set,
        &mut strings,
        &mut seen,
    );

    strings
}

/// Extract strings by scanning for runs of printable ASCII characters.
/// This mimics the behavior of the traditional `strings` command.
fn extract_printable_runs(
    data: &[u8],
    min_length: usize,
    section: &Option<String>,
    segment_names_set: &HashSet<&str>,
    strings: &mut Vec<ExtractedString>,
    seen: &mut HashSet<String>,
) {
    let mut run_start: Option<usize> = None;

    for (i, &b) in data.iter().enumerate() {
        let is_printable = b.is_ascii_graphic() || matches!(b, b' ' | b'\t');

        if is_printable {
            if run_start.is_none() {
                run_start = Some(i);
            }
        } else if let Some(start) = run_start {
            // End of a printable run
            let run = &data[start..i];
            if run.len() >= min_length {
                if let Ok(s) = std::str::from_utf8(run) {
                    let trimmed = s.trim();
                    if trimmed.len() >= min_length && !seen.contains(trimmed) {
                        let kind = if segment_names_set.contains(trimmed) {
                            StringKind::Section
                        } else {
                            go::classify_string(trimmed)
                        };

                        seen.insert(trimmed.to_string());
                        strings.push(ExtractedString {
                            value: trimmed.to_string(),
                            data_offset: start as u64,
                            section: section.clone(),
                            method: StringMethod::RawScan,
                            kind,
                            library: None,
                        });
                    }
                }
            }
            run_start = None;
        }
    }

    // Handle run at end of data
    if let Some(start) = run_start {
        let run = &data[start..];
        if run.len() >= min_length {
            if let Ok(s) = std::str::from_utf8(run) {
                let trimmed = s.trim();
                if trimmed.len() >= min_length && !seen.contains(trimmed) {
                    let kind = if segment_names_set.contains(trimmed) {
                        StringKind::Section
                    } else {
                        go::classify_string(trimmed)
                    };

                    seen.insert(trimmed.to_string());
                    strings.push(ExtractedString {
                        value: trimmed.to_string(),
                        data_offset: start as u64,
                        section: section.clone(),
                        method: StringMethod::RawScan,
                        kind,
                        library: None,
                    });
                }
            }
        }
    }
}

/// Extract UTF-16LE wide strings from binary data.
///
/// Windows binaries commonly use UTF-16LE for strings (file paths, registry keys,
/// .NET strings, resource data). This scans for the characteristic pattern of
/// ASCII bytes alternating with null bytes.
fn extract_wide_strings(
    data: &[u8],
    min_length: usize,
    section: Option<String>,
    segment_names: &[String],
) -> Vec<ExtractedString> {
    let segment_names_set: HashSet<&str> = segment_names.iter().map(|s| s.as_str()).collect();
    let mut strings = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();

    // Need at least 4 bytes for a 2-char wide string
    if data.len() < 4 {
        return strings;
    }

    let mut i = 0;
    while i + 1 < data.len() {
        // Look for start of UTF-16LE sequence: printable ASCII followed by 0x00
        let lo = data[i];
        let hi = data[i + 1];

        if is_printable_ascii(lo) && hi == 0 {
            // Found potential start of wide string
            let start = i;
            let mut code_units: Vec<u16> = Vec::new();

            // Collect UTF-16LE code units
            while i + 1 < data.len() {
                let lo = data[i];
                let hi = data[i + 1];
                let code_unit = u16::from_le_bytes([lo, hi]);

                // Check for null terminator
                if code_unit == 0 {
                    break;
                }

                // For BMP characters, check if it's a printable character
                // Allow ASCII printable range and common Unicode ranges
                if is_valid_wide_char(code_unit) {
                    code_units.push(code_unit);
                    i += 2;
                } else {
                    break;
                }
            }

            // Decode and validate the string
            if code_units.len() >= min_length {
                let decoded = String::from_utf16_lossy(&code_units);
                let trimmed = decoded.trim();

                if trimmed.len() >= min_length && !trimmed.is_empty() && !seen.contains(trimmed) {
                    let kind = if segment_names_set.contains(trimmed) {
                        StringKind::Section
                    } else {
                        go::classify_string(trimmed)
                    };

                    seen.insert(trimmed.to_string());
                    strings.push(ExtractedString {
                        value: trimmed.to_string(),
                        data_offset: start as u64,
                        section: section.clone(),
                        method: StringMethod::WideString,
                        kind,
                        library: None,
                    });
                }
            }

            // Skip the null terminator if present
            if i + 1 < data.len() && data[i] == 0 && data[i + 1] == 0 {
                i += 2;
            }
        } else {
            i += 1;
        }
    }

    strings
}

/// Check if a byte is printable ASCII (space through tilde, plus tab and newline).
#[inline]
fn is_printable_ascii(b: u8) -> bool {
    b.is_ascii_graphic() || matches!(b, b' ' | b'\t' | b'\n' | b'\r')
}

/// Check if a UTF-16 code unit represents a valid printable character.
#[inline]
fn is_valid_wide_char(code_unit: u16) -> bool {
    match code_unit {
        // ASCII printable range (space through tilde) plus tab, newline, carriage return
        0x0009 | 0x000A | 0x000D | 0x0020..=0x007E => true,
        // Latin-1 Supplement (common accented characters)
        0x00A0..=0x00FF => true,
        // Latin Extended-A and B (European languages)
        0x0100..=0x024F => true,
        // Greek and Coptic
        0x0370..=0x03FF => true,
        // Cyrillic
        0x0400..=0x04FF => true,
        // CJK ranges would add too much noise, skip them
        // General punctuation
        0x2000..=0x206F => true,
        // Currency symbols
        0x20A0..=0x20CF => true,
        // Arrows, math operators, etc. - skip as they add noise
        _ => false,
    }
}

/// Detect the language of a binary.
///
/// Returns "go", "rust", "text", or "unknown".
pub fn detect_language(data: &[u8]) -> &'static str {
    if is_go_binary(data) {
        "go"
    } else if is_rust_binary(data) {
        "rust"
    } else if is_text_file(data) {
        "text"
    } else {
        "unknown"
    }
}

/// Check if data appears to be a text file rather than a binary.
///
/// Uses heuristics:
/// - Must be valid UTF-8 (or mostly ASCII)
/// - High ratio of printable characters
/// - No binary magic numbers at the start
pub fn is_text_file(data: &[u8]) -> bool {
    if data.is_empty() {
        return false;
    }

    // Check for common binary magic numbers
    if data.len() >= 4 {
        let magic = &data[0..4];
        // ELF
        if magic == [0x7f, b'E', b'L', b'F'] {
            return false;
        }
        // Mach-O (32-bit and 64-bit, both endiannesses)
        if magic == [0xfe, 0xed, 0xfa, 0xce]
            || magic == [0xce, 0xfa, 0xed, 0xfe]
            || magic == [0xfe, 0xed, 0xfa, 0xcf]
            || magic == [0xcf, 0xfa, 0xed, 0xfe]
        {
            return false;
        }
        // Fat Mach-O
        if magic == [0xca, 0xfe, 0xba, 0xbe] || magic == [0xbe, 0xba, 0xfe, 0xca] {
            return false;
        }
    }
    if data.len() >= 2 {
        // PE (MZ header)
        if data[0..2] == [b'M', b'Z'] {
            return false;
        }
    }

    // Sample up to 8KB for performance
    let sample_size = data.len().min(8192);
    let sample = &data[..sample_size];

    // Count printable vs non-printable bytes
    let mut printable = 0usize;
    let mut null_bytes = 0usize;

    for &b in sample {
        if b == 0 {
            null_bytes += 1;
        } else if b.is_ascii_graphic() || b.is_ascii_whitespace() {
            printable += 1;
        }
    }

    // Text files should have very few null bytes (allow a couple for edge cases)
    if null_bytes > 2 {
        return false;
    }

    // At least 85% should be printable ASCII for it to be considered text
    printable * 100 / sample_size >= 85
}

/// Detect overlay/appended data after the ELF binary structure.
///
/// Returns `Some(OverlayInfo)` if there is data after the expected end of the ELF file,
/// or `None` if the file ends at the expected boundary (or is not an ELF).
pub fn detect_elf_overlay(data: &[u8]) -> Option<OverlayInfo> {
    let elf = match Object::parse(data) {
        Ok(Object::Elf(elf)) => elf,
        _ => return None,
    };

    // Calculate the expected end of the ELF file by finding the maximum of:
    // 1. End of section header table: e_shoff + (e_shnum * e_shentsize)
    // 2. End of each section: sh_offset + sh_size
    // 3. End of each program segment: p_offset + p_filesz
    let mut expected_end: u64 = 0;

    // Section header table end
    if elf.header.e_shnum > 0 {
        let sh_table_end =
            elf.header.e_shoff + (elf.header.e_shnum as u64 * elf.header.e_shentsize as u64);
        expected_end = expected_end.max(sh_table_end);
    }

    // End of each section
    for sh in &elf.section_headers {
        if sh.sh_type != goblin::elf::section_header::SHT_NOBITS {
            let section_end = sh.sh_offset + sh.sh_size;
            expected_end = expected_end.max(section_end);
        }
    }

    // End of each program header/segment
    for ph in &elf.program_headers {
        let segment_end = ph.p_offset + ph.p_filesz;
        expected_end = expected_end.max(segment_end);
    }

    let file_size = data.len() as u64;

    // If there's data after the expected end, we have an overlay
    if file_size > expected_end && expected_end > 0 {
        Some(OverlayInfo {
            start_offset: expected_end,
            size: file_size - expected_end,
        })
    } else {
        None
    }
}

/// Extract strings from overlay data (appended after ELF structure).
///
/// This extracts both null-terminated and wide strings from the overlay region,
/// classifying them as `StringKind::Overlay` for high-severity highlighting.
pub fn extract_overlay_strings(data: &[u8], min_length: usize) -> Vec<ExtractedString> {
    let overlay = match detect_elf_overlay(data) {
        Some(o) => o,
        None => return Vec::new(),
    };

    let start = overlay.start_offset as usize;
    if start >= data.len() {
        return Vec::new();
    }

    let overlay_data = &data[start..];
    let mut strings = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();

    // Extract null-terminated strings
    let mut prev_end = 0usize;
    for null_pos in memchr_iter(0, overlay_data) {
        let chunk = &overlay_data[prev_end..null_pos];
        let chunk_start = prev_end;
        prev_end = null_pos + 1;

        if chunk.len() < min_length {
            continue;
        }

        // Find the last contiguous printable run
        let mut run_start = None;
        for (i, &b) in chunk.iter().enumerate() {
            if b.is_ascii_graphic() || b.is_ascii_whitespace() {
                if run_start.is_none() {
                    run_start = Some(i);
                }
            } else {
                run_start = None;
            }
        }

        let Some(rs) = run_start else { continue };
        let candidate = &chunk[rs..];

        if candidate.len() < min_length {
            continue;
        }

        if let Ok(s) = std::str::from_utf8(candidate) {
            let trimmed = s.trim();
            if trimmed.len() >= min_length && !trimmed.is_empty() && !seen.contains(trimmed) {
                seen.insert(trimmed.to_string());
                strings.push(ExtractedString {
                    value: trimmed.to_string(),
                    data_offset: (start + chunk_start + rs) as u64,
                    section: Some("(overlay)".to_string()),
                    method: StringMethod::RawScan,
                    kind: StringKind::Overlay,
                    library: None,
                });
            }
        }
    }

    // Extract UTF-16LE wide strings (common in malware config)
    let mut i = 0;
    while i + 1 < overlay_data.len() {
        let lo = overlay_data[i];
        let hi = overlay_data[i + 1];

        if is_printable_ascii(lo) && hi == 0 {
            let wide_start = i;
            let mut code_units: Vec<u16> = Vec::new();

            while i + 1 < overlay_data.len() {
                let lo = overlay_data[i];
                let hi = overlay_data[i + 1];
                let code_unit = u16::from_le_bytes([lo, hi]);

                if code_unit == 0 {
                    break;
                }

                if is_valid_wide_char(code_unit) {
                    code_units.push(code_unit);
                    i += 2;
                } else {
                    break;
                }
            }

            if code_units.len() >= min_length {
                let decoded = String::from_utf16_lossy(&code_units);
                let trimmed = decoded.trim();

                if trimmed.len() >= min_length && !trimmed.is_empty() && !seen.contains(trimmed) {
                    seen.insert(trimmed.to_string());
                    strings.push(ExtractedString {
                        value: trimmed.to_string(),
                        data_offset: (start + wide_start) as u64,
                        section: Some("(overlay)".to_string()),
                        method: StringMethod::WideString,
                        kind: StringKind::OverlayWide,
                        library: None,
                    });
                }
            }

            if i + 1 < overlay_data.len() && overlay_data[i] == 0 && overlay_data[i + 1] == 0 {
                i += 2;
            }
        } else {
            i += 1;
        }
    }

    strings
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
    fn test_extract_strings_from_printable_data() {
        // Printable data should now be extracted (like traditional `strings`)
        let data = b"not a valid binary format";
        let strings = extract_strings(data, 4);
        // Should find the printable string
        assert!(!strings.is_empty());
        assert!(strings.iter().any(|s| s.value.contains("valid")));
    }

    #[test]
    fn test_extract_strings_pure_binary() {
        // Pure binary data with no printable runs should return empty
        let data = &[0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07];
        let strings = extract_strings(data, 4);
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

    #[test]
    fn test_is_text_file_basic() {
        assert!(is_text_file(b"Hello, world!"));
        assert!(is_text_file(b"fn main() {\n    println!(\"Hello\");\n}"));
    }

    #[test]
    fn test_is_text_file_empty() {
        assert!(!is_text_file(&[]));
    }

    #[test]
    fn test_is_text_file_binary() {
        // Binary data with null bytes
        assert!(!is_text_file(&[0x00, 0x01, 0x02, 0x03]));
        // ELF magic
        assert!(!is_text_file(&[0x7f, b'E', b'L', b'F', 0x02, 0x01]));
        // Mach-O magic
        assert!(!is_text_file(&[0xcf, 0xfa, 0xed, 0xfe, 0x07, 0x00]));
        // PE magic
        assert!(!is_text_file(&[b'M', b'Z', 0x90, 0x00]));
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

        assert!(strings
            .iter()
            .all(|s| s.section == Some(".rodata".to_string())));
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

        let url = strings
            .iter()
            .find(|s| s.value.contains("example"))
            .unwrap();
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
        let fake_r2_strings = vec![ExtractedString {
            value: "test_string".to_string(),
            data_offset: 0x1000,
            section: None,
            method: StringMethod::R2String,
            kind: StringKind::Const,
            library: None,
        }];
        let opts = ExtractOptions::new(4).with_r2_strings(fake_r2_strings.clone());
        assert!(opts.r2_strings.is_some());
        assert_eq!(opts.r2_strings.unwrap().len(), 1);
    }

    #[test]
    fn test_get_r2_strings_preextracted() {
        let fake_r2_strings = vec![ExtractedString {
            value: "preextracted".to_string(),
            data_offset: 0x2000,
            section: Some(".text".to_string()),
            method: StringMethod::R2String,
            kind: StringKind::FuncName,
            library: None,
        }];
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
            let fake_r2_strings = vec![ExtractedString {
                value: "from_r2".to_string(),
                data_offset: 0x3000,
                section: None,
                method: StringMethod::R2String,
                kind: StringKind::Const,
                library: None,
            }];
            let opts = ExtractOptions::new(4).with_r2_strings(fake_r2_strings);
            let strings = extract_from_object(&object, &data, &opts);
            // Should include the pre-extracted r2 string
            assert!(strings.iter().any(|s| s.value == "from_r2"));
        }
    }

    // Wide string (UTF-16LE) extraction tests

    /// Helper to encode a string as UTF-16LE with null terminator
    fn to_utf16le_null(s: &str) -> Vec<u8> {
        let mut bytes = Vec::new();
        for c in s.encode_utf16() {
            bytes.extend_from_slice(&c.to_le_bytes());
        }
        // Add null terminator (two zero bytes)
        bytes.extend_from_slice(&[0x00, 0x00]);
        bytes
    }

    #[test]
    fn test_extract_wide_strings_empty() {
        let strings = extract_wide_strings(&[], 4, None, &[]);
        assert!(strings.is_empty());
    }

    #[test]
    fn test_extract_wide_strings_too_short() {
        // Less than 4 bytes
        let strings = extract_wide_strings(&[0x41, 0x00], 4, None, &[]);
        assert!(strings.is_empty());
    }

    #[test]
    fn test_extract_wide_strings_basic() {
        let data = to_utf16le_null("Hello");
        let strings = extract_wide_strings(&data, 4, None, &[]);

        assert_eq!(strings.len(), 1);
        assert_eq!(strings[0].value, "Hello");
        assert_eq!(strings[0].method, StringMethod::WideString);
        assert_eq!(strings[0].data_offset, 0);
    }

    #[test]
    fn test_extract_wide_strings_multiple() {
        let mut data = to_utf16le_null("Hello");
        data.extend(to_utf16le_null("World"));
        let strings = extract_wide_strings(&data, 4, None, &[]);

        assert_eq!(strings.len(), 2);
        assert!(strings.iter().any(|s| s.value == "Hello"));
        assert!(strings.iter().any(|s| s.value == "World"));
    }

    #[test]
    fn test_extract_wide_strings_min_length() {
        let mut data = to_utf16le_null("Hi"); // 2 chars - below min
        data.extend(to_utf16le_null("Hello")); // 5 chars - above min
        let strings = extract_wide_strings(&data, 4, None, &[]);

        assert_eq!(strings.len(), 1);
        assert_eq!(strings[0].value, "Hello");
    }

    #[test]
    fn test_extract_wide_strings_with_section() {
        let data = to_utf16le_null("Hello");
        let strings = extract_wide_strings(&data, 4, Some(".rsrc".to_string()), &[]);

        assert_eq!(strings[0].section, Some(".rsrc".to_string()));
    }

    #[test]
    fn test_extract_wide_strings_mixed_with_ascii() {
        // Mix of UTF-8 and UTF-16LE data - wide string follows ASCII with some padding
        let mut data = b"ASCII string\0\0".to_vec(); // Extra null for alignment
        data.extend(to_utf16le_null("WideString"));
        data.extend(b"more ASCII\0");

        let strings = extract_wide_strings(&data, 4, None, &[]);

        // Should extract the wide string
        assert!(
            strings.iter().any(|s| s.value == "WideString"),
            "Expected to find 'WideString', found: {:?}",
            strings.iter().map(|s| &s.value).collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_extract_wide_strings_path() {
        let data = to_utf16le_null("C:\\Windows\\System32\\kernel32.dll");
        let strings = extract_wide_strings(&data, 4, None, &[]);

        assert_eq!(strings.len(), 1);
        assert!(strings[0].value.contains("Windows"));
        assert_eq!(strings[0].kind, StringKind::Path);
    }

    #[test]
    fn test_extract_wide_strings_url() {
        let data = to_utf16le_null("https://example.com/api");
        let strings = extract_wide_strings(&data, 4, None, &[]);

        assert_eq!(strings.len(), 1);
        assert_eq!(strings[0].kind, StringKind::Url);
    }

    #[test]
    fn test_extract_wide_strings_deduplication() {
        let mut data = to_utf16le_null("Hello");
        data.extend(to_utf16le_null("Hello")); // Duplicate
        let strings = extract_wide_strings(&data, 4, None, &[]);

        assert_eq!(strings.iter().filter(|s| s.value == "Hello").count(), 1);
    }

    #[test]
    fn test_extract_wide_strings_segment_detection() {
        let segment_names = vec![".rdata".to_string()];
        let data = to_utf16le_null(".rdata");
        let strings = extract_wide_strings(&data, 4, None, &segment_names);

        assert_eq!(strings[0].kind, StringKind::Section);
    }

    #[test]
    fn test_extract_wide_strings_with_spaces() {
        let data = to_utf16le_null("Hello World");
        let strings = extract_wide_strings(&data, 4, None, &[]);

        assert_eq!(strings.len(), 1);
        assert_eq!(strings[0].value, "Hello World");
    }

    #[test]
    fn test_extract_wide_strings_trimming() {
        let data = to_utf16le_null("  Hello  ");
        let strings = extract_wide_strings(&data, 4, None, &[]);

        assert_eq!(strings[0].value, "Hello");
    }

    #[test]
    fn test_extract_wide_strings_registry_path() {
        let data = to_utf16le_null("HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft");
        let strings = extract_wide_strings(&data, 4, None, &[]);

        assert_eq!(strings.len(), 1);
        assert_eq!(strings[0].kind, StringKind::Registry);
    }

    #[test]
    fn test_extract_wide_strings_no_null_terminator() {
        // Wide string without null terminator at end of data
        let mut data = Vec::new();
        for c in "Hello".encode_utf16() {
            data.extend_from_slice(&c.to_le_bytes());
        }
        // No null terminator - string ends at data boundary

        let strings = extract_wide_strings(&data, 4, None, &[]);
        assert_eq!(strings.len(), 1);
        assert_eq!(strings[0].value, "Hello");
    }

    #[test]
    fn test_extract_wide_strings_embedded_in_binary() {
        // Binary data, then wide string, then more binary
        let mut data = vec![0x00, 0x01, 0x02, 0x03, 0xFF, 0xFE]; // random bytes
        data.extend(to_utf16le_null("Embedded"));
        data.extend(vec![0x00, 0x01, 0x02, 0x03]); // more random bytes

        let strings = extract_wide_strings(&data, 4, None, &[]);
        assert!(strings.iter().any(|s| s.value == "Embedded"));
    }

    #[test]
    fn test_extract_wide_strings_special_chars() {
        // Test with common Windows special characters
        let data = to_utf16le_null("file.exe");
        let strings = extract_wide_strings(&data, 4, None, &[]);

        assert_eq!(strings.len(), 1);
        assert_eq!(strings[0].value, "file.exe");
    }

    #[test]
    fn test_extract_wide_strings_unicode_latin() {
        // Latin characters with accents (common in European Windows apps)
        let data = to_utf16le_null("caf\u{00E9}"); // café
        let strings = extract_wide_strings(&data, 4, None, &[]);

        assert_eq!(strings.len(), 1);
        assert_eq!(strings[0].value, "caf\u{00E9}");
    }

    #[test]
    fn test_is_printable_ascii() {
        assert!(is_printable_ascii(b'A'));
        assert!(is_printable_ascii(b'z'));
        assert!(is_printable_ascii(b'0'));
        assert!(is_printable_ascii(b' '));
        assert!(is_printable_ascii(b'\t'));
        assert!(is_printable_ascii(b'\n'));
        assert!(!is_printable_ascii(0x00));
        assert!(!is_printable_ascii(0x01));
        assert!(!is_printable_ascii(0x7F)); // DEL
    }

    #[test]
    fn test_is_valid_wide_char() {
        // ASCII printable
        assert!(is_valid_wide_char(0x0041)); // 'A'
        assert!(is_valid_wide_char(0x0020)); // space
        assert!(is_valid_wide_char(0x0009)); // tab

        // Latin-1 Supplement
        assert!(is_valid_wide_char(0x00E9)); // é
        assert!(is_valid_wide_char(0x00F1)); // ñ

        // Control characters should be rejected
        assert!(!is_valid_wide_char(0x0000)); // NULL
        assert!(!is_valid_wide_char(0x0001)); // SOH
        assert!(!is_valid_wide_char(0x007F)); // DEL

        // CJK should be rejected (too much noise)
        assert!(!is_valid_wide_char(0x4E00)); // CJK
    }

    #[test]
    fn test_find_subsequence() {
        let haystack = b"hello world";
        assert_eq!(find_subsequence(haystack, b"world"), Some(6));
        assert_eq!(find_subsequence(haystack, b"hello"), Some(0));
        assert_eq!(find_subsequence(haystack, b"notfound"), None);
        assert_eq!(find_subsequence(haystack, b""), Some(0));
    }

    #[test]
    fn test_parse_entitlement_keys_basic() {
        let xml = b"<?xml version=\"1.0\"?>\
            <plist version=\"1.0\">\
            <dict>\
            <key>com.apple.security.get-task-allow</key>\
            <true/>\
            </dict>\
            </plist>";

        let result = parse_entitlement_keys(xml, 0, 4);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].value, "com.apple.security.get-task-allow");
        assert_eq!(result[0].kind, StringKind::Entitlement);
        assert_eq!(result[0].method, StringMethod::CodeSignature);
        assert_eq!(result[0].section, Some("__LINKEDIT".to_string()));
    }

    #[test]
    fn test_parse_entitlement_keys_with_string_values() {
        let xml = b"<?xml version=\"1.0\"?>\
            <plist version=\"1.0\">\
            <dict>\
            <key>com.apple.security.temporary-exception.mach-lookup.global-name</key>\
            <string>com.apple.testmanagerd</string>\
            </dict>\
            </plist>";

        let result = parse_entitlement_keys(xml, 0, 4);
        assert_eq!(result.len(), 2);

        // Should have both the entitlement key and the app ID
        let entitlement = result
            .iter()
            .find(|s| s.kind == StringKind::Entitlement)
            .unwrap();
        assert_eq!(
            entitlement.value,
            "com.apple.security.temporary-exception.mach-lookup.global-name"
        );

        let appid = result.iter().find(|s| s.kind == StringKind::AppId).unwrap();
        assert_eq!(appid.value, "com.apple.testmanagerd");
    }

    #[test]
    fn test_parse_entitlement_keys_multiple() {
        let xml = b"<?xml version=\"1.0\"?>\
            <plist version=\"1.0\">\
            <dict>\
            <key>com.apple.security.get-task-allow</key>\
            <true/>\
            <key>com.apple.security.files.absolute-path.read-only</key>\
            <string>/usr/bin</string>\
            <key>com.apple.security.network.client</key>\
            <true/>\
            </dict>\
            </plist>";

        let result = parse_entitlement_keys(xml, 0, 4);

        // Should have 3 entitlement keys + 1 string value
        let entitlements: Vec<_> = result
            .iter()
            .filter(|s| s.kind == StringKind::Entitlement)
            .collect();
        assert_eq!(entitlements.len(), 3);

        let appids: Vec<_> = result
            .iter()
            .filter(|s| s.kind == StringKind::AppId)
            .collect();
        assert_eq!(appids.len(), 1);
        assert_eq!(appids[0].value, "/usr/bin");
    }

    #[test]
    fn test_parse_entitlement_keys_min_length() {
        let xml = b"<?xml version=\"1.0\"?>\
            <plist version=\"1.0\">\
            <dict>\
            <key>abc</key>\
            <true/>\
            <key>com.apple.security.get-task-allow</key>\
            <true/>\
            </dict>\
            </plist>";

        // Min length 10 should filter out "abc" but keep the long one
        let result = parse_entitlement_keys(xml, 0, 10);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].value, "com.apple.security.get-task-allow");
    }

    #[test]
    fn test_parse_entitlement_keys_offset_calculation() {
        let xml = b"<?xml version=\"1.0\"?>\
            <plist version=\"1.0\">\
            <dict>\
            <key>test.entitlement</key>\
            <true/>\
            </dict>\
            </plist>";

        let base_offset = 1000u64;
        let result = parse_entitlement_keys(xml, base_offset, 4);

        // Offset should be base_offset + position in XML
        assert!(result[0].data_offset >= base_offset);
        assert!(result[0].data_offset < base_offset + xml.len() as u64);
    }

    #[test]
    fn test_parse_entitlement_keys_malformed_xml() {
        // Missing closing tags - should not panic
        let xml = b"<key>incomplete";
        let result = parse_entitlement_keys(xml, 0, 4);
        assert!(result.is_empty());

        // Missing key content
        let xml = b"<key></key>";
        let result = parse_entitlement_keys(xml, 0, 4);
        assert!(result.is_empty());
    }

    #[test]
    fn test_parse_entitlement_keys_empty() {
        let xml = b"";
        let result = parse_entitlement_keys(xml, 0, 4);
        assert!(result.is_empty());

        let xml = b"<dict></dict>";
        let result = parse_entitlement_keys(xml, 0, 4);
        assert!(result.is_empty());
    }

    #[test]
    fn test_extract_macho_entitlements_real_binary() {
        // Test with system utilities that may have entitlements
        // Try multiple paths for cross-platform compatibility
        let paths = vec![
            "/usr/bin/codesign",
            "/usr/bin/security",
            "/System/Library/CoreServices/Finder.app/Contents/MacOS/Finder",
        ];

        for path in paths {
            if let Ok(data) = std::fs::read(path) {
                use goblin::Object;

                if let Ok(Object::Mach(goblin::mach::Mach::Binary(macho))) = Object::parse(&data) {
                    let entitlements = extract_macho_entitlements(&macho, &data, 4);

                    // System binaries may or may not have entitlements
                    // Just verify the function doesn't panic and returns valid data
                    for ent in &entitlements {
                        assert_eq!(ent.section, Some("__LINKEDIT".to_string()));
                        assert_eq!(ent.method, StringMethod::CodeSignature);
                        assert!(
                            ent.kind == StringKind::Entitlement || ent.kind == StringKind::AppId
                        );
                    }
                    return; // Test passed with at least one binary
                }
            }
        }
        // If no system binaries found, skip test
    }

    #[test]
    fn test_extract_macho_entitlements_no_signature() {
        // Create a minimal Mach-O without code signature
        let data = vec![
            0xCF, 0xFA, 0xED, 0xFE, // MH_MAGIC_64
            0x07, 0x00, 0x00, 0x01, // CPU_TYPE_X86_64
            0x03, 0x00, 0x00, 0x00, // CPU_SUBTYPE_X86_64_ALL
            0x02, 0x00, 0x00, 0x00, // MH_EXECUTE
            0x00, 0x00, 0x00, 0x00, // ncmds
            0x00, 0x00, 0x00, 0x00, // sizeofcmds
            0x00, 0x00, 0x00, 0x00, // flags
            0x00, 0x00, 0x00, 0x00, // reserved
        ];

        use goblin::Object;

        if let Ok(Object::Mach(goblin::mach::Mach::Binary(macho))) = Object::parse(&data) {
            let entitlements = extract_macho_entitlements(&macho, &data, 4);
            assert!(
                entitlements.is_empty(),
                "Should return empty vec for binary without code signature"
            );
        }
    }

    #[test]
    fn test_entitlements_integrated_extraction() {
        // Test that entitlements are included in full extraction with system binaries
        let paths = vec!["/usr/bin/codesign", "/usr/bin/security"];

        for path in paths {
            if let Ok(data) = std::fs::read(path) {
                let opts = ExtractOptions::new(4);
                let strings = extract_strings_with_options(&data, &opts);

                // Filter for entitlements if any exist
                let entitlements: Vec<_> = strings
                    .iter()
                    .filter(|s| s.kind == StringKind::Entitlement || s.kind == StringKind::AppId)
                    .collect();

                // If entitlements exist, verify they have High severity
                for ent in entitlements {
                    assert_eq!(ent.kind.severity(), Severity::High);
                }
                return; // Test completed successfully
            }
        }
        // If no system binaries found, skip test
    }

    #[test]
    fn test_entitlements_no_duplicate_strings() {
        // Verify that entitlement XML content doesn't create duplicate strings
        let paths = vec![
            "/System/Library/CoreServices/Finder.app/Contents/MacOS/Finder",
            "/usr/bin/codesign",
        ];

        for path in paths {
            if let Ok(data) = std::fs::read(path) {
                let opts = ExtractOptions::new(4);
                let strings = extract_strings_with_options(&data, &opts);

                // Find EntitlementsXml entries
                let xml_entries: Vec<_> = strings
                    .iter()
                    .filter(|s| s.kind == StringKind::EntitlementsXml)
                    .collect();

                if xml_entries.is_empty() {
                    continue; // No entitlements in this binary, try next
                }

                // For each EntitlementsXml entry, verify no other strings overlap its byte range
                for xml_entry in &xml_entries {
                    let xml_start = xml_entry.data_offset;
                    let xml_end = xml_start + xml_entry.value.len() as u64;

                    // Check for overlapping strings
                    let overlaps: Vec<_> = strings
                        .iter()
                        .filter(|s| {
                            if s.kind == StringKind::EntitlementsXml {
                                return false; // Skip the XML entry itself
                            }
                            let s_start = s.data_offset;
                            let s_end = s_start + s.value.len() as u64;
                            // Check if ranges overlap
                            !(s_end <= xml_start || s_start >= xml_end)
                        })
                        .collect();

                    assert!(
                        overlaps.is_empty(),
                        "Found {} strings overlapping with entitlement XML at offset 0x{:x}",
                        overlaps.len(),
                        xml_start
                    );
                }

                return; // Test passed with at least one binary
            }
        }
        // If no system binaries found, skip test
    }
}
