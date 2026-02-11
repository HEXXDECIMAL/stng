//! # stng - Language-aware string extraction
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
//! use stng::extract_strings;
//!
//! let data = std::fs::read("my_binary").unwrap();
//! let strings = extract_strings(&data, 4);
//!
//! for s in strings {
//!     println!("{}: {}", s.data_offset, s.value);
//! }
//! ```

// Core modules
mod extraction;
mod types;
mod validation;

// Binary format modules
mod binary;
mod binary_net;
mod detect;
mod entitlements;
mod imports;
mod overlay;
mod raw;
mod stack_strings;

// Language-specific extractors
mod go;
mod instr;
pub mod r2;
mod rust;
pub mod xor;

// Decoders for encoded strings
pub mod decoders;

// Re-export public API
pub use binary::{is_go_binary, is_rust_binary};
pub use detect::{detect_language, is_text_file};
pub use entitlements::extract_macho_entitlements_xml;
pub use go::{classify_string, GoStringExtractor};
pub use overlay::{detect_elf_overlay, extract_overlay_strings};
pub use rust::RustStringExtractor;
pub use stack_strings::extract_stack_strings;
pub use types::{
    BinaryInfo, ExtractedString, OverlayInfo, Severity, StringKind, StringMethod, StringStruct,
};
pub use validation::is_garbage;

// Re-export goblin so library clients can parse binaries themselves
pub use goblin;
use goblin::mach::MachO;
use goblin::Object;
use std::collections::HashSet;

// Import internal modules for use in this file
use binary::{collect_elf_segments, collect_macho_segments, macho_has_go_sections};
use binary_net::scan_binary_ips;
use entitlements::extract_macho_entitlements;
use imports::{extract_elf_imports, extract_macho_imports};
use raw::{extract_raw_strings, extract_wide_strings};

/// Enrich strings with section information based on their file offsets (ELF)
fn enrich_elf_sections(strings: &mut [ExtractedString], elf: &goblin::elf::Elf) {
    for s in strings {
        if s.section.is_none() {
            // Find which section this offset belongs to
            for sh in &elf.section_headers {
                if s.data_offset >= sh.sh_offset && s.data_offset < sh.sh_offset + sh.sh_size {
                    if let Some(name) = elf.shdr_strtab.get_at(sh.sh_name) {
                        if !name.is_empty() {
                            s.section = Some(name.to_string());
                            break;
                        }
                    }
                }
            }
        }
    }
}

/// Enrich strings with section information based on their file offsets (Mach-O)
///
/// `base_offset` is the file offset where this architecture starts (0 for regular binaries,
/// arch.offset for fat binaries).
fn enrich_macho_sections(
    strings: &mut [ExtractedString],
    macho: &goblin::mach::MachO,
    base_offset: u64,
) {
    // Calculate Mach-O header regions (relative to architecture start)
    // Header is 32 bytes for 64-bit, 28 bytes for 32-bit
    let header_size: u64 = if macho.is_64 { 32 } else { 28 };
    let load_cmds_end = base_offset + header_size + u64::from(macho.header.sizeofcmds);


    // Find LINKEDIT segment range (contains symbol/string tables)
    // Segment fileoff is relative to architecture, so add base_offset
    let mut linkedit_range: Option<(u64, u64)> = None;
    for segment in &macho.segments {
        if let Ok(name) = segment.name() {
            if name == "__LINKEDIT" {
                let start = base_offset + segment.fileoff;
                let end = start + segment.filesize;
                linkedit_range = Some((start, end));
                break;
            }
        }
    }

    for s in strings {
        // Check if section needs enrichment (None or empty string)
        let needs_section = s.section.as_ref().map_or(true, |sec| sec.is_empty());
        if needs_section {
            // First check actual sections
            // Section offsets are relative to architecture, so add base_offset
            let mut found = false;
            for segment in &macho.segments {
                for (section, _data) in segment.into_iter().flatten() {
                    // Skip BSS/uninitialized sections (offset 0, no file content)
                    if section.offset == 0 {
                        continue;
                    }
                    let section_start = base_offset + u64::from(section.offset);
                    let section_end = section_start + section.size;
                    if s.data_offset >= section_start && s.data_offset < section_end {
                        s.section = Some(section.name().unwrap_or("(unknown)").to_string());
                        found = true;
                        break;
                    }
                }
                if found {
                    break;
                }
            }

            // If not in a section, check Mach-O specific regions
            if !found {
                if s.data_offset >= base_offset && s.data_offset < load_cmds_end {
                    // In header or load commands area
                    s.section = Some("load_commands".to_string());
                } else if let Some((start, end)) = linkedit_range {
                    if s.data_offset >= start && s.data_offset < end {
                        // In LINKEDIT but not in a specific section (symbol/string tables)
                        s.section = Some("__LINKEDIT".to_string());
                    }
                }
            }
        }
    }
}

/// Enrich strings with section information based on their file offsets (PE)
fn enrich_pe_sections(strings: &mut [ExtractedString], pe: &goblin::pe::PE) {
    for s in strings {
        if s.section.is_none() {
            // Find which section this offset belongs to
            for section in &pe.sections {
                let section_start = u64::from(section.pointer_to_raw_data);
                let section_end = section_start + u64::from(section.size_of_raw_data);
                if s.data_offset >= section_start && s.data_offset < section_end {
                    let name = String::from_utf8_lossy(&section.name)
                        .trim_end_matches('\0')
                        .to_string();
                    if !name.is_empty() {
                        s.section = Some(name);
                        break;
                    }
                }
            }
        }
    }
}
// use stack_strings::extract_stack_strings; // Already exported

#[derive(Debug, Clone, Default)]
pub struct ExtractOptions {
    /// Minimum string length to extract
    pub min_length: usize,
    /// Use radare2 for extraction (if available). Default: false for library use.
    pub use_r2: bool,
    /// Path to the binary file (required if `use_r2` is true)
    pub path: Option<String>,
    /// Pre-extracted strings from radare2 (allows clients to run r2 themselves)
    pub r2_strings: Option<Vec<ExtractedString>>,
    /// Filter out garbage strings (default: false for library, true for CLI)
    pub filter_garbage: bool,
    /// Enable XOR string detection (single-byte keys). Default: false.
    pub xor_scan: bool,
    /// Custom XOR key for decoding (overrides auto-detection if set).
    pub xor_key: Option<Vec<u8>>,
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
            xor_key: None,
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

    /// Specify a custom XOR key for decoding.
    /// The key can be single-byte or multi-byte and will be applied to all byte streams.
    /// This overrides automatic XOR detection when set.
    pub fn with_xor_key(mut self, key: Vec<u8>) -> Self {
        self.xor_key = Some(key);
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

/// Extract strings from binary data using multiple techniques.
///
/// This is the primary entry point for language-aware string extraction from
/// compiled binaries. It automatically detects the binary format and language,
/// then applies appropriate extraction techniques.
///
/// # Arguments
///
/// * `data` - The raw binary data to analyze
/// * `min_length` - Minimum string length to extract (typically 4-8)
///
/// # Returns
///
/// A vector of extracted strings with metadata about where they were found,
/// how they were extracted, and semantic classification.
///
/// # Examples
///
/// ```no_run
/// use stng::extract_strings;
///
/// let data = std::fs::read("/bin/ls").unwrap();
/// let strings = extract_strings(&data, 4);
///
/// for s in strings.iter().take(10) {
///     println!("{:?}: {}", s.kind, s.value);
/// }
/// ```
#[must_use]
pub fn extract_strings(data: &[u8], min_length: usize) -> Vec<ExtractedString> {
    extract_strings_with_options(data, &ExtractOptions::new(min_length))
}

fn method_priority(m: StringMethod) -> u8 {
    match m {
        StringMethod::Structure | StringMethod::StackString | StringMethod::InstructionPattern => 3,
        StringMethod::R2String
        | StringMethod::R2Symbol
        | StringMethod::WideString
        | StringMethod::XorDecode
        | StringMethod::Base64Decode
        | StringMethod::HexDecode
        | StringMethod::UrlDecode
        | StringMethod::UnicodeEscapeDecode
        | StringMethod::CodeSignature => 2,
        StringMethod::Heuristic => 1,
        StringMethod::RawScan => 0,
    }
}

/// Deduplicate strings by keeping only the longest string at each offset.
/// This handles cases where overlapping strings exist at the same offset.
fn deduplicate_by_offset(strings: Vec<ExtractedString>) -> Vec<ExtractedString> {
    use std::collections::HashMap;

    let mut offset_map: HashMap<u64, Vec<ExtractedString>> = HashMap::new();
    for s in strings {
        offset_map.entry(s.data_offset).or_default().push(s);
    }

    offset_map
        .into_values()
        .map(|mut strings_at_offset| {
            if strings_at_offset.len() > 1 {
                strings_at_offset.sort_by(|a, b| {
                    // First compare by method priority (higher is better)
                    let pa = method_priority(a.method);
                    let pb = method_priority(b.method);
                    match pb.cmp(&pa) {
                        std::cmp::Ordering::Equal => {
                            // Then by length (longer is better)
                            b.value.len().cmp(&a.value.len())
                        }
                        other => other,
                    }
                });
            }
            strings_at_offset.into_iter().next().unwrap()
        })
        .collect()
}

/// Extract strings with additional options.
///
/// Provides fine-grained control over the extraction process through the
/// `ExtractOptions` builder pattern.
///
/// # Arguments
///
/// * `data` - The raw binary data to analyze
/// * `opts` - Extraction options (min length, filters, external tool integration)
///
/// # Examples
///
/// ```
/// use stng::{extract_strings_with_options, ExtractOptions};
///
/// let data = std::fs::read("/bin/ls").unwrap();
/// let opts = ExtractOptions::new(4)
///     .with_garbage_filter(true);
/// let strings = extract_strings_with_options(&data, &opts);
/// ```
#[must_use]
pub fn extract_strings_with_options(data: &[u8], opts: &ExtractOptions) -> Vec<ExtractedString> {
    if let Ok(object) = Object::parse(data) {
        deduplicate_by_offset(extract_from_object(&object, data, opts))
    } else {
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

        // XOR string detection
        if !data.is_empty() {
            // Get radare2 string boundaries for XOR hints (if r2 is enabled)
            let r2_boundaries = if opts.use_r2 {
                if let Some(path) = &opts.path {
                    r2::extract_string_boundaries(path)
                } else {
                    None
                }
            } else {
                None
            };

            // Custom XOR key takes precedence over auto-detection
            if let Some(ref key) = opts.xor_key {
                tracing::debug!("Custom XOR: using {} byte key", key.len());

                // Check if the XOR key exists in the already-extracted strings
                let key_str = String::from_utf8_lossy(key).to_string();
                let key_found = strings.iter_mut().find(|s| s.value == key_str);
                if let Some(key_string) = key_found {
                    // Mark the key as XorKey type
                    key_string.kind = StringKind::XorKey;
                }

                if opts.filter_garbage {
                    strings.extend(xor::extract_custom_xor_strings_with_hints(
                        data,
                        key,
                        opts.xor_min_length,
                        r2_boundaries.as_deref(),
                        true,
                    ));
                } else {
                    strings.extend(xor::extract_custom_xor_strings_with_hints(
                        data,
                        key,
                        opts.xor_min_length,
                        r2_boundaries.as_deref(),
                        false,
                    ));
                }
            } else if opts.xor_scan {
                // Try auto-detecting XOR key from extracted strings (small files only)
                let auto_key = if data.len() <= xor::MAX_AUTO_DETECT_SIZE {
                    xor::auto_detect_xor_key(data, &strings, opts.xor_min_length)
                } else {
                    None
                };

                if let Some((key, key_str, _key_offset)) = auto_key {
                    // Auto-detected key - use it
                    tracing::info!("Using auto-detected XOR key: '{}'", key_str);

                    // Mark the XOR key string as XorKey type (it already exists from raw scan)
                    if let Some(key_string) = strings.iter_mut().find(|s| s.value == key_str) {
                        key_string.kind = StringKind::XorKey;
                    }

                    if opts.filter_garbage {
                        strings.extend(xor::extract_custom_xor_strings_with_hints(
                            data,
                            &key,
                            opts.xor_min_length,
                            r2_boundaries.as_deref(),
                            true,
                        ));
                    } else {
                        strings.extend(xor::extract_custom_xor_strings_with_hints(
                            data,
                            &key,
                            opts.xor_min_length,
                            r2_boundaries.as_deref(),
                            false,
                        ));
                    }
                } else {
                    // Fallback to single-byte XOR scan
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
                            tracing::debug!(
                                "Multi-byte XOR: found {} potential keys",
                                xor_keys.len()
                            );
                            if xor_keys.is_empty() {
                                tracing::debug!("Multi-byte XOR: no high-confidence keys found");
                            } else {
                                let decoded = xor::extract_multikey_xor_strings(
                                    data,
                                    &xor_keys,
                                    opts.xor_min_length,
                                );
                                tracing::debug!(
                                    "Multi-byte XOR: decoded {} strings",
                                    decoded.len()
                                );
                                strings.extend(decoded);
                            }
                        } else {
                            tracing::debug!("Multi-byte XOR: path not provided, skipping");
                        }
                    }
                }
            }
        }

        // Decode encoded strings (base64, hex, URL-encoding, unicode escapes)
        // This happens BEFORE garbage filtering so we can decode potentially-garbage-looking encodings
        tracing::debug!("Running decoders on {} strings", strings.len());
        let mut decoded = Vec::new();
        decoded.extend(decoders::decode_base64_strings(&strings));
        decoded.extend(decoders::decode_hex_strings(&strings));
        decoded.extend(decoders::decode_url_strings(&strings));
        decoded.extend(decoders::decode_unicode_escape_strings(&strings));

        tracing::debug!("Decoded {} additional strings", decoded.len());

        // Add decoded strings to the main list
        strings.extend(decoded);

        // Apply garbage filter if enabled (but never filter entitlements XML, section names, or encoded strings)
        // Note: Encoded strings (Base64, HexEncoded, etc.) are kept even if they look like garbage,
        // because the decoded version might be valuable
        if opts.filter_garbage {
            strings.retain(|s| {
                s.kind == StringKind::EntitlementsXml
                    || s.kind == StringKind::Section
                    || s.kind == StringKind::Base64
                    || s.kind == StringKind::HexEncoded
                    || s.kind == StringKind::UrlEncoded
                    || s.kind == StringKind::UnicodeEscaped
                    || !validation::is_garbage(&s.value)
            });
        }

        deduplicate_by_offset(strings)
    }
}

/// Helper to get r2 strings from options (pre-extracted or by running r2)
pub fn extract_from_object(
    object: &Object,
    data: &[u8],
    opts: &ExtractOptions,
) -> Vec<ExtractedString> {
    let min_length = opts.min_length;
    let mut strings = Vec::new();
    // Track if this is a Go binary - skip XOR scanning for Go (rarely obfuscated)
    let mut is_go_binary = false;

    match object {
        Object::Mach(goblin::mach::Mach::Binary(macho)) => {
            let segments = collect_macho_segments(macho);
            if macho_has_go_sections(macho) {
                is_go_binary = true;
                let extractor = GoStringExtractor::new(min_length);
                strings.extend(extractor.extract_macho(macho, data));
            } else if binary::macho_is_rust(macho) {
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
            // Skip stack string extraction for Go binaries
            if !is_go_binary {
                strings.extend(extract_stack_strings(data, min_length));
            }
            // Add imports/exports, upgrading existing strings
            let imports = extract_macho_imports(macho, min_length);
            let import_map: std::collections::HashMap<&str, (&StringKind, Option<&str>)> = imports
                .iter()
                .map(|s| (s.value.as_str(), (&s.kind, s.library.as_deref())))
                .collect();
            for s in &mut strings {
                if let Some(&(kind, lib)) = import_map.get(s.value.as_str()) {
                    s.kind = *kind;
                    s.library = lib.map(std::string::ToString::to_string);
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
            for arch_result in fat {
                if let Ok(goblin::mach::SingleArch::MachO(macho)) = arch_result {
                    segments = collect_macho_segments(&macho);
                    if macho_has_go_sections(&macho) {
                        is_go = true;
                        is_go_binary = true;
                        let extractor = GoStringExtractor::new(min_length);
                        strings.extend(extractor.extract_macho(&macho, data));
                    } else if binary::macho_is_rust(&macho) {
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
            // Skip stack string extraction for Go binaries
            if !is_go_binary {
                strings.extend(extract_stack_strings(data, min_length));
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
                for s in &mut strings {
                    if let Some(&(kind, lib)) = import_map.get(s.value.as_str()) {
                        s.kind = *kind;
                        s.library = lib.map(std::string::ToString::to_string);
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
                is_go_binary = true;
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
            // Extract UTF-16LE wide strings (less common in ELF but can occur, especially in malware)
            strings.extend(extract_wide_strings(data, min_length, None, &segments));

            // Extract binary network data (IPs and ports in network byte order)
            strings.extend(scan_binary_ips(
                data,
                min_length,
                elf.header.e_machine,
                Some(elf),
            ));

            // Skip stack string extraction for Go binaries (they don't use stack-based obfuscation)
            if !is_go_binary {
                strings.extend(extract_stack_strings(data, min_length));
            }
            // Add imports/exports from dynamic symbols, upgrading existing strings
            let imports = extract_elf_imports(elf, min_length);
            let import_map: std::collections::HashMap<&str, (&StringKind, Option<&str>)> = imports
                .iter()
                .map(|s| (s.value.as_str(), (&s.kind, s.library.as_deref())))
                .collect();
            for s in &mut strings {
                if let Some(&(kind, lib)) = import_map.get(s.value.as_str()) {
                    s.kind = *kind;
                    s.library = lib.map(ToString::to_string);
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
                is_go_binary = true;
                let extractor = GoStringExtractor::new(min_length);
                strings.extend(extractor.extract_pe(pe, data));
            }

            // Use r2 if available
            if let Some(r2_strings) = get_r2_strings(opts) {
                strings.extend(r2_strings);
            }

            // Extract UTF-16LE wide strings (common in Windows binaries)
            strings.extend(extract_wide_strings(data, min_length, None, &segments));

            // Extract binary network data (IPs and ports in network byte order)
            strings.extend(scan_binary_ips(
                data,
                min_length,
                pe.header.coff_header.machine,
                None,
            ));

            // Raw scan for PE (catches strings missed by structure extraction)
            strings.extend(extract_raw_strings(data, min_length, None, &segments));

            // Skip stack string extraction for Go binaries
            if !is_go_binary {
                strings.extend(extract_stack_strings(data, min_length));
            }

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
            // Extract binary network data (IPs and ports in network byte order)
            // For unknown formats, use 0 (not M68000) to process normally
            strings.extend(scan_binary_ips(data, min_length, 0, None));
            strings.extend(extract_stack_strings(data, min_length));
        }
    }

    // XOR string detection - skip for Go binaries (they don't use XOR obfuscation)
    if !data.is_empty() && !is_go_binary {
        // Get radare2 string boundaries for XOR hints (if r2 is enabled)
        let r2_boundaries = if opts.use_r2 {
            if let Some(path) = &opts.path {
                r2::extract_string_boundaries(path)
            } else {
                None
            }
        } else {
            None
        };

        // Custom XOR key takes precedence over auto-detection
        if let Some(ref key) = opts.xor_key {
            tracing::info!("Custom XOR: using {} byte key", key.len());

            // Check if the XOR key exists in the already-extracted strings
            let key_str = String::from_utf8_lossy(key).to_string();
            let key_found = strings.iter_mut().find(|s| s.value == key_str);
            if let Some(key_string) = key_found {
                // Mark the key as XorKey type
                key_string.kind = StringKind::XorKey;
            }

            if opts.filter_garbage {
                strings.extend(xor::extract_custom_xor_strings_with_hints(
                    data,
                    key,
                    opts.xor_min_length,
                    r2_boundaries.as_deref(),
                    true,
                ));
            } else {
                strings.extend(xor::extract_custom_xor_strings_with_hints(
                    data,
                    key,
                    opts.xor_min_length,
                    r2_boundaries.as_deref(),
                    false,
                ));
            }
        } else if opts.xor_scan {
            // Try auto-detecting XOR key from extracted strings (small files only)
            let auto_key = if data.len() <= xor::MAX_AUTO_DETECT_SIZE {
                xor::auto_detect_xor_key(data, &strings, opts.xor_min_length)
            } else {
                None
            };

            if let Some((key, key_str, _key_offset)) = auto_key {
                // Auto-detected key - use it
                tracing::info!("Using auto-detected XOR key: '{}'", key_str);

                // Mark the XOR key string as XorKey type (it already exists from raw scan)
                if let Some(key_string) = strings.iter_mut().find(|s| s.value == key_str) {
                    key_string.kind = StringKind::XorKey;
                }

                if opts.filter_garbage {
                    strings.extend(xor::extract_custom_xor_strings_with_hints(
                        data,
                        &key,
                        opts.xor_min_length,
                        r2_boundaries.as_deref(),
                        true,
                    ));
                } else {
                    strings.extend(xor::extract_custom_xor_strings_with_hints(
                        data,
                        &key,
                        opts.xor_min_length,
                        r2_boundaries.as_deref(),
                        false,
                    ));
                }
            } else {
                // Fallback to single-byte XOR scan
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
                        if xor_keys.is_empty() {
                            tracing::debug!("Multi-byte XOR: no high-confidence keys found");
                        } else {
                            tracing::debug!(
                                "Multi-byte XOR: attempting decryption with {} keys",
                                xor_keys.len()
                            );
                            let decoded = xor::extract_multikey_xor_strings(
                                data,
                                &xor_keys,
                                opts.xor_min_length,
                            );
                            tracing::debug!("Multi-byte XOR: decoded {} strings", decoded.len());
                            strings.extend(decoded);
                        }
                    } else {
                        tracing::debug!("Multi-byte XOR: path not provided, skipping");
                    }
                }
            }
        }
    }

    // Extract IP addresses from connect() syscalls using radare2 (if enabled)
    if opts.use_r2 {
        if let Some(ref path) = opts.path {
            let connect_addrs = r2::extract_connect_addrs(path, data);
            if !connect_addrs.is_empty() {
                tracing::debug!(
                    "Found {} IP addresses from connect() calls",
                    connect_addrs.len()
                );
                strings.extend(connect_addrs);
            }
        }
    }

    // XOR string detection with auto-discovery
    // Try to auto-detect XOR key from extracted strings if XOR scanning is enabled
    if !data.is_empty() && opts.xor_scan {
        // Auto-detect XOR key from high-quality candidates in extracted strings
        if let Some((key, key_str, _key_offset)) = xor::auto_detect_xor_key(data, &strings, opts.xor_min_length) {
            tracing::info!("Auto-detected XOR key: '{}' (from extracted strings)", key_str);

            // Mark the key string as XorKey type if it exists in extracted strings
            if let Some(key_string) = strings.iter_mut().find(|s| s.value == key_str) {
                key_string.kind = StringKind::XorKey;
            }

            // Extract XOR strings with the detected key
            strings.extend(xor::extract_custom_xor_strings_with_hints(
                data,
                &key,
                opts.xor_min_length,
                None,
                opts.filter_garbage,
            ));
        }
    }

    // Enrich all strings with section information based on file offsets
    // This happens AFTER all extraction (including XOR) is complete
    match object {
        Object::Elf(elf) => enrich_elf_sections(&mut strings, elf),
        Object::Mach(goblin::mach::Mach::Binary(macho)) => {
            enrich_macho_sections(&mut strings, macho, 0)
        }
        Object::Mach(goblin::mach::Mach::Fat(fat)) => {
            // Collect architecture offsets first
            let arch_offsets: Vec<u64> = fat
                .iter_arches()
                .filter_map(|r| r.ok())
                .map(|a| u64::from(a.offset))
                .collect();

            // Enrich strings against each architecture
            for (macho_result, base_offset) in fat.into_iter().zip(arch_offsets) {
                if let Ok(goblin::mach::SingleArch::MachO(macho)) = macho_result {
                    enrich_macho_sections(&mut strings, &macho, base_offset);
                }
            }
        }
        Object::PE(pe) => enrich_pe_sections(&mut strings, pe),
        _ => {}
    }

    // Decode encoded strings (base64, hex, URL-encoding, unicode escapes)
    // This happens BEFORE garbage filtering so we can decode potentially-garbage-looking encodings
    let mut decoded = Vec::new();
    decoded.extend(decoders::decode_base64_strings(&strings));
    decoded.extend(decoders::decode_hex_strings(&strings));
    decoded.extend(decoders::decode_url_strings(&strings));
    decoded.extend(decoders::decode_unicode_escape_strings(&strings));

    // Add decoded strings to the main list
    strings.extend(decoded);

    // Apply garbage filter if enabled (but never filter entitlements XML, section names, or encoded strings)
    if opts.filter_garbage {
        strings.retain(|s| {
            s.kind == StringKind::EntitlementsXml
                || s.kind == StringKind::Section
                || s.kind == StringKind::Base64
                || s.kind == StringKind::HexEncoded
                || s.kind == StringKind::UrlEncoded
                || s.kind == StringKind::UnicodeEscaped
                || !validation::is_garbage(&s.value)
        });
    }

    deduplicate_by_offset(strings)
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
    } else if binary::macho_is_rust(macho) {
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
    for s in &mut strings {
        if let Some(&(kind, lib)) = import_map.get(s.value.as_str()) {
            s.kind = *kind;
            s.library = lib.map(std::string::ToString::to_string);
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

    // Apply garbage filter if enabled (but never filter entitlements XML, section names, or encoded strings)
    if opts.filter_garbage {
        strings.retain(|s| {
            s.kind == StringKind::EntitlementsXml
                || s.kind == StringKind::Section
                || s.kind == StringKind::Base64
                || s.kind == StringKind::HexEncoded
                || s.kind == StringKind::UrlEncoded
                || s.kind == StringKind::UnicodeEscaped
                || !validation::is_garbage(&s.value)
        });
    }

    strings
}

/// Extract entitlements XML from Mach-O code signature.
///
/// Returns the raw XML plist from `LC_CODE_SIGNATURE` if present.
#[allow(dead_code)]
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
    for s in &mut strings {
        if let Some(&(kind, lib)) = import_map.get(s.value.as_str()) {
            s.kind = *kind;
            s.library = lib.map(std::string::ToString::to_string);
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

    // Apply garbage filter if enabled (but never filter entitlements XML, section names, or encoded strings)
    if opts.filter_garbage {
        strings.retain(|s| {
            s.kind == StringKind::EntitlementsXml
                || s.kind == StringKind::Section
                || s.kind == StringKind::Base64
                || s.kind == StringKind::HexEncoded
                || s.kind == StringKind::UrlEncoded
                || s.kind == StringKind::UnicodeEscaped
                || !validation::is_garbage(&s.value)
        });
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

    // Apply garbage filter if enabled (but never filter entitlements XML, section names, or encoded strings)
    if opts.filter_garbage {
        strings.retain(|s| {
            s.kind == StringKind::EntitlementsXml
                || s.kind == StringKind::Section
                || s.kind == StringKind::Base64
                || s.kind == StringKind::HexEncoded
                || s.kind == StringKind::UrlEncoded
                || s.kind == StringKind::UnicodeEscaped
                || !validation::is_garbage(&s.value)
        });
    }

    strings
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
