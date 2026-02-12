//! stng - Language-aware string extraction CLI
//!
//! Extract strings from Go and Rust binaries with proper boundary detection.

use anyhow::Result;
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use clap::Parser;
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::fs;
use std::io::{self, IsTerminal};
use std::path::Path;
use stng::{Severity, StringKind};

#[derive(Parser, Debug)]
#[command(name = "stng")]
#[command(
    author,
    version,
    about = "Security-focused string extraction for binary analysis"
)]
#[command(long_about = "
stng extracts and classifies strings from binaries with a focus on
security research. It highlights IOCs like IPs, URLs, shell commands,
and suspicious paths while filtering noise. XOR-encoded strings are
detected by default.

EXAMPLES:
    stng malware.elf                            # Full analysis with single-byte XOR detection
    stng -i malware.elf                         # Filter out raw scan noise
    stng --xor 0xAB malware.elf                 # Decode with custom hex XOR key
    stng --xor \"secretkey\" malware.elf          # Decode with string XOR key
    stng --xorscan malware.elf                  # Deep scan with multi-byte XOR (slow, requires r2/rizin)
    stng --no-xor malware.elf                   # Disable all XOR detection
    stng --debug malware.elf                    # Show debug logging
    stng --json malware.elf                     # JSON output for tooling
")]
struct Cli {
    /// Target binary file to analyze
    #[arg(required = true)]
    target: String,

    /// Minimum string length to extract
    #[arg(short = 'm', long, default_value = "4")]
    min_length: usize,

    /// Output as JSON
    #[arg(long)]
    json: bool,

    /// Simple output (one string per line, no columns)
    #[arg(long)]
    simple: bool,

    /// Show detected language and exit
    #[arg(long)]
    detect: bool,

    /// Don't group by section (flat output)
    #[arg(long)]
    flat: bool,

    /// Show unfiltered results including garbage/noise
    #[arg(long)]
    unfiltered: bool,

    /// Use radare2 for extraction (auto-detected by default)
    #[arg(long)]
    r2: bool,

    /// Disable radare2 even if installed
    #[arg(long)]
    no_r2: bool,

    /// Disable colored output
    #[arg(long)]
    no_color: bool,

    /// Filter out raw scan noise (keep structured, r2, and symbol data)
    #[arg(short = 'i', long)]
    interesting: bool,

    /// Disable XOR-encoded string detection
    #[arg(long)]
    no_xor: bool,

    /// Custom XOR key (hex bytes like "0xABCD" or plain string)
    #[arg(long)]
    xor: Option<String>,

    /// Minimum length for XOR-decoded strings
    #[arg(long, default_value = "10")]
    xor_min_length: usize,

    /// Enable advanced XOR scanning with radare2/rizin (slow but finds multi-byte keys)
    #[arg(long)]
    xorscan: bool,

    /// Disable radare2/rizin result caching
    #[arg(long)]
    no_cache: bool,

    /// Clear cached r2 results for this file before analysis
    #[arg(long)]
    flush_cache: bool,

    /// Enable debug logging
    #[arg(long)]
    debug: bool,
}

// ANSI color codes
const RESET: &str = "\x1b[0m";
const BOLD: &str = "\x1b[1m";
const DIM: &str = "\x1b[2m";
const RED: &str = "\x1b[31m"; // Dark red text
const CYAN: &str = "\x1b[36m"; // For medium severity items
const GREEN: &str = "\x1b[32m";
const BRIGHT_YELLOW: &str = "\x1b[93m"; // For XOR-decoded/decrypted content (stands out)

/// Parse XOR key from command line (hex bytes or plain string)
fn parse_xor_key(input: &str) -> Result<Vec<u8>> {
    // Check if it's hex format (0x... or just hex digits)
    let hex_input = if let Some(stripped) = input.strip_prefix("0x") {
        stripped
    } else if input.chars().all(|c| c.is_ascii_hexdigit()) && input.len().is_multiple_of(2) {
        input
    } else {
        // Plain string - convert to bytes
        return Ok(input.as_bytes().to_vec());
    };

    // Parse hex bytes
    let mut bytes = Vec::new();
    for chunk in hex_input.as_bytes().chunks(2) {
        if chunk.len() != 2 {
            anyhow::bail!("Invalid hex string: must have even number of hex digits");
        }
        let hex_str = std::str::from_utf8(chunk)?;
        let byte = u8::from_str_radix(hex_str, 16)
            .map_err(|e| anyhow::anyhow!("Invalid hex byte '{hex_str}': {e}"))?;
        bytes.push(byte);
    }

    if bytes.is_empty() {
        anyhow::bail!("XOR key cannot be empty");
    }

    Ok(bytes)
}

/// Get binary format and architecture string (e.g., "ELF arm32", "PE x64", "Mach-O arm64")
fn get_binary_format(data: &[u8]) -> String {
    use stng::goblin::Object;

    match Object::parse(data) {
        Ok(Object::Elf(elf)) => {
            let arch = match elf.header.e_machine {
                stng::goblin::elf::header::EM_X86_64 => "x64",
                stng::goblin::elf::header::EM_386 => "x86",
                stng::goblin::elf::header::EM_AARCH64 => "arm64",
                stng::goblin::elf::header::EM_ARM => "arm32",
                stng::goblin::elf::header::EM_MIPS => "mips",
                stng::goblin::elf::header::EM_PPC => "ppc",
                stng::goblin::elf::header::EM_PPC64 => "ppc64",
                stng::goblin::elf::header::EM_RISCV => "riscv",
                stng::goblin::elf::header::EM_S390 => "s390x",
                _ => "unknown",
            };
            format!("ELF {arch}")
        }
        Ok(Object::PE(pe)) => {
            let arch = match pe.header.coff_header.machine {
                stng::goblin::pe::header::COFF_MACHINE_X86_64 => "x64",
                stng::goblin::pe::header::COFF_MACHINE_X86 => "x86",
                stng::goblin::pe::header::COFF_MACHINE_ARM64 => "arm64",
                stng::goblin::pe::header::COFF_MACHINE_ARMNT => "arm32",
                _ => "unknown",
            };
            format!("PE {arch}")
        }
        Ok(Object::Mach(stng::goblin::mach::Mach::Binary(macho))) => {
            let arch = match macho.header.cputype() {
                stng::goblin::mach::cputype::CPU_TYPE_X86_64 => "x64",
                stng::goblin::mach::cputype::CPU_TYPE_X86 => "x86",
                stng::goblin::mach::cputype::CPU_TYPE_ARM64 => "arm64",
                stng::goblin::mach::cputype::CPU_TYPE_ARM => "arm32",
                stng::goblin::mach::cputype::CPU_TYPE_POWERPC => "ppc",
                stng::goblin::mach::cputype::CPU_TYPE_POWERPC64 => "ppc64",
                _ => "unknown",
            };
            format!("Mach-O {arch}")
        }
        Ok(Object::Mach(stng::goblin::mach::Mach::Fat(_))) => "Mach-O fat".to_string(),
        _ => "unknown".to_string(),
    }
}

/// Decode Unicode escape sequences from a string
fn decode_unicode_escapes(s: &str) -> Vec<u8> {
    let mut result = Vec::new();
    let mut chars = s.chars();

    while let Some(c) = chars.next() {
        if c == '\\' {
            if let Some(next) = chars.next() {
                match next {
                    // \xXX format (2 hex digits)
                    'x' => {
                        let hex: String = chars.by_ref().take(2).collect();
                        if hex.len() == 2 {
                            if let Ok(byte) = u8::from_str_radix(&hex, 16) {
                                result.push(byte);
                                continue;
                            }
                        }
                        // Failed to parse, add literal characters
                        result.push(b'\\');
                        result.push(b'x');
                        result.extend(hex.as_bytes());
                    }
                    // \uXXXX format (4 hex digits)
                    'u' => {
                        let hex: String = chars.by_ref().take(4).collect();
                        if hex.len() == 4 {
                            if let Ok(codepoint) = u16::from_str_radix(&hex, 16) {
                                // Convert to UTF-8
                                if let Some(ch) = char::from_u32(codepoint as u32) {
                                    let mut buf = [0u8; 4];
                                    let encoded = ch.encode_utf8(&mut buf);
                                    result.extend_from_slice(encoded.as_bytes());
                                    continue;
                                }
                            }
                        }
                        // Failed to parse, add literal characters
                        result.push(b'\\');
                        result.push(b'u');
                        result.extend(hex.as_bytes());
                    }
                    // Other escape sequences - just add as-is
                    _ => {
                        result.push(b'\\');
                        result.push(next as u8);
                    }
                }
            } else {
                result.push(b'\\');
            }
        } else {
            // Regular character
            result.push(c as u8);
        }
    }

    result
}

/// Decode URL-encoded string (%XX format)
fn decode_url_encoding(s: &str) -> Vec<u8> {
    let mut result = Vec::new();
    let mut chars = s.chars();

    while let Some(c) = chars.next() {
        if c == '%' {
            // Try to read two hex digits
            let hex: String = chars.by_ref().take(2).collect();
            if hex.len() == 2 {
                if let Ok(byte) = u8::from_str_radix(&hex, 16) {
                    result.push(byte);
                    continue;
                }
            }
            // Failed to parse, add literal characters
            result.push(b'%');
            result.extend(hex.as_bytes());
        } else if c == '+' {
            // In URL encoding, + represents space
            result.push(b' ');
        } else {
            // Regular character
            result.push(c as u8);
        }
    }

    result
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    // Initialize tracing (modern structured logging)
    if cli.debug {
        tracing_subscriber::fmt()
            .with_max_level(tracing::Level::DEBUG)
            .with_target(false)
            .init();
    } else {
        tracing_subscriber::fmt()
            .with_max_level(tracing::Level::WARN)
            .with_target(false)
            .init();
    }

    // Handle cache flushing if requested
    if cli.flush_cache {
        if let Err(e) = stng::r2::flush_cache(&cli.target) {
            eprintln!("Warning: failed to flush cache: {}", e);
        }
    }

    let path = Path::new(&cli.target);
    if !path.exists() {
        anyhow::bail!("File does not exist: {}", cli.target);
    }

    let data = fs::read(path)?;

    // Handle --detect flag
    if cli.detect {
        let lang = stng::detect_language(&data);
        println!("{lang}");
        return Ok(());
    }

    // Handle text files by extracting and classifying strings from lines
    if stng::is_text_file(&data) {
        let content = String::from_utf8_lossy(&data);
        let mut strings: Vec<stng::ExtractedString> = content
            .lines()
            .enumerate()
            .filter_map(|(idx, line)| {
                let trimmed = line.trim();
                if trimmed.len() >= cli.min_length {
                    Some(stng::ExtractedString {
                        value: trimmed.to_string(),
                        data_offset: idx as u64,
                        section: None,
                        method: stng::StringMethod::RawScan,
                        kind: stng::classify_string(trimmed),
                        library: None,
                        fragments: None,
                        section_size: None,
                        section_executable: None,
                        section_writable: None,
                        architecture: None,
                        function_meta: None,
                    })
                } else {
                    None
                }
            })
            .collect();

        // Decode encoded strings (base64, hex, URL-encoding, unicode escapes)
        let mut decoded = Vec::new();
        decoded.extend(stng::decoders::decode_base64_strings(&strings));
        decoded.extend(stng::decoders::decode_hex_strings(&strings));
        decoded.extend(stng::decoders::decode_url_strings(&strings));
        decoded.extend(stng::decoders::decode_unicode_escape_strings(&strings));
        strings.extend(decoded);

        // Jump to output section
        if strings.is_empty() {
            if !cli.json {
                eprintln!("No strings found in {}", cli.target);
            }
            return Ok(());
        }

        // Continue to normal output handling below
        let use_color = !cli.no_color && !cli.json && io::stdout().is_terminal();
        if cli.json {
            println!("{}", serde_json::to_string_pretty(&strings)?);
            return Ok(());
        }

        // Sort and display
        strings.sort_by(|a, b| {
            b.kind
                .severity()
                .cmp(&a.kind.severity())
                .then_with(|| a.value.cmp(&b.value))
        });

        for s in &strings {
            print_string_line(s, use_color);
        }

        return Ok(());
    }

    // Determine whether to use radare2
    // Note: R2 module now handles large files intelligently (symbols only, no slow string scan)
    let use_r2 = if cli.no_r2 {
        false
    } else if cli.r2 {
        true
    } else {
        stng::r2::is_available()
    };

    // Extract strings with options
    let mut opts = stng::ExtractOptions::new(cli.min_length)
        .with_garbage_filter(!cli.unfiltered)
        .with_cache(!cli.no_cache);

    if use_r2 {
        opts = opts.with_r2(&cli.target);
    }

    // Handle custom XOR key if provided
    let custom_xor_key: Option<Vec<u8>> = if let Some(ref xor_key_str) = cli.xor {
        let xor_key = parse_xor_key(xor_key_str)?;
        opts = opts.with_xor_key(xor_key.clone());
        Some(xor_key)
    } else if !cli.no_xor {
        // Auto-detection mode
        opts = opts.with_xor(Some(cli.xor_min_length));
        if cli.xorscan {
            opts = opts.with_xorscan(true);
        }
        None
    } else {
        None
    };

    // Show brief status message only if we'll actually scan (file is within size limits)
    if !cli.no_xor && !cli.debug && io::stderr().is_terminal() && data.len() <= stng::xor::MAX_XOR_SCAN_SIZE {
        eprintln!("Scanning file for encoded material...");
    }

    let mut strings = stng::extract_strings_with_options(&data, &opts);

    // Detect overlay for display purposes (even if no strings found)
    let overlay_info = stng::detect_elf_overlay(&data);

    // Deduplicate: when multiple strings at same offset, keep only the longest
    use std::collections::HashMap;
    let mut offset_map: HashMap<u64, Vec<usize>> = HashMap::new();
    for (idx, s) in strings.iter().enumerate() {
        offset_map.entry(s.data_offset).or_default().push(idx);
    }

    let mut keep_indices = HashSet::new();
    for indices in offset_map.values() {
        if indices.len() == 1 {
            keep_indices.insert(indices[0]);
        } else {
            // Multiple strings at same offset - keep the longest
            let longest_idx = indices
                .iter()
                .max_by_key(|&&idx| strings[idx].value.len())
                .copied()
                .unwrap();
            keep_indices.insert(longest_idx);
        }
    }

    let mut idx = 0;
    strings.retain(|_| {
        let keep = keep_indices.contains(&idx);
        idx += 1;
        keep
    });

    // Deduplicate by value
    let mut seen_values: HashSet<String> = HashSet::new();
    strings.retain(|s| {
        let normalized: String = s
            .value
            .trim()
            .trim_end_matches(|c: char| c.is_control())
            .to_string();
        seen_values.insert(normalized)
    });

    // Filter out raw scan noise if --interesting
    if cli.interesting {
        strings.retain(|s| s.method != stng::StringMethod::RawScan);
    }

    // Determine if we should use colors
    let use_color = !cli.no_color && !cli.json && io::stdout().is_terminal();

    // Output results
    if cli.json {
        println!("{}", serde_json::to_string_pretty(&strings)?);
    } else if cli.simple {
        for s in &strings {
            println!("{}", s.value.trim_end_matches(|c: char| c.is_control()));
        }
        eprintln!("\n{} strings extracted", strings.len());
    } else {
        if strings.is_empty() {
            println!("No strings found in {}", cli.target);
            return Ok(());
        }

        // Print header with format info
        let filename = path.file_name().unwrap_or_default().to_string_lossy();
        let format = get_binary_format(&data);
        let size = data.len();
        let mut hasher = Sha256::new();
        hasher.update(&data);
        let hash = format!("{:x}", hasher.finalize());

        // Format custom XOR key for display
        // Check for XOR key (custom or auto-detected)
        let xor_key_display = if let Some(ref key) = custom_xor_key {
            // Custom XOR key from --xor flag
            format!(" · xor:{}", String::from_utf8_lossy(key))
        } else if let Some(xor_key_str) = strings.iter().find(|s| s.kind == StringKind::XorKey) {
            // Auto-detected XOR key
            format!(" · xor:{}", xor_key_str.value)
        } else {
            String::new()
        };

        if use_color {
            println!(
                "{}{}{} · {} · {} bytes · {} strings · {}{}{}",
                BOLD,
                DIM,
                filename,
                format,
                size,
                strings.len(),
                hash,
                xor_key_display,
                RESET
            );
        } else {
            println!(
                "{} · {} · {} bytes · {} strings · {}{}",
                filename,
                format,
                size,
                strings.len(),
                hash,
                xor_key_display
            );
        }
        println!();

        // Sort by section (in file offset order), then by offset within section
        // In --flat mode, sort purely by offset for raw file order
        if cli.flat {
            strings.sort_by_key(|s| s.data_offset);
        } else {
            // Build section order map based on minimum offset per section
            let mut section_min_offset: std::collections::HashMap<Option<String>, u64> =
                std::collections::HashMap::new();
            for s in &strings {
                let section = s.section.clone();
                section_min_offset
                    .entry(section)
                    .and_modify(|min| *min = (*min).min(s.data_offset))
                    .or_insert(s.data_offset);
            }

            // Sort by section's minimum offset, then by string offset within section
            strings.sort_by(|a, b| {
                let a_section_offset = section_min_offset.get(&a.section).copied().unwrap_or(u64::MAX);
                let b_section_offset = section_min_offset.get(&b.section).copied().unwrap_or(u64::MAX);
                a_section_offset
                    .cmp(&b_section_offset)
                    .then(a.data_offset.cmp(&b.data_offset))
            });
        }

        // Build section metadata map directly from binary format
        let section_metadata: std::collections::HashMap<String, String> = {
            use goblin::Object;
            match Object::parse(&data) {
                Ok(Object::PE(pe)) => {
                    use stng::binary::collect_pe_section_info;
                    let info = collect_pe_section_info(&pe);
                    info.into_iter()
                        .map(|(name, si)| {
                            let type_str = match (si.is_executable, si.is_writable) {
                                (true, true) => "TEXT+DATA",
                                (true, false) => "TEXT",
                                (false, true) => "DATA",
                                (false, false) => "DATA",
                            };
                            let size_str = if si.size < 1024 {
                                format!("{}b", si.size)
                            } else if si.size < 1024 * 1024 {
                                format!("{:.1}kb", si.size as f64 / 1024.0)
                            } else {
                                format!("{:.1}mb", si.size as f64 / (1024.0 * 1024.0))
                            };
                            (name, format!("({}, {})", size_str, type_str))
                        })
                        .collect()
                }
                Ok(Object::Elf(elf)) => {
                    use stng::binary::collect_elf_section_info;
                    let info = collect_elf_section_info(&elf);
                    info.into_iter()
                        .map(|(name, si)| {
                            let type_str = match (si.is_executable, si.is_writable) {
                                (true, true) => "TEXT+DATA",
                                (true, false) => "TEXT",
                                (false, true) => "DATA",
                                (false, false) => "DATA",
                            };
                            let size_str = if si.size < 1024 {
                                format!("{}b", si.size)
                            } else if si.size < 1024 * 1024 {
                                format!("{:.1}kb", si.size as f64 / 1024.0)
                            } else {
                                format!("{:.1}mb", si.size as f64 / (1024.0 * 1024.0))
                            };
                            (name, format!("({}, {})", size_str, type_str))
                        })
                        .collect()
                }
                Ok(Object::Mach(goblin::mach::Mach::Binary(macho))) => {
                    use stng::binary::collect_macho_section_info;
                    let info = collect_macho_section_info(&macho);
                    info.into_iter()
                        .map(|(name, si)| {
                            let type_str = match (si.is_executable, si.is_writable) {
                                (true, true) => "TEXT+DATA",
                                (true, false) => "TEXT",
                                (false, true) => "DATA",
                                (false, false) => "DATA",
                            };
                            let size_str = if si.size < 1024 {
                                format!("{}b", si.size)
                            } else if si.size < 1024 * 1024 {
                                format!("{:.1}kb", si.size as f64 / 1024.0)
                            } else {
                                format!("{:.1}mb", si.size as f64 / (1024.0 * 1024.0))
                            };
                            (name, format!("({}, {})", size_str, type_str))
                        })
                        .collect()
                }
                _ => std::collections::HashMap::new(),
            }
        };

        // Use sentinel to detect first section (distinguishes from "no section yet" vs "section is None")
        let mut current_section: Option<Option<&str>> = None;
        let mut current_arch: Option<Option<&str>> = None;

        // Track section offsets (first string's offset in each section)
        let mut section_offsets: std::collections::HashMap<Option<String>, u64> = std::collections::HashMap::new();

        // Collect high-severity items for summary
        let mut notable: Vec<&stng::ExtractedString> = Vec::new();

        for s in &strings {
            let section = s.section.as_deref();
            let arch = s.architecture.as_deref();

            // Print section header when section or architecture changes
            // Track as tuple (section, arch) to detect when either changes
            let section_changed = current_section != Some(section);
            let arch_changed = current_arch != Some(arch);
            if !cli.flat && (section_changed || arch_changed) {
                if current_section.is_some() {
                    println!();
                }

                // Skip empty section names
                if let Some("") = section {
                    current_section = Some(section);
                    continue;
                }

                // Record offset for this section (first string's offset)
                let section_key = section.map(|s| s.to_string());
                section_offsets.entry(section_key.clone()).or_insert(s.data_offset);
                let section_offset = section_offsets.get(&section_key).copied().unwrap_or(0);

                let section_name = section.unwrap_or("(analysis)");

                // Build section header with optional architecture
                let mut section_header = if let Some(sect) = section {
                    // Try exact match first, then prefix match for section strings with trailing garbage
                    let metadata = section_metadata.get(sect)
                        .or_else(|| {
                            section_metadata.iter()
                                .find(|(k, _)| k.starts_with(sect) || sect.starts_with(k.as_str()))
                                .map(|(_, v)| v)
                        });

                    if let Some(meta) = metadata {
                        format!("{} {}", section_name, meta)
                    } else {
                        section_name.to_string()
                    }
                } else {
                    section_name.to_string()
                };

                // Add architecture if present (for fat binaries)
                if let Some(architecture) = arch {
                    section_header = format!("{} ({})", section_header, architecture);
                }

                let offset_str = format!("{:>8x}", section_offset);
                if use_color {
                    println!("{DIM}{} ── {} ──{RESET}", offset_str, section_header);
                } else {
                    println!("{} ── {} ──", offset_str, section_header);
                }
                current_section = Some(section);
                current_arch = Some(arch);
            }

            print_string_line(s, use_color);

            // Collect all high-severity items (we'll sort and truncate later)
            if s.kind.severity() == Severity::High {
                notable.push(s);
            }
        }

        // Show overlay section even if no printable strings were found
        if let Some(ref overlay) = overlay_info {
            let has_overlay_strings = strings
                .iter()
                .any(|s| s.section.as_deref() == Some("overlay"));

            if !has_overlay_strings && !cli.flat {
                // Overlay exists but no printable strings - show informational message
                if current_section.is_some() {
                    println!();
                }
                if use_color {
                    println!("{DIM}── overlay ──{RESET}");
                    println!(
                        "  {}{:>8x}{} {}{:<12}{} {}{} bytes (unprintable){}",
                        DIM, overlay.start_offset, RESET, DIM, "-", RESET, DIM, overlay.size, RESET
                    );
                } else {
                    println!("── overlay ──");
                    println!(
                        "  {:>8x} {:<12} {} bytes (unprintable)",
                        overlay.start_offset, "-", overlay.size
                    );
                }
            }
        }

        // Sort notable items by priority: IPs first, then shell/suspicious, then base64, then URLs
        notable.sort_by_key(|s| match s.kind {
            stng::StringKind::IP | stng::StringKind::IPPort => 0,
            stng::StringKind::ShellCmd | stng::StringKind::SuspiciousPath => 1,
            stng::StringKind::Base64 => 2,
            stng::StringKind::Overlay | stng::StringKind::OverlayWide => 3,
            stng::StringKind::Url => 4,
            _ => 5,
        });
        notable.truncate(8);

        // Print notable summary if there are high-severity items
        if !notable.is_empty() {
            println!();
            if use_color {
                println!("{RED}{BOLD}▌ Notable{RESET}");
            } else {
                println!("── Notable ──");
            }
            for s in notable {
                print_string_line(s, use_color);
            }
        }

        println!();
    }

    Ok(())
}

fn colorize_xml_line(line: &str) -> String {
    let mut output = line.to_string();

    // Colorize <key>...</key> content (entitlement names) in red
    if let Some(key_start) = output.find("<key>") {
        if let Some(key_end) = output.find("</key>") {
            let before = &output[..key_start + 5];
            let content = &output[key_start + 5..key_end];
            let after = &output[key_end..];
            output = format!("{before}{RED}{content}{RESET}{after}");
        }
    }

    // Colorize <string>...</string> content (values) in yellow
    if let Some(str_start) = output.find("<string>") {
        if let Some(str_end) = output.find("</string>") {
            let before = &output[..str_start + 8];
            let content = &output[str_start + 8..str_end];
            let after = &output[str_end..];
            output = format!("{before}{CYAN}{content}{RESET}{after}");
        }
    }

    output
}

#[allow(dead_code)]
fn print_colorized_entitlements(xml: &str, use_color: bool) {
    if !use_color {
        println!("{xml}");
        return;
    }

    // Colorize entitlement keys and values
    let mut output = xml.to_string();

    // Colorize <key>...</key> content (entitlement names) in red
    let key_pattern = "<key>";
    let key_end = "</key>";
    let mut result = String::new();
    let mut last_end = 0;

    while let Some(start) = output[last_end..].find(key_pattern) {
        let abs_start = last_end + start;
        result.push_str(&output[last_end..abs_start]);
        result.push_str(key_pattern);

        let content_start = abs_start + key_pattern.len();
        if let Some(end_pos) = output[content_start..].find(key_end) {
            let content_end = content_start + end_pos;
            result.push_str(&format!(
                "{}{}{}",
                RED,
                &output[content_start..content_end],
                RESET
            ));
            result.push_str(key_end);
            last_end = content_end + key_end.len();
        } else {
            result.push_str(&output[content_start..]);
            break;
        }
    }
    result.push_str(&output[last_end..]);

    // Colorize <string>...</string> content (values) in yellow
    output = result;
    result = String::new();
    last_end = 0;
    let string_pattern = "<string>";
    let string_end = "</string>";

    while let Some(start) = output[last_end..].find(string_pattern) {
        let abs_start = last_end + start;
        result.push_str(&output[last_end..abs_start]);
        result.push_str(string_pattern);

        let content_start = abs_start + string_pattern.len();
        if let Some(end_pos) = output[content_start..].find(string_end) {
            let content_end = content_start + end_pos;
            result.push_str(&format!(
                "{}{}{}",
                CYAN,
                &output[content_start..content_end],
                RESET
            ));
            result.push_str(string_end);
            last_end = content_end + string_end.len();
        } else {
            result.push_str(&output[content_start..]);
            break;
        }
    }
    result.push_str(&output[last_end..]);

    println!("{result}");
}

fn print_string_line(s: &stng::ExtractedString, use_color: bool) {
    // Special handling for multi-line entitlements XML
    if s.kind == stng::StringKind::EntitlementsXml {
        let kind_color = if use_color { CYAN } else { "" };
        let mut byte_offset = s.data_offset;

        // Print each line with its calculated offset
        for line in s.value.lines() {
            let offset = format!("{byte_offset:>8x}");

            if use_color {
                let colorized = colorize_xml_line(line);
                println!(
                    "  {}{}{} {}{:<12}{} {}",
                    DIM, offset, RESET, kind_color, "entitlement", RESET, colorized
                );
            } else {
                println!("  {} {:<12} {}", offset, "entitlement", line);
            }

            // Update offset for next line (line length + newline)
            byte_offset += line.len() as u64 + 1;
        }
        return;
    }

    // Special handling for multi-line XOR-decoded strings
    if s.method == stng::StringMethod::XorDecode && s.value.contains('\n') {
        let kind = format!("xor/{}", s.kind.short_name());
        // XOR-decoded content always uses bright yellow to stand out
        let (color, kind_color) = if use_color {
            (BRIGHT_YELLOW, BRIGHT_YELLOW)
        } else {
            ("", "")
        };

        let mut byte_offset = s.data_offset;

        // Print each line with its calculated offset
        for line in s.value.lines() {
            let offset = format!("{byte_offset:>8x}");
            let clean_line = line.trim_end_matches(|c: char| c.is_control());

            if use_color {
                println!(
                    "  {DIM}{offset}{RESET} {kind_color}{kind:<12}{RESET} {color}{clean_line}{RESET}"
                );
            } else {
                println!("  {offset} {kind:<12} {clean_line}");
            }

            // Update offset for next line (line length + newline)
            byte_offset += line.len() as u64 + 1;
        }
        return;
    }

    let offset = format!("{:>8x}", s.data_offset);

    // Build kind string with prefixes for special methods
    let kind = if s.method == stng::StringMethod::XorDecode {
        // XOR-decoded strings get "xor/" prefix
        format!("xor/{}", s.kind.short_name())
    } else if s.method == stng::StringMethod::WideString && s.kind != stng::StringKind::OverlayWide
    {
        // Wide strings get ":16LE" suffix
        format!("{}:16LE", s.kind.short_name())
    } else {
        s.kind.short_name().to_string()
    };

    // Get color based on method and severity
    let (color, kind_color) = if use_color {
        // XOR-decoded content always uses bright yellow to stand out
        if s.method == stng::StringMethod::XorDecode {
            (BRIGHT_YELLOW, BRIGHT_YELLOW)
        } else if s.kind == stng::StringKind::Section {
            // Section names are rarely interesting - show in dim grey
            (DIM, DIM)
        } else {
            match s.kind.severity() {
                Severity::High => (RED, RED),
                Severity::Medium => (CYAN, CYAN),
                Severity::Low => (GREEN, GREEN),
                Severity::Info => ("", DIM),
            }
        }
    } else {
        ("", "")
    };

    // Format the value, trimming control characters and truncating if very long
    let clean_value = s.value.trim_end_matches(|c: char| c.is_control());
    let mut value = if clean_value.chars().count() > 120 {
        let truncated: String = clean_value.chars().take(117).collect();
        format!("{truncated}...")
    } else {
        clean_value.to_string()
    };

    // Append section metadata if this is a section
    if let Some(metadata) = s.section_metadata_str() {
        value = format!("{} {}", value, metadata);
    }

    // Decode base64 strings and show plaintext/hex in brackets
    if s.kind == stng::StringKind::Base64 {
        if let Ok(decoded) = BASE64.decode(s.value.trim()) {
            if !decoded.is_empty() {
                let printable = decoded
                    .iter()
                    .filter(|&&b| b.is_ascii_graphic() || b.is_ascii_whitespace())
                    .count();

                // Show decoded content (text or hex)
                if printable > decoded.len() / 2 {
                    // Mostly printable - show as text
                    if let Ok(text) = String::from_utf8(decoded) {
                        let text = text.trim();
                        if !text.is_empty() {
                            if use_color {
                                value = format!("{value} {DIM}[{text}]{RESET}");
                            } else {
                                value = format!("{value} [{text}]");
                            }
                        }
                    }
                } else {
                    // Binary data - show as hex (especially useful for XOR-decoded base64)
                    let hex_preview = if decoded.len() <= 16 {
                        decoded
                            .iter()
                            .map(|b| format!("{b:02x}"))
                            .collect::<String>()
                    } else {
                        format!(
                            "{}...",
                            decoded[..16]
                                .iter()
                                .map(|b| format!("{b:02x}"))
                                .collect::<String>()
                        )
                    };
                    if use_color {
                        value = format!("{value} {DIM}[0x{hex_preview}]{RESET}");
                    } else {
                        value = format!("{value} [0x{hex_preview}]");
                    }
                }
            }
        }
    }

    // Decode hex-encoded strings
    if s.kind == stng::StringKind::HexEncoded {
        let decoded: Vec<u8> = (0..s.value.len())
            .step_by(2)
            .filter_map(|i| u8::from_str_radix(&s.value[i..i + 2], 16).ok())
            .collect();

        if !decoded.is_empty() {
            if let Ok(text) = String::from_utf8(decoded) {
                let text = text.trim();
                if !text.is_empty() {
                    if use_color {
                        value = format!("{value} {DIM}[{text}]{RESET}");
                    } else {
                        value = format!("{value} [{text}]");
                    }
                }
            }
        }
    }

    // Decode Unicode escape sequences
    if s.kind == stng::StringKind::UnicodeEscaped {
        let decoded = decode_unicode_escapes(&s.value);
        if !decoded.is_empty() {
            if let Ok(text) = String::from_utf8(decoded) {
                let text = text.trim();
                if !text.is_empty() {
                    if use_color {
                        value = format!("{value} {DIM}[{text}]{RESET}");
                    } else {
                        value = format!("{value} [{text}]");
                    }
                }
            }
        }
    }

    // Decode URL-encoded strings
    if s.kind == stng::StringKind::UrlEncoded {
        let decoded = decode_url_encoding(&s.value);
        if !decoded.is_empty() {
            if let Ok(text) = String::from_utf8(decoded) {
                let text = text.trim();
                if !text.is_empty() {
                    if use_color {
                        value = format!("{value} {DIM}[{text}]{RESET}");
                    } else {
                        value = format!("{value} [{text}]");
                    }
                }
            }
        }
    }

    // Add library info for imports (but not for custom XOR keys - those are shown in header)
    let display_value = if let Some(ref lib) = s.library {
        if s.method == stng::StringMethod::XorDecode {
            // For XOR-decoded strings:
            // - Custom keys (library starts with "key:"): don't show (displayed in header)
            // - Auto-detected keys (library starts with "0x"): show the key
            if lib.starts_with("key:") {
                // Custom XOR key - already shown in header, don't repeat
                value
            } else {
                // Auto-detected XOR key - show it
                if use_color {
                    format!("{value} {DIM}[{lib}]{RESET}")
                } else {
                    format!("{value} [{lib}]")
                }
            }
        } else {
            // For imports, show with arrow
            if use_color {
                format!("{value} {DIM}<- {lib}{RESET}")
            } else {
                format!("{value} <- {lib}")
            }
        }
    } else {
        value
    };

    // Add function metadata for interesting functions
    let display_value = if s.kind == stng::StringKind::FuncName {
        if let Some(ref meta) = s.function_meta {
            // Check if function is "interesting" - worth showing metadata
            let is_interesting = meta.basic_blocks >= 5  // Complex branching
                || meta.branches >= 3                     // Multiple branches
                || meta.size > 300                        // Large function
                || meta.noreturn == Some(true);           // Never returns

            if is_interesting {
                let mut metadata_parts = Vec::new();

                // Always show size and basic blocks for interesting functions
                metadata_parts.push(format!("{}b", meta.size));
                metadata_parts.push(format!("{}bb", meta.basic_blocks));

                // Show branches if any
                if meta.branches > 0 {
                    metadata_parts.push(format!("{}br", meta.branches));
                }

                // Show noreturn flag
                if meta.noreturn == Some(true) {
                    metadata_parts.push("noret".to_string());
                }

                let metadata_str = metadata_parts.join("·");
                if use_color {
                    format!("{display_value} {DIM}[{metadata_str}]{RESET}")
                } else {
                    format!("{display_value} [{metadata_str}]")
                }
            } else {
                display_value
            }
        } else {
            display_value
        }
    } else {
        display_value
    };

    if use_color {
        println!(
            "  {DIM}{offset}{RESET} {kind_color}{kind:<12}{RESET} {color}{display_value}{RESET}"
        );
    } else {
        println!("  {offset} {kind:<12} {display_value}");
    }
}
