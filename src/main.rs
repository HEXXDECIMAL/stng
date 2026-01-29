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
            .map_err(|e| anyhow::anyhow!("Invalid hex byte '{}': {}", hex_str, e))?;
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
            format!("ELF {}", arch)
        }
        Ok(Object::PE(pe)) => {
            let arch = match pe.header.coff_header.machine {
                stng::goblin::pe::header::COFF_MACHINE_X86_64 => "x64",
                stng::goblin::pe::header::COFF_MACHINE_X86 => "x86",
                stng::goblin::pe::header::COFF_MACHINE_ARM64 => "arm64",
                stng::goblin::pe::header::COFF_MACHINE_ARMNT => "arm32",
                _ => "unknown",
            };
            format!("PE {}", arch)
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
            format!("Mach-O {}", arch)
        }
        Ok(Object::Mach(stng::goblin::mach::Mach::Fat(_))) => "Mach-O fat".to_string(),
        _ => "unknown".to_string(),
    }
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

    let path = Path::new(&cli.target);
    if !path.exists() {
        anyhow::bail!("File does not exist: {}", cli.target);
    }

    let data = fs::read(path)?;

    // Handle --detect flag
    if cli.detect {
        let lang = stng::detect_language(&data);
        println!("{}", lang);
        return Ok(());
    }

    // Handle text files like cat
    if stng::is_text_file(&data) {
        let content = String::from_utf8_lossy(&data);
        print!("{}", content);
        return Ok(());
    }

    // Determine whether to use radare2
    let use_r2 = if cli.no_r2 {
        false
    } else if cli.r2 {
        true
    } else {
        stng::r2::is_available()
    };

    // Extract strings with options
    let mut opts =
        stng::ExtractOptions::new(cli.min_length).with_garbage_filter(!cli.unfiltered);

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

    let mut strings = stng::extract_strings_with_options(&data, &opts);

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

        // Sort by section, then by offset (preserves file order)
        // When XOR scan is enabled, sort purely by offset to show XOR strings inline
        if cli.no_xor {
            strings.sort_by(|a, b| match (&a.section, &b.section) {
                (Some(sa), Some(sb)) => sa.cmp(sb).then(a.data_offset.cmp(&b.data_offset)),
                (Some(_), None) => std::cmp::Ordering::Less,
                (None, Some(_)) => std::cmp::Ordering::Greater,
                (None, None) => a.data_offset.cmp(&b.data_offset),
            });
        } else {
            strings.sort_by_key(|s| s.data_offset);
        }

        let mut current_section: Option<&str> = None;

        // Collect high-severity items for summary
        let mut notable: Vec<&stng::ExtractedString> = Vec::new();

        for s in &strings {
            let section = s.section.as_deref();

            // Print section header when section changes
            // Skip section headers when XOR scan is enabled (sorted by offset, not section)
            if !cli.flat && cli.no_xor && section != current_section {
                if current_section.is_some() {
                    println!();
                }
                let section_name = section.unwrap_or("(unknown)");
                if use_color {
                    println!("{}── {} ──{}", DIM, section_name, RESET);
                } else {
                    println!("── {} ──", section_name);
                }
                current_section = section;
            }

            print_string_line(s, use_color);

            // Collect all high-severity items (we'll sort and truncate later)
            if s.kind.severity() == Severity::High {
                notable.push(s);
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
                println!("{}{}▌ Notable{}", RED, BOLD, RESET);
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
            output = format!("{}{}{}{}{}", before, RED, content, RESET, after);
        }
    }

    // Colorize <string>...</string> content (values) in yellow
    if let Some(str_start) = output.find("<string>") {
        if let Some(str_end) = output.find("</string>") {
            let before = &output[..str_start + 8];
            let content = &output[str_start + 8..str_end];
            let after = &output[str_end..];
            output = format!("{}{}{}{}{}", before, CYAN, content, RESET, after);
        }
    }

    output
}

#[allow(dead_code)]
fn print_colorized_entitlements(xml: &str, use_color: bool) {
    if !use_color {
        println!("{}", xml);
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

    println!("{}", result);
}

fn print_string_line(s: &stng::ExtractedString, use_color: bool) {
    // Special handling for multi-line entitlements XML
    if s.kind == stng::StringKind::EntitlementsXml {
        let kind_color = if use_color { CYAN } else { "" };
        let mut byte_offset = s.data_offset;

        // Print each line with its calculated offset
        for line in s.value.lines() {
            let offset = format!("{:>8x}", byte_offset);

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
            let offset = format!("{:>8x}", byte_offset);
            let clean_line = line.trim_end_matches(|c: char| c.is_control());

            if use_color {
                println!(
                    "  {}{}{} {}{:<12}{} {}{}{}",
                    DIM, offset, RESET, kind_color, kind, RESET, color, clean_line, RESET
                );
            } else {
                println!("  {} {:<12} {}", offset, kind, clean_line);
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
    } else if s.method == stng::StringMethod::WideString
        && s.kind != stng::StringKind::OverlayWide
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
        format!("{}...", truncated)
    } else {
        clean_value.to_string()
    };

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
                                value = format!("{} {}[{}]{}", value, DIM, text, RESET);
                            } else {
                                value = format!("{} [{}]", value, text);
                            }
                        }
                    }
                } else {
                    // Binary data - show as hex (especially useful for XOR-decoded base64)
                    let hex_preview = if decoded.len() <= 16 {
                        decoded.iter().map(|b| format!("{:02x}", b)).collect::<String>()
                    } else {
                        format!("{}...", decoded[..16].iter().map(|b| format!("{:02x}", b)).collect::<String>())
                    };
                    if use_color {
                        value = format!("{} {}[0x{}]{}", value, DIM, hex_preview, RESET);
                    } else {
                        value = format!("{} [0x{}]", value, hex_preview);
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
                    format!("{} {}[{}]{}", value, DIM, lib, RESET)
                } else {
                    format!("{} [{}]", value, lib)
                }
            }
        } else {
            // For imports, show with arrow
            if use_color {
                format!("{} {}<- {}{}", value, DIM, lib, RESET)
            } else {
                format!("{} <- {}", value, lib)
            }
        }
    } else {
        value
    };

    if use_color {
        println!(
            "  {}{}{} {}{:<12}{} {}{}{}",
            DIM, offset, RESET, kind_color, kind, RESET, color, display_value, RESET
        );
    } else {
        println!("  {} {:<12} {}", offset, kind, display_value);
    }
}
