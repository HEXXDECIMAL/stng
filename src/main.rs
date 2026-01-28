//! strangs - Language-aware string extraction CLI
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
use strangs::Severity;

#[derive(Parser, Debug)]
#[command(name = "strangs")]
#[command(
    author,
    version,
    about = "Security-focused string extraction for binary analysis"
)]
#[command(long_about = "
strangs extracts and classifies strings from binaries with a focus on
security research. It highlights IOCs like IPs, URLs, shell commands,
and suspicious paths while filtering noise. XOR-encoded strings are
detected by default.

EXAMPLES:
    strangs malware.elf              # Full analysis with XOR detection
    strangs -i malware.elf           # Filter out raw scan noise
    strangs --no-xor malware.elf     # Disable XOR detection
    strangs --json malware.elf       # JSON output for tooling
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

    /// Minimum length for XOR-decoded strings
    #[arg(long, default_value = "10")]
    xor_min_length: usize,
}

// ANSI color codes
const RESET: &str = "\x1b[0m";
const BOLD: &str = "\x1b[1m";
const DIM: &str = "\x1b[2m";
const RED: &str = "\x1b[31m"; // Dark red text
const YELLOW: &str = "\x1b[33m";
const GREEN: &str = "\x1b[32m";

/// Get binary format and architecture string (e.g., "ELF arm32", "PE x64", "Mach-O arm64")
fn get_binary_format(data: &[u8]) -> String {
    use strangs::goblin::Object;

    match Object::parse(data) {
        Ok(Object::Elf(elf)) => {
            let arch = match elf.header.e_machine {
                strangs::goblin::elf::header::EM_X86_64 => "x64",
                strangs::goblin::elf::header::EM_386 => "x86",
                strangs::goblin::elf::header::EM_AARCH64 => "arm64",
                strangs::goblin::elf::header::EM_ARM => "arm32",
                strangs::goblin::elf::header::EM_MIPS => "mips",
                strangs::goblin::elf::header::EM_PPC => "ppc",
                strangs::goblin::elf::header::EM_PPC64 => "ppc64",
                strangs::goblin::elf::header::EM_RISCV => "riscv",
                strangs::goblin::elf::header::EM_S390 => "s390x",
                _ => "unknown",
            };
            format!("ELF {}", arch)
        }
        Ok(Object::PE(pe)) => {
            let arch = match pe.header.coff_header.machine {
                strangs::goblin::pe::header::COFF_MACHINE_X86_64 => "x64",
                strangs::goblin::pe::header::COFF_MACHINE_X86 => "x86",
                strangs::goblin::pe::header::COFF_MACHINE_ARM64 => "arm64",
                strangs::goblin::pe::header::COFF_MACHINE_ARMNT => "arm32",
                _ => "unknown",
            };
            format!("PE {}", arch)
        }
        Ok(Object::Mach(strangs::goblin::mach::Mach::Binary(macho))) => {
            let arch = match macho.header.cputype() {
                strangs::goblin::mach::cputype::CPU_TYPE_X86_64 => "x64",
                strangs::goblin::mach::cputype::CPU_TYPE_X86 => "x86",
                strangs::goblin::mach::cputype::CPU_TYPE_ARM64 => "arm64",
                strangs::goblin::mach::cputype::CPU_TYPE_ARM => "arm32",
                strangs::goblin::mach::cputype::CPU_TYPE_POWERPC => "ppc",
                strangs::goblin::mach::cputype::CPU_TYPE_POWERPC64 => "ppc64",
                _ => "unknown",
            };
            format!("Mach-O {}", arch)
        }
        Ok(Object::Mach(strangs::goblin::mach::Mach::Fat(_))) => "Mach-O fat".to_string(),
        _ => "unknown".to_string(),
    }
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    let path = Path::new(&cli.target);
    if !path.exists() {
        anyhow::bail!("File does not exist: {}", cli.target);
    }

    let data = fs::read(path)?;

    // Handle --detect flag
    if cli.detect {
        let lang = strangs::detect_language(&data);
        println!("{}", lang);
        return Ok(());
    }

    // Handle text files like cat
    if strangs::is_text_file(&data) {
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
        strangs::r2::is_available()
    };

    // Extract strings with options
    let mut opts =
        strangs::ExtractOptions::new(cli.min_length).with_garbage_filter(!cli.unfiltered);

    if use_r2 {
        opts = opts.with_r2(&cli.target);
    }

    if !cli.no_xor {
        opts = opts.with_xor(Some(cli.xor_min_length));
    }

    let mut strings = strangs::extract_strings_with_options(&data, &opts);

    // Deduplicate
    let mut seen_at_offset: HashSet<(u64, String)> = HashSet::new();
    let mut seen_values: HashSet<String> = HashSet::new();
    strings.retain(|s| {
        let normalized: String = s
            .value
            .trim()
            .trim_end_matches(|c: char| c.is_control())
            .to_string();
        let key = (s.data_offset, normalized.clone());
        if !seen_at_offset.insert(key) {
            return false;
        }
        if !seen_values.insert(normalized) {
            return false;
        }
        true
    });

    // Filter out raw scan noise if --interesting
    if cli.interesting {
        strings.retain(|s| s.method != strangs::StringMethod::RawScan);
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

        if use_color {
            println!(
                "{}{}{} · {} · {} bytes · {} strings · {}{}",
                BOLD,
                DIM,
                filename,
                format,
                size,
                strings.len(),
                hash,
                RESET
            );
        } else {
            println!(
                "{} · {} · {} bytes · {} strings · {}",
                filename, format, size, strings.len(), hash
            );
        }
        println!();

        // Sort by section, then by offset (preserves file order)
        // When XOR scan is enabled, sort purely by offset to show XOR strings inline
        if !cli.no_xor {
            strings.sort_by_key(|s| s.data_offset);
        } else {
            strings.sort_by(|a, b| match (&a.section, &b.section) {
                (Some(sa), Some(sb)) => sa.cmp(sb).then(a.data_offset.cmp(&b.data_offset)),
                (Some(_), None) => std::cmp::Ordering::Less,
                (None, Some(_)) => std::cmp::Ordering::Greater,
                (None, None) => a.data_offset.cmp(&b.data_offset),
            });
        }

        let mut current_section: Option<&str> = None;

        // Collect high-severity items for summary
        let mut notable: Vec<&strangs::ExtractedString> = Vec::new();

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
            strangs::StringKind::IP | strangs::StringKind::IPPort => 0,
            strangs::StringKind::ShellCmd | strangs::StringKind::SuspiciousPath => 1,
            strangs::StringKind::Base64 => 2,
            strangs::StringKind::Overlay | strangs::StringKind::OverlayWide => 3,
            strangs::StringKind::Url => 4,
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
            output = format!("{}{}{}{}{}", before, YELLOW, content, RESET, after);
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
            result.push_str(&format!("{}{}{}", RED, &output[content_start..content_end], RESET));
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
            result.push_str(&format!("{}{}{}", YELLOW, &output[content_start..content_end], RESET));
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

fn print_string_line(s: &strangs::ExtractedString, use_color: bool) {
    // Special handling for multi-line entitlements XML
    if s.kind == strangs::StringKind::EntitlementsXml {
        let kind_color = if use_color { YELLOW } else { "" };
        let mut byte_offset = s.data_offset;

        // Print each line with its calculated offset
        for line in s.value.lines() {
            let offset = format!("{:>8x}", byte_offset);

            if use_color {
                let colorized = colorize_xml_line(line);
                println!("  {}{}{} {}{:<12}{} {}", DIM, offset, RESET, kind_color, "entitlements", RESET, colorized);
            } else {
                println!("  {} {:<12} {}", offset, "entitlements", line);
            }

            // Update offset for next line (line length + newline)
            byte_offset += line.len() as u64 + 1;
        }
        return;
    }

    let offset = format!("{:>8x}", s.data_offset);

    // Show encoding suffix for wide strings (except overlay:16LE which already has it)
    let kind = if s.method == strangs::StringMethod::WideString
        && s.kind != strangs::StringKind::OverlayWide
    {
        format!("{}:16LE", s.kind.short_name())
    } else {
        s.kind.short_name().to_string()
    };

    // Get color based on severity
    let (color, kind_color) = if use_color {
        match s.kind.severity() {
            Severity::High => (RED, RED),
            Severity::Medium => (YELLOW, YELLOW),
            Severity::Low => (GREEN, GREEN),
            Severity::Info => ("", DIM),
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

    // Decode base64 strings and show plaintext in brackets if printable
    if s.kind == strangs::StringKind::Base64 {
        if let Ok(decoded) = BASE64.decode(s.value.trim()) {
            // Only show if mostly printable ASCII
            let printable = decoded
                .iter()
                .filter(|&&b| b.is_ascii_graphic() || b.is_ascii_whitespace())
                .count();
            if printable > decoded.len() / 2 && !decoded.is_empty() {
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
            }
        }
    }

    // Add library info for imports
    let display_value = if let Some(ref lib) = s.library {
        if use_color {
            format!("{} {}<- {}{}", value, DIM, lib, RESET)
        } else {
            format!("{} <- {}", value, lib)
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
