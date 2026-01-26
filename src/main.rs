//! strangs - Language-aware string extraction CLI
//!
//! Extract strings from Go and Rust binaries with proper boundary detection.

use anyhow::Result;
use clap::Parser;
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
and suspicious paths while filtering noise.

EXAMPLES:
    strangs malware.elf              # Full analysis with colors
    strangs -i malware.elf           # Filter out raw scan noise
    strangs --json malware.elf       # JSON output for tooling
    strangs --no-color malware.elf   # Plain text output
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
}

// ANSI color codes
const RESET: &str = "\x1b[0m";
const BOLD: &str = "\x1b[1m";
const DIM: &str = "\x1b[2m";
const RED: &str = "\x1b[31m"; // Dark red text
const YELLOW: &str = "\x1b[33m";
const GREEN: &str = "\x1b[32m";

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
            println!("{}", s.value);
        }
        eprintln!("\n{} strings extracted", strings.len());
    } else {
        if strings.is_empty() {
            println!("No strings found in {}", cli.target);
            return Ok(());
        }

        // Print header
        let filename = path.file_name().unwrap_or_default().to_string_lossy();
        if use_color {
            println!(
                "{}{}  {} strings from {}{}",
                BOLD,
                DIM,
                strings.len(),
                filename,
                RESET
            );
        } else {
            println!("  {} strings from {}", strings.len(), filename);
        }
        println!();

        // Sort by section, then by offset (preserves file order)
        strings.sort_by(|a, b| match (&a.section, &b.section) {
            (Some(sa), Some(sb)) => sa.cmp(sb).then(a.data_offset.cmp(&b.data_offset)),
            (Some(_), None) => std::cmp::Ordering::Less,
            (None, Some(_)) => std::cmp::Ordering::Greater,
            (None, None) => a.data_offset.cmp(&b.data_offset),
        });

        let mut current_section: Option<&str> = None;

        // Collect high-severity items for summary
        let mut notable: Vec<&strangs::ExtractedString> = Vec::new();

        for s in &strings {
            let section = s.section.as_deref();

            // Print section header when section changes
            if !cli.flat && section != current_section {
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

            // Track high-severity items for summary
            if s.kind.severity() == Severity::High && notable.len() < 5 {
                notable.push(s);
            }
        }

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

fn print_string_line(s: &strangs::ExtractedString, use_color: bool) {
    let offset = format!("{:>8x}", s.data_offset);
    let kind = s.kind.short_name();

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

    // Format the value, truncating if very long
    let value = if s.value.len() > 120 {
        format!("{}...", &s.value[..117])
    } else {
        s.value.clone()
    };

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
            "  {}{}{} {}{:<8}{} {}{}{}",
            DIM, offset, RESET, kind_color, kind, RESET, color, display_value, RESET
        );
    } else {
        println!("  {} {:<8} {}", offset, kind, display_value);
    }
}
