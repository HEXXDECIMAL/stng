//! strangs - Language-aware string extraction CLI
//!
//! Extract strings from Go and Rust binaries with proper boundary detection.

use anyhow::Result;
use clap::Parser;
use std::collections::HashSet;
use std::fs;
use std::path::Path;

#[derive(Parser, Debug)]
#[command(name = "strangs")]
#[command(author, version, about = "Language-aware string extraction for Go and Rust binaries")]
#[command(long_about = "
strangs extracts strings from compiled Go and Rust binaries with proper
boundary detection. Unlike traditional `strings(1)`, it understands how
these languages store strings internally (pointer + length pairs, NOT
null-terminated) and can properly extract individual strings from packed
string data.

EXAMPLES:
    strangs my_go_binary
    strangs -m 6 my_rust_binary
    strangs --json my_binary | jq '.[] | .value'
    strangs --simple my_binary
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

    /// Show unfiltered results including garbage/noise (by default, garbage is filtered)
    #[arg(long)]
    unfiltered: bool,

    /// Use radare2 for extraction (auto-detected by default if installed)
    #[arg(long)]
    r2: bool,

    /// Disable radare2 even if installed
    #[arg(long)]
    no_r2: bool,
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

    // Determine whether to use radare2
    let use_r2 = if cli.no_r2 {
        false
    } else if cli.r2 {
        true
    } else {
        // Auto-detect: use r2 if installed
        strangs::r2::is_available()
    };

    // Extract strings
    let opts = if use_r2 {
        strangs::ExtractOptions::new(cli.min_length).with_r2(&cli.target)
    } else {
        strangs::ExtractOptions::new(cli.min_length)
    };
    let mut strings = strangs::extract_strings_with_options(&data, &opts);

    // Deduplicate strings at the same offset (e.g., "foo" and "foo\0" from structure variations)
    // Also deduplicate by normalized value across different offsets
    let mut seen_at_offset: HashSet<(u64, String)> = HashSet::new();
    let mut seen_values: HashSet<String> = HashSet::new();
    strings.retain(|s| {
        // Normalize: trim whitespace and trailing null/control characters
        let normalized: String = s
            .value
            .trim()
            .trim_end_matches(|c: char| c.is_control())
            .to_string();
        let key = (s.data_offset, normalized.clone());
        // Skip if we've seen this exact (offset, normalized_value) pair
        if !seen_at_offset.insert(key) {
            return false;
        }
        // Skip if we've seen this normalized value before (keep first occurrence)
        if !seen_values.insert(normalized) {
            return false;
        }
        true
    });

    // Filter garbage strings by default (unless --unfiltered is specified)
    if !cli.unfiltered {
        strings.retain(|s| !strangs::is_garbage(&s.value));
    }

    // Output results
    if cli.json {
        println!("{}", serde_json::to_string_pretty(&strings)?);
    } else if cli.simple {
        // Simple output: one string per line
        for s in &strings {
            println!("{}", s.value);
        }
        eprintln!("\n{} strings extracted", strings.len());
    } else {
        // Columned output with section grouping
        if strings.is_empty() {
            println!("No strings found in {}", cli.target);
            return Ok(());
        }

        println!(
            "Extracted {} strings from {}\n",
            strings.len(),
            cli.target
        );

        // Sort by section, then by offset
        strings.sort_by(|a, b| {
            match (&a.section, &b.section) {
                (Some(sa), Some(sb)) => sa.cmp(sb).then(a.data_offset.cmp(&b.data_offset)),
                (Some(_), None) => std::cmp::Ordering::Less,
                (None, Some(_)) => std::cmp::Ordering::Greater,
                (None, None) => a.data_offset.cmp(&b.data_offset),
            }
        });

        let mut current_section: Option<&str> = None;

        for s in &strings {
            let section = s.section.as_deref();

            // Print section delimiter when section changes
            if !cli.flat && section != current_section {
                if current_section.is_some() {
                    println!(); // Blank line between sections
                }
                let section_name = section.unwrap_or("(unknown)");
                println!("-- {} {:-<60}", section_name, "");
                println!(
                    "{:<12} {:<18} VALUE",
                    "OFFSET", "KIND"
                );
                current_section = section;
            }

            // Add subtle divider before section names
            if s.kind == strangs::StringKind::Section {
                println!("  ·");
            }

            let offset = format!("0x{:x}", s.data_offset);

            // For sections, just show "segment" instead of method/kind
            let combined = if s.kind == strangs::StringKind::Section {
                "segment".to_string()
            } else {
                let method_short = match s.method {
                    strangs::StringMethod::Structure => "struct",
                    strangs::StringMethod::InstructionPattern => "instr",
                    strangs::StringMethod::RawScan => "raw",
                    strangs::StringMethod::Heuristic => "heur",
                    strangs::StringMethod::R2String => "r2",
                    strangs::StringMethod::R2Symbol => "r2sym",
                };
                let kind = format!("{:?}", s.kind);
                format!("{}/{}", method_short, kind)
            };

            // Show library for imports
            let display_value = if let Some(ref lib) = s.library {
                format!("{} <- {}", s.value, lib)
            } else {
                s.value.clone()
            };

            println!("{:<12} {:<18} {}", offset, combined, display_value);
        }
    }

    Ok(())
}
