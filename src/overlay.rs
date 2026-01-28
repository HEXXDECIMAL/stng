//! Detection and extraction of overlay/appended data after binary boundaries.

use crate::raw::{extract_printable_runs, extract_wide_strings};
use crate::types::{ExtractedString, OverlayInfo, StringKind};
use std::collections::HashSet;

/// Detect overlay/appended data after an ELF binary.
///
/// Malware often appends encrypted payloads or configuration after the ELF structure.
/// This function identifies data beyond the normal ELF boundaries.
pub fn detect_elf_overlay(data: &[u8]) -> Option<OverlayInfo> {
    let elf = match goblin::elf::Elf::parse(data) {
        Ok(e) => e,
        Err(_) => return None,
    };

    // Find the highest file offset used by any program or section header
    let mut max_offset: u64 = 0;

    // Check program headers (segments)
    for ph in &elf.program_headers {
        let end = ph.p_offset + ph.p_filesz;
        if end > max_offset {
            max_offset = end;
        }
    }

    // Check section headers
    for sh in &elf.section_headers {
        let end = sh.sh_offset + sh.sh_size;
        if end > max_offset {
            max_offset = end;
        }
    }

    // If there's data after the highest offset, it's overlay/appended data
    let overlay_start = max_offset as usize;
    if overlay_start < data.len() {
        Some(OverlayInfo {
            start_offset: max_offset,
            size: (data.len() - overlay_start) as u64,
        })
    } else {
        None
    }
}

/// Extract strings from overlay/appended data after binary boundaries.
///
/// Malware often hides encrypted payloads or configuration in overlay data.
/// This function extracts both ASCII and wide (UTF-16LE) strings from overlay regions.
pub fn extract_overlay_strings(data: &[u8], min_length: usize) -> Vec<ExtractedString> {
    let mut strings = Vec::new();

    // Try ELF overlay detection
    if let Some(overlay_info) = detect_elf_overlay(data) {
        let start = overlay_info.start_offset as usize;
        if start < data.len() {
            let overlay_data = &data[start..];

            // Extract ASCII strings
            let section = Some("overlay".to_string());
            let segment_names_set = HashSet::new();
            let mut seen = HashSet::new();
            let initial_count = strings.len();
            extract_printable_runs(overlay_data, min_length, &section, &segment_names_set, &mut strings, &mut seen);

            // Mark all newly added strings as overlay
            for s in &mut strings[initial_count..] {
                s.kind = StringKind::Overlay;
            }

            // Extract wide strings
            let wide_strings = extract_wide_strings(overlay_data, min_length, Some("overlay".to_string()), &[]);
            for mut s in wide_strings {
                s.kind = StringKind::OverlayWide;
                strings.push(s);
            }
        }
    }

    strings
}
