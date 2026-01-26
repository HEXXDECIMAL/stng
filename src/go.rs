//! Go string extraction.
//!
//! Go strings are represented as `{ptr: *byte, len: int}` structures (16 bytes on 64-bit).
//! The string data is typically stored in `.rodata` (ELF) or `__rodata` (Mach-O) sections,
//! while the pointer+length structures are scattered throughout data sections.
//!
//! For inline literals (function arguments, map keys/values), we also perform
//! instruction pattern analysis to extract strings that don't have stored structures.

use super::common::{
    extract_from_structures, find_string_structures, BinaryInfo, ExtractedString, StringKind,
    StringMethod, StringStruct,
};
use super::instr::{extract_inline_strings_amd64, extract_inline_strings_arm64};
use goblin::elf::Elf;
use goblin::mach::cputype::{CPU_TYPE_ARM64, CPU_TYPE_X86_64};
use goblin::mach::MachO;
use goblin::pe::PE;
use rayon::prelude::*;
use std::collections::HashSet;

/// Extracts strings from Go binaries using structure analysis.
pub struct GoStringExtractor {
    min_length: usize,
}

impl GoStringExtractor {
    pub fn new(min_length: usize) -> Self {
        Self { min_length }
    }

    /// Extract strings from a Mach-O binary.
    pub fn extract_macho(&self, macho: &MachO, _data: &[u8]) -> Vec<ExtractedString> {
        let mut strings = Vec::new();
        // Mach-O is always little-endian on modern systems (x86_64, ARM64)
        let info = BinaryInfo::from_macho(macho.is_64);

        // Find __rodata section in __TEXT segment (contains string data)
        let mut rodata_info: Option<(u64, &[u8])> = None;
        let mut text_info: Option<(u64, &[u8])> = None;

        for seg in &macho.segments {
            let seg_name = seg.name().unwrap_or("");
            if seg_name == "__TEXT" {
                if let Ok(sections) = seg.sections() {
                    for (section, section_data) in sections {
                        let name = section.name().unwrap_or("");
                        if name == "__rodata" {
                            rodata_info = Some((section.addr, section_data));
                        }
                        if name == "__text" {
                            text_info = Some((section.addr, section_data));
                        }
                    }
                }
            }
        }

        let Some((rodata_addr, rodata_data)) = rodata_info else {
            return strings;
        };

        // Collect all sections first for parallel processing
        let sections_info: Vec<(u64, &[u8])> = macho
            .segments
            .iter()
            .filter_map(|seg| seg.sections().ok())
            .flatten()
            .map(|(section, section_data)| (section.addr, section_data))
            .collect();

        // Search all sections for string structures in parallel
        let all_structs: Vec<StringStruct> = sections_info
            .par_iter()
            .flat_map(|(section_addr, section_data)| {
                find_string_structures(
                    section_data,
                    *section_addr,
                    rodata_addr,
                    rodata_data.len() as u64,
                    &info,
                )
            })
            .collect();

        // Extract strings using structure boundaries
        let structured = extract_from_structures(
            rodata_data,
            rodata_addr,
            &all_structs,
            Some("__rodata"),
            classify_string,
        );

        // Filter by minimum length
        for s in structured {
            if s.value.len() >= self.min_length {
                strings.push(s);
            }
        }

        // Perform instruction pattern analysis for inline literals
        if let Some((text_addr, text_data)) = text_info {
            let inline_strings = match macho.header.cputype() {
                CPU_TYPE_ARM64 => extract_inline_strings_arm64(
                    text_data,
                    text_addr,
                    rodata_data,
                    rodata_addr,
                    self.min_length,
                ),
                CPU_TYPE_X86_64 => extract_inline_strings_amd64(
                    text_data,
                    text_addr,
                    rodata_data,
                    rodata_addr,
                    self.min_length,
                ),
                _ => Vec::new(),
            };

            // Deduplicate against already found strings
            let existing: HashSet<&str> = strings.iter().map(|s| s.value.as_str()).collect();
            let new_strings: Vec<_> = inline_strings
                .into_iter()
                .filter(|s| !existing.contains(s.value.as_str()))
                .collect();
            strings.extend(new_strings);
        }

        // Also extract from __gopclntab (function/file names)
        for seg in &macho.segments {
            if let Ok(sections) = seg.sections() {
                for (section, section_data) in sections {
                    let name = section.name().unwrap_or("");
                    if name == "__gopclntab" {
                        let gopclntab_strings =
                            self.extract_raw_strings(section_data, Some(name.to_string()));
                        strings.extend(gopclntab_strings);
                    }
                }
            }
        }

        strings
    }

    /// Extract strings from an ELF binary.
    pub fn extract_elf(&self, elf: &Elf, data: &[u8]) -> Vec<ExtractedString> {
        let mut strings = Vec::new();
        // Use actual endianness from ELF header
        let info = BinaryInfo::from_elf(elf.is_64, elf.little_endian);

        // Find .rodata and .text sections
        let mut rodata_info: Option<(u64, usize, usize)> = None;
        let mut text_info: Option<(u64, usize, usize)> = None;

        for sh in &elf.section_headers {
            let name = elf.shdr_strtab.get_at(sh.sh_name).unwrap_or("");
            if name == ".rodata" {
                rodata_info = Some((sh.sh_addr, sh.sh_offset as usize, sh.sh_size as usize));
            }
            if name == ".text" {
                text_info = Some((sh.sh_addr, sh.sh_offset as usize, sh.sh_size as usize));
            }
        }

        let Some((rodata_addr, rodata_offset, rodata_size)) = rodata_info else {
            return strings;
        };

        if rodata_offset + rodata_size > data.len() {
            return strings;
        }

        let rodata_data = &data[rodata_offset..rodata_offset + rodata_size];

        // Search all sections for string structures (in parallel)
        let all_structs: Vec<StringStruct> = elf
            .section_headers
            .par_iter()
            .filter(|sh| sh.sh_type != goblin::elf::section_header::SHT_NOBITS && sh.sh_size > 0)
            .filter_map(|sh| {
                let offset = sh.sh_offset as usize;
                let size = sh.sh_size as usize;
                if offset + size > data.len() {
                    return None;
                }
                let section_data = &data[offset..offset + size];
                Some(find_string_structures(
                    section_data,
                    sh.sh_addr,
                    rodata_addr,
                    rodata_size as u64,
                    &info,
                ))
            })
            .flatten()
            .collect();

        // Extract strings using structure boundaries
        let structured = extract_from_structures(
            rodata_data,
            rodata_addr,
            &all_structs,
            Some(".rodata"),
            classify_string,
        );

        for s in structured {
            if s.value.len() >= self.min_length {
                strings.push(s);
            }
        }

        // Perform instruction pattern analysis for inline literals
        if let Some((text_addr, text_offset, text_size)) = text_info {
            if text_offset + text_size <= data.len() {
                let text_data = &data[text_offset..text_offset + text_size];

                // Determine architecture from ELF machine type
                let inline_strings = match elf.header.e_machine {
                    goblin::elf::header::EM_X86_64 => extract_inline_strings_amd64(
                        text_data,
                        text_addr,
                        rodata_data,
                        rodata_addr,
                        self.min_length,
                    ),
                    goblin::elf::header::EM_AARCH64 => extract_inline_strings_arm64(
                        text_data,
                        text_addr,
                        rodata_data,
                        rodata_addr,
                        self.min_length,
                    ),
                    _ => Vec::new(),
                };

                // Deduplicate against already found strings
                let existing: HashSet<&str> = strings.iter().map(|s| s.value.as_str()).collect();
                let new_strings: Vec<_> = inline_strings
                    .into_iter()
                    .filter(|s| !existing.contains(s.value.as_str()))
                    .collect();
                strings.extend(new_strings);
            }
        }

        // Also extract from .gopclntab
        for sh in &elf.section_headers {
            let name = elf.shdr_strtab.get_at(sh.sh_name).unwrap_or("");
            if name == ".gopclntab" {
                let offset = sh.sh_offset as usize;
                let size = sh.sh_size as usize;

                if offset + size <= data.len() {
                    let section_data = &data[offset..offset + size];
                    let gopclntab_strings =
                        self.extract_raw_strings(section_data, Some(name.to_string()));
                    strings.extend(gopclntab_strings);
                }
            }
        }

        strings
    }

    /// Extract strings from a PE binary.
    pub fn extract_pe(&self, pe: &PE, data: &[u8]) -> Vec<ExtractedString> {
        let mut strings = Vec::new();
        // PE is always little-endian
        let info = BinaryInfo::from_pe(pe.is_64);

        // Find .rdata section (contains string data in PE Go binaries)
        let mut rdata_info: Option<(u64, usize, usize)> = None;

        for section in &pe.sections {
            let name = String::from_utf8_lossy(&section.name);
            let name = name.trim_end_matches('\0');
            if name == ".rdata" {
                let base = pe
                    .header
                    .optional_header
                    .map(|h| h.windows_fields.image_base)
                    .unwrap_or(0);
                rdata_info = Some((
                    base + section.virtual_address as u64,
                    section.pointer_to_raw_data as usize,
                    section.size_of_raw_data as usize,
                ));
                break;
            }
        }

        let Some((rdata_addr, rdata_offset, rdata_size)) = rdata_info else {
            return strings;
        };

        if rdata_offset + rdata_size > data.len() {
            return strings;
        }

        let rdata_data = &data[rdata_offset..rdata_offset + rdata_size];

        // Search all sections for string structures
        let mut all_structs = Vec::new();

        for section in &pe.sections {
            let offset = section.pointer_to_raw_data as usize;
            let size = section.size_of_raw_data as usize;

            if offset + size > data.len() {
                continue;
            }

            let base = pe
                .header
                .optional_header
                .map(|h| h.windows_fields.image_base)
                .unwrap_or(0);

            let section_data = &data[offset..offset + size];
            let section_addr = base + section.virtual_address as u64;

            let structs = find_string_structures(
                section_data,
                section_addr,
                rdata_addr,
                rdata_size as u64,
                &info,
            );
            all_structs.extend(structs);
        }

        // Extract strings using structure boundaries
        let structured = extract_from_structures(
            rdata_data,
            rdata_addr,
            &all_structs,
            Some(".rdata"),
            classify_string,
        );

        for s in structured {
            if s.value.len() >= self.min_length {
                strings.push(s);
            }
        }

        strings
    }

    /// Extract raw strings (null-terminated fallback) from a section.
    /// For gopclntab, classifies strings as function names or file paths.
    fn extract_raw_strings(
        &self,
        data: &[u8],
        section_name: Option<String>,
    ) -> Vec<ExtractedString> {
        let mut strings = Vec::new();
        let mut seen: HashSet<String> = HashSet::new();
        let mut current = Vec::new();
        let mut start_offset = 0usize;

        let is_gopclntab = section_name
            .as_ref()
            .map(|s| s.contains("gopclntab"))
            .unwrap_or(false);

        for (i, &byte) in data.iter().enumerate() {
            if byte == 0 {
                if current.len() >= self.min_length {
                    if let Ok(s) = std::str::from_utf8(&current) {
                        let trimmed = s.trim();
                        if !trimmed.is_empty() && !seen.contains(trimmed) {
                            seen.insert(trimmed.to_string());

                            // Classify gopclntab strings
                            let kind = if is_gopclntab {
                                classify_gopclntab_string(trimmed)
                            } else {
                                classify_string(trimmed)
                            };

                            strings.push(ExtractedString {
                                value: trimmed.to_string(),
                                data_offset: start_offset as u64,
                                section: section_name.clone(),
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
}

/// Classify a string from gopclntab section.
fn classify_gopclntab_string(s: &str) -> StringKind {
    // Source file paths end with file extensions
    if s.ends_with(".go") || s.ends_with(".s") || s.ends_with(".c") || s.ends_with(".h") {
        return StringKind::FilePath;
    }

    // Go symbols: package/path.Function or package/path.(*Type).Method
    // They contain dots AND (slashes OR parentheses for method receivers)
    if s.contains('.') && !s.contains(' ') {
        // Has method receiver like (*Type) or type assertion
        if s.contains("(*") || s.contains(".(") {
            return StringKind::FuncName;
        }
        // Package path with function: contains / and ends with .Something
        if s.contains('/') {
            // Check if last component after final / contains a dot (package.Func)
            if let Some(last_part) = s.rsplit('/').next() {
                if last_part.contains('.') {
                    return StringKind::FuncName;
                }
            }
        }
        // Simple package.Function format (no slashes)
        if !s.contains('/')
            && s.chars()
                .all(|c| c.is_alphanumeric() || c == '.' || c == '_')
        {
            return StringKind::FuncName;
        }
    }

    // Type equality functions: type:.eq.xxx
    if s.starts_with("type:") {
        return StringKind::FuncName;
    }

    // Bare identifiers (no dots, no slashes)
    if !s.contains('.') && !s.contains('/') {
        return StringKind::Ident;
    }

    StringKind::Ident
}

/// Classify a general string by its content.
/// Note: Section names are detected via goblin, not pattern matching here.
pub fn classify_string(s: &str) -> StringKind {
    // Check for shell commands first (high priority for security)
    if is_shell_command(s) {
        return StringKind::ShellCmd;
    }

    // IP addresses and IP:port
    if let Some(kind) = classify_ip(s) {
        return kind;
    }

    // URLs (including database URLs) - but skip known benign ones
    if s.starts_with("http://")
        || s.starts_with("https://")
        || s.starts_with("ftp://")
        || s.starts_with("postgresql://")
        || s.starts_with("mysql://")
        || s.starts_with("redis://")
        || s.starts_with("mongodb://")
        || s.starts_with("ssh://")
        || s.starts_with("tcp://")
        || s.starts_with("udp://")
    {
        // Skip common benign URLs (Apple certs, etc.)
        if s.starts_with("https://www.apple.com/appleca") {
            return StringKind::Const;
        }
        return StringKind::Url;
    }

    // Windows registry paths
    if s.starts_with("HKEY_") || s.starts_with("HKLM\\") || s.starts_with("HKCU\\") {
        return StringKind::Registry;
    }

    // File paths - check for suspicious patterns
    // Skip Go runtime metrics (e.g., /gc/heap/allocs:bytes, /sched/latencies:seconds)
    if s.starts_with('/') || s.starts_with("C:\\") || s.starts_with("./") || s.starts_with("../") {
        // Go runtime metrics start with / and have colon (not URLs like file://)
        if s.starts_with('/') && s.contains(':') && !s.contains("://") {
            return StringKind::Const;
        }
        if is_suspicious_path(s) {
            return StringKind::SuspiciousPath;
        }
        return StringKind::Path;
    }

    // Base64-encoded data (long strings, right charset, proper padding)
    if is_base64(s) {
        return StringKind::Base64;
    }

    // Environment variable names (UPPERCASE, optionally with _ and digits)
    // May have trailing = for assignment context (e.g., "GOMEMLIMIT=")
    // This avoids matching x86 instruction patterns like "AWAVAUATSH"
    let env_name = s.strip_suffix('=').unwrap_or(s);
    if env_name.len() >= 3
        && env_name
            .chars()
            .next()
            .map(|c| c.is_ascii_uppercase())
            .unwrap_or(false)
        && env_name
            .chars()
            .all(|c| c.is_ascii_uppercase() || c == '_' || c.is_ascii_digit())
    {
        let has_underscore = env_name.contains('_');
        let has_digit = env_name.chars().any(|c| c.is_ascii_digit());
        // Go runtime env vars (GODEBUG, GOTRACEBACK, GOMAXPROCS, GOMEMLIMIT, etc.)
        let is_go_env = env_name.starts_with("GO") && env_name.len() >= 4;
        let is_known = matches!(
            env_name,
            "PATH"
                | "HOME"
                | "USER"
                | "TERM"
                | "SHELL"
                | "LANG"
                | "PWD"
                | "TMP"
                | "TEMP"
                | "EDITOR"
                | "PAGER"
                | "MAIL"
                | "LOGNAME"
                | "HOSTNAME"
                | "COLUMNS"
                | "LINES"
                | "DISPLAY"
                | "TZ"
                | "CLICOLOR"
                | "LSCOLORS"
                | "COLORTERM"
        );

        // Accept if: has underscore, has digits, Go env var, known pattern, or short (4-8 chars)
        if has_underscore
            || has_digit
            || is_go_env
            || is_known
            || (env_name.len() <= 8 && env_name.len() >= 4)
        {
            return StringKind::EnvVar;
        }
    }

    StringKind::Const
}

/// Check if a string looks like a shell command
fn is_shell_command(s: &str) -> bool {
    // Must have some length and typically contain spaces
    if s.len() < 4 {
        return false;
    }

    // Skip if it looks like a .NET generic type (contains backtick followed by digit)
    // e.g., IEnumerable`1, Dictionary`2, etc.
    if s.contains('`') {
        // Check if it's a .NET generic pattern: Name`N where N is a digit
        let has_generic_pattern = s
            .chars()
            .zip(s.chars().skip(1))
            .any(|(a, b)| a == '`' && b.is_ascii_digit());
        if has_generic_pattern {
            return false;
        }
    }

    // Skip strings that look like code/programming expressions
    // These contain comparison operators that wouldn't appear in shell commands
    if s.contains("!=") || s.contains("==") || s.contains("<=") || s.contains(">=") {
        return false;
    }

    // Shell operators and redirects
    if s.contains(" | ")
        || s.contains(">/dev/null")
        || s.contains("2>/dev/null")
        || s.contains("2>&1")
        || s.contains(" && ")
        || s.contains("$(")
    {
        return true;
    }

    // Backtick command substitution - must start with backtick and look like actual command
    // Skip documentation references like "see `go doc ...`" or inline code in error messages
    if let Some(rest) = s.strip_prefix('`') {
        if let Some(end) = rest.find('`') {
            let content = &rest[..end];
            // Must have command-like content and not look like a doc reference
            if !content.is_empty()
                && content.contains(' ')
                && !content.starts_with("go ")
                && !content.contains(" doc ")
            {
                return true;
            }
        }
    }

    // Common command prefixes with arguments
    // Note: "exec " removed - too many false positives with "exec format error" etc.
    let cmd_prefixes = [
        "sed ",
        "rm ",
        "kill ",
        "chmod ",
        "chown ",
        "wget ",
        "curl ",
        "bash ",
        "sh ",
        "/bin/sh",
        "/bin/bash",
        "nc ",
        "ncat ",
        "python ",
        "perl ",
        "ruby ",
        "php ",
        "echo ",
        "cat ",
        "mkdir ",
        "cp ",
        "mv ",
        "touch ",
        "tar ",
        "gzip ",
        "gunzip ",
        "base64 ",
        "openssl ",
        "dd ",
        "mount ",
        "umount ",
        "iptables ",
        "systemctl ",
        "service ",
        "crontab ",
        "useradd ",
        "userdel ",
        "passwd ",
        "sudo ",
        "su ",
        "chroot ",
        "nohup ",
        "setsid ",
        "eval ",
    ];

    for prefix in cmd_prefixes {
        if s.starts_with(prefix) || s.contains(&format!(" {}", prefix)) {
            return true;
        }
    }

    false
}

/// Check if a string is a suspicious/security-relevant path
fn is_suspicious_path(s: &str) -> bool {
    // Hidden paths (contain /. component)
    if s.contains("/.") {
        return true;
    }

    // Known suspicious/rootkit locations
    let suspicious = [
        "/etc/ld.so.preload",
        "/etc/ld.so.conf",
        "/dev/shm",
        "/dev/mem",
        "/dev/kmem",
        "/proc/",
        "/sys/",
        "/.ssh/",
        "/etc/cron",
        "/etc/init.d",
        "/etc/systemd",
        "/etc/rc.local",
        "/var/spool/cron",
        "/Library/LaunchAgents",
        "/Library/LaunchDaemons",
        "/.bash_profile",
        "/.bashrc",
        "/.profile",
        "/.bash_login",
        "/.zshrc",
        "/tmp/",
        "/var/tmp/",
    ];

    for path in suspicious {
        if s.contains(path) {
            return true;
        }
    }

    false
}

/// Classify IP addresses and IP:port combinations
fn classify_ip(s: &str) -> Option<StringKind> {
    let s = s.trim();

    // Check for IP:port pattern first
    if let Some(colon_pos) = s.rfind(':') {
        let (ip_part, port_part) = s.split_at(colon_pos);
        let port_str = &port_part[1..];

        // Verify port is numeric and reasonable
        if let Ok(port) = port_str.parse::<u16>() {
            if port > 0 && is_ipv4(ip_part) {
                return Some(StringKind::IPPort);
            }
        }
    }

    // Plain IPv4
    if is_ipv4(s) {
        return Some(StringKind::IP);
    }

    // IPv6 (contains multiple colons, hex chars)
    if s.contains(':') && s.chars().filter(|&c| c == ':').count() >= 2 {
        let valid_ipv6 = s
            .chars()
            .all(|c| c.is_ascii_hexdigit() || c == ':' || c == '.');
        if valid_ipv6 && s.len() >= 3 {
            return Some(StringKind::IP);
        }
    }

    None
}

/// Check if a string is a valid IPv4 address (not a version number)
fn is_ipv4(s: &str) -> bool {
    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() != 4 {
        return false;
    }

    let mut octets = [0u8; 4];
    for (i, part) in parts.iter().enumerate() {
        match part.parse::<u8>() {
            Ok(n) => octets[i] = n,
            Err(_) => return false,
        }
    }

    // Filter out common version number patterns (false positives)
    // Pattern: X.0.0.0 (e.g., 1.0.0.0, 4.0.0.0, 11.0.0.0) - assembly versions
    if octets[1] == 0 && octets[2] == 0 && octets[3] == 0 {
        return false;
    }

    // Pattern: X.Y.0.0 (e.g., 2.1.0.0, 4.5.0.0) - also common versions
    if octets[2] == 0 && octets[3] == 0 {
        return false;
    }

    // 0.0.0.0 is not a useful IOC
    if octets == [0, 0, 0, 0] {
        return false;
    }

    // 127.x.x.x localhost is rarely an IOC
    if octets[0] == 127 {
        return false;
    }

    true
}

/// Check if a string looks like base64-encoded data
fn is_base64(s: &str) -> bool {
    // Must be reasonably long (short base64 could be anything)
    if s.len() < 20 {
        return false;
    }

    // Must not contain spaces or common text patterns
    if s.contains(' ') || s.contains("the ") || s.contains("and ") {
        return false;
    }

    // Check base64 charset: A-Z, a-z, 0-9, +, /, =
    let valid_b64 = s
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=');

    if !valid_b64 {
        return false;
    }

    // Should have mixed case and possibly end with = padding
    let has_upper = s.chars().any(|c| c.is_ascii_uppercase());
    let has_lower = s.chars().any(|c| c.is_ascii_lowercase());
    let has_digit = s.chars().any(|c| c.is_ascii_digit());

    // Base64 typically has good entropy - mixed chars
    has_upper && has_lower && has_digit
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::StringStruct;

    #[test]
    fn test_find_string_structures() {
        let info = BinaryInfo::new_64bit_le();

        // Create test data with a string structure
        // ptr = 0x1000, len = 5
        let mut section_data = vec![0u8; 32];
        section_data[0..8].copy_from_slice(&0x1000u64.to_le_bytes());
        section_data[8..16].copy_from_slice(&5u64.to_le_bytes());

        let structs = find_string_structures(
            &section_data,
            0x2000, // section_addr
            0x1000, // blob_addr
            0x100,  // blob_size
            &info,
        );

        assert_eq!(structs.len(), 1);
        assert_eq!(structs[0].ptr, 0x1000);
        assert_eq!(structs[0].len, 5);
    }

    #[test]
    fn test_extract_from_structures() {
        let blob = b"HelloWorld";
        let structs = vec![
            StringStruct {
                struct_offset: 0,
                ptr: 0x1000,
                len: 5,
            },
            StringStruct {
                struct_offset: 16,
                ptr: 0x1005,
                len: 5,
            },
        ];

        let strings =
            extract_from_structures(blob, 0x1000, &structs, Some("test"), |_| StringKind::Const);

        assert_eq!(strings.len(), 2);
        assert_eq!(strings[0].value, "Hello");
        assert_eq!(strings[1].value, "World");
    }

    #[test]
    fn test_classify_string_env_vars() {
        // Should be classified as EnvVar
        assert_eq!(classify_string("COLUMNS"), StringKind::EnvVar);
        assert_eq!(classify_string("TERM"), StringKind::EnvVar);
        assert_eq!(classify_string("CLICOLOR"), StringKind::EnvVar);
        assert_eq!(classify_string("LSCOLORS"), StringKind::EnvVar);
        assert_eq!(classify_string("COLORTERM"), StringKind::EnvVar);
        assert_eq!(classify_string("LS_SAMESORT"), StringKind::EnvVar);
        assert_eq!(classify_string("CLICOLOR_FORCE"), StringKind::EnvVar);
        assert_eq!(classify_string("PATH"), StringKind::EnvVar);
        assert_eq!(classify_string("HOME"), StringKind::EnvVar);
        assert_eq!(classify_string("USER"), StringKind::EnvVar);
        assert_eq!(classify_string("LC_ALL"), StringKind::EnvVar);
        assert_eq!(classify_string("XDG_CONFIG_HOME"), StringKind::EnvVar);
        assert_eq!(classify_string("GO111MODULE"), StringKind::EnvVar);

        // Go runtime env vars (no underscore, but start with GO)
        assert_eq!(classify_string("GODEBUG"), StringKind::EnvVar);
        assert_eq!(classify_string("GOTRACEBACK"), StringKind::EnvVar);
        assert_eq!(classify_string("GOMAXPROCS"), StringKind::EnvVar);
        assert_eq!(classify_string("GOMEMLIMIT"), StringKind::EnvVar);
        assert_eq!(classify_string("GOMEMLIMIT="), StringKind::EnvVar);

        // Should NOT be classified as EnvVar (too short without underscore)
        assert_ne!(classify_string("THE"), StringKind::EnvVar);
        assert_ne!(classify_string("FOR"), StringKind::EnvVar);
        assert_ne!(classify_string("AND"), StringKind::EnvVar);

        // With underscore, 3 chars is OK
        assert_eq!(classify_string("A_B"), StringKind::EnvVar);
    }

    #[test]
    fn test_classify_string_urls() {
        assert_eq!(classify_string("https://example.com"), StringKind::Url);
        assert_eq!(classify_string("http://localhost:8080"), StringKind::Url);
        assert_eq!(
            classify_string("postgresql://user:pass@host/db"),
            StringKind::Url
        );
    }

    #[test]
    fn test_classify_string_paths() {
        assert_eq!(classify_string("/usr/bin/ls"), StringKind::Path);
        assert_eq!(classify_string("./config.yaml"), StringKind::Path);
        assert_eq!(classify_string("../parent/file"), StringKind::Path);

        // Go runtime metrics should NOT be classified as paths
        assert_eq!(classify_string("/gc/heap/allocs:bytes"), StringKind::Const);
        assert_eq!(
            classify_string("/sched/latencies:seconds"),
            StringKind::Const
        );
        assert_eq!(
            classify_string("/memory/classes/total:bytes"),
            StringKind::Const
        );
        assert_eq!(
            classify_string("/cpu/classes/gc/mark/assist:cpu-seconds"),
            StringKind::Const
        );
    }

    // Note: Section detection is now done via goblin address matching,
    // not pattern matching in classify_string. See lib.rs extract_raw_strings.

    #[test]
    fn test_go_string_extractor_new() {
        let extractor = GoStringExtractor::new(4);
        assert_eq!(extractor.min_length, 4);
    }

    #[test]
    fn test_go_string_extractor_new_different_lengths() {
        let extractor1 = GoStringExtractor::new(0);
        assert_eq!(extractor1.min_length, 0);
        let extractor2 = GoStringExtractor::new(100);
        assert_eq!(extractor2.min_length, 100);
    }

    #[test]
    fn test_classify_gopclntab_string_source_files() {
        assert_eq!(classify_gopclntab_string("main.go"), StringKind::FilePath);
        assert_eq!(
            classify_gopclntab_string("runtime/proc.go"),
            StringKind::FilePath
        );
        assert_eq!(
            classify_gopclntab_string("asm_amd64.s"),
            StringKind::FilePath
        );
        assert_eq!(classify_gopclntab_string("syscall.c"), StringKind::FilePath);
        assert_eq!(classify_gopclntab_string("types.h"), StringKind::FilePath);
    }

    #[test]
    fn test_classify_gopclntab_string_functions() {
        // Package.Function format
        assert_eq!(
            classify_gopclntab_string("runtime.main"),
            StringKind::FuncName
        );
        assert_eq!(classify_gopclntab_string("main.init"), StringKind::FuncName);

        // With method receiver
        assert_eq!(
            classify_gopclntab_string("(*Server).ServeHTTP"),
            StringKind::FuncName
        );
        assert_eq!(
            classify_gopclntab_string("bufio.(*Reader).Read"),
            StringKind::FuncName
        );

        // Type assertion
        assert_eq!(
            classify_gopclntab_string("error.(Error)"),
            StringKind::FuncName
        );

        // Package path with function
        assert_eq!(
            classify_gopclntab_string("github.com/user/repo/pkg.Function"),
            StringKind::FuncName
        );

        // Type equality functions
        assert_eq!(
            classify_gopclntab_string("type:.eq.runtime.mspan"),
            StringKind::FuncName
        );
    }

    #[test]
    fn test_classify_gopclntab_string_identifiers() {
        // Bare identifiers without dots or slashes
        assert_eq!(classify_gopclntab_string("hello"), StringKind::Ident);
        assert_eq!(classify_gopclntab_string("myVar"), StringKind::Ident);
        assert_eq!(classify_gopclntab_string("CONSTANT"), StringKind::Ident);
    }

    #[test]
    fn test_classify_string_database_urls() {
        assert_eq!(
            classify_string("mysql://user:pass@localhost/db"),
            StringKind::Url
        );
        assert_eq!(classify_string("redis://localhost:6379"), StringKind::Url);
        assert_eq!(
            classify_string("mongodb://user:pass@cluster.mongodb.net/db"),
            StringKind::Url
        );
        assert_eq!(
            classify_string("ftp://ftp.example.com/file.txt"),
            StringKind::Url
        );
    }

    #[test]
    fn test_classify_string_windows_paths() {
        assert_eq!(classify_string("C:\\Windows\\System32"), StringKind::Path);
    }

    #[test]
    fn test_classify_string_relative_paths() {
        assert_eq!(classify_string("./config.json"), StringKind::Path);
        assert_eq!(classify_string("../parent/dir"), StringKind::Path);
    }

    #[test]
    fn test_classify_string_const_fallback() {
        // Regular strings that don't match other patterns
        assert_eq!(classify_string("hello world"), StringKind::Const);
        assert_eq!(classify_string("version 1.0.0"), StringKind::Const);
        assert_eq!(classify_string("some random text"), StringKind::Const);
    }

    #[test]
    fn test_extract_raw_strings_basic() {
        let extractor = GoStringExtractor::new(4);
        let data = b"Hello\0World\0foo\0";
        let strings = extractor.extract_raw_strings(data, Some(".rodata".to_string()));

        assert_eq!(strings.len(), 2); // Hello and World, foo is < 4
        assert!(strings.iter().any(|s| s.value == "Hello"));
        assert!(strings.iter().any(|s| s.value == "World"));
    }

    #[test]
    fn test_extract_raw_strings_deduplication() {
        let extractor = GoStringExtractor::new(4);
        let data = b"Hello\0Hello\0World\0";
        let strings = extractor.extract_raw_strings(data, None);

        assert_eq!(strings.iter().filter(|s| s.value == "Hello").count(), 1);
    }

    #[test]
    fn test_extract_raw_strings_non_printable() {
        let extractor = GoStringExtractor::new(4);
        // Non-printable bytes should break the string
        let data = b"Hello\x01World\0";
        let strings = extractor.extract_raw_strings(data, None);

        // "Hello" is broken by \x01, then "World" follows
        assert!(strings.iter().any(|s| s.value == "World"));
    }

    #[test]
    fn test_extract_raw_strings_gopclntab_classification() {
        let extractor = GoStringExtractor::new(4);
        let data = b"main.go\0runtime.main\0hello\0";
        let strings = extractor.extract_raw_strings(data, Some("__gopclntab".to_string()));

        // Should use gopclntab classification
        let main_go = strings.iter().find(|s| s.value == "main.go").unwrap();
        assert_eq!(main_go.kind, StringKind::FilePath);

        let runtime_main = strings.iter().find(|s| s.value == "runtime.main").unwrap();
        assert_eq!(runtime_main.kind, StringKind::FuncName);

        let hello = strings.iter().find(|s| s.value == "hello").unwrap();
        assert_eq!(hello.kind, StringKind::Ident);
    }

    #[test]
    fn test_extract_raw_strings_min_length() {
        let extractor = GoStringExtractor::new(10);
        let data = b"Hello\0World\0LongerString\0";
        let strings = extractor.extract_raw_strings(data, None);

        // Only "LongerString" (12 chars) should pass
        assert_eq!(strings.len(), 1);
        assert_eq!(strings[0].value, "LongerString");
    }

    #[test]
    fn test_extract_raw_strings_whitespace_trimming() {
        let extractor = GoStringExtractor::new(4);
        let data = b"  Hello  \0  World  \0";
        let strings = extractor.extract_raw_strings(data, None);

        // Should trim whitespace
        assert!(strings.iter().any(|s| s.value == "Hello"));
        assert!(strings.iter().any(|s| s.value == "World"));
    }

    #[test]
    fn test_find_string_structures_32bit() {
        let info = BinaryInfo::new_32bit_le();

        // Create 32-bit structure: ptr = 0x1000, len = 5
        let mut section_data = vec![0u8; 16];
        section_data[0..4].copy_from_slice(&0x1000u32.to_le_bytes());
        section_data[4..8].copy_from_slice(&5u32.to_le_bytes());

        let structs = find_string_structures(&section_data, 0x2000, 0x1000, 0x100, &info);

        assert_eq!(structs.len(), 1);
        assert_eq!(structs[0].ptr, 0x1000);
        assert_eq!(structs[0].len, 5);
    }

    #[test]
    fn test_find_string_structures_big_endian() {
        let info = BinaryInfo::new_64bit_be();

        // Create big-endian structure
        let mut section_data = vec![0u8; 32];
        section_data[0..8].copy_from_slice(&0x1000u64.to_be_bytes());
        section_data[8..16].copy_from_slice(&5u64.to_be_bytes());

        let structs = find_string_structures(&section_data, 0x2000, 0x1000, 0x100, &info);

        assert_eq!(structs.len(), 1);
        assert_eq!(structs[0].ptr, 0x1000);
        assert_eq!(structs[0].len, 5);
    }

    #[test]
    fn test_find_string_structures_out_of_range() {
        let info = BinaryInfo::new_64bit_le();

        // Create structure pointing outside blob range
        let mut section_data = vec![0u8; 32];
        section_data[0..8].copy_from_slice(&0x5000u64.to_le_bytes()); // Outside blob
        section_data[8..16].copy_from_slice(&5u64.to_le_bytes());

        let structs = find_string_structures(
            &section_data,
            0x2000,
            0x1000, // blob starts at 0x1000
            0x100,  // blob is 0x100 bytes
            &info,
        );

        // Should find nothing since pointer is out of range
        assert!(structs.is_empty());
    }

    #[test]
    fn test_find_string_structures_too_long() {
        let info = BinaryInfo::new_64bit_le();

        // Create structure with very long length
        let mut section_data = vec![0u8; 32];
        section_data[0..8].copy_from_slice(&0x1000u64.to_le_bytes());
        section_data[8..16].copy_from_slice(&0x200000u64.to_le_bytes()); // > 1MB

        let structs = find_string_structures(&section_data, 0x2000, 0x1000, 0x100, &info);

        // Should reject strings > 1MB
        assert!(structs.is_empty());
    }

    #[test]
    fn test_find_string_structures_zero_length() {
        let info = BinaryInfo::new_64bit_le();

        // Create structure with zero length
        let mut section_data = vec![0u8; 32];
        section_data[0..8].copy_from_slice(&0x1000u64.to_le_bytes());
        section_data[8..16].copy_from_slice(&0u64.to_le_bytes());

        let structs = find_string_structures(&section_data, 0x2000, 0x1000, 0x100, &info);

        // Should reject zero-length strings
        assert!(structs.is_empty());
    }

    #[test]
    fn test_is_ipv4_valid_ips() {
        // Real IP addresses should be detected
        assert!(is_ipv4("168.235.103.57"));
        assert!(is_ipv4("192.168.1.1"));
        assert!(is_ipv4("10.0.0.1"));
        assert!(is_ipv4("8.8.8.8"));
        assert!(is_ipv4("1.2.3.4"));
        assert!(is_ipv4("255.255.255.255"));
    }

    #[test]
    fn test_is_ipv4_rejects_version_numbers() {
        // Assembly/software version patterns should NOT be detected as IPs
        // Pattern: X.0.0.0
        assert!(!is_ipv4("1.0.0.0"));
        assert!(!is_ipv4("4.0.0.0"));
        assert!(!is_ipv4("11.0.0.0"));
        assert!(!is_ipv4("255.0.0.0"));

        // Pattern: X.Y.0.0
        assert!(!is_ipv4("2.1.0.0"));
        assert!(!is_ipv4("4.5.0.0"));
        assert!(!is_ipv4("10.2.0.0"));
    }

    #[test]
    fn test_is_ipv4_rejects_special_addresses() {
        // 0.0.0.0 is not a useful IOC
        assert!(!is_ipv4("0.0.0.0"));

        // Localhost is rarely an IOC
        assert!(!is_ipv4("127.0.0.1"));
        assert!(!is_ipv4("127.0.0.2"));
        assert!(!is_ipv4("127.255.255.255"));
    }

    #[test]
    fn test_is_ipv4_rejects_invalid() {
        // Not valid IP formats
        assert!(!is_ipv4(""));
        assert!(!is_ipv4("1.2.3"));
        assert!(!is_ipv4("1.2.3.4.5"));
        assert!(!is_ipv4("256.1.1.1"));
        assert!(!is_ipv4("1.2.3.abc"));
        assert!(!is_ipv4("hello"));
    }

    #[test]
    fn test_is_shell_command_detects_commands() {
        // Should detect shell commands
        assert!(is_shell_command("ls -la | grep foo"));
        assert!(is_shell_command("cat file 2>/dev/null"));
        assert!(is_shell_command("echo test && rm -rf /tmp"));
        assert!(is_shell_command("curl http://example.com"));
        assert!(is_shell_command("wget http://example.com"));
        assert!(is_shell_command("/bin/bash -c 'echo test'"));
        assert!(is_shell_command("$(whoami)"));
    }

    #[test]
    fn test_is_shell_command_rejects_dotnet_generics() {
        // .NET generic types should NOT be detected as shell commands
        assert!(!is_shell_command("IEnumerable`1"));
        assert!(!is_shell_command("Dictionary`2"));
        assert!(!is_shell_command("List`1"));
        assert!(!is_shell_command("Func`3"));
        assert!(!is_shell_command("Action`1"));
        assert!(!is_shell_command("System.Collections.Generic.List`1"));
    }

    #[test]
    fn test_is_shell_command_backtick_requires_content() {
        // Backtick must have command-like content with spaces
        assert!(is_shell_command("`ls -la`"));
        assert!(is_shell_command("echo `whoami foo`"));

        // Single backtick or empty content should not match
        assert!(!is_shell_command("foo`bar"));
        assert!(!is_shell_command("test`"));
    }

    #[test]
    fn test_classify_string_ip_detection() {
        // Real IPs should be classified as IP
        assert_eq!(classify_string("168.235.103.57"), StringKind::IP);
        assert_eq!(classify_string("192.168.1.100"), StringKind::IP);

        // Version numbers should NOT be classified as IP
        assert_ne!(classify_string("1.0.0.0"), StringKind::IP);
        assert_ne!(classify_string("4.0.0.0"), StringKind::IP);
        assert_ne!(classify_string("2.1.0.0"), StringKind::IP);
    }

    #[test]
    fn test_classify_string_shell_command_detection() {
        // Shell commands should be classified
        assert_eq!(
            classify_string("curl http://evil.com"),
            StringKind::ShellCmd
        );
        assert_eq!(
            classify_string("cat /etc/passwd | grep root"),
            StringKind::ShellCmd
        );

        // .NET generics should NOT be classified as shell commands
        assert_ne!(classify_string("IEnumerable`1"), StringKind::ShellCmd);
        assert_ne!(classify_string("Dictionary`2"), StringKind::ShellCmd);

        // Go runtime strings should NOT be classified as shell commands
        assert_ne!(
            classify_string("s.allocCount != s.nelems && freeIndex == s.nelems"),
            StringKind::ShellCmd
        );
        assert_ne!(
            classify_string("malformed GOMEMLIMIT; see `go doc runtime/debug.SetMemoryLimit`"),
            StringKind::ShellCmd
        );
        assert_ne!(classify_string("exec format error"), StringKind::ShellCmd);
    }
}
