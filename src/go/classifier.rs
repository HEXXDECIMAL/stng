//! String classification for Go binaries.
//!
//! Classifies extracted strings by their semantic type (path, URL, error, etc.).

use crate::types::StringKind;

pub(super) fn classify_gopclntab_string(s: &str) -> StringKind {
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

    // Well-known config/system files (even without path prefix)
    let well_known_files = [
        ".DS_Store",
        ".localized",
        ".bashrc",
        ".zshrc",
        ".profile",
        ".bash_profile",
        ".gitignore",
        ".gitconfig",
        ".ssh/",
        ".aws/",
        ".docker/",
        "authorized_keys",
        "id_rsa",
        "id_ed25519",
        "known_hosts",
        ".npmrc",
        ".yarnrc",
        "package.json",
        "Cargo.toml",
        "go.mod",
        "requirements.txt",
    ];
    for file in &well_known_files {
        if s == *file || s.ends_with(file) {
            return StringKind::FilePath;
        }
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
            .is_some_and(|c| c.is_ascii_uppercase())
        && env_name
            .chars()
            .all(|c| c.is_ascii_uppercase() || c == '_' || c.is_ascii_digit())
    {
        let has_underscore = env_name.contains('_');

        // Go runtime env vars (GODEBUG, GOTRACEBACK, GOMAXPROCS, GOMEMLIMIT, etc.)
        let is_go_env = env_name.starts_with("GO") && env_name.len() >= 4;

        // Comprehensive whitelist of well-known environment variables
        let is_known = matches!(
            env_name,
            // POSIX/Unix standard
            "PATH" | "HOME" | "USER" | "SHELL" | "TERM" | "LANG" | "PWD" | "TMP" | "TEMP"
            | "TMPDIR" | "EDITOR" | "PAGER" | "MAIL" | "LOGNAME" | "HOSTNAME" | "DISPLAY"
            | "TZ" | "UID" | "GID" | "EUID" | "EGID"
            // Locale
            | "LC_ALL" | "LC_CTYPE" | "LC_COLLATE" | "LC_MESSAGES" | "LC_MONETARY"
            | "LC_NUMERIC" | "LC_TIME"
            // Terminal/Display
            | "COLUMNS" | "LINES" | "COLORTERM" | "CLICOLOR" | "LSCOLORS"
            // Development/Build
            | "CC" | "CXX" | "CFLAGS" | "CXXFLAGS" | "LDFLAGS" | "MAKE" | "AR" | "AS"
            | "LD" | "NM" | "RANLIB" | "STRIP"
            // Common application vars
            | "JAVA_HOME" | "PYTHONPATH" | "NODE_PATH" | "RUBYLIB" | "PERL5LIB"
            | "CARGO_HOME" | "RUSTUP_HOME" | "GOPATH" | "GOROOT" | "GOBIN" | "GOCACHE"
            // XDG Base Directory
            | "XDG_CONFIG_HOME" | "XDG_DATA_HOME" | "XDG_CACHE_HOME" | "XDG_STATE_HOME"
            | "XDG_RUNTIME_DIR"
            // Security/Auth
            | "SSH_AUTH_SOCK" | "SSH_AGENT_PID" | "GPG_AGENT_INFO" | "SUDO_USER"
            | "SUDO_UID" | "SUDO_GID" | "SUDO_COMMAND"
            // HTTP/Network
            | "HTTP_PROXY" | "HTTPS_PROXY" | "FTP_PROXY" | "NO_PROXY" | "ALL_PROXY"
            // Debugging/Profiling
            | "DEBUG" | "VERBOSE" | "TRACE"
            // glibc/system
            | "LD_LIBRARY_PATH" | "LD_PRELOAD" | "GLIBC_TUNABLES"
            // macOS specific
            | "DYLD_LIBRARY_PATH" | "DYLD_INSERT_LIBRARIES" | "DYLD_FRAMEWORK_PATH"
            // Windows common (for cross-platform tools)
            | "APPDATA" | "LOCALAPPDATA" | "PROGRAMFILES" | "SYSTEMROOT" | "WINDIR"
            | "USERPROFILE" | "COMPUTERNAME"
        );

        // Accept if: well-known name, has underscore (like BUILD_ID, CI_JOB), or Go env var
        if is_known || (has_underscore && env_name.len() >= 3) || is_go_env {
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

    // Must be properly padded (length must be multiple of 4)
    if !s.len().is_multiple_of(4) {
        return false;
    }

    // Exclude sequential patterns (alphabet lookups, test data)
    if s.contains("ABCDE") || s.contains("012345") {
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
    use crate::types::BinaryInfo;
    use crate::extraction::{extract_from_structures, find_string_structures};
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

        // Whitelisted well-known vars
        assert_eq!(classify_string("GLIBC_TUNABLES"), StringKind::EnvVar);
        assert_eq!(classify_string("LD_PRELOAD"), StringKind::EnvVar);
        assert_eq!(classify_string("DYLD_INSERT_LIBRARIES"), StringKind::EnvVar);
        assert_eq!(classify_string("JAVA_HOME"), StringKind::EnvVar);
        assert_eq!(classify_string("HTTP_PROXY"), StringKind::EnvVar);

        // Should NOT be classified as EnvVar (not in whitelist, no underscore)
        assert_ne!(classify_string("THE"), StringKind::EnvVar);
        assert_ne!(classify_string("FOR"), StringKind::EnvVar);
        assert_ne!(classify_string("AND"), StringKind::EnvVar);
        assert_ne!(classify_string("DATA"), StringKind::EnvVar);
        assert_ne!(classify_string("OBJECT"), StringKind::EnvVar);
        assert_ne!(classify_string("CLASS"), StringKind::EnvVar);

        // With underscore, 3+ chars is OK
        assert_eq!(classify_string("A_B"), StringKind::EnvVar);
        assert_eq!(classify_string("BUILD_ID"), StringKind::EnvVar);
        assert_eq!(classify_string("CI_JOB"), StringKind::EnvVar);
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
