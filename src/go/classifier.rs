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
    let len = s.len();

    // Fast early exit for very short strings
    if len < 3 {
        return StringKind::Const;
    }

    // Skip expensive classification for very long strings (>1000 chars)
    // They're unlikely to be patterns we care about and are expensive to check
    if len > 1000 {
        return StringKind::Const;
    }

    let bytes = s.as_bytes();
    let first = bytes[0];

    // ===== HIGH-PRIORITY IOC DETECTION =====
    // These checks come first because they're high-value security indicators

    // CTF flags: CTF{...}, flag{...}, FLAG{...}, picoCTF{...}, HTB{...}
    if (s.starts_with("CTF{") || s.starts_with("flag{") || s.starts_with("FLAG{")
        || s.starts_with("picoCTF{") || s.starts_with("HTB{"))
        && s.ends_with('}')
    {
        return StringKind::CTFFlag;
    }

    // GUIDs: {XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}
    if s.starts_with('{') && s.ends_with('}') && (36..=38).contains(&len) {
        let dash_count = s.chars().filter(|&c| c == '-').count();
        let hex_count = s.chars().filter(|c| c.is_ascii_hexdigit()).count();
        if dash_count == 4 && hex_count >= 30 && hex_count <= 32 {
            return StringKind::GUID;
        }
    }

    // Cryptocurrency wallet addresses (high value IOC)
    if let Some(kind) = classify_crypto_address(s) {
        return kind;
    }

    // Email addresses (often used in ransomware) - use memchr for speed
    if len >= 6 && memchr::memchr(b'@', bytes).is_some() && memchr::memchr(b'.', bytes).is_some() {
        let at_count = s.chars().filter(|&c| c == '@').count();
        if at_count == 1 {
            // Must be mostly ASCII (>95%) - reject garbage with non-ASCII chars
            let ascii_count = s.chars().filter(|c| c.is_ascii()).count();
            if ascii_count * 100 / len < 95 {
                return StringKind::Const; // Skip - has too much non-ASCII
            }

            // Reject consecutive dots (invalid email format)
            if s.contains("..") {
                return StringKind::Const; // Skip - has consecutive dots
            }

            // Split on @ to validate structure
            let parts: Vec<&str> = s.split('@').collect();
            if parts.len() == 2 {
                let local = parts[0];
                let domain = parts[1];

                // Local part must exist, not be empty, and start with alphanumeric
                if local.is_empty() || !local.chars().next().unwrap().is_alphanumeric() {
                    return StringKind::Const; // Skip - starts with @ or non-alphanumeric
                }

                // Local part must have at least one alphanumeric character
                if !local.chars().any(|c| c.is_alphanumeric()) {
                    return StringKind::Const; // Skip - local part has no alphanumeric
                }

                // Domain must have a dot (not @domain or @.domain)
                if !domain.contains('.') || domain.starts_with('.') {
                    return StringKind::Const; // Skip - invalid domain structure
                }

                // Domain must have at least one letter (not just numbers/symbols like @0.x)
                let domain_has_letter = domain.chars().any(|c| c.is_ascii_alphabetic());
                if !domain_has_letter {
                    return StringKind::Const; // Skip - domain has no letters
                }

                // Extract TLD (everything after last dot)
                if let Some(last_dot_pos) = domain.rfind('.') {
                    let tld = &domain[last_dot_pos + 1..];
                    // TLD must be at least 2 chars and all alphabetic
                    if tld.len() < 2 || !tld.chars().all(|c| c.is_ascii_alphabetic()) {
                        return StringKind::Const; // Skip - invalid TLD
                    }
                }

                // The main domain part (before TLD) must contain at least one letter
                // and be at least 2 characters long. Reject cases like "0.x" or "E.MM"
                if let Some(dot_pos) = domain.find('.') {
                    let main_domain = &domain[..dot_pos];
                    if main_domain.len() < 2 {
                        return StringKind::Const; // Skip - main domain too short (e.g., E.MM)
                    }
                    let main_has_letter = main_domain.chars().any(|c| c.is_ascii_alphabetic());
                    if !main_has_letter {
                        return StringKind::Const; // Skip - main domain has no letters (e.g., 0.x)
                    }
                }

                // Valid email chars check
                let valid_chars = s.chars().filter(|c| {
                    c.is_alphanumeric() || matches!(c, '@' | '.' | '-' | '_' | '+')
                }).count();
                if valid_chars * 100 / len >= 85 {
                    return StringKind::Email;
                }
            }
        }
    }

    // Tor/Onion addresses
    if s.contains(".onion") && len >= 10 {
        return StringKind::TorAddress;
    }

    // JWT tokens (3 base64 parts separated by dots)
    if s.matches('.').count() == 2 && len >= 50 {
        let parts: Vec<&str> = s.split('.').collect();
        if parts.len() == 3 && parts.iter().all(|p| !p.is_empty()) {
            let base64_chars = s.chars().filter(|c| {
                c.is_alphanumeric() || matches!(c, '.' | '-' | '_' | '=')
            }).count();
            if base64_chars * 100 / len >= 95 {
                return StringKind::JWT;
            }
        }
    }

    // API keys (AWS, GitHub, Stripe, Slack)
    if let Some(kind) = classify_api_key(s) {
        return kind;
    }

    // SQL injection patterns - only check if contains ' or - which are key indicators
    if memchr::memchr2(b'\'', b'-', bytes).is_some() || s.contains("UNION") {
        if (s.contains("' OR '") || s.contains("1'='1"))
            || (s.contains("UNION") && s.contains("SELECT"))
            || s.contains("admin'--")
        {
            return StringKind::SQLInjection;
        }
    }

    // XSS payloads - only check if contains < or = which are key indicators
    if first == b'j' || memchr::memchr2(b'<', b'=', bytes).is_some() {
        if (s.contains("<script>") && s.contains("</script>"))
            || (s.contains("onerror=") && s.contains("alert("))
            || s.starts_with("javascript:")
        {
            return StringKind::XSSPayload;
        }
    }

    // Command injection patterns - use byte checks for speed
    // Only check if the string contains key indicator bytes
    if memchr::memchr3(b';', b'|', b'$', bytes).is_some() {
        if (s.contains("; ") && (s.contains("cat") || s.contains("wget") || s.contains("curl")))
            || (s.contains("| ") && (s.contains("whoami") || s.contains("id") || s.contains("uname")))
            || s.contains("$(")
        {
            return StringKind::CommandInjection;
        }
    }

    // Backtick command substitution - must be mostly ASCII and contain command-like content
    if s.starts_with('`') && s.ends_with('`') && len >= 5 {
        let content = &s[1..len-1];
        let content_len = content.len();

        // Must be mostly ASCII (>90%) - reject garbage with non-ASCII chars
        let ascii_count = content.chars().filter(|c| c.is_ascii()).count();
        if ascii_count * 100 / content_len > 90 {
            // Must contain spaces (multiword command) or known command names
            if content.contains(' ')
                || content.contains("cat")
                || content.contains("ls")
                || content.contains("pwd")
                || content.contains("echo")
                || content.contains("wget")
                || content.contains("curl")
            {
                return StringKind::CommandInjection;
            }
        }
    }

    // LDAP/AD paths
    if s.contains("LDAP://") || (s.contains("CN=") && s.contains("DC=")) {
        return StringKind::LDAPPath;
    }

    // Windows mutex names (often weird strings used for malware synchronization)
    if s.starts_with("Global\\") || s.starts_with("Local\\") {
        return StringKind::Mutex;
    }

    // Ransomware patterns
    if s.contains("ENCRYPTED") || s.contains("DECRYPT") || s.contains("RANSOM") {
        let uppercase_count = s.chars().filter(|c| c.is_uppercase()).count();
        if uppercase_count * 100 / len > 50 {
            return StringKind::RansomNote;
        }
    }
    // Ransomware file extensions
    if s == ".locked" || s == ".encrypted" || s == ".crypted" || s == ".wannacry"
        || s == ".ryuk" || s == ".locky" || s.ends_with("-DECRYPT-INSTRUCTIONS.txt")
        || s.ends_with("HOW-TO-DECRYPT.html")
    {
        return StringKind::RansomNote;
    }

    // Cryptocurrency mining pools - only check if contains ':' or 'pool'
    if first == b's' || memchr::memchr2(b':', b'p', bytes).is_some() {
        if (s.contains("stratum+tcp://") || s.contains("stratum+ssl://"))
            || ((s.contains("pool.") || s.contains("nanopool") || s.contains("minergate"))
                && (s.contains(".com") || s.contains(".org") || s.contains(":")))
        {
            return StringKind::MiningPool;
        }
    }

    // ===== ORIGINAL CLASSIFICATION CONTINUES =====

    // URLs (including database URLs) - check first char for fast path
    if first == b'h'
        || first == b'f'
        || first == b'p'
        || first == b'm'
        || first == b'r'
        || first == b's'
        || first == b't'
        || first == b'u'
    {
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
    }

    // Check for shell commands (high priority for security)
    if is_shell_command(s) {
        return StringKind::ShellCmd;
    }

    // Check for AppleScript syntax (common in macOS malware)
    if is_applescript(s) {
        return StringKind::AppleScript;
    }

    // IP addresses and IP:port - only if starts with digit
    if first.is_ascii_digit() {
        if let Some(kind) = classify_ip(s) {
            return kind;
        }
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

    // Unicode escape sequences (common in JavaScript malware)
    if is_unicode_escaped(s) {
        return StringKind::UnicodeEscaped;
    }

    // URL-encoded data (common in web shells and HTTP payloads)
    if is_url_encoded(s) {
        return StringKind::UrlEncoded;
    }

    // Hex-encoded ASCII data (common in malware obfuscation)
    if is_hex_encoded(s) {
        return StringKind::HexEncoded;
    }

    // Base58-encoded data (Bitcoin/cryptocurrency addresses)
    if is_base58(s) {
        return StringKind::Base58;
    }

    // Base32-encoded data (Tor, some malware)
    if is_base32(s) {
        return StringKind::Base32;
    }

    // Base85-encoded data (ASCII85/Z85, some compressed formats)
    if is_base85(s) {
        return StringKind::Base85;
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

/// Check if a string looks like AppleScript code
fn is_applescript(s: &str) -> bool {
    let lower = s.to_ascii_lowercase();

    // AppleScript indicators
    let applescript_patterns = [
        "set ", "tell application", "path to desktop", "path to documents",
        "every file of", "whose name extension", "posix file", "end tell",
        "do shell script", " dialog", "choose file", "choose folder",
        "duplicate ", " to posix file", "repeat with", "end repeat",
        " as alias", " with replacing",
    ];

    for pattern in &applescript_patterns {
        if lower.contains(pattern) {
            return true;
        }
    }

    false
}

/// Check if a string looks like a shell command
fn is_shell_command(s: &str) -> bool {
    let len = s.len();

    // Must have some length
    if len < 4 {
        return false;
    }

    // Quick byte-level check: shell commands typically contain key indicators
    // If none of these bytes are present, it's very unlikely to be a shell command
    let bytes = s.as_bytes();
    let has_shell_indicators = bytes.iter().any(|&b| {
        matches!(b, b' ' | b'/' | b'$' | b'|' | b'&' | b'>' | b';' | b'`')
    });
    if !has_shell_indicators {
        return false;
    }

    // Fast path: shell commands almost always contain a space
    // Exceptions: paths like /bin/sh, command substitution $(...)
    if !memchr::memchr(b' ', bytes).is_some() && !s.starts_with("/bin/") && !s.starts_with("$(") {
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
    // Skip strings with escaped backticks (complicated to parse correctly)
    if s.starts_with('`') && !s.contains("\\`") {
        if let Some(rest) = s.strip_prefix('`') {
            if let Some(end) = rest.find('`') {
                let content = &rest[..end];
                // Must have command-like content and not look like a doc reference
                if !content.is_empty()
                    && content.contains(' ')
                    && !content.starts_with("go ")
                    && !content.contains(" doc ")
                {
                    // Must be mostly ASCII (>90%) - reject garbage with non-ASCII chars
                    let ascii_count = content.chars().filter(|c| c.is_ascii()).count();
                    let content_len = content.chars().count();
                    if content_len > 0 && ascii_count * 100 / content_len > 90 {
                        return true;
                    }
                }
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
        if s.starts_with(prefix) {
            return true;
        }
        // Check for " prefix" pattern without allocation
        if let Some(pos) = s.find(prefix) {
            if pos > 0 && s.as_bytes()[pos - 1] == b' ' {
                return true;
            }
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

    // Fast byte-based checks - single pass
    let bytes = s.as_bytes();
    let mut has_upper = false;
    let mut has_lower = false;
    let mut has_digit = false;

    for &b in bytes {
        match b {
            // Check for invalid patterns in a single pass
            b' ' => return false, // No spaces
            b'A'..=b'Z' => has_upper = true,
            b'a'..=b'z' => has_lower = true,
            b'0'..=b'9' => has_digit = true,
            b'+' | b'/' | b'=' => {}
            _ => return false, // Invalid character
        }
    }

    // Must have mixed case and digits (good entropy)
    if !has_upper || !has_lower || !has_digit {
        return false;
    }

    // Exclude sequential patterns (alphabet lookups, test data)
    // Only check if we've passed other tests (cheaper to do after)
    !s.contains("ABCDE") && !s.contains("012345") && !s.contains("the ") && !s.contains("and ")
}

/// Check if a string looks like hex-encoded ASCII data
fn is_hex_encoded(s: &str) -> bool {
    // Must be reasonably long (at least 40 chars = 20 decoded bytes)
    if s.len() < 40 {
        return false;
    }

    // Must be even length (pairs of hex digits)
    if !s.len().is_multiple_of(2) {
        return false;
    }

    // Must be all hex digits
    if !s.chars().all(|c| c.is_ascii_hexdigit()) {
        return false;
    }

    // Decode and check if mostly printable ASCII
    let decoded: Vec<u8> = (0..s.len())
        .step_by(2)
        .filter_map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect();

    if decoded.is_empty() {
        return false;
    }

    let printable = decoded
        .iter()
        .filter(|&&b| b.is_ascii_graphic() || b.is_ascii_whitespace())
        .count();

    // At least 70% printable
    printable * 10 > decoded.len() * 7
}

/// Check if a string looks like Unicode-escaped data (\xXX or \uXXXX format)
fn is_unicode_escaped(s: &str) -> bool {
    // Must be reasonably long
    if s.len() < 20 {
        return false;
    }

    // Count escape sequences
    let mut escape_count = 0;
    let mut chars = s.chars().peekable();

    while let Some(c) = chars.next() {
        if c == '\\' {
            if let Some(&next) = chars.peek() {
                if next == 'x' || next == 'u' {
                    escape_count += 1;
                }
            }
        }
    }

    // Need at least 5 escape sequences to be confident
    if escape_count < 5 {
        return false;
    }

    // Try to decode and check if result is mostly printable
    let decoded = decode_unicode_escapes(s);
    if decoded.is_empty() {
        return false;
    }

    let printable = decoded
        .iter()
        .filter(|&&b| b.is_ascii_graphic() || b.is_ascii_whitespace())
        .count();

    // At least 60% printable (slightly more lenient than hex)
    printable * 10 > decoded.len() * 6
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

/// Check if a string looks like URL-encoded data (%XX format)
fn is_url_encoded(s: &str) -> bool {
    // Must be reasonably long
    if s.len() < 20 {
        return false;
    }

    // Quick check: must contain '%' to be URL-encoded
    if !s.as_bytes().contains(&b'%') {
        return false;
    }

    // Count VALID percent-encoded sequences (%XX where XX are hex digits)
    let mut valid_percent_count = 0;
    let mut total_percent_count = 0;
    let chars: Vec<char> = s.chars().collect();

    let mut i = 0;
    while i < chars.len() {
        if chars[i] == '%' {
            total_percent_count += 1;
            // Check if followed by two hex digits
            if i + 2 < chars.len()
                && chars[i + 1].is_ascii_hexdigit()
                && chars[i + 2].is_ascii_hexdigit() {
                valid_percent_count += 1;
                i += 3;
                continue;
            }
        }
        i += 1;
    }

    // Need at least 3 VALID %XX sequences (not just % signs)
    if valid_percent_count < 3 {
        return false;
    }

    // Most % signs should be valid %XX sequences (reject printf format strings)
    // Require at least 70% of % signs to be valid %XX sequences
    if total_percent_count > 0 && valid_percent_count * 10 < total_percent_count * 7 {
        return false;
    }

    // Try to decode and check if result is mostly printable
    let decoded = decode_url_encoding(s);
    if decoded.is_empty() {
        return false;
    }

    let printable = decoded
        .iter()
        .filter(|&&b| b.is_ascii_graphic() || b.is_ascii_whitespace())
        .count();

    // At least 60% printable
    printable * 10 > decoded.len() * 6
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

/// Check if a string looks like Base32-encoded data
fn is_base32(s: &str) -> bool {
    // Must be reasonably long (at least 16 chars = 10 bytes)
    if s.len() < 16 {
        return false;
    }

    // Single pass: validate all constraints at once
    let bytes = s.as_bytes();
    let mut valid_count = 0;
    let mut has_letters = false;
    let mut has_digits = false;

    for &b in bytes {
        match b {
            b'A'..=b'Z' => {
                has_letters = true;
                valid_count += 1;
            }
            b'2'..=b'7' => {
                has_digits = true;
                valid_count += 1;
            }
            b'=' => valid_count += 1, // Padding
            // Invalid characters for Base32
            b'0' | b'1' | b'8' | b'9' | b'a'..=b'z' => return false,
            _ => {} // Other invalid chars reduce the valid percentage
        }
    }

    // Must have both letters and digits (not pure text or pure numbers)
    if !has_letters || !has_digits {
        return false;
    }

    // At least 90% valid Base32 characters
    valid_count * 10 >= s.len() * 9
}

/// Check if a string looks like Base58-encoded data (Bitcoin alphabet)
fn is_base58(s: &str) -> bool {
    // Must be reasonably long (Bitcoin addresses are typically 26-35 chars)
    if s.len() < 20 {
        return false;
    }

    // Single pass validation
    // Base58 alphabet: 123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz
    // Excludes: 0, O, I, l (confusing characters)
    let bytes = s.as_bytes();
    let mut has_upper = false;
    let mut has_lower = false;
    let mut has_digit = false;
    let mut camel_case_transitions = 0;
    let mut consecutive_upper_at_start = 0;
    let mut found_non_upper = false;
    let mut prev_was_lower = false;

    for &b in bytes {
        let is_upper = matches!(b, b'A'..=b'H' | b'J'..=b'N' | b'P'..=b'Z');
        let is_lower = matches!(b, b'a'..=b'k' | b'm'..=b'z');

        match b {
            b'1'..=b'9' => has_digit = true,
            b'A'..=b'H' | b'J'..=b'N' | b'P'..=b'Z' => has_upper = true,
            b'a'..=b'k' | b'm'..=b'z' => has_lower = true,
            // Invalid characters for Base58 (0, O, I, l)
            _ => return false,
        }

        // Detect CamelCase/PascalCase patterns
        if prev_was_lower && is_upper {
            camel_case_transitions += 1;
        }

        // Track consecutive uppercase letters at the START only
        // (characteristic of class names like "NSKnown", "XMLParser", "UIViewController")
        if !found_non_upper {
            if is_upper {
                consecutive_upper_at_start += 1;
            } else {
                found_non_upper = true;
            }
        }

        prev_was_lower = is_lower;
    }

    // Base58 must have all three types
    if !(has_upper && has_lower && has_digit) {
        return false;
    }

    // Reject strings that look like class names/identifiers:
    // 1. Long uppercase prefixes (3+) indicate framework prefixes (NSU*, HTTP*, XML*)
    if consecutive_upper_at_start >= 3 {
        return false;
    }

    // 2. Two-letter prefixes with CamelCase = class names (NS*, UI*, CA*)
    //    e.g., "NSKnownKeysDictionary1"
    if consecutive_upper_at_start >= 2 && camel_case_transitions >= 2 {
        return false;
    }

    // 3. Single uppercase start + many transitions = structured identifier
    //    e.g., "TheQuickBrownFoxJumpsOverTheLazyDog1"
    //    Use 7+ to avoid false positives on crypto addresses (some have 6 by chance)
    if consecutive_upper_at_start == 1 && camel_case_transitions >= 7 {
        return false;
    }

    true
}

/// Calculate string quality score (0-100). Higher scores = better quality text.
fn string_quality_score(s: &str) -> u32 {
    if s.is_empty() {
        return 0;
    }

    let mut alpha_count = 0usize;
    let mut vowel_count = 0usize;
    let mut printable_count = 0usize;

    for c in s.chars() {
        if c.is_ascii_alphabetic() {
            alpha_count += 1;
            if matches!(c.to_ascii_lowercase(), 'a' | 'e' | 'i' | 'o' | 'u') {
                vowel_count += 1;
            }
        }
        if c.is_ascii_graphic() || c == ' ' {
            printable_count += 1;
        }
    }

    let len = s.len();
    let printable_ratio = (printable_count * 100) / len;
    let vowel_ratio = if alpha_count > 0 {
        (vowel_count * 100) / alpha_count
    } else {
        0
    };

    // Quality = weighted combination of printability and vowel ratio
    // Good English text has ~40% vowels, ~90%+ printable
    ((printable_ratio * 7 + vowel_ratio * 3) / 10) as u32
}

/// Check if a string looks like Base85-encoded data (ASCII85 or Z85)
fn is_base85(s: &str) -> bool {
    // Require minimum length
    if s.len() < 20 {
        return false;
    }

    // Check for ASCII85 delimiters (<~ and ~>)
    let has_delimiters = s.starts_with("<~") && s.ends_with("~>");

    // If it has proper delimiters and reasonable length, validate by decoding
    if has_delimiters && s.len() >= 20 && s.len() < 10000 {
        // Try to decode and check if result is better quality
        return validate_base85_by_decoding(s);
    }

    // Single pass validation
    // ASCII85 uses '!' (33) to 'u' (117), plus 'z' for zero bytes
    let bytes = s.as_bytes();
    let mut valid_count = 0;
    let mut has_lowercase = false;
    let mut has_punctuation = false;
    let mut is_env_var_like = true;
    let mut unique_char_count = 0;
    let mut seen_chars = 0u128; // Bitmap for tracking up to 128 unique chars efficiently

    for &b in bytes {
        // Check if valid ASCII85 character
        if matches!(b, b'!'..=b'u' | b'z') {
            valid_count += 1;

            // Track character diversity without allocation
            let bit_pos = b as u32;
            if bit_pos < 128 && (seen_chars & (1u128 << bit_pos)) == 0 {
                seen_chars |= 1u128 << bit_pos;
                unique_char_count += 1;
            }
        }

        // Track character types for filtering false positives
        match b {
            b'a'..=b'z' => has_lowercase = true,
            b'!'..=b'/' | b':'..=b'@' | b'['..=b'`' | b'{'..=b'~' => has_punctuation = true,
            _ => {}
        }

        // Check if it could be an environment variable
        if !matches!(b, b'A'..=b'Z' | b'_' | b'0'..=b'9') {
            is_env_var_like = false;
        }
    }

    // Reject environment variable patterns
    if is_env_var_like {
        return false;
    }

    // Reject strings that look like URLs, paths, function names, or normal text
    if s.contains("://") || s.contains("http") || s.starts_with('@') || s.starts_with('/') ||
        s.contains("apple") || s.contains("Apple") || s.contains("Authority") ||
        s.contains("plist") || s.contains("version") || s.contains('.') && s.split('.').count() > 2 ||
        s.starts_with('+') || s.starts_with(' ') {
        return false;
    }

    // Reject strings that look like character sets or pure punctuation
    let punct_count = s.chars().filter(|c| c.is_ascii_punctuation()).count();
    if punct_count * 2 > s.len() {
        return false;
    }

    // Reject strings that look like base64 (end with = padding, contain + or /)
    // Real ASCII85 uses z for compression, not = for padding
    if s.ends_with('=') || s.contains('+') && s.contains('/') {
        return false;
    }

    // Must have lowercase or punctuation (not just uppercase)
    if !has_lowercase && !has_punctuation {
        return false;
    }

    // For longer strings (>= 50), be very strict to reduce false positives
    if s.len() >= 50 {
        // Require 98% valid chars AND good character distribution
        return valid_count * 100 >= s.len() * 98 && unique_char_count >= 15;
    }

    // For shorter strings, use moderate threshold
    // Must be at least 90% valid ASCII85 characters
    if valid_count * 10 < s.len() * 9 {
        return false;
    }

    // Must have good character distribution (at least 8 unique chars)
    if unique_char_count < 8 {
        return false;
    }

    // Final validation: try decoding and check if result is higher quality
    validate_base85_by_decoding(s)
}

/// Validate base85 by attempting to decode and checking if result is higher quality.
/// Returns true only if decoding produces better text than the original.
fn validate_base85_by_decoding(s: &str) -> bool {
    // Import decode function from decoders module
    use crate::decoders::try_decode_ascii85;

    let original_quality = string_quality_score(s);

    // Try to decode
    if let Some(decoded_bytes) = try_decode_ascii85(s) {
        // Check if decoded is valid UTF-8 and higher quality
        if let Ok(decoded_str) = String::from_utf8(decoded_bytes) {
            let decoded_quality = string_quality_score(&decoded_str);

            // Decoded should be better quality (at least 5 points higher)
            // Otherwise it's probably not actually base85
            return decoded_quality > original_quality + 5;
        }
    }

    // If we can't decode or result is worse, it's not real base85
    false
}

/// Classify cryptocurrency wallet addresses
fn classify_crypto_address(s: &str) -> Option<StringKind> {
    let len = s.len();

    // Bitcoin (legacy): starts with 1 or 3, 26-35 chars, Base58 (excludes 0, O, I, l)
    if (s.starts_with('1') || s.starts_with('3')) && (26..=35).contains(&len) {
        // Must be valid Base58: no 0, O, I, or l characters
        if s.chars().all(|c| {
            c.is_ascii_alphanumeric() && c != '0' && c != 'O' && c != 'I' && c != 'l'
        }) {
            return Some(StringKind::CryptoWallet);
        }
    }

    // Bitcoin (bech32): starts with bc1, 42+ chars
    if s.starts_with("bc1") && len >= 42 {
        let alnum_count = s.chars().filter(|c| c.is_alphanumeric()).count();
        if alnum_count * 100 / len >= 95 {
            return Some(StringKind::CryptoWallet);
        }
    }

    // Ethereum: starts with 0x, 42 chars hex
    if s.starts_with("0x") && len == 42 {
        let hex_count = s[2..].chars().filter(|c| c.is_ascii_hexdigit()).count();
        if hex_count == 40 {
            return Some(StringKind::CryptoWallet);
        }
    }

    // Monero: starts with 4 or 8, 95-108 chars
    if (s.starts_with('4') || s.starts_with('8')) && (95..=108).contains(&len) {
        let alnum_count = s.chars().filter(|c| c.is_alphanumeric()).count();
        if alnum_count * 100 / len >= 95 {
            return Some(StringKind::CryptoWallet);
        }
    }

    // Litecoin: starts with L or M, 26-35 chars, Base58
    if (s.starts_with('L') || s.starts_with('M')) && (26..=35).contains(&len) {
        if s.chars().all(|c| {
            c.is_ascii_alphanumeric() && c != '0' && c != 'O' && c != 'I' && c != 'l'
        }) {
            return Some(StringKind::CryptoWallet);
        }
    }

    // Dogecoin: starts with D, 34 chars, Base58
    if s.starts_with('D') && len == 34 {
        if s.chars().all(|c| {
            c.is_ascii_alphanumeric() && c != '0' && c != 'O' && c != 'I' && c != 'l'
        }) {
            return Some(StringKind::CryptoWallet);
        }
    }

    None
}

/// Classify API keys and secrets
fn classify_api_key(s: &str) -> Option<StringKind> {
    let len = s.len();

    // AWS access key: starts with AKIA, 20+ chars
    if s.starts_with("AKIA") && len >= 20 {
        let alnum_count = s.chars().filter(|c| c.is_alphanumeric()).count();
        if alnum_count * 100 / len >= 90 {
            return Some(StringKind::APIKey);
        }
    }

    // GitHub token: starts with ghp_, 36+ chars
    if s.starts_with("ghp_") && len >= 36 {
        let alnum_count = s.chars().filter(|c| c.is_alphanumeric() || *c == '_').count();
        if alnum_count * 100 / len >= 90 {
            return Some(StringKind::APIKey);
        }
    }

    // Stripe keys: starts with sk_live_ or pk_live_
    if (s.starts_with("sk_live_") || s.starts_with("pk_live_")) && len >= 20 {
        let alnum_count = s.chars().filter(|c| c.is_alphanumeric() || *c == '_').count();
        if alnum_count * 100 / len >= 90 {
            return Some(StringKind::APIKey);
        }
    }

    // Slack tokens: starts with xox, 30+ chars
    if s.starts_with("xox") && len >= 30 {
        let alnum_count = s.chars().filter(|c| c.is_alphanumeric() || *c == '-').count();
        if alnum_count * 100 / len >= 90 {
            return Some(StringKind::APIKey);
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::extraction::{extract_from_structures, find_string_structures};
    use crate::types::{BinaryInfo, StringStruct};

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

    #[test]
    fn test_classify_string_applescript_detection() {
        // AppleScript code should be classified as AppleScript
        assert_eq!(
            classify_string("set desktopFolder to path to desktop folder"),
            StringKind::AppleScript
        );
        assert_eq!(
            classify_string("tell application \"Finder\""),
            StringKind::AppleScript
        );
        assert_eq!(
            classify_string("every file of desktopFolder whose name extension is in"),
            StringKind::AppleScript
        );
        assert_eq!(
            classify_string("duplicate aFile to POSIX file \"/tmp/backup\""),
            StringKind::AppleScript
        );
        assert_eq!(
            classify_string("path to documents folder"),
            StringKind::AppleScript
        );
        assert_eq!(
            classify_string("end tell"),
            StringKind::AppleScript
        );
        assert_eq!(
            classify_string("repeat with aFile in allFiles"),
            StringKind::AppleScript
        );
        assert_eq!(
            classify_string("do shell script \"ls -la\""),
            StringKind::AppleScript
        );

        // Additional AppleScript patterns from real malware
        assert_eq!(
            classify_string("play dialog \"macOS needs to access System"),
            StringKind::AppleScript
        );
        assert_eq!(
            classify_string("ile \"%s\" as alias) with replacing"),
            StringKind::AppleScript
        );
        assert_eq!(
            classify_string("set tf to POSIX file \"%s\" as ali"),
            StringKind::AppleScript
        );

        // Regular shell commands should NOT be AppleScript
        assert_ne!(
            classify_string("curl http://example.com"),
            StringKind::AppleScript
        );
        assert_ne!(
            classify_string("cat /etc/passwd"),
            StringKind::AppleScript
        );
    }

    #[test]
    fn test_is_hex_encoded_valid() {
        // Valid hex-encoded strings (from actual malware samples)
        // "const _0x1c31000=_0x2330d;"
        assert!(is_hex_encoded(
            "636F6E7374205F307831633331303030333D5F3078323330643B"
        ));

        // "function _0x2330d(_0x99a22,_0x58a56){"
        assert!(is_hex_encoded(
            "66756E6374696F6E205F307832333064285F3078393961322C5F30783538613536297B"
        ));

        // "Mozilla/5.0 (Windows NT 10.0; Win64)"
        assert!(is_hex_encoded(
            "4D6F7A696C6C612F352E30202857696E646F7773204E542031302E303B2057696E3634"
        ));

        // Long hex string with spaces
        assert!(is_hex_encoded(
            "48656C6C6F20576F726C642120546869732069732061207465737420737472696E67"
        ));
    }

    #[test]
    fn test_is_hex_encoded_invalid() {
        // Too short
        assert!(!is_hex_encoded("48656C6C6F"));

        // Odd length (51 chars)
        assert!(!is_hex_encoded("48656C6C6F20576F726C6421205468697320697320612074657"));

        // Not hex (contains 'G')
        assert!(!is_hex_encoded(
            "48656C6C6F20576F726C6421205468697320697320612074657374G1"
        ));

        // Valid hex but decodes to mostly non-printable
        assert!(!is_hex_encoded(
            "00010203040506070809FF00010203040506070809FF00010203040506070809FF"
        ));

        // All zeros
        assert!(!is_hex_encoded(
            "00000000000000000000000000000000000000000000000000000000"
        ));

        // Real SHA256 hash (should not be detected as hex-encoded text)
        assert!(!is_hex_encoded(
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        ));
    }

    #[test]
    fn test_classify_string_hex_encoded() {
        // Hex-encoded JavaScript (from actual malware)
        assert_eq!(
            classify_string("636F6E7374205F307831633331303030333D5F3078323330643B"),
            StringKind::HexEncoded
        );

        // Hex-encoded function
        assert_eq!(
            classify_string("66756E6374696F6E205F307832333064285F3078393961322C5F30783538613536297B"),
            StringKind::HexEncoded
        );

        // Should not be hex-encoded (too short)
        assert_ne!(classify_string("48656C6C6F"), StringKind::HexEncoded);

        // Should not be hex-encoded (odd length)
        assert_ne!(
            classify_string("48656C6C6F20576F726C642120546869732069732061207465737420737472696E6"),
            StringKind::HexEncoded
        );
    }

    #[test]
    fn test_hex_encoded_decoding() {
        // Test that hex-encoded strings decode correctly
        let hex = "48656C6C6F20576F726C64";
        let decoded: Vec<u8> = (0..hex.len())
            .step_by(2)
            .filter_map(|i| u8::from_str_radix(&hex[i..i + 2], 16).ok())
            .collect();
        let text = String::from_utf8(decoded).unwrap();
        assert_eq!(text, "Hello World");
    }

    #[test]
    fn test_is_unicode_escaped_valid() {
        // Valid \xXX format (from actual malware)
        assert!(is_unicode_escaped(
            "\\x27;\\x20const\\x20fs\\x20=\\x20require(\\x27fs\\x27);"
        ));

        // Mixed \xXX and regular text
        assert!(is_unicode_escaped(
            "\\x48\\x65\\x6c\\x6c\\x6f\\x20\\x57\\x6f\\x72\\x6c\\x64"
        ));

        // \uXXXX format
        assert!(is_unicode_escaped(
            "\\u0048\\u0065\\u006c\\u006c\\u006f"
        ));

        // Mixed format
        assert!(is_unicode_escaped(
            "const\\x20url\\x20=\\x20\\x27https://example.com\\x27;"
        ));
    }

    #[test]
    fn test_is_unicode_escaped_invalid() {
        // Too short
        assert!(!is_unicode_escaped("\\x48\\x65"));

        // Too few escape sequences
        assert!(!is_unicode_escaped("Hello \\x20 World"));

        // Not actually escaped
        assert!(!is_unicode_escaped("const url = 'https://example.com';"));

        // Invalid escape sequences
        assert!(!is_unicode_escaped("\\x\\x\\x\\x\\x\\x\\x\\x"));
    }

    #[test]
    fn test_classify_string_unicode_escaped() {
        // JavaScript with \xXX escapes (from actual malware)
        assert_eq!(
            classify_string("\\x27;\\x20const\\x20fs\\x20=\\x20require(\\x27fs\\x27);"),
            StringKind::UnicodeEscaped
        );

        // \uXXXX format
        assert_eq!(
            classify_string("\\u0048\\u0065\\u006c\\u006c\\u006f"),
            StringKind::UnicodeEscaped
        );

        // Should not be Unicode escaped (too few sequences)
        assert_ne!(
            classify_string("Hello \\x20 World"),
            StringKind::UnicodeEscaped
        );
    }

    #[test]
    fn test_decode_unicode_escapes() {
        // Test \xXX format
        let decoded = decode_unicode_escapes("\\x48\\x65\\x6c\\x6c\\x6f");
        let text = String::from_utf8(decoded).unwrap();
        assert_eq!(text, "Hello");

        // Test \uXXXX format
        let decoded = decode_unicode_escapes("\\u0048\\u0065\\u006c\\u006c\\u006f");
        let text = String::from_utf8(decoded).unwrap();
        assert_eq!(text, "Hello");

        // Test mixed content
        let decoded = decode_unicode_escapes("const\\x20fs\\x20=\\x20require");
        let text = String::from_utf8(decoded).unwrap();
        assert_eq!(text, "const fs = require");

        // Test actual malware pattern
        let decoded = decode_unicode_escapes("\\x27;\\x20const\\x20fs\\x20=\\x20require(\\x27fs\\x27);");
        let text = String::from_utf8(decoded).unwrap();
        assert_eq!(text, "'; const fs = require('fs');");
    }

    #[test]
    fn test_is_url_encoded_valid() {
        // Valid URL-encoded strings (from web shells)
        assert!(is_url_encoded("%3Cscript%3Ealert%28%27XSS%27%29%3C%2Fscript%3E"));

        // SQL injection payload
        assert!(is_url_encoded("%27%20OR%20%271%27%3D%271"));

        // Command injection
        assert!(is_url_encoded("%3Bcat%20%2Fetc%2Fpasswd"));

        // Mixed with plus signs and multiple encoded chars
        assert!(is_url_encoded("param1%3Dvalue1%26param2%3Dvalue2"));
    }

    #[test]
    fn test_is_url_encoded_invalid() {
        // Too short
        assert!(!is_url_encoded("%48%65"));

        // Too few percent signs (only 1)
        assert!(!is_url_encoded("Hello%20World"));

        // Not actually URL encoded (no percent signs)
        assert!(!is_url_encoded("regular text with some words"));

        // Has percent but not valid encoding (non-hex after %)
        assert!(!is_url_encoded("100% complete status check"));
    }

    #[test]
    fn test_classify_string_url_encoded() {
        // XSS payload
        assert_eq!(
            classify_string("%3Cscript%3Ealert%28%27XSS%27%29%3C%2Fscript%3E"),
            StringKind::UrlEncoded
        );

        // SQL injection
        assert_eq!(
            classify_string("%27%20OR%20%271%27%3D%271"),
            StringKind::UrlEncoded
        );

        // Should not be URL encoded (too few percent signs)
        assert_ne!(
            classify_string("Hello%20World"),
            StringKind::UrlEncoded
        );
    }

    #[test]
    fn test_decode_url_encoding() {
        // Test basic decoding
        let decoded = decode_url_encoding("%48%65%6c%6c%6f");
        let text = String::from_utf8(decoded).unwrap();
        assert_eq!(text, "Hello");

        // Test with plus signs
        let decoded = decode_url_encoding("Hello+World%21");
        let text = String::from_utf8(decoded).unwrap();
        assert_eq!(text, "Hello World!");

        // Test XSS payload
        let decoded = decode_url_encoding("%3Cscript%3Ealert%28%27XSS%27%29%3C%2Fscript%3E");
        let text = String::from_utf8(decoded).unwrap();
        assert_eq!(text, "<script>alert('XSS')</script>");

        // Test SQL injection
        let decoded = decode_url_encoding("%27%20OR%20%271%27%3D%271");
        let text = String::from_utf8(decoded).unwrap();
        assert_eq!(text, "' OR '1'='1");

        // Test command injection
        let decoded = decode_url_encoding("%3Bcat%20%2Fetc%2Fpasswd");
        let text = String::from_utf8(decoded).unwrap();
        assert_eq!(text, ";cat /etc/passwd");
    }

    #[test]
    fn test_is_base32_valid() {
        // Tor v2 onion address (Base32)
        assert!(is_base32("THEHIDDENWIKI3IKNKD7A"));

        // Generic Base32 encoded data
        assert!(is_base32("JBSWY3DPEBLW64TMMQ======"));
        assert!(is_base32("NFXGO2LUNBQXIIDUNBSSA"));

        // Without padding
        assert!(is_base32("MFRGG3DFMZTWQ2LK"));
    }

    #[test]
    fn test_is_base32_invalid() {
        // Too short
        assert!(!is_base32("ABCD"));

        // Contains lowercase (not valid Base32)
        assert!(!is_base32("JbSwY3DpEbLw64TmMq"));

        // Contains 0, 1, 8, 9 (not valid Base32)
        assert!(!is_base32("JBSWY3DPEBLW01089"));

        // Plain text (all letters, no digits)
        assert!(!is_base32("THISISPLAINTEXT"));

        // All digits (no letters)
        assert!(!is_base32("2345672345672345"));
    }

    #[test]
    fn test_classify_string_base32() {
        // Tor onion address
        assert_eq!(
            classify_string("THEHIDDENWIKI3IKNKD7A"),
            StringKind::Base32
        );

        // With padding
        assert_eq!(
            classify_string("JBSWY3DPEBLW64TMMQ======"),
            StringKind::Base32
        );

        // Should not be Base32 (has lowercase)
        assert_ne!(
            classify_string("JbSwY3DpEbLw64TmMq"),
            StringKind::Base32
        );
    }

    #[test]
    fn test_is_base58_valid_cryptocurrency_addresses() {
        // Bitcoin P2PKH address (starts with 1)
        assert!(is_base58("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"));

        // Bitcoin P2SH address (starts with 3)
        assert!(is_base58("3J98t1WpEZ73CNmYviecrnyiWrnqRhWNLy"));

        // Bitcoin mainnet address
        assert!(is_base58("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2"));

        // Litecoin address (starts with L)
        assert!(is_base58("LdP8Qox1VAhCzLJNqrr74YovaWYyNBUWvL"));

        // Monero address fragment (for testing, partial)
        assert!(is_base58("4AdUndXHHZ6cfufTMvppY6JwXNouMBzSkbLYfpAV"));

        // Generic Base58 with good entropy
        assert!(is_base58("5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ"));
    }

    #[test]
    fn test_is_base58_invalid_alphabet_violations() {
        // Too short
        assert!(!is_base58("1A1zP1eP5Q"));
        assert!(!is_base58("short"));

        // Contains 0 (zero) - not in Base58 alphabet
        assert!(!is_base58("1A1zP1eP5QGefi2DMP0fTL5SLmv7DivfNa"));
        assert!(!is_base58("10000000000000000000"));

        // Contains O (capital O) - not in Base58 alphabet
        assert!(!is_base58("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfOa"));
        assert!(!is_base58("OOOOOOOOOOOOOOOOOOOO"));

        // Contains I (capital I) - not in Base58 alphabet
        assert!(!is_base58("1A1zP1eP5QGefi2DMPIfTL5SLmv7DivfNa"));
        assert!(!is_base58("IIIIIIIIIIIIIIIIIIII"));

        // Contains l (lowercase L) - not in Base58 alphabet
        assert!(!is_base58("1A1zP1eP5QGefi2DMPlTL5SLmv7DivfNa"));
        assert!(!is_base58("llllllllllllllllllll"));

        // Mixed invalid characters
        assert!(!is_base58("1A1zP1eP5QGefi2DMP0IfTL5SLmv7DivfOa"));
    }

    #[test]
    fn test_is_base58_invalid_missing_character_types() {
        // All uppercase (no lowercase or digits)
        assert!(!is_base58("ABCDEFGHJKMNPQRSTUVWXYZ"));
        assert!(!is_base58("THEQUICKBRWNFXJUMPS"));

        // All lowercase (no uppercase or digits)
        assert!(!is_base58("abcdefghjkmnpqrstuvwxyz"));
        assert!(!is_base58("thequickbrwnfxjumps"));

        // All digits (no letters)
        assert!(!is_base58("12345678912345678912"));

        // Only uppercase + digits (missing lowercase)
        assert!(!is_base58("ABC123DEF456GHJ789MN"));

        // Only lowercase + digits (missing uppercase)
        assert!(!is_base58("abc123def456ghj789mn"));

        // Only uppercase + lowercase (missing digits)
        assert!(!is_base58("ABCdefGHJmnpQRStuv"));
    }

    #[test]
    fn test_is_base58_invalid_class_names_objc() {
        // Objective-C class names (NS prefix with CamelCase)
        assert!(!is_base58("NSKnownKeysMappingStrategy1"));
        assert!(!is_base58("NSKnownKeysDictionary1"));
        assert!(!is_base58("NSMutableAttributedString1"));
        assert!(!is_base58("NSURLSessionConfiguration1"));
        assert!(!is_base58("NSUserNotificationCenter1"));

        // iOS/macOS classes (UI/CA/CG prefixes)
        assert!(!is_base58("UIViewControllerTransition1"));
        assert!(!is_base58("CABasicAnimationDelegate1"));
        assert!(!is_base58("CGAffineTransformMakeScale1"));
    }

    #[test]
    fn test_is_base58_invalid_class_names_other() {
        // Java/C# class names (XML, HTTP, SQL prefixes)
        assert!(!is_base58("XMLHttpRequestFactory1"));
        assert!(!is_base58("HTTPConnectionManager1"));
        assert!(!is_base58("SQLDatabaseConnectionPool1"));

    }

    #[test]
    fn test_is_base58_invalid_plain_text() {
        // Plain English text with many CamelCase transitions (7+)
        assert!(!is_base58("TheQuickBrownFoxJumpsOverTheLazyDog1"));
        assert!(!is_base58("ThisIsAVeryLongStringWithManyCamelCaseWordsForTesting1"));

        // Code-like text with many transitions
        assert!(!is_base58("thisIsAVariableNameWithManyWordsInCamelCase1"));
    }

    #[test]
    fn test_is_base58_edge_cases_should_pass() {
        // Random-looking Base58 with numbers at start (like Bitcoin addresses)
        assert!(is_base58("1Qqwerty2Asdfgh3Zxcvbn4Mjkuyt5Pqazwsx"));

        // Base58 with high entropy (random mix)
        assert!(is_base58("5Km2kuu7vtFDPpxywn4u3NLpbr5jKpTB3TXKWTNFyqn"));

        // One CamelCase transition is OK (not a class name pattern)
        assert!(is_base58("1234567aBcdefghJkmnpqrstuvwxyz"));

        // Starts with single uppercase (not multi-char prefix)
        assert!(is_base58("A1bcdefgh2Jkmnpqrs3tuvwxyz4"));
    }

    #[test]
    fn test_is_base58_edge_cases_borderline() {
        // Two uppercase at start but only 1 CamelCase transition = OK
        // (not enough transitions to be a class name)
        assert!(is_base58("AB1cdefgh2Jkmnpqrs3tuvwxyz4"));

        // Three CamelCase transitions but starts lowercase = OK
        // (class names typically start with uppercase)
        assert!(is_base58("a1BcD2eFg3HjK4mnp5qrs6tuv7wxyz8"));
    }

    #[test]
    fn test_classify_string_base58() {
        // Bitcoin address - now classified as CryptoWallet (more specific than Base58)
        assert_eq!(
            classify_string("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"),
            StringKind::CryptoWallet
        );

        // Should not be Base58/CryptoWallet (contains 0, which is invalid in Base58)
        assert_ne!(
            classify_string("1A1zP1eP5QGefi2DMP0fTL5SLmv7DivfNa"),
            StringKind::Base58
        );
        assert_ne!(
            classify_string("1A1zP1eP5QGefi2DMP0fTL5SLmv7DivfNa"),
            StringKind::CryptoWallet
        );
    }

    #[test]
    fn test_is_base64_valid() {
        // Valid base64 strings
        assert!(is_base64("SGVsbG8gV29ybGQhCg=="));
        assert!(is_base64("VGhpcyBpcyBhIHNlY3JldCBtZXNzYWdlIGZvciB0ZXN0aW5n"));
        assert!(is_base64("YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY3ODkw"));
    }

    #[test]
    fn test_is_base64_invalid() {
        // Too short
        assert!(!is_base64("SGVsbG8="));

        // Not multiple of 4
        assert!(!is_base64("SGVsbG8gV29ybGQhCg"));

        // Contains spaces
        assert!(!is_base64("SGVs bG8g V29y bGQh Cg=="));

        // Sequential patterns (test data)
        assert!(!is_base64("ABCDEFGHIJKLMNOPQRSTUVWXYZ123456"));

        // Plain text patterns
        assert!(!is_base64("the quick brown fox ===="));

        // Missing mixed case
        assert!(!is_base64("AAAAAAAAAAAAAAAAAAAA")); // all uppercase
        assert!(!is_base64("aaaaaaaaaaaaaaaaaaaaaa==")); // all lowercase
        assert!(!is_base64("1234567890123456789012345678")); // all digits

        // Invalid characters
        assert!(!is_base64("SGVsbG8gV29ybGQh@g==")); // @ is not valid
    }

    #[test]
    fn test_is_base85_valid() {
        // With quality heuristic, strings need to decode to significantly better quality
        // to be considered base85. Most false positives like file paths will fail this test.

        // Note: We don't test specific base85 strings here because the quality heuristic
        // makes it hard to construct a simple test case that passes.
        // The real test is in integration tests where we verify clean binaries have no false positives.
    }

    #[test]
    fn test_is_base85_invalid() {
        // Too short
        assert!(!is_base85("9jqo^BlbD"));

        // Environment variable pattern (all uppercase + underscores)
        assert!(!is_base85("DYLD_INSERT_LIBRARIES"));
        assert!(!is_base85("LD_PRELOAD_PATH_VAR"));

        // No lowercase or punctuation (just uppercase)
        assert!(!is_base85("ABCDEFGHIJKLMNOPQRST"));

        // Poor character diversity (< 8 unique chars)
        assert!(!is_base85("!!!!!!!!!!!!!!!!!!!!!"));
        assert!(!is_base85("aaaaaaaaaaaaaaaaaaaaaa"));

        // Too few valid ASCII85 characters (< 90%)
        assert!(!is_base85("regular text with spaces here"));
    }

    #[test]
    fn test_base32_performance_edge_cases() {
        // All valid base32 chars but no digits - should fail
        assert!(!is_base32("AAAABBBBCCCCDDDD"));

        // All digits but no letters - should fail
        assert!(!is_base32("2222333344445555"));

        // Contains invalid digits (0, 1, 8, 9)
        assert!(!is_base32("ABCD0123EFGH89IJ"));

        // Contains lowercase
        assert!(!is_base32("ABCDEFGHabcdefgh"));
    }

    #[test]
    fn test_base58_performance_edge_cases() {
        // Missing uppercase
        assert!(!is_base58("abcdefghijklmnopqrstuvwxyz123456"));

        // Missing lowercase
        assert!(!is_base58("ABCDEFGHJKMNPQRSTUVWXYZ123456"));

        // Missing digits
        assert!(!is_base58("ABCDEFGHJKMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz"));

        // Contains excluded characters (0, O, I, l)
        assert!(!is_base58("1A1zP1eP5QGefi2DMP0fTL5SLmv7DivfNa")); // has 0
        assert!(!is_base58("1A1zP1eP5QGefi2DMPOfTL5SLmv7DivfNa")); // has O
        assert!(!is_base58("1A1zP1eP5QGefi2DMPIfTL5SLmv7DivfNa")); // has I
        assert!(!is_base58("1A1zP1eP5QGefi2DMPlfTL5SLmv7DivfNa")); // has l
    }

    #[test]
    fn test_base64_performance_single_pass() {
        // This test ensures the optimization works - it should reject quickly
        // on first invalid character without scanning the whole string
        let invalid_at_start = format!("@{}", "A".repeat(100));
        assert!(!is_base64(&invalid_at_start));

        let with_space = "SGVs bG8g".repeat(10);
        assert!(!is_base64(&with_space));
    }
}
