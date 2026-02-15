// Test trim_leading_garbage on the AppleScript string

fn main() {
    let original = "?2ftell application \"Finder\"\nset desktopFolder to path to desktop folder\nset documentsFolder to path to documents folder\nset srcFiles to every file of desktopFolder whose name extension is in %s\nset docsFiles to every file of documentsFolder whose name extension is in %s\nset allFiles to srcFiles &";

    println!("Original length: {}", original.len());
    println!("Original first 100 chars: '{}'", original.chars().take(100).collect::<String>());
    println!();

    let trimmed = trim_leading_garbage(original);
    println!("After trim_leading_garbage:");
    println!("  Length: {}", trimmed.len());
    println!("  First 100 chars: '{}'", trimmed.chars().take(100).collect::<String>());
    println!("  Bytes trimmed: {}", original.len() - trimmed.len());
    println!();

    if trimmed.len() < 10 {
        println!("🔴 BUG: String was trimmed to almost nothing!");
    } else if trimmed.len() < original.len() / 2 {
        println!("⚠️  Warning: More than half the string was trimmed");
    } else {
        println!("✓ String mostly preserved");
    }
}

fn trim_leading_garbage(s: &str) -> &str {
    if s.is_empty() {
        return s;
    }

    // Strip leading single-byte XOR key artifacts
    if s.len() >= 2 {
        let without_first = &s[1..];

        let known_starts = [
            "launchctl",
            "screencapture",
            "osascript",
            "open ",
            "curl ",
            "wget ",
            "/bin/",
            "/usr/",
            "/Library/",
            "/etc/",
            "/var/",
            "~/",
        ];

        for pattern in &known_starts {
            if without_first.starts_with(pattern) {
                println!("  Trimmed prefix to known start: '{}'", pattern);
                return without_first;
            }
        }
    }

    // Strip single non-alphanumeric garbage bytes
    let chars: Vec<char> = s.chars().collect();
    if chars.len() >= 2 {
        let first = chars[0];
        let second = chars[1];

        let is_legitimate_prefix = matches!(
            first,
            '$' | '@' | '~' | '%' | '"' | '\'' | '(' | '[' | '{' | '<' | '/' | '\\' | '.'
        );

        if !first.is_alphanumeric()
            && !is_legitimate_prefix
            && !first.is_whitespace()
            && second.is_ascii_alphabetic()
        {
            println!("  Trimmed one garbage byte: '{}' (0x{:02x})", first, first as u8);
            return &s[first.len_utf8()..];
        }
    }

    // Check for URLs
    if let Some(pos) = s.find("http://") {
        println!("  Trimmed to http:// at position {}", pos);
        return &s[pos..];
    }
    if let Some(pos) = s.find("https://") {
        println!("  Trimmed to https:// at position {}", pos);
        return &s[pos..];
    }

    // Other path checks would go here...

    println!("  No trimming applied");
    s
}
