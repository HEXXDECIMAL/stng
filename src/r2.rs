//! Optional rizin/radare2 integration for smarter string extraction.
//!
//! Prefers rizin when available, falls back to radare2.
//! Provides better differentiation between true strings and symbols.

use crate::go::classify_string;
use crate::{ExtractedString, StringKind, StringMethod};
use std::collections::HashSet;
use std::process::Command;
use std::sync::OnceLock;

/// Which tool is available (cached after first check)
static TOOL: OnceLock<Option<&'static str>> = OnceLock::new();

/// Check if rizin or radare2 is available, preferring rizin.
pub fn is_available() -> bool {
    get_tool().is_some()
}

/// Get the available tool name (rizin preferred, then radare2)
fn get_tool() -> Option<&'static str> {
    *TOOL.get_or_init(|| {
        if Command::new("rizin")
            .arg("-v")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
        {
            Some("rizin")
        } else if Command::new("r2")
            .arg("-v")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
        {
            Some("r2")
        } else {
            None
        }
    })
}

/// Extract strings using rizin or radare2.
///
/// Uses `iz` for data section strings and `is` for symbols.
/// Returns strings with R2String/R2Symbol methods for clear identification.
pub fn extract_strings(path: &str, min_length: usize) -> Option<Vec<ExtractedString>> {
    let tool = get_tool()?;

    // Get file size to filter out symbols with invalid offsets
    let file_size = std::fs::metadata(path).ok()?.len();

    // Run both commands in parallel
    let path_owned = path.to_string();
    let (data_result, symbols_result) = rayon::join(
        || run_tool_command(tool, &path_owned, "izj"),
        || run_tool_command(tool, &path_owned, "isj"),
    );

    let mut strings = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();

    // Process strings from data sections
    if let Some(data_strings) = data_result {
        if let Ok(json) = serde_json::from_str::<Vec<R2String>>(&data_strings) {
            for s in json {
                // Skip strings with invalid file offsets
                if s.paddr > file_size {
                    continue;
                }
                if s.string.len() >= min_length && seen.insert(s.string.clone()) {
                    let kind = classify_string(&s.string);
                    strings.push(ExtractedString {
                        value: s.string,
                        data_offset: s.paddr,
                        section: Some(s.section),
                        method: StringMethod::R2String,
                        library: None,
                        kind,
                    });
                }
            }
        }
    }

    // Process symbols
    if let Some(symbols) = symbols_result {
        if let Ok(json) = serde_json::from_str::<Vec<R2Symbol>>(&symbols) {
            for s in json {
                // Skip symbols with invalid file offsets
                if s.paddr > file_size {
                    continue;
                }
                if s.name.len() >= min_length && seen.insert(s.name.clone()) {
                    strings.push(ExtractedString {
                        value: s.name,
                        data_offset: s.paddr,
                        section: s.section,
                        method: StringMethod::R2Symbol,
                        kind: classify_r2_symbol(&s.r#type, &s.bind),
                        library: None,
                    });
                }
            }
        }
    }

    if strings.is_empty() {
        None
    } else {
        Some(strings)
    }
}

fn run_tool_command(tool: &str, path: &str, cmd: &str) -> Option<String> {
    let output = Command::new(tool)
        .args(["-q", "-c", cmd, path])
        .output()
        .ok()?;

    if output.status.success() {
        String::from_utf8(output.stdout).ok()
    } else {
        None
    }
}

#[derive(serde::Deserialize)]
struct R2String {
    paddr: u64,
    string: String,
    section: String,
}

#[derive(serde::Deserialize)]
struct R2Symbol {
    paddr: u64,
    name: String,
    #[serde(default)]
    section: Option<String>,
    #[serde(default)]
    r#type: String,
    #[serde(default)]
    bind: String,
}

fn classify_r2_symbol(type_str: &str, bind: &str) -> StringKind {
    match type_str {
        "FUNC" | "METH" => StringKind::FuncName,
        "FILE" => StringKind::FilePath,
        "OBJECT" if bind == "GLOBAL" => StringKind::Ident,
        _ => StringKind::Ident,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_available() {
        // Just test that the function doesn't panic
        let _ = is_available();
    }

    #[test]
    fn test_classify_r2_symbol() {
        assert_eq!(classify_r2_symbol("FUNC", "GLOBAL"), StringKind::FuncName);
        assert_eq!(classify_r2_symbol("FILE", "LOCAL"), StringKind::FilePath);
        assert_eq!(classify_r2_symbol("OBJECT", "GLOBAL"), StringKind::Ident);
    }

    #[test]
    fn test_classify_r2_symbol_meth() {
        assert_eq!(classify_r2_symbol("METH", "GLOBAL"), StringKind::FuncName);
        assert_eq!(classify_r2_symbol("METH", "LOCAL"), StringKind::FuncName);
    }

    #[test]
    fn test_classify_r2_symbol_unknown_type() {
        assert_eq!(classify_r2_symbol("UNKNOWN", "GLOBAL"), StringKind::Ident);
        assert_eq!(classify_r2_symbol("", ""), StringKind::Ident);
        assert_eq!(classify_r2_symbol("NOTYPE", "LOCAL"), StringKind::Ident);
    }

    #[test]
    fn test_classify_r2_symbol_object_local() {
        // OBJECT with LOCAL binding should not be Ident
        assert_eq!(classify_r2_symbol("OBJECT", "LOCAL"), StringKind::Ident);
    }

    #[test]
    fn test_extract_strings_nonexistent_file() {
        let result = extract_strings("/nonexistent/file/path", 4);
        // Should return None for non-existent files
        assert!(result.is_none());
    }

    #[test]
    fn test_run_tool_command_nonexistent() {
        if let Some(tool) = get_tool() {
            let result = run_tool_command(tool, "/nonexistent/file", "iz");
            assert!(result.is_none());
        }
    }

    #[test]
    fn test_r2_string_deserialize() {
        let json = r#"{"paddr": 4096, "string": "hello", "section": ".rodata"}"#;
        let r2_str: R2String = serde_json::from_str(json).unwrap();
        assert_eq!(r2_str.paddr, 4096);
        assert_eq!(r2_str.string, "hello");
        assert_eq!(r2_str.section, ".rodata");
    }

    #[test]
    fn test_r2_symbol_deserialize() {
        let json = r#"{"paddr": 4096, "name": "_main", "section": ".text", "type": "FUNC", "bind": "GLOBAL"}"#;
        let r2_sym: R2Symbol = serde_json::from_str(json).unwrap();
        assert_eq!(r2_sym.paddr, 4096);
        assert_eq!(r2_sym.name, "_main");
        assert_eq!(r2_sym.section, Some(".text".to_string()));
        assert_eq!(r2_sym.r#type, "FUNC");
        assert_eq!(r2_sym.bind, "GLOBAL");
    }

    #[test]
    fn test_r2_symbol_deserialize_defaults() {
        // Missing optional fields should use defaults
        let json = r#"{"paddr": 4096, "name": "_main"}"#;
        let r2_sym: R2Symbol = serde_json::from_str(json).unwrap();
        assert_eq!(r2_sym.paddr, 4096);
        assert_eq!(r2_sym.name, "_main");
        assert!(r2_sym.section.is_none());
        assert_eq!(r2_sym.r#type, "");
        assert_eq!(r2_sym.bind, "");
    }

    #[test]
    fn test_extract_strings_returns_file_offsets() {
        if !is_available() {
            return;
        }
        // Use /bin/ls which exists on all Unix systems
        let result = extract_strings("/bin/ls", 4);
        if let Some(strings) = result {
            // /bin/ls is typically < 200KB, virtual addresses would be > 0x100000000
            let max_reasonable_offset = 0x100000; // 1MB - generous upper bound
            for s in &strings {
                assert!(
                    s.data_offset < max_reasonable_offset,
                    "Offset 0x{:x} for '{}' looks like a virtual address, not a file offset",
                    s.data_offset,
                    s.value
                );
            }
        }
    }

    #[test]
    fn test_paddr_present_in_tool_output() {
        // Verify both rizin and r2 provide paddr field
        let tool = match get_tool() {
            Some(t) => t,
            None => return,
        };

        // Check symbols JSON has paddr
        if let Some(output) = run_tool_command(tool, "/bin/ls", "isj") {
            let json: serde_json::Value = serde_json::from_str(&output).unwrap();
            if let Some(arr) = json.as_array() {
                if let Some(first) = arr.first() {
                    assert!(
                        first.get("paddr").is_some(),
                        "{} isj output missing paddr field",
                        tool
                    );
                }
            }
        }

        // Check strings JSON has paddr
        if let Some(output) = run_tool_command(tool, "/bin/ls", "izj") {
            let json: serde_json::Value = serde_json::from_str(&output).unwrap();
            if let Some(arr) = json.as_array() {
                if let Some(first) = arr.first() {
                    assert!(
                        first.get("paddr").is_some(),
                        "{} izj output missing paddr field",
                        tool
                    );
                }
            }
        }
    }
}
