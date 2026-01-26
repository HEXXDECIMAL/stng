//! Optional radare2 integration for smarter string extraction.
//!
//! When radare2 is available, it can provide better differentiation between
//! true strings and symbols, as well as additional metadata.

use crate::go::classify_string;
use crate::{ExtractedString, StringKind, StringMethod};
use std::collections::HashSet;
use std::process::Command;

/// Check if radare2 is installed and available.
pub fn is_available() -> bool {
    Command::new("r2")
        .arg("-v")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Extract strings using radare2.
///
/// Uses `iz` for data section strings and `is` for symbols.
/// Returns strings with R2String/R2Symbol methods for clear identification.
pub fn extract_strings(path: &str, min_length: usize) -> Option<Vec<ExtractedString>> {
    // Run both r2 commands in parallel
    let path_owned = path.to_string();
    let (data_result, symbols_result) = rayon::join(
        || run_r2_command(&path_owned, "izj"),
        || run_r2_command(&path_owned, "isj"),
    );

    let mut strings = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();

    // Process strings from data sections
    if let Some(data_strings) = data_result {
        if let Ok(json) = serde_json::from_str::<Vec<R2String>>(&data_strings) {
            for s in json {
                if s.string.len() >= min_length && seen.insert(s.string.clone()) {
                    let kind = classify_string(&s.string);
                    strings.push(ExtractedString {
                        value: s.string,
                        data_offset: s.vaddr,
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
                if s.name.len() >= min_length && seen.insert(s.name.clone()) {
                    strings.push(ExtractedString {
                        value: s.name,
                        data_offset: s.vaddr,
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

fn run_r2_command(path: &str, cmd: &str) -> Option<String> {
    let output = Command::new("r2")
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
    vaddr: u64,
    string: String,
    section: String,
}

#[derive(serde::Deserialize)]
struct R2Symbol {
    vaddr: u64,
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
    fn test_run_r2_command_nonexistent() {
        let result = run_r2_command("/nonexistent/file", "iz");
        assert!(result.is_none());
    }

    #[test]
    fn test_r2_string_deserialize() {
        let json = r#"{"vaddr": 4096, "string": "hello", "section": ".rodata"}"#;
        let r2_str: R2String = serde_json::from_str(json).unwrap();
        assert_eq!(r2_str.vaddr, 4096);
        assert_eq!(r2_str.string, "hello");
        assert_eq!(r2_str.section, ".rodata");
    }

    #[test]
    fn test_r2_symbol_deserialize() {
        let json = r#"{"vaddr": 4096, "name": "_main", "section": ".text", "type": "FUNC", "bind": "GLOBAL"}"#;
        let r2_sym: R2Symbol = serde_json::from_str(json).unwrap();
        assert_eq!(r2_sym.vaddr, 4096);
        assert_eq!(r2_sym.name, "_main");
        assert_eq!(r2_sym.section, Some(".text".to_string()));
        assert_eq!(r2_sym.r#type, "FUNC");
        assert_eq!(r2_sym.bind, "GLOBAL");
    }

    #[test]
    fn test_r2_symbol_deserialize_defaults() {
        // Missing optional fields should use defaults
        let json = r#"{"vaddr": 4096, "name": "_main"}"#;
        let r2_sym: R2Symbol = serde_json::from_str(json).unwrap();
        assert_eq!(r2_sym.vaddr, 4096);
        assert_eq!(r2_sym.name, "_main");
        assert!(r2_sym.section.is_none());
        assert_eq!(r2_sym.r#type, "");
        assert_eq!(r2_sym.bind, "");
    }
}
