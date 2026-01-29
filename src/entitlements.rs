//! Mach-O entitlements extraction from code signatures.

use crate::types::{ExtractedString, StringKind, StringMethod};
use goblin::mach::MachO;

pub fn extract_macho_entitlements_xml(data: &[u8]) -> Option<String> {
    use goblin::mach::load_command::CommandVariant;
    use goblin::Object;

    let macho = match Object::parse(data) {
        Ok(Object::Mach(goblin::mach::Mach::Binary(m))) => m,
        _ => return None,
    };

    // Find LC_CODE_SIGNATURE load command
    for cmd in &macho.load_commands {
        if let CommandVariant::CodeSignature(ref cs) = cmd.command {
            let offset = cs.dataoff as usize;
            let size = cs.datasize as usize;

            if offset + size > data.len() {
                continue;
            }

            let cs_data = &data[offset..offset + size];

            // Look for XML plist (starts with <?xml)
            if let Some(xml_start) = cs_data.windows(5).position(|w| w == b"<?xml") {
                let xml_data = &cs_data[xml_start..];

                // Find end of plist
                if let Some(plist_end) = xml_data.windows(8).position(|w| w == b"</plist>") {
                    let xml_content = &xml_data[..plist_end + 8]; // include </plist>

                    if let Ok(xml_str) = String::from_utf8(xml_content.to_vec()) {
                        return Some(xml_str);
                    }
                }
            }
        }
    }

    None
}

/// Extract entitlements from Mach-O code signature as raw XML.
///
/// Returns the full XML plist as a single string for inline display.
pub(crate) fn extract_macho_entitlements(
    macho: &MachO,
    data: &[u8],
    _min_length: usize,
) -> Vec<ExtractedString> {
    use goblin::mach::load_command::CommandVariant;

    let mut entitlements = Vec::new();

    // Find LC_CODE_SIGNATURE load command
    for cmd in &macho.load_commands {
        if let CommandVariant::CodeSignature(ref cs) = cmd.command {
            let offset = cs.dataoff as usize;
            let size = cs.datasize as usize;

            if offset + size > data.len() {
                continue;
            }

            let cs_data = &data[offset..offset + size];

            // Look for XML plist (starts with <?xml)
            if let Some(xml_start) = cs_data.windows(5).position(|w| w == b"<?xml") {
                let xml_data = &cs_data[xml_start..];

                // Find end of plist
                if let Some(plist_end) = xml_data.windows(8).position(|w| w == b"</plist>") {
                    let xml_content = &xml_data[..plist_end + 8]; // include </plist>

                    if let Ok(xml_str) = String::from_utf8(xml_content.to_vec()) {
                        entitlements.push(ExtractedString {
                            value: xml_str,
                            data_offset: (offset + xml_start) as u64,
                            section: Some("__LINKEDIT".to_string()),
                            method: StringMethod::CodeSignature,
                            kind: StringKind::EntitlementsXml,
                            library: None,
                    fragments: None,
                    });
                    }
                }
            }
        }
    }

    entitlements
}

/// Simple XML parser to extract entitlement key strings from plist.
///
/// Extracts text between <key> and </key> tags.
#[allow(dead_code)]
fn parse_entitlement_keys(xml: &[u8], base_offset: u64, min_length: usize) -> Vec<ExtractedString> {
    let mut keys = Vec::new();
    let xml_str = String::from_utf8_lossy(xml);

    // Simple regex-free parser: find <key>...</key> patterns
    let mut offset = 0;
    while let Some(key_start) = xml_str[offset..].find("<key>") {
        let key_content_start = offset + key_start + 5; // after "<key>"
        if let Some(key_end_pos) = xml_str[key_content_start..].find("</key>") {
            let key_value = &xml_str[key_content_start..key_content_start + key_end_pos];

            if key_value.len() >= min_length {
                keys.push(ExtractedString {
                    value: key_value.to_string(),
                    data_offset: base_offset + key_content_start as u64,
                    section: Some("__LINKEDIT".to_string()),
                    method: StringMethod::CodeSignature,
                    kind: StringKind::Entitlement,
                    library: None,
                    fragments: None,
                    });
            }

            offset = key_content_start + key_end_pos + 6; // after "</key>"
        } else {
            break;
        }
    }

    // Also extract <string>...</string> values (app IDs, paths, etc.)
    let mut offset = 0;
    while let Some(str_start) = xml_str[offset..].find("<string>") {
        let str_content_start = offset + str_start + 8; // after "<string>"
        if let Some(str_end_pos) = xml_str[str_content_start..].find("</string>") {
            let str_value = &xml_str[str_content_start..str_content_start + str_end_pos];

            if str_value.len() >= min_length {
                keys.push(ExtractedString {
                    value: str_value.to_string(),
                    data_offset: base_offset + str_content_start as u64,
                    section: Some("__LINKEDIT".to_string()),
                    method: StringMethod::CodeSignature,
                    kind: StringKind::AppId,
                    library: None,
                    fragments: None,
                    });
            }

            offset = str_content_start + str_end_pos + 9; // after "</string>"
        } else {
            break;
        }
    }

    keys
}

