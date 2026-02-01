use stng::extract_stack_strings;
use std::path::PathBuf;

#[test]
fn test_react2shell_stack_strings() {
    let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    d.push("testdata/malware/react2shell");
    
    // Read the binary
    let data = std::fs::read(&d).expect("failed to read react2shell binary");

    // Extract stack strings
    let strings = extract_stack_strings(&data, 4);

    // Filter for the interesting ones
    let interesting: Vec<String> = strings.iter()
        .map(|s| s.value.clone())
        .filter(|s: &String| s.contains("/proc/"))
        .collect();

    // We expect the cleaned up versions, not the mangled ones
    // Old mangled: /proc/veversion
    // New expected: /proc/version
    assert!(interesting.contains(&"/proc/version".to_string()), "Should contain '/proc/version', found: {:?}", interesting);
    assert!(!interesting.contains(&"/proc/veversion".to_string()), "Should NOT contain mangled '/proc/veversion'");

    // Old mangled: /proc/se/self/se + tgroups
    // Result: /proc/self/setgroups (fully reconstructed across 3 writes)
    assert!(interesting.contains(&"/proc/self/setgroups".to_string()), "Should contain '/proc/self/setgroups', found: {:?}", interesting);
    
    // Check gid_map and uid_map
    assert!(interesting.contains(&"/proc/self/gid_map".to_string()), "Should contain '/proc/self/gid_map'");
    assert!(interesting.contains(&"/proc/self/uid_map".to_string()), "Should contain '/proc/self/uid_map'");
}
