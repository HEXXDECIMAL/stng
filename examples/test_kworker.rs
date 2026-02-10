use std::fs;

fn main() {
    let data = fs::read("testdata/kworker_samples/kworker_obfuscated_1").expect("read");

    let opts = stng::ExtractOptions::new(4);
    let extracted = stng::extract_strings_with_options(&data, &opts);

    println!("Total strings extracted: {}", extracted.len());

    println!("\nAll StackString kinds:");
    for s in &extracted {
        if matches!(s.kind, stng::StringKind::StackString) {
            println!("  0x{:x}: {:?}", s.data_offset, s.value);
        }
    }

    // Look specifically for kworker strings
    let kworker_strings: Vec<_> = extracted
        .iter()
        .filter(|s| s.value.contains("kworker") || s.value.contains("[k"))
        .collect();

    println!("\nKworker-related strings found: {}", kworker_strings.len());
    for s in &kworker_strings {
        println!(
            "  0x{:x}: {:?} (kind: {:?})",
            s.data_offset, s.value, s.kind
        );
    }
}
