use std::fs;

fn main() {
    let sample_path = "testdata/malware/brew_agent";
    let data = fs::read(sample_path).expect("Failed to read malware sample");
    let key = b"fYztZORL5VNS7nCUH1ktn5UoJ8VSgaf";
    
    let opts = stng::ExtractOptions::new(4)
        .with_xor_key(key.to_vec())
        .with_garbage_filter(false);
    
    let extracted = stng::extract_strings_with_options(&data, &opts);
    
    let xor_strings: Vec<_> = extracted
        .iter()
        .filter(|s| s.method == stng::StringMethod::XorDecode)
        .collect();
    
    println!("Found {} XOR strings (min_length=4, no filtering):\n", xor_strings.len());
    
    // Find ru_RU, Electrum, C2 URL
    let mut found_ru_ru = false;
    let mut found_electrum = false;
    let mut found_c2 = false;
    
    for s in &xor_strings {
        if s.value.contains("ru_RU") {
            println!("[ru_RU] {}", s.value);
            found_ru_ru = true;
        }
        if s.value.to_lowercase().contains("electrum") {
            println!("[Electrum] {}", s.value);
            found_electrum = true;
        }
        if s.value.contains("46.30.191") {
            println!("[C2] {}", s.value);
            found_c2 = true;
        }
    }
    
    println!("\nResults:");
    println!("  ru_RU found: {}", found_ru_ru);
    println!("  Electrum found: {}", found_electrum);
    println!("  C2 URL found: {}", found_c2);
}
