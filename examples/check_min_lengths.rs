use std::fs;

fn main() {
    let sample_path = "testdata/malware/brew_agent";
    let data = fs::read(sample_path).expect("Failed to read malware sample");
    let key = b"fYztZORL5VNS7nCUH1ktn5UoJ8VSgaf";
    
    for min_length in &[1, 2, 3, 4, 5, 8, 10] {
        let opts = stng::ExtractOptions::new(*min_length)
            .with_xor_key(key.to_vec())
            .with_garbage_filter(false);
        
        let extracted = stng::extract_strings_with_options(&data, &opts);
        let xor_strings: Vec<_> = extracted
            .iter()
            .filter(|s| s.method == stng::StringMethod::XorDecode)
            .collect();
        
        let has_ru_ru = xor_strings.iter().any(|s| s.value.contains("ru_RU"));
        
        println!("min_length={}: {} strings, has ru_RU: {}", 
                 min_length, xor_strings.len(), has_ru_ru);
    }
}
