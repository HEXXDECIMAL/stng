use std::fs;

fn main() {
    let sample_path = "testdata/xor/brew_agent_xor_sample";
    let data = fs::read(sample_path).expect("Failed to read malware sample");
    let key = b"fYztZORL5VNS7nCUH1ktn5UoJ8VSgaf";
    
    let opts = stng::ExtractOptions::new(10)
        .with_xor_key(key.to_vec())
        .with_garbage_filter(false);
    
    let extracted = stng::extract_strings_with_options(&data, &opts);
    
    let xor_strings: Vec<_> = extracted
        .iter()
        .filter(|s| s.method == stng::StringMethod::XorDecode)
        .collect();
    
    println!("Found {} XOR strings:\n", xor_strings.len());
    
    for (i, s) in xor_strings.iter().enumerate() {
        let display = s.value.replace('\n', "\\n").replace('\r', "\\r");
        println!("[{}] {}", i, display);
    }
}
