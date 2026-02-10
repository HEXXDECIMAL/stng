use std::fs;
use std::time::Instant;

fn main() {
    let data = fs::read("testdata/malware/brew_agent").expect("read file");

    println!("File size: {} bytes", data.len());

    let opts = stng::ExtractOptions::new(4);

    let start = Instant::now();
    let extracted = stng::extract_strings_with_options(&data, &opts);
    let elapsed = start.elapsed();

    println!("Extraction took: {:.2}s", elapsed.as_secs_f64());
    println!("Extracted {} strings", extracted.len());
    println!(
        "Throughput: {:.2} MB/s",
        (data.len() as f64 / 1_000_000.0) / elapsed.as_secs_f64()
    );
}
