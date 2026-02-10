use std::fs;
use std::time::Instant;

fn main() {
    let data = fs::read("testdata/malware/brew_agent").expect("read file");
    println!(
        "File size: {} bytes ({:.1} MB)",
        data.len(),
        data.len() as f64 / 1_000_000.0
    );

    // Run multiple times to get better timing
    let iterations = 10;
    let mut total_time = std::time::Duration::ZERO;

    for run in 1..=iterations {
        let opts = stng::ExtractOptions::new(4);
        let start = Instant::now();
        let extracted = stng::extract_strings_with_options(&data, &opts);
        let elapsed = start.elapsed();

        total_time += elapsed;
        println!(
            "Run {}: {:.4}s, {} strings",
            run,
            elapsed.as_secs_f64(),
            extracted.len()
        );
    }

    let avg = total_time / iterations;
    println!("\nAverage time: {:.4}s", avg.as_secs_f64());
    println!(
        "Throughput: {:.2} MB/s",
        (data.len() as f64 / 1_000_000.0) / avg.as_secs_f64()
    );
}
