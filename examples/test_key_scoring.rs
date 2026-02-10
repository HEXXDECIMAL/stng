fn main() {
    let candidates = vec![
        "Mozilla/5.0 (X11; Linux x86)",  // Low score - plaintext UA
        "12GWAPCT1F0I1S14",              // Good score - random-looking  
        "fYztZORL5VNS7nCUH1ktn5UoJ8VSgaf",  // Excellent score - 32 chars, diverse
        "AAAA12121212BBBB",              // Low score - high repetition
        "Test_String_With_Underscores",  // Rejected earlier
    ];
    
    for candidate in &candidates {
        // Simulate the scoring
        let len = candidate.len();
        let mut score = 0u32;
        
        // Length bonus
        if len == 32 {
            score += 100;
        } else if len >= 24 {
            score += 80;
        }
        
        // Character frequency analysis
        let mut char_freq = [0u32; 256];
        for &byte in candidate.as_bytes() {
            char_freq[byte as usize] += 1;
        }
        let max_freq = *char_freq.iter().max().unwrap_or(&1);
        let unique_chars = char_freq.iter().filter(|&&f| f > 0).count();
        
        if max_freq <= 2 {
            score += 80;
        } else if max_freq <= 3 {
            score += 60;
        } else {
            score = score.saturating_sub(20);
        }
        
        if unique_chars >= 20 {
            score += 60;
        } else if unique_chars >= 15 {
            score += 40;
        }
        
        println!("{}", format!("'{}': score={}, len={}, max_freq={}, unique_chars={}", 
                 candidate, score, len, max_freq, unique_chars));
    }
}
