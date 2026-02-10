use std::fs;

fn main() {
    let data = fs::read("testdata/kworker_samples/kworker_obfuscated_1").expect("read");

    // Extract at offset 0x36df and see what's there
    println!("Raw bytes at 0x36df and beyond:");
    for i in 0x36df..0x36df + 100 {
        let b = data[i];
        if b.is_ascii_graphic() || b == b' ' {
            print!("{}", b as char);
        } else {
            print!(".");
        }
    }
    println!("\n");

    println!("Looking for '66 c7 00' (mov word [mem], imm) patterns:");
    let mut found_patterns = Vec::new();
    let mut i = 0;
    while i + 4 < data.len() {
        if data[i] == 0x66 && data[i + 1] == 0xC7 && data[i + 2] == 0x00 {
            let b1 = data[i + 3];
            let b2 = data[i + 4];
            if (b1.is_ascii_graphic() || b1 == b' ') && (b2.is_ascii_graphic() || b2 == b' ') {
                found_patterns.push((i, b1 as char, b2 as char));
                println!("  0x{:x}: {:?}{:?}", i, b1 as char, b2 as char);
            }
        }
        i += 1;
    }

    println!("\nGrouping by gap (expect ~37 bytes between kworker chars):");
    if found_patterns.len() > 1 {
        for i in 1..found_patterns.len() {
            let gap = found_patterns[i].0 - found_patterns[i - 1].0;
            println!(
                "  Gap from 0x{:x} to 0x{:x}: {} bytes",
                found_patterns[i - 1].0,
                found_patterns[i].0,
                gap
            );
        }
    }

    // Group them
    let mut j = 0;
    println!("\nGrouped strings:");
    while j < found_patterns.len() {
        let mut s = String::new();
        s.push(found_patterns[j].1);
        s.push(found_patterns[j].2);

        let expected_gap = if j + 1 < found_patterns.len() {
            (found_patterns[j + 1].0 - found_patterns[j].0) as i64
        } else {
            37
        };

        let mut k = j + 1;
        while k < found_patterns.len() {
            let gap = (found_patterns[k].0 - found_patterns[k - 1].0) as i64;
            let variance = (gap - expected_gap).abs();
            if variance > 2 {
                break;
            }
            s.push(found_patterns[k].1);
            s.push(found_patterns[k].2);
            k += 1;
        }

        if s.len() >= 4 {
            println!("  Group starting at 0x{:x}: {:?}", found_patterns[j].0, s);
        }

        j = k.max(j + 1);
    }
}
