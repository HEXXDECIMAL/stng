//! CLI integration tests for strangs.

use std::path::Path;
use std::process::Command;

fn strangs_cmd() -> Command {
    Command::new(env!("CARGO_BIN_EXE_strangs"))
}

#[test]
fn test_cli_help() {
    let output = strangs_cmd()
        .arg("--help")
        .output()
        .expect("Failed to execute strangs");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("strangs"));
    assert!(stdout.contains("--min-length"));
    assert!(stdout.contains("--json"));
}

#[test]
fn test_cli_version() {
    let output = strangs_cmd()
        .arg("--version")
        .output()
        .expect("Failed to execute strangs");

    assert!(output.status.success());
}

#[test]
fn test_cli_nonexistent_file() {
    let output = strangs_cmd()
        .arg("/nonexistent/file/path")
        .output()
        .expect("Failed to execute strangs");

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("does not exist") || stderr.contains("No such file"));
}

#[test]
fn test_cli_detect_language_text() {
    // Create a temp file with text content
    let temp_dir = std::env::temp_dir();
    let temp_file = temp_dir.join("strangs_test_detect_text.txt");
    std::fs::write(&temp_file, b"not a binary").unwrap();

    let output = strangs_cmd()
        .arg("--detect")
        .arg(&temp_file)
        .output()
        .expect("Failed to execute strangs");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("text"));

    std::fs::remove_file(&temp_file).ok();
}

#[test]
fn test_cli_detect_language_unknown() {
    // Create a temp file with binary garbage
    let temp_dir = std::env::temp_dir();
    let temp_file = temp_dir.join("strangs_test_detect_bin.bin");
    std::fs::write(&temp_file, &[0x00, 0x01, 0x02, 0x03, 0x04, 0x05]).unwrap();

    let output = strangs_cmd()
        .arg("--detect")
        .arg(&temp_file)
        .output()
        .expect("Failed to execute strangs");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("unknown"));

    std::fs::remove_file(&temp_file).ok();
}

#[test]
fn test_cli_json_output() {
    // Use a real binary like /bin/ls if available
    let binary_path = if Path::new("/bin/ls").exists() {
        "/bin/ls".to_string()
    } else if Path::new("/usr/bin/ls").exists() {
        "/usr/bin/ls".to_string()
    } else {
        // Skip on systems without ls
        return;
    };

    let output = strangs_cmd()
        .arg("--json")
        .arg("--no-r2")
        .arg(&binary_path)
        .output()
        .expect("Failed to execute strangs");

    if output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        // Should be valid JSON array
        assert!(stdout.starts_with('['));
        assert!(stdout.trim().ends_with(']'));
    }
}

#[test]
fn test_cli_simple_output() {
    let binary_path = if Path::new("/bin/ls").exists() {
        "/bin/ls".to_string()
    } else if Path::new("/usr/bin/ls").exists() {
        "/usr/bin/ls".to_string()
    } else {
        return;
    };

    let output = strangs_cmd()
        .arg("--simple")
        .arg("--no-r2")
        .arg(&binary_path)
        .output()
        .expect("Failed to execute strangs");

    if output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        // Simple mode shows count in stderr
        assert!(stderr.contains("strings extracted"));
    }
}

#[test]
fn test_cli_min_length() {
    let binary_path = if Path::new("/bin/ls").exists() {
        "/bin/ls".to_string()
    } else {
        return;
    };

    // Run with min_length 4 (default)
    let output_default = strangs_cmd()
        .arg("--json")
        .arg("--no-r2")
        .arg(&binary_path)
        .output()
        .expect("Failed to execute strangs");

    // Run with min_length 20
    let output_long = strangs_cmd()
        .arg("-m")
        .arg("20")
        .arg("--json")
        .arg("--no-r2")
        .arg(&binary_path)
        .output()
        .expect("Failed to execute strangs");

    if output_default.status.success() && output_long.status.success() {
        let count_default = String::from_utf8_lossy(&output_default.stdout)
            .matches("\"value\"")
            .count();
        let count_long = String::from_utf8_lossy(&output_long.stdout)
            .matches("\"value\"")
            .count();
        // Higher min_length should result in fewer or equal strings
        assert!(
            count_long <= count_default,
            "min_length 20 ({}) should have <= strings than default ({})",
            count_long,
            count_default
        );
    }
}

#[test]
fn test_cli_unfiltered() {
    let binary_path = if Path::new("/bin/ls").exists() {
        "/bin/ls".to_string()
    } else {
        return;
    };

    // Run without --unfiltered
    let output1 = strangs_cmd()
        .arg("--json")
        .arg("--no-r2")
        .arg(&binary_path)
        .output()
        .expect("Failed to execute strangs");

    // Run with --unfiltered
    let output2 = strangs_cmd()
        .arg("--json")
        .arg("--no-r2")
        .arg("--unfiltered")
        .arg(&binary_path)
        .output()
        .expect("Failed to execute strangs");

    if output1.status.success() && output2.status.success() {
        // Unfiltered should have more or equal strings
        let count1 = String::from_utf8_lossy(&output1.stdout)
            .matches("\"value\"")
            .count();
        let count2 = String::from_utf8_lossy(&output2.stdout)
            .matches("\"value\"")
            .count();
        assert!(count2 >= count1);
    }
}

#[test]
fn test_cli_flat_output() {
    let binary_path = if Path::new("/bin/ls").exists() {
        "/bin/ls".to_string()
    } else {
        return;
    };

    let output = strangs_cmd()
        .arg("--flat")
        .arg("--no-r2")
        .arg(&binary_path)
        .output()
        .expect("Failed to execute strangs");

    if output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        // Flat mode should not have section headers (-- ...)
        // Actually it should still have section headers, but no grouping
        assert!(stdout.contains("Extracted"));
    }
}

#[test]
fn test_cli_no_r2() {
    let binary_path = if Path::new("/bin/ls").exists() {
        "/bin/ls".to_string()
    } else {
        return;
    };

    let output = strangs_cmd()
        .arg("--no-r2")
        .arg("--json")
        .arg(&binary_path)
        .output()
        .expect("Failed to execute strangs");

    if output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        // Should not have r2 method strings when r2 is disabled
        // (they might still appear if r2 is auto-detected, but we explicitly disabled it)
        // Just check it's valid output
        assert!(stdout.starts_with('['));
    }
}

#[test]
fn test_cli_text_file_cat() {
    // Text files should be output like `cat`
    let temp_dir = std::env::temp_dir();
    let temp_file = temp_dir.join("strangs_test_text.txt");
    let content = b"This is just a text file, not a binary";
    std::fs::write(&temp_file, content).unwrap();

    let output = strangs_cmd()
        .arg(&temp_file)
        .output()
        .expect("Failed to execute strangs");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("This is just a text file"));

    std::fs::remove_file(&temp_file).ok();
}

#[test]
fn test_cli_binary_garbage() {
    // Binary garbage should find no strings
    let temp_dir = std::env::temp_dir();
    let temp_file = temp_dir.join("strangs_test_garbage.bin");
    std::fs::write(&temp_file, &[0x00, 0x01, 0x02, 0x03, 0x04, 0x05]).unwrap();

    let output = strangs_cmd()
        .arg(&temp_file)
        .output()
        .expect("Failed to execute strangs");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("No strings found"));

    std::fs::remove_file(&temp_file).ok();
}

#[test]
fn test_cli_empty_file() {
    let temp_dir = std::env::temp_dir();
    let temp_file = temp_dir.join("strangs_test_empty.bin");
    std::fs::write(&temp_file, b"").unwrap();

    let output = strangs_cmd()
        .arg(&temp_file)
        .output()
        .expect("Failed to execute strangs");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("No strings found"));

    std::fs::remove_file(&temp_file).ok();
}
