# stng

Language-aware string extraction for binary analysis. A smarter `strings(1)` for security research.

## Install

```bash
cargo install --path .
```

## Usage

```bash
stng malware.bin                 # Full analysis with auto XOR detection
stng -i malware.bin              # Filter out noise
stng --xor "key" malware.bin     # Custom XOR key (hex or string)
stng --json malware.bin          # JSON output
```

## Features

- **Go/Rust aware**: Extracts strings from `{ptr, len}` structures, not just null-terminated
- **XOR detection**: Auto-detects and decodes XOR'd strings (single and multi-byte keys)
- **IOC classification**: Tags IPs, URLs, shell commands, suspicious paths, registry keys
- **Wide strings**: UTF-16LE extraction for Windows PE files
- **Overlay extraction**: Finds strings appended after binary boundaries
- **Mach-O entitlements**: Extracts security capabilities from code signatures

Strings are classified by type and colored by severity. Run `stng --help` for options.

## Library Usage

```rust
let strings = stng::extract_strings(&std::fs::read("binary")?, 4);
```

License: Apache-2.0
