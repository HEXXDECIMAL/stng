# strangs

Language-aware string extraction for binary analysis. A smarter `strings(1)` replacement for security research.

## Why?

Traditional `strings` fails on modern binaries:

- **Go/Rust binaries** use `{ptr, len}` string representations, not null-terminated strings. Packed string data becomes unreadable garbage.
- **Windows PE files** use UTF-16LE, which `strings` misses entirely.
- **Malware** often appends data after the ELF/PE structure (overlay), hiding configs and C2 addresses.

`strangs` understands all of this and automatically classifies what it finds.

## Install

```
cargo install --path .
```

Optionally install [radare2](https://rada.re) or [rizin](https://rizin.re) for enhanced extraction.

## Usage

```
strangs malware.elf              # Full analysis with colored output
strangs -i malware.elf           # Interesting strings only (skip raw scan noise)
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
  247 strings from sample.elf

── .rodata ──
    1a40 const        runtime.memequal
    1a60 path         /usr/lib/go
    1b80 url          https://api.evil.com/beacon
    1c00 ip:port      192.168.1.100:4444
    1d20 shell        /bin/sh -c wget ...
    1e00 base64       c2VjcmV0X2tleQ== [secret_key]

── (overlay) ──
   4f000 overlay      config.json
   4f100 overlay:16LE C:\Windows\Temp\payload.exe

▌ Notable
    1b80 url          https://api.evil.com/beacon
    1c00 ip:port      192.168.1.100:4444
```

## Flags

```
-m, --min-length <N>   Minimum string length (default: 4)
-i, --interesting      Filter out raw scan noise
    --json             JSON output
    --simple           One string per line, no formatting
    --flat             Don't group by section
    --unfiltered       Include garbage/noise strings
    --detect           Show detected language and exit
    --r2               Force radare2 usage
    --no-r2            Disable radare2
    --no-color         Plain text output
```

## Features

- **Go/Rust structure extraction**: Finds `{ptr, len}` pairs and extracts precise string boundaries
- **IOC classification**: Automatically tags IPs, URLs, shell commands, suspicious paths, registry keys, base64
- **Overlay detection**: Extracts strings from data appended after ELF/PE boundaries
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

Methods: `Structure`, `RawScan`, `WideString`, `R2String`, `R2Symbol`, `Heuristic`, `InstructionPattern`

## Library Usage

```rust
use strangs::{extract_strings, ExtractOptions};

let data = std::fs::read("binary")?;
let strings = strangs::extract_strings(&data, 4);

// With options
let opts = ExtractOptions::new(4)
    .with_r2("/path/to/binary")
    .with_garbage_filter(true);
let strings = strangs::extract_strings_with_options(&data, &opts);
```

## License

Apache-2.0
