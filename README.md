![stng](media/logo-small.png)

**stng** — Language-aware string extraction for binary malware analysis. Extract indicators, hardcoded credentials, C2 addresses, and obfuscated strings from any binary.

## Quick Start

```bash
stng malware.bin              # Full analysis with XOR auto-detection
stng -i malware.bin           # Filter noise (known library strings)
stng --json malware.bin       # Machine-readable output
```

## Detection Capabilities

- **Binary network structures**: Hardcoded IPs/ports in socket structures, network byte order
- **XOR obfuscation**: Single/multi-byte keys with entropy analysis
- **Language-aware extraction**: Go/Rust `{ptr, len}`, DWARF stack strings
- **IOC classification**: IPs, URLs, shell commands, paths, registry keys, credentials
- **Wide strings**: UTF-16LE in Windows PE binaries
- **Format support**: ELF, PE, Mach-O, raw binaries, overlays

## Use Cases

- **C2 enumeration**: Extract hardcoded callbacks, encryption keys, beacon URLs
- **Credential hunting**: Locate database passwords, API keys, private keys
- **Evasion analysis**: Identify XOR'd strings, packed payloads, obfuscated indicators
- **YARA acceleration**: Find strings for signature development

## Library

```rust
let strings = stng::extract_strings(&std::fs::read("sample")?, 4);
```

License: Apache-2.0
