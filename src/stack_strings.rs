//! Extraction of stack-constructed strings (immediate values).
//!
//! Identifies strings built at runtime via:
//! - Immediate loads to registers (`mov reg, imm`).
//! - Immediate stores to memory (`mov [mem], imm`).
//! - Register stores to memory (`mov [mem], reg`).
//!
//! Tracks register state and memory offsets to correctly reconstruct
//! strings that are built out-of-order or with overlaps.

use crate::types::{ExtractedString, StringFragment, StringKind, StringMethod};
use std::collections::HashMap;

/// Extract strings constructed on the stack.
pub fn extract_stack_strings(data: &[u8], min_length: usize) -> Vec<ExtractedString> {
    let extractor = StackStringExtractor::new(data, min_length);
    extractor.extract()
}

struct StackStringExtractor<'a> {
    data: &'a [u8],
    min_length: usize,
    // Register state: (Value, Instruction Offset, Flavor)
    regs: [Option<(String, u64, String)>; 16],
    // Captured stack writes: grouped by (Base Reg, Index Reg, Scale) -> Vec<StackWrite>
    // We simplify: group by "Base Register" and assume standard stack frames.
    // If base is RIP (0x05 in ModRM), we track it separately?
    // For now, simple Base Reg grouping.
    writes: HashMap<u8, Vec<StackWrite>>,
}

#[derive(Debug, Clone)]
struct StackWrite {
    string: String,
    disp: i64,      // Displacement from base register
    instr_off: u64, // Offset of the instruction that wrote this
    flavor: String, // "movabs", "mov_byte", etc.
}

impl<'a> StackStringExtractor<'a> {
    fn new(data: &'a [u8], min_length: usize) -> Self {
        Self {
            data,
            min_length,
            regs: Default::default(),
            writes: HashMap::new(),
        }
    }

    fn extract(mut self) -> Vec<ExtractedString> {
        let mut results = Vec::new();

        // First pass: look for loop-based string building patterns
        // Used by kworker_pretenders and similar malware
        // Pattern: repeated "mov word [mem], imm" with ASCII-decodable immediates
        results.extend(self.extract_loop_built_strings());

        let mut i = 0;
        while i < self.data.len() {
            // Safety check
            if i + 15 > self.data.len() {
                break;
            }

            // Decode instruction at i
            // We only care about:
            // 1. mov reg, imm (B8..BF, C7)
            // 2. mov [mem], imm (C6, C7)
            // 3. mov [mem], reg (88, 89)
            // 4. Control flow (reset state)

            // Skip prefixes
            let mut p = i;
            let mut rex = 0u8;
            let mut _segment = 0u8;

            loop {
                if p >= self.data.len() {
                    break;
                }
                let b = self.data[p];
                match b {
                    0x26 | 0x2E | 0x36 | 0x3E | 0x64 | 0x65 => _segment = b,
                    0x66 | 0x67 | 0xF0 | 0xF2 | 0xF3 => {} // Ignore other prefixes
                    0x40..=0x4F => rex = b,
                    _ => break,
                }
                p += 1;
            }
            let opcode_start = p;
            if opcode_start >= self.data.len() {
                break;
            }
            let opcode = self.data[opcode_start];

            let mut handled = false;
            let mut len = 0;

            // --- 1. mov reg, imm ---
            // B8+rd: mov r32/r64, imm
            if opcode >= 0xB8 && opcode <= 0xBF {
                let reg = (opcode & 0x07) + if (rex & 1) != 0 { 8 } else { 0 };
                let is_64 = (rex & 8) != 0;
                let imm_len = if is_64 { 8 } else { 4 };

                if opcode_start + 1 + imm_len <= self.data.len() {
                    let imm_data = &self.data[opcode_start + 1..opcode_start + 1 + imm_len];
                    if let Some(s) = check_printable(imm_data, self.min_length) {
                        self.regs[reg as usize] = Some((
                            s,
                            i as u64,
                            if is_64 {
                                "movabs".into()
                            } else {
                                "mov_r32".into()
                            },
                        ));
                    } else {
                        self.regs[reg as usize] = None;
                    }
                    len = (opcode_start - i) + 1 + imm_len;
                    handled = true;
                }
            }
            // C7 /0: mov r/m, imm32
            else if opcode == 0xC7 {
                // Need ModRM
                if opcode_start + 2 <= self.data.len() {
                    let modrm = self.data[opcode_start + 1];
                    let reg_op = (modrm >> 3) & 7;
                    if reg_op == 0 {
                        // /0
                        let (op_len, base, disp) = self.decode_modrm(opcode_start + 1, rex);
                        if op_len > 0 && opcode_start + 1 + op_len + 4 <= self.data.len() {
                            let imm_offset = opcode_start + 1 + op_len;
                            let imm_data = &self.data[imm_offset..imm_offset + 4];

                            // Check if destination is register or memory
                            let mod_bits = modrm >> 6;
                            if mod_bits == 3 {
                                // mov reg, imm32
                                let dst_reg = (modrm & 7) + if (rex & 1) != 0 { 8 } else { 0 };
                                if let Some(s) = check_printable(imm_data, self.min_length) {
                                    self.regs[dst_reg as usize] =
                                        Some((s, i as u64, "mov_r32".into()));
                                } else {
                                    self.regs[dst_reg as usize] = None;
                                }
                            } else if let Some(base_reg) = base {
                                // mov [mem], imm32
                                if let Some(s) = check_printable(imm_data, 4) {
                                    // Always 4 bytes for C7
                                    self.add_write(
                                        base_reg,
                                        disp,
                                        s,
                                        i as u64,
                                        "mov_mem_imm32".into(),
                                    );
                                }
                            }
                            len = (opcode_start - i) + 1 + op_len + 4;
                            handled = true;
                        }
                    }
                }
            }
            // --- 2. mov [mem], imm8 ---
            // C6 /0: mov r/m8, imm8
            else if opcode == 0xC6 {
                if opcode_start + 2 <= self.data.len() {
                    let modrm = self.data[opcode_start + 1];
                    let reg_op = (modrm >> 3) & 7;
                    if reg_op == 0 {
                        let (op_len, base, disp) = self.decode_modrm(opcode_start + 1, rex);
                        if op_len > 0 && opcode_start + 1 + op_len + 1 <= self.data.len() {
                            let imm_offset = opcode_start + 1 + op_len;
                            let b = self.data[imm_offset];

                            // Only memory stores
                            let mod_bits = modrm >> 6;
                            if mod_bits != 3 {
                                if let Some(base_reg) = base {
                                    if b.is_ascii_graphic() || b == b' ' {
                                        let s = (b as char).to_string();
                                        self.add_write(
                                            base_reg,
                                            disp,
                                            s,
                                            i as u64,
                                            "stack_array".into(),
                                        );
                                    }
                                }
                            }
                            len = (opcode_start - i) + 1 + op_len + 1;
                            handled = true;
                        }
                    }
                }
            }
            // --- 3. mov [mem], reg ---
            // 88 /r: mov r/m8, r8
            // 89 /r: mov r/m, r
            else if opcode == 0x88 || opcode == 0x89 {
                if opcode_start + 2 <= self.data.len() {
                    let modrm = self.data[opcode_start + 1];
                    let src_reg = ((modrm >> 3) & 7) + if (rex & 4) != 0 { 8 } else { 0 };

                    let (op_len, base, disp) = self.decode_modrm(opcode_start + 1, rex);
                    if op_len > 0 {
                        let mod_bits = modrm >> 6;
                        if mod_bits != 3 {
                            // Store to memory
                            if let Some(base_reg) = base {
                                // Check if we have a string in src_reg
                                if let Some((s, _orig_off, flavor)) = &self.regs[src_reg as usize] {
                                    self.add_write(
                                        base_reg,
                                        disp,
                                        s.clone(),
                                        i as u64,
                                        flavor.clone(),
                                    );
                                }
                            }
                        }
                        len = (opcode_start - i) + 1 + op_len;
                        handled = true;
                    }
                }
            }
            // --- 4. Control Flow / Clear ---
            // C3 (ret), E8 (call), E9 (jmp), EB (jmp short), FF (call/jmp indirect)
            // 7x (jcc), 0F 8x (jcc long)
            else if opcode == 0xC3
                || opcode == 0xCB
                || opcode == 0xE8
                || opcode == 0xE9
                || opcode == 0xEB
            {
                results.extend(self.finalize_writes());
                self.clear_regs();
                len = 1;
                if opcode == 0xE8 || opcode == 0xE9 {
                    len = 5;
                }
                // approx
                else if opcode == 0xEB {
                    len = 2;
                }
                handled = true;
            }
            // ALU reg, imm32 (81 /r id) - To support "xor reg, imm" string loading
            else if opcode == 0x81 {
                // Check if it's an ALU op.
                // We don't track ALU results in registers (too complex), but we can extract the immediate
                // if it looks like a string, assuming it might be part of an obfuscated load.
                // This handles the `vget` case where `xor rdx, "cAMD"` contained the string.
                if opcode_start + 6 <= self.data.len() {
                    let imm_data = &self.data[opcode_start + 2..opcode_start + 6];
                    if let Some(s) = check_printable(imm_data, self.min_length) {
                        // We found a string in an ALU instruction.
                        // We can't map it to a memory write easily, so we treat it as a standalone stack string.
                        // We store it as a "write" to a dummy register (e.g. 0xFF) or just emit it directly?
                        // We can't emit directly because we return at the end.
                        // Let's add it to a special "Global" list or just generic base 0xFF?
                        // Better: Treat as a write to "Global" (base 255) with linear displacement (file offset).
                        self.add_write(255, i as i64, s, i as u64, "alu_imm32".into());
                    }
                    len = 6;
                    handled = true;
                }
            }

            if !handled {
                i += 1;
            } else {
                i += len;
            }
        }

        results.extend(self.finalize_writes());
        results
    }

    // Returns (length of ModRM+SIB+Disp, BaseReg, Displacement)
    fn decode_modrm(&self, offset: usize, rex: u8) -> (usize, Option<u8>, i64) {
        if offset >= self.data.len() {
            return (0, None, 0);
        }
        let modrm = self.data[offset];
        let mod_bits = modrm >> 6;
        let rm = modrm & 7;
        let base_reg_idx = rm + if (rex & 1) != 0 { 8 } else { 0 };

        let mut len = 1;
        let mut base = Some(base_reg_idx);
        let mut disp: i64 = 0;

        if mod_bits == 3 {
            // Register mode
            return (1, None, 0);
        }

        let has_sib = rm == 4;
        if has_sib {
            if offset + 1 >= self.data.len() {
                return (0, None, 0);
            }
            let sib = self.data[offset + 1];
            len += 1;
            let base_in_sib = sib & 7;
            // SIB base with REX.B
            let real_base = base_in_sib + if (rex & 1) != 0 { 8 } else { 0 };

            if mod_bits == 0 && base_in_sib == 5 {
                base = None; // disp32 only
            } else {
                base = Some(real_base);
            }
        } else if mod_bits == 0 && rm == 5 {
            // RIP relative (32-bit disp)
            base = None; // We don't resolve RIP, treat as independent
        }

        if mod_bits == 1 {
            if offset + len + 1 > self.data.len() {
                return (0, None, 0);
            }
            disp = self.data[offset + len] as i8 as i64;
            len += 1;
        } else if mod_bits == 2
            || (mod_bits == 0 && rm == 5)
            || (has_sib && mod_bits == 0 && (self.data[offset + 1] & 7) == 5)
        {
            if offset + len + 4 > self.data.len() {
                return (0, None, 0);
            }
            let disp32 = u32::from_le_bytes(
                self.data[offset + len..offset + len + 4]
                    .try_into()
                    .unwrap(),
            );
            disp = disp32 as i32 as i64;
            len += 4;
        }

        (len, base, disp)
    }

    fn add_write(&mut self, base: u8, disp: i64, s: String, instr_off: u64, flavor: String) {
        self.writes.entry(base).or_default().push(StackWrite {
            string: s,
            disp,
            instr_off,
            flavor,
        });
    }

    fn clear_regs(&mut self) {
        for r in self.regs.iter_mut() {
            *r = None;
        }
    }

    fn finalize_writes(&mut self) -> Vec<ExtractedString> {
        let mut results = Vec::new();
        let writes = std::mem::take(&mut self.writes);

        // Process each base register group
        for (base, mut writes) in writes {
            if writes.is_empty() {
                continue;
            }

            // Sort by displacement to find memory order
            writes.sort_by(|a, b| a.disp.cmp(&b.disp));

            // Merge logic
            let mut current = ExtractedString {
                value: String::new(),
                data_offset: 0,
                section: None,
                method: StringMethod::StackString,
                kind: StringKind::StackString,
                library: None,
                fragments: Some(Vec::new()),
                    section_size: None,
                    section_executable: None,
                    section_writable: None,
                    architecture: None,
                    function_meta: None,
            };

            // We need to initialize 'current' with the first write
            let mut first = true;
            let mut current_end_disp = 0;

            for w in writes {
                if first {
                    current.value = w.string.clone();
                    current.data_offset = w.instr_off;
                    if let Some(frags) = &mut current.fragments {
                        frags.push(StringFragment {
                            offset: w.instr_off,
                            length: w.string.len(),
                            flavor: Some(w.flavor),
                        });
                    }
                    current_end_disp = w.disp + w.string.len() as i64;
                    first = false;
                    continue;
                }

                let gap = w.disp - current_end_disp;

                // For memory writes (base < 255), allow a small gap to account for
                // character-by-character assembly where each instruction writes to successive bytes.
                // Some instructions may have implicit padding or alignment that creates small gaps.
                // For instruction-embedded strings (base == 255), we allow a small gap (e.g. 16 bytes)
                // to merge strings from sequential instructions.
                // Threshold: 4 bytes covers most cases (mov dword writes with 1-byte gaps between them)
                let allowed_gap = if base == 255 { 16 } else { 4 };

                if gap <= allowed_gap {
                    if gap >= 0 {
                        // Strict adjacency or small gap
                        current.value.push_str(&w.string);
                        if let Some(frags) = &mut current.fragments {
                            frags.push(StringFragment {
                                offset: w.instr_off,
                                length: w.string.len(),
                                flavor: Some(w.flavor),
                            });
                        }
                        current_end_disp = w.disp + w.string.len() as i64;
                    } else {
                        // Overlap (gap < 0)
                        // w.disp starts BEFORE current ends.
                        // This is the overwrite case (React2Shell).
                        // We need to merge them intelligently.
                        let overlap = current_end_disp - w.disp;
                        if overlap < w.string.len() as i64 {
                            let new_part_start = overlap as usize;
                            if new_part_start < w.string.len() {
                                let new_part = &w.string[new_part_start..];
                                current.value.push_str(new_part);
                                if let Some(frags) = &mut current.fragments {
                                    frags.push(StringFragment {
                                        offset: w.instr_off,
                                        length: w.string.len(),
                                        flavor: Some(w.flavor),
                                    });
                                }
                                current_end_disp = w.disp + w.string.len() as i64;
                            }
                        }
                    }
                } else {
                    // Gap > 0: split into distinct strings
                    results.push(current);
                    current = ExtractedString {
                        value: w.string.clone(),
                        data_offset: w.instr_off,
                        section: None,
                        method: StringMethod::StackString,
                        kind: StringKind::StackString,
                        library: None,
                        fragments: Some(vec![StringFragment {
                            offset: w.instr_off,
                            length: w.string.len(),
                            flavor: Some(w.flavor),
                        }]),
                        section_size: None,
                        section_executable: None,
                        section_writable: None,
                    architecture: None,
                    function_meta: None,
                    };
                    current_end_disp = w.disp + w.string.len() as i64;
                }
            }
            results.push(current);
        }

        // Second pass: merge adjacent short fragments that were split due to small gaps.
        // This handles character-by-character assembly like "[k" "w" "o" "r" "k" "e" "r" "]"
        // where fragments end up in the results list but should be combined.
        results = self.merge_adjacent_fragments(results);

        // Final sanity check: filter out very short merged strings
        results.retain(|s| s.value.len() >= self.min_length);
        results
    }

    /// Merge adjacent short fragments that likely belong together.
    /// This catches cases where character-by-character assembly creates many 1-2 byte fragments.
    fn merge_adjacent_fragments(&self, mut strings: Vec<ExtractedString>) -> Vec<ExtractedString> {
        if strings.is_empty() {
            return strings;
        }

        let mut merged = Vec::new();
        let mut current_group = vec![strings.remove(0)];

        for next_str in strings {
            let last = current_group.last().unwrap();

            // Check if this string is adjacent to the last one (within a small gap)
            // and both are short (suggesting character-by-character assembly)
            let last_end = last.data_offset + last.value.len() as u64;
            let gap = next_str.data_offset as i64 - last_end as i64;

            // Merge if:
            // 1. Strings are adjacent or very close (gap < 8 bytes, accounting for instruction padding)
            // 2. At least one of them is short (< 4 bytes, suggesting fragments)
            // 3. Neither is suspiciously garbage-like
            if gap >= -4 && gap < 8 && (last.value.len() < 4 || next_str.value.len() < 4) {
                // They likely belong together
                current_group.push(next_str);
            } else {
                // End the current group and merge it
                if current_group.len() > 1 {
                    merged.push(self.merge_group(&current_group));
                } else {
                    merged.extend(current_group);
                }
                current_group = vec![next_str];
            }
        }

        // Handle the last group
        if !current_group.is_empty() {
            if current_group.len() > 1 {
                merged.push(self.merge_group(&current_group));
            } else {
                merged.extend(current_group);
            }
        }

        merged
    }

    /// Merge a group of adjacent fragments into a single string.
    fn merge_group(&self, group: &[ExtractedString]) -> ExtractedString {
        if group.is_empty() {
            return ExtractedString {
                value: String::new(),
                data_offset: 0,
                section: None,
                method: StringMethod::StackString,
                kind: StringKind::StackString,
                library: None,
                fragments: None,
                section_size: None,
                section_executable: None,
                section_writable: None,
                    architecture: None,
                    function_meta: None,
            };
        }

        if group.len() == 1 {
            return group[0].clone();
        }

        let mut merged_value = String::new();
        let first_offset = group[0].data_offset;
        let mut merged_fragments = Vec::new();

        for (_idx, s) in group.iter().enumerate() {
            merged_value.push_str(&s.value);
            if let Some(frags) = &s.fragments {
                merged_fragments.extend(frags.clone());
            }
            // If there's a gap to the next string, we might want to note it
            // but for now we just concatenate
        }

        ExtractedString {
            value: merged_value,
            data_offset: first_offset,
            section: group[0].section.clone(),
            method: StringMethod::StackString,
            kind: StringKind::StackString,
            library: None,
            fragments: if merged_fragments.is_empty() {
                None
            } else {
                Some(merged_fragments)
            },
            ..Default::default()
        }
    }

    /// Extract strings built using loop-based patterns.
    /// Detects patterns like: mov word [rax], imm; ... strlen; ... mov word [rax], imm
    /// Used by malware like kworker_pretenders that builds strings iteratively.
    fn extract_loop_built_strings(&self) -> Vec<ExtractedString> {
        let mut results = Vec::new();

        // Collect all "mov word [mem], imm16" instructions with ASCII immediates
        let mut mov_word_instrs = Vec::new();
        let mut i = 0;
        while i + 4 < self.data.len() {
            if self.data[i] == 0x66 && self.data[i + 1] == 0xC7 && self.data[i + 2] == 0x00 {
                let b1 = self.data[i + 3];
                let b2 = self.data[i + 4];

                // Accept patterns where:
                // - b1 is printable ASCII (first byte of the 2-byte immediate)
                // - b2 is either printable ASCII or null (second byte - null acts as string terminator)
                let is_valid = (b1.is_ascii_graphic() || b1 == b' ')
                    && (b2.is_ascii_graphic() || b2 == b' ' || b2 == 0);
                if is_valid {
                    mov_word_instrs.push((i, b1, b2));
                    i += 5;
                    continue;
                }
            }
            i += 1;
        }

        // Group consecutive mov word instructions within a function/block
        // A new group starts if gap changes significantly or we hit invalid chars
        let mut j = 0;
        while j < mov_word_instrs.len() {
            let (start_pos, b1, b2) = mov_word_instrs[j];
            let mut chunk = String::new();
            chunk.push(b1 as char);

            // Only add b2 if it's not a null terminator
            let is_terminated = b2 == 0;
            if !is_terminated {
                chunk.push(b2 as char);
            }

            let mut k = j + 1;
            let expected_gap = if k < mov_word_instrs.len() {
                (mov_word_instrs[k].0 - start_pos) as i64
            } else {
                37 // Default kworker pattern gap
            };

            while k < mov_word_instrs.len() {
                let (pos, b3, b4) = mov_word_instrs[k];
                let gap = (pos - start_pos) as i64;
                let prev_pos = if k > 0 {
                    mov_word_instrs[k - 1].0
                } else {
                    start_pos
                };
                let current_gap = (pos - prev_pos) as i64;

                // Stop if:
                // 1. Gap changes significantly (likely different loop/string)
                // 2. String would be unreasonably long
                // 3. We've hit a null terminator (end of string)
                let gap_variance = (current_gap - expected_gap).abs();
                if gap_variance > 2 || gap > 500 || chunk.len() > 64 {
                    break;
                }

                chunk.push(b3 as char);
                // Only add b4 if it's not a null terminator
                if b4 != 0 {
                    chunk.push(b4 as char);
                } else {
                    // We've hit the end of the string
                    k += 1;
                    break;
                }
                k += 1;
            }

            // If we have at least 2 pairs (4+ chars), it's likely a real string
            // Also check that it doesn't look like random garbage
            if chunk.len() >= self.min_length
                && chunk.len() < 256
                && self.looks_like_real_string(&chunk)
            {
                let chunk_len = chunk.len();
                results.push(ExtractedString {
                    value: chunk,
                    data_offset: start_pos as u64,
                    section: None,
                    method: StringMethod::StackString,
                    kind: StringKind::StackString,
                    library: None,
                    fragments: Some(vec![StringFragment {
                        offset: start_pos as u64,
                        length: chunk_len,
                        flavor: Some("mov_word_loop".into()),
                    }]),
                    ..Default::default()
                });
            }

            j = k.max(j + 1);
        }

        results
    }

    /// Check if a string looks like it was intentionally constructed
    /// rather than random bytes that happen to be printable.
    fn looks_like_real_string(&self, s: &str) -> bool {
        // Very short strings are less reliable
        if s.len() < 4 {
            return false;
        }

        // Strings that are all special characters are suspicious
        let special_count = s.chars().filter(|c| !c.is_alphanumeric()).count();
        if special_count > s.len() / 2 {
            return false;
        }

        // Common malware strings patterns
        let suspicious_patterns = [
            "[kworker]",
            "bashrc",
            "profile",
            ".ICE",
            "/tmp",
            "/etc",
            "home",
            "user",
            "root",
            "bin",
            "lib",
            "var",
            "proc",
        ];

        for pattern in &suspicious_patterns {
            if s.contains(pattern) {
                return true;
            }
        }

        // If it has multiple alphanumeric runs, it's likely real
        let mut alphanumeric_runs = 0;
        let mut in_run = false;
        for c in s.chars() {
            if c.is_alphanumeric() {
                if !in_run {
                    alphanumeric_runs += 1;
                    in_run = true;
                }
            } else {
                in_run = false;
            }
        }

        alphanumeric_runs >= 2
    }
}

fn check_printable(bytes: &[u8], min_length: usize) -> Option<String> {
    // Filter out nulls if they are at the end (padding)
    let mut trimmed = bytes;
    while let Some((last, rest)) = trimmed.split_last() {
        if *last == 0 {
            trimmed = rest;
        } else {
            break;
        }
    }

    if trimmed.len() < min_length {
        return None;
    }

    // Must be all printable/valid ascii (or utf8)
    if trimmed.iter().all(|&b| b.is_ascii_graphic() || b == b' ') {
        return String::from_utf8(trimmed.to_vec()).ok();
    }

    None
}
