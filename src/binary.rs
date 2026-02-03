//! Binary format helpers and type detection.

use goblin::mach::MachO;

/// Collect segment and section names from a Mach-O binary.
pub fn collect_macho_segments(macho: &MachO) -> Vec<String> {
    let mut segments = Vec::new();
    for seg in &macho.segments {
        if let Ok(name) = seg.name() {
            segments.push(name.to_string());
        }
        if let Ok(sections) = seg.sections() {
            for (sec, _) in sections {
                if let Ok(name) = sec.name() {
                    segments.push(name.to_string());
                }
            }
        }
    }
    segments
}

/// Collect section names from an ELF binary.
pub fn collect_elf_segments(elf: &goblin::elf::Elf) -> Vec<String> {
    elf.section_headers
        .iter()
        .filter_map(|sh| {
            elf.shdr_strtab
                .get_at(sh.sh_name)
                .map(std::string::ToString::to_string)
        })
        .collect()
}

/// Helper to check if a Mach-O binary has Go sections.
pub fn macho_has_go_sections(macho: &MachO) -> bool {
    macho.segments.iter().any(|seg| {
        seg.sections().is_ok_and(|secs| {
            secs.iter().any(|(sec, _)| {
                let name = sec.name().unwrap_or("");
                name == "__gopclntab" || name == "__go_buildinfo"
            })
        })
    })
}

/// Check if a binary is a Go binary by looking for Go-specific sections.
pub fn is_go_binary(data: &[u8]) -> bool {
    use goblin::Object;
    match Object::parse(data) {
        Ok(Object::Mach(goblin::mach::Mach::Binary(macho))) => macho_has_go_sections(&macho),
        Ok(Object::Mach(goblin::mach::Mach::Fat(_))) => false,
        Ok(Object::Elf(elf)) => elf.section_headers.iter().any(|sh| {
            let name = elf.shdr_strtab.get_at(sh.sh_name).unwrap_or("");
            name == ".gopclntab" || name == ".go.buildinfo"
        }),
        Ok(Object::PE(_pe)) => false,
        _ => false,
    }
}

/// Check if a binary is a Rust binary.
pub fn is_rust_binary(data: &[u8]) -> bool {
    use goblin::Object;
    match Object::parse(data) {
        Ok(Object::Mach(goblin::mach::Mach::Binary(macho))) => macho_is_rust(&macho),
        Ok(Object::Elf(elf)) => elf.section_headers.iter().any(|sh| {
            let name = elf.shdr_strtab.get_at(sh.sh_name).unwrap_or("");
            name.contains("rust") || name == ".rustc"
        }),
        _ => false,
    }
}

/// Check if a Mach-O binary appears to be a Rust binary.
pub fn macho_is_rust(macho: &MachO) -> bool {
    macho.segments.iter().any(|seg| {
        seg.sections().is_ok_and(|secs| {
            secs.iter().any(|(sec, _)| {
                let name = sec.name().unwrap_or("");
                name.contains("rust")
            })
        })
    })
}

/// Find the section name containing an address in a Mach-O binary.
pub fn find_macho_section(macho: &MachO, addr: u64) -> Option<String> {
    for seg in &macho.segments {
        for (sec, _) in &seg.sections().ok()? {
            let start = sec.addr;
            let end = start + sec.size;
            if addr >= start && addr < end {
                return Some(sec.name().ok()?.to_string());
            }
        }
    }
    None
}

/// Convert virtual address to file offset for Mach-O binaries.
pub fn macho_vaddr_to_file_offset(macho: &MachO, vaddr: u64) -> u64 {
    for seg in &macho.segments {
        let vm_start = seg.vmaddr;
        let vm_end = vm_start + seg.vmsize;

        if vaddr >= vm_start && vaddr < vm_end {
            // file_offset = (virtual_address - segment_vmaddr) + segment_fileoff
            return (vaddr - vm_start) + seg.fileoff;
        }
    }

    // If not found in any segment, return the vaddr as-is
    vaddr
}
