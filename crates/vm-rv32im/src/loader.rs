//! ELF32 RISC-V loader. Parses program headers and lays out segments
//! into guest memory with appropriate permissions.

#![allow(missing_docs, clippy::too_many_lines)]

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use crate::Trap;
use crate::memory::{Memory, Permissions};

const ELF_MAGIC: [u8; 4] = [0x7F, b'E', b'L', b'F'];
const ELFCLASS32: u8 = 1;
const ELFDATA2LSB: u8 = 1;
const ET_EXEC: u16 = 2;
const EM_RISCV: u16 = 0xF3;
const PT_LOAD: u32 = 1;
const PT_NULL: u32 = 0;

/// Result of parsing an ELF.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoadedElf {
    /// Entry-point address.
    pub entry: u32,
    /// Loadable segments.
    pub segments: Vec<LoadedSegment>,
}

/// One loadable segment from the ELF program headers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoadedSegment {
    /// Virtual address in guest memory.
    pub vaddr: u32,
    /// Size in memory (may be larger than `filesz` for .bss).
    pub memsz: u32,
    /// Size of data in the ELF file.
    pub filesz: u32,
    /// Memory permissions for this segment.
    pub permissions: Permissions,
}

/// Parse a static ELF32 RISC-V binary. Returns the entry point and a list
/// of loadable segments.
pub fn parse_elf(elf_bytes: &[u8]) -> Result<LoadedElf, String> {
    if elf_bytes.len() < 52 {
        return Err("ELF too small for header".into());
    }

    if elf_bytes[0..4] != ELF_MAGIC {
        return Err("invalid ELF magic".into());
    }

    if elf_bytes[4] != ELFCLASS32 {
        return Err(format!("expected ELFCLASS32, got {}", elf_bytes[4]));
    }

    if elf_bytes[5] != ELFDATA2LSB {
        return Err(format!("expected little-endian, got {}", elf_bytes[5]));
    }

    let e_type = u16::from_le_bytes([elf_bytes[16], elf_bytes[17]]);
    if e_type != ET_EXEC {
        return Err(format!("expected ET_EXEC, got {e_type}"));
    }

    let e_machine = u16::from_le_bytes([elf_bytes[18], elf_bytes[19]]);
    if e_machine != EM_RISCV {
        return Err(format!("expected EM_RISCV (0xF3), got 0x{e_machine:04X}"));
    }

    let entry = u32::from_le_bytes([elf_bytes[24], elf_bytes[25], elf_bytes[26], elf_bytes[27]]);
    let phoff = u32::from_le_bytes([elf_bytes[28], elf_bytes[29], elf_bytes[30], elf_bytes[31]]);
    let phnum = u16::from_le_bytes([elf_bytes[44], elf_bytes[45]]);

    let mut segments = Vec::new();

    for i in 0..phnum {
        let offset = usize::try_from(phoff).map_err(|_| "phoff overflow")? + usize::from(i) * 32;
        if offset + 32 > elf_bytes.len() {
            return Err(format!("program header {i} out of bounds"));
        }

        let p_type = u32::from_le_bytes([
            elf_bytes[offset],
            elf_bytes[offset + 1],
            elf_bytes[offset + 2],
            elf_bytes[offset + 3],
        ]);

        if p_type == PT_NULL {
            continue;
        }

        if p_type != PT_LOAD {
            return Err(format!("unsupported program header type {p_type}"));
        }

        let p_offset = u32::from_le_bytes([
            elf_bytes[offset + 4],
            elf_bytes[offset + 5],
            elf_bytes[offset + 6],
            elf_bytes[offset + 7],
        ]);

        let p_vaddr = u32::from_le_bytes([
            elf_bytes[offset + 8],
            elf_bytes[offset + 9],
            elf_bytes[offset + 10],
            elf_bytes[offset + 11],
        ]);

        let p_filesz = u32::from_le_bytes([
            elf_bytes[offset + 16],
            elf_bytes[offset + 17],
            elf_bytes[offset + 18],
            elf_bytes[offset + 19],
        ]);

        let p_memsz = u32::from_le_bytes([
            elf_bytes[offset + 20],
            elf_bytes[offset + 21],
            elf_bytes[offset + 22],
            elf_bytes[offset + 23],
        ]);

        let p_flags = u32::from_le_bytes([
            elf_bytes[offset + 24],
            elf_bytes[offset + 25],
            elf_bytes[offset + 26],
            elf_bytes[offset + 27],
        ]);

        if p_filesz > p_memsz {
            return Err(format!(
                "segment {i}: filesz ({p_filesz}) > memsz ({p_memsz})"
            ));
        }

        let file_start = usize::try_from(p_offset).map_err(|_| "p_offset overflow")?;
        let filesz_usize = usize::try_from(p_filesz).map_err(|_| "p_filesz overflow")?;
        let file_end = file_start
            .checked_add(filesz_usize)
            .ok_or("file segment overflow")?;
        if file_end > elf_bytes.len() {
            return Err(format!(
                "segment {i}: data out of bounds (offset {file_start}, filesz {p_filesz})"
            ));
        }

        let permissions = Permissions {
            read: (p_flags & 0x4) != 0,
            write: (p_flags & 0x2) != 0,
            execute: (p_flags & 0x1) != 0,
        };

        segments.push(LoadedSegment {
            vaddr: p_vaddr,
            memsz: p_memsz,
            filesz: p_filesz,
            permissions,
        });
    }

    Ok(LoadedElf { entry, segments })
}

/// Load an ELF binary into guest memory, creating regions for each
/// loadable segment. Returns the entry-point address.
pub fn load_elf_into_memory(elf_bytes: &[u8], memory: &mut Memory) -> Result<u32, Trap> {
    let elf = parse_elf(elf_bytes).map_err(|_| Trap::InvalidInstruction)?;

    for segment in &elf.segments {
        let file_start = find_ph_offset(elf_bytes, segment.vaddr, segment.filesz, segment.memsz)
            .map_err(|_| Trap::InvalidInstruction)?;
        let segment_data = &elf_bytes[file_start..file_start + segment.filesz as usize];

        memory.add_region(segment.vaddr, segment.memsz, segment.permissions);

        if segment.filesz > 0 {
            memory.write_bytes(segment.vaddr, segment_data)?;
        }
    }

    Ok(elf.entry)
}

fn find_ph_offset(elf_bytes: &[u8], vaddr: u32, filesz: u32, memsz: u32) -> Result<usize, String> {
    if elf_bytes.len() < 52 {
        return Err("ELF too small".into());
    }
    let phoff = u32::from_le_bytes([elf_bytes[28], elf_bytes[29], elf_bytes[30], elf_bytes[31]]);
    let phnum = u16::from_le_bytes([elf_bytes[44], elf_bytes[45]]);

    for i in 0..phnum {
        let offset = usize::try_from(phoff).map_err(|_| "phoff overflow")? + usize::from(i) * 32;
        if offset + 32 > elf_bytes.len() {
            return Err("phdr out of bounds".into());
        }
        let p_type = u32::from_le_bytes([
            elf_bytes[offset],
            elf_bytes[offset + 1],
            elf_bytes[offset + 2],
            elf_bytes[offset + 3],
        ]);
        if p_type != PT_LOAD {
            continue;
        }
        let p_vaddr = u32::from_le_bytes([
            elf_bytes[offset + 8],
            elf_bytes[offset + 9],
            elf_bytes[offset + 10],
            elf_bytes[offset + 11],
        ]);
        let p_offset = u32::from_le_bytes([
            elf_bytes[offset + 4],
            elf_bytes[offset + 5],
            elf_bytes[offset + 6],
            elf_bytes[offset + 7],
        ]);
        let p_filesz = u32::from_le_bytes([
            elf_bytes[offset + 16],
            elf_bytes[offset + 17],
            elf_bytes[offset + 18],
            elf_bytes[offset + 19],
        ]);
        let p_memsz = u32::from_le_bytes([
            elf_bytes[offset + 20],
            elf_bytes[offset + 21],
            elf_bytes[offset + 22],
            elf_bytes[offset + 23],
        ]);

        if p_vaddr == vaddr && p_filesz == filesz && p_memsz == memsz {
            return Ok(usize::try_from(p_offset).map_err(|_| "p_offset overflow")?);
        }
    }

    Err("matching segment not found".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::Memory;

    fn build_elf32(entry: u32, segments: &[(u32, u32, u32, u32, u32)]) -> Vec<u8> {
        let phoff: u32 = 52;
        let phnum: u16 = u16::try_from(segments.len()).unwrap();
        let mut elf = vec![0u8; 52 + segments.len() * 32];

        elf[0..4].copy_from_slice(&ELF_MAGIC);
        elf[4] = ELFCLASS32;
        elf[5] = ELFDATA2LSB;
        elf[16..18].copy_from_slice(&ET_EXEC.to_le_bytes());
        elf[18..20].copy_from_slice(&EM_RISCV.to_le_bytes());
        elf[24..28].copy_from_slice(&entry.to_le_bytes());
        elf[28..32].copy_from_slice(&phoff.to_le_bytes());
        elf[44..46].copy_from_slice(&phnum.to_le_bytes());

        for (i, &(vaddr, offset, filesz, memsz, flags)) in segments.iter().enumerate() {
            let base = 52 + i * 32;
            elf[base..base + 4].copy_from_slice(&PT_LOAD.to_le_bytes());
            elf[base + 4..base + 8].copy_from_slice(&offset.to_le_bytes());
            elf[base + 8..base + 12].copy_from_slice(&vaddr.to_le_bytes());
            elf[base + 16..base + 20].copy_from_slice(&filesz.to_le_bytes());
            elf[base + 20..base + 24].copy_from_slice(&memsz.to_le_bytes());
            elf[base + 24..base + 28].copy_from_slice(&flags.to_le_bytes());
        }

        if !segments.is_empty() {
            let (_, offset, filesz, _, _) = segments[segments.len() - 1];
            let end = usize::try_from(offset + filesz).unwrap();
            if end > elf.len() {
                elf.resize(end, 0);
            }
        }

        elf
    }

    #[test]
    fn parse_valid_static_elf() {
        let elf = build_elf32(0x1000, &[(0x1000, 0x1000, 0, 0x2000, 0x5)]);
        let result = parse_elf(&elf).unwrap();
        assert_eq!(result.entry, 0x1000);
        assert_eq!(result.segments.len(), 1);
        assert_eq!(result.segments[0].vaddr, 0x1000);
        assert_eq!(result.segments[0].memsz, 0x2000);
        assert!(result.segments[0].permissions.read);
        assert!(result.segments[0].permissions.execute);
        assert!(!result.segments[0].permissions.write);
    }

    #[test]
    fn parse_multiple_segments() {
        let elf = build_elf32(
            0x1000,
            &[
                (0x1000, 0x1000, 0x100, 0x100, 5),
                (0x2000, 0x1200, 0x80, 0x100, 6),
            ],
        );
        let result = parse_elf(&elf).unwrap();
        assert_eq!(result.segments.len(), 2);
        assert!(result.segments[0].permissions.read);
        assert!(result.segments[0].permissions.execute);
        assert!(!result.segments[0].permissions.write);
        assert!(result.segments[1].permissions.read);
        assert!(result.segments[1].permissions.write);
        assert!(!result.segments[1].permissions.execute);
    }

    #[test]
    fn reject_non_elf_magic() {
        let mut bytes = vec![0u8; 100];
        bytes[0] = 0x00;
        assert!(parse_elf(&bytes).is_err());
    }

    #[test]
    fn reject_64bit_elf() {
        let mut elf = build_elf32(0x1000, &[]);
        elf[4] = 2;
        assert!(parse_elf(&elf).is_err());
    }

    #[test]
    fn reject_big_endian_elf() {
        let mut elf = build_elf32(0x1000, &[]);
        elf[5] = 2;
        assert!(parse_elf(&elf).is_err());
    }

    #[test]
    fn reject_wrong_machine() {
        let mut elf = build_elf32(0x1000, &[]);
        elf[18] = 0x3E;
        assert!(parse_elf(&elf).is_err());
    }

    #[test]
    fn reject_non_exec_file() {
        let mut elf = build_elf32(0x1000, &[]);
        elf[16] = 1;
        assert!(parse_elf(&elf).is_err());
    }

    #[test]
    fn reject_truncated_elf() {
        let elf = vec![0u8; 10];
        assert!(parse_elf(&elf).is_err());
    }

    #[test]
    fn load_elf_into_memory_places_data() {
        let mut data = vec![0u8; 0x1200];
        data[0x1000..0x1100].fill(0xAB);
        let mut elf = build_elf32(0x1000, &[(0x1000, 0x1000, 0x100, 0x100, 0x5)]);
        elf[0x1000..0x1100].copy_from_slice(&data[0x1000..0x1100]);

        let mut mem = Memory::new(0x2000);
        let entry = load_elf_into_memory(&elf, &mut mem).unwrap();
        assert_eq!(entry, 0x1000);

        let b = mem.load_u8(0x1000).unwrap();
        assert_eq!(b, 0xAB);
    }

    #[test]
    fn load_elf_bss_zero_filled() {
        let elf = build_elf32(0x1000, &[(0x1000, 0x1000, 0x40, 0x100, 0x6)]);

        let mut mem = Memory::new(0x2000);
        let _ = load_elf_into_memory(&elf, &mut mem).unwrap();

        let b = mem.load_u8(0x1050).unwrap();
        assert_eq!(b, 0);
    }

    #[test]
    fn load_elf_segment_with_data() {
        let mut elf = build_elf32(0x1000, &[(0x1000, 0x1000, 0x80, 0x80, 0x7)]);
        for i in 0u32..0x80 {
            elf[0x1000 + i as usize] = (i & 0xFF) as u8;
        }

        let mut mem = Memory::new(0x2000);
        let _ = load_elf_into_memory(&elf, &mut mem).unwrap();

        for i in 0u32..0x80 {
            assert_eq!(mem.load_u8(0x1000 + i).unwrap(), (i & 0xFF) as u8);
        }
    }

    #[test]
    fn load_elf_sets_correct_permissions() {
        let elf = build_elf32(0x1000, &[(0x1000, 0x1000, 0, 0x100, 0x5)]);

        let mut mem = Memory::new(0x2000);
        let _ = load_elf_into_memory(&elf, &mut mem).unwrap();

        assert!(mem.load_insn(0x1000).is_ok());
        assert!(mem.store_u8(0x1000, 0).is_err());

        let elf2 = build_elf32(0x1000, &[(0x2000, 0x1000, 0, 0x100, 0x6)]);
        let mut mem2 = Memory::new(0x4000);
        let _ = load_elf_into_memory(&elf2, &mut mem2).unwrap();
        assert!(mem2.store_u8(0x2000, 0).is_ok());
        assert!(mem2.load_insn(0x2000).is_err());
    }

    #[test]
    fn empty_elf_no_segments() {
        let elf = build_elf32(0xDEAD, &[]);
        let result = parse_elf(&elf).unwrap();
        assert_eq!(result.entry, 0xDEAD);
        assert!(result.segments.is_empty());
    }
}
