//! End-to-end integration tests for the public M1 API.
//!
//! Synthesise a minimal static ELF32 RISC-V binary, feed it through
//! `load_elf_into_memory`, then run from the entry point with the
//! interpreter. Verify the final register state matches the program's
//! intent. These tests exercise loader → memory → decoder → executor
//! → host as a single unit using only the crate's public surface.

use neutrino_vm_rv32im::host::NoopHost;
use neutrino_vm_rv32im::loader::load_elf_into_memory;
use neutrino_vm_rv32im::memory::Memory;
use neutrino_vm_rv32im::{Halt, cpu::Cpu, executor::execute};

const ELF_MAGIC: [u8; 4] = [0x7F, b'E', b'L', b'F'];
const ELFCLASS32: u8 = 1;
const ELFDATA2LSB: u8 = 1;
const ET_EXEC: u16 = 2;
const EM_RISCV: u16 = 0xF3;
const PT_LOAD: u32 = 1;

/// Build a minimal static ELF32 little-endian RISC-V executable
/// containing a single loadable RX segment populated with the given
/// instruction words. Entry point lands at the start of the segment.
fn build_static_rx_elf(entry: u32, vaddr: u32, instructions: &[u32]) -> Vec<u8> {
    // Layout:
    //   0x00..0x34 : 52-byte ELF header
    //   0x34..0x54 : one 32-byte program header (PT_LOAD)
    //   0x54..     : instruction bytes
    let phoff: u32 = 52;
    let p_offset = phoff + 32;
    let code_len = u32::try_from(instructions.len() * 4).unwrap();

    let mut elf = vec![0u8; (p_offset + code_len) as usize];

    // ELF identification.
    elf[0..4].copy_from_slice(&ELF_MAGIC);
    elf[4] = ELFCLASS32;
    elf[5] = ELFDATA2LSB;
    elf[6] = 1; // EI_VERSION = EV_CURRENT
    // bytes 7..16 left zero (EI_OSABI, EI_ABIVERSION, padding)

    // Header fields.
    elf[16..18].copy_from_slice(&ET_EXEC.to_le_bytes()); // e_type
    elf[18..20].copy_from_slice(&EM_RISCV.to_le_bytes()); // e_machine
    elf[20..24].copy_from_slice(&1u32.to_le_bytes()); // e_version
    elf[24..28].copy_from_slice(&entry.to_le_bytes()); // e_entry
    elf[28..32].copy_from_slice(&phoff.to_le_bytes()); // e_phoff
    // e_shoff, e_flags zero
    elf[40..42].copy_from_slice(&52u16.to_le_bytes()); // e_ehsize
    elf[42..44].copy_from_slice(&32u16.to_le_bytes()); // e_phentsize
    elf[44..46].copy_from_slice(&1u16.to_le_bytes()); // e_phnum

    // Program header (PT_LOAD, RX).
    let ph = phoff as usize;
    elf[ph..ph + 4].copy_from_slice(&PT_LOAD.to_le_bytes()); // p_type
    elf[ph + 4..ph + 8].copy_from_slice(&p_offset.to_le_bytes()); // p_offset
    elf[ph + 8..ph + 12].copy_from_slice(&vaddr.to_le_bytes()); // p_vaddr
    elf[ph + 12..ph + 16].copy_from_slice(&vaddr.to_le_bytes()); // p_paddr
    elf[ph + 16..ph + 20].copy_from_slice(&code_len.to_le_bytes()); // p_filesz
    elf[ph + 20..ph + 24].copy_from_slice(&code_len.to_le_bytes()); // p_memsz
    elf[ph + 24..ph + 28].copy_from_slice(&0x5u32.to_le_bytes()); // p_flags = R | X
    elf[ph + 28..ph + 32].copy_from_slice(&4u32.to_le_bytes()); // p_align

    // Instruction bytes.
    for (i, word) in instructions.iter().enumerate() {
        let off = p_offset as usize + i * 4;
        elf[off..off + 4].copy_from_slice(&word.to_le_bytes());
    }

    elf
}

#[test]
fn loader_to_executor_pipeline_runs_arithmetic_program() {
    // Hand-encoded RV32IM program at vaddr 0x1000:
    //   addi x10, x0, 5       0x00500513
    //   addi x11, x0, 7       0x00700593
    //   add  x12, x10, x11    0x00B50633
    //   mul  x13, x10, x11    0x02B506B3
    //   ebreak                0x00100073
    let program = [
        0x0050_0513u32,
        0x0070_0593u32,
        0x00B5_0633u32,
        0x02B5_06B3u32,
        0x0010_0073u32,
    ];

    let elf = build_static_rx_elf(0x1000, 0x1000, &program);

    let mut memory = Memory::new(0);
    let entry = load_elf_into_memory(&elf, &mut memory).expect("load_elf_into_memory failed");
    assert_eq!(entry, 0x1000);

    let mut cpu = Cpu::new();
    cpu.pc = entry;

    let mut host = NoopHost;
    let mut gas = 1_000u64;
    let halt =
        execute(&mut cpu, &mut memory, &mut host, &mut gas, 100).expect("execute returned trap");

    assert_eq!(halt, Halt::ExplicitAbort { code: 2 });
    assert_eq!(cpu.read(10), 5);
    assert_eq!(cpu.read(11), 7);
    assert_eq!(cpu.read(12), 12);
    assert_eq!(cpu.read(13), 35);
}

#[test]
fn loader_to_executor_pipeline_runs_branch_loop() {
    // Countdown loop that decrements x5 from 4 to 0:
    //   addi x5, x0, 4        0x00400293
    //   addi x5, x5, -1       0xFFF28293
    //   bne  x5, x0, -4       0xFE029EE3   (branch back to the addi)
    //   ebreak                0x00100073
    let program = [
        0x0040_0293u32,
        0xFFF2_8293u32,
        0xFE02_9EE3u32,
        0x0010_0073u32,
    ];

    let elf = build_static_rx_elf(0x1000, 0x1000, &program);

    let mut memory = Memory::new(0);
    let entry = load_elf_into_memory(&elf, &mut memory).expect("load_elf_into_memory failed");

    let mut cpu = Cpu::new();
    cpu.pc = entry;

    let mut host = NoopHost;
    let mut gas = 1_000u64;
    let halt =
        execute(&mut cpu, &mut memory, &mut host, &mut gas, 1_000).expect("execute returned trap");

    assert_eq!(halt, Halt::ExplicitAbort { code: 2 });
    assert_eq!(cpu.read(5), 0);
    // 1 (initial addi) + 4 * (addi + bne) + 1 (ebreak) instructions executed.
    // Each costs 1 gas in the default cost table; gas should have dropped by 10.
    assert_eq!(gas, 1_000 - 10);
}

#[test]
fn loader_to_executor_pipeline_propagates_division_by_zero_as_minus_one() {
    // Demonstrate spec-conforming DIV/0 behavior across the full pipeline:
    //   addi x10, x0,  42        0x02A00513
    //   addi x11, x0,   0        0x00000593
    //   div  x12, x10, x11       0x02B5_4633
    //   ebreak                   0x00100073
    let program = [
        0x02A0_0513u32,
        0x0000_0593u32,
        0x02B5_4633u32,
        0x0010_0073u32,
    ];

    let elf = build_static_rx_elf(0x1000, 0x1000, &program);

    let mut memory = Memory::new(0);
    let entry = load_elf_into_memory(&elf, &mut memory).expect("load failed");

    let mut cpu = Cpu::new();
    cpu.pc = entry;

    let mut host = NoopHost;
    let mut gas = 1_000u64;
    let halt = execute(&mut cpu, &mut memory, &mut host, &mut gas, 100).expect("trapped");

    assert_eq!(halt, Halt::ExplicitAbort { code: 2 });
    assert_eq!(cpu.read(10), 42);
    assert_eq!(cpu.read(11), 0);
    // Per RISC-V "M" spec: DIV-by-zero is non-trapping and returns all-1s.
    assert_eq!(cpu.read(12), u32::MAX);
}
