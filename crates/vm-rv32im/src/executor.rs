//! RV32IM instruction executor.
//!
//! Implements the main fetch-decode-execute loop with gas metering and
//! host ECALL dispatch.

#![allow(
    missing_docs,
    clippy::too_many_lines,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    clippy::cast_lossless,
    clippy::cast_possible_truncation,
    clippy::if_not_else,
    clippy::type_complexity
)]

use crate::cpu::Cpu;
use crate::host::HostInterface;
use crate::instruction;
use crate::instruction::Instruction;
use crate::memory::Memory;
use crate::{Halt, Trap};

/// Execute RV32IM instructions in a loop until the program halts, traps,
/// or exhausts gas or step budget.
pub fn execute(
    cpu: &mut Cpu,
    memory: &mut Memory,
    host: &mut dyn HostInterface,
    gas_remaining: &mut u64,
    max_steps: u64,
) -> Result<Halt, Trap> {
    let mut steps: u64 = 0;

    loop {
        if steps >= max_steps {
            return Err(Trap::OutOfGas);
        }

        let insn_word = memory.load_insn(cpu.pc)?;
        let insn = instruction::decode(insn_word).map_err(|_| Trap::InvalidInstruction)?;

        let cost = instruction::gas_cost(&insn);
        *gas_remaining = gas_remaining.checked_sub(cost).ok_or(Trap::OutOfGas)?;

        let next_pc = cpu.pc.wrapping_add(4);

        match insn {
            Instruction::Lui { rd, imm_u20 } => {
                cpu.write(rd, imm_u20);
                cpu.pc = next_pc;
            }
            Instruction::Auipc { rd, imm_u20 } => {
                cpu.write(rd, cpu.pc.wrapping_add(imm_u20));
                cpu.pc = next_pc;
            }
            Instruction::Jal { rd, offset } => {
                let target = (cpu.pc as i32).wrapping_add(offset) as u32;
                if target & 0x3 != 0 {
                    return Err(Trap::InstructionAddressMisaligned { addr: target });
                }
                cpu.write(rd, next_pc);
                cpu.pc = target;
            }
            Instruction::Jalr { rd, rs1, offset } => {
                let target = (cpu.read(rs1) as i32).wrapping_add(offset) as u32 & !1u32;
                if target & 0x3 != 0 {
                    return Err(Trap::InstructionAddressMisaligned { addr: target });
                }
                cpu.write(rd, next_pc);
                cpu.pc = target;
            }
            Instruction::Beq { rs1, rs2, offset } => {
                cpu.pc = if cpu.read(rs1) == cpu.read(rs2) {
                    (cpu.pc as i32).wrapping_add(offset) as u32
                } else {
                    next_pc
                };
            }
            Instruction::Bne { rs1, rs2, offset } => {
                cpu.pc = if cpu.read(rs1) != cpu.read(rs2) {
                    (cpu.pc as i32).wrapping_add(offset) as u32
                } else {
                    next_pc
                };
            }
            Instruction::Blt { rs1, rs2, offset } => {
                let a = cpu.read(rs1) as i32;
                let b = cpu.read(rs2) as i32;
                cpu.pc = if a < b {
                    (cpu.pc as i32).wrapping_add(offset) as u32
                } else {
                    next_pc
                };
            }
            Instruction::Bge { rs1, rs2, offset } => {
                let a = cpu.read(rs1) as i32;
                let b = cpu.read(rs2) as i32;
                cpu.pc = if a >= b {
                    (cpu.pc as i32).wrapping_add(offset) as u32
                } else {
                    next_pc
                };
            }
            Instruction::Bltu { rs1, rs2, offset } => {
                let a = cpu.read(rs1);
                let b = cpu.read(rs2);
                cpu.pc = if a < b {
                    (cpu.pc as i32).wrapping_add(offset) as u32
                } else {
                    next_pc
                };
            }
            Instruction::Bgeu { rs1, rs2, offset } => {
                let a = cpu.read(rs1);
                let b = cpu.read(rs2);
                cpu.pc = if a >= b {
                    (cpu.pc as i32).wrapping_add(offset) as u32
                } else {
                    next_pc
                };
            }
            Instruction::Lb { rd, rs1, offset } => {
                let addr = cpu.read(rs1).wrapping_add_signed(offset);
                let val = memory.load_u8(addr)? as i8 as i32 as u32;
                cpu.write(rd, val);
                cpu.pc = next_pc;
            }
            Instruction::Lh { rd, rs1, offset } => {
                let addr = cpu.read(rs1).wrapping_add_signed(offset);
                let val = memory.load_u16(addr)? as i16 as i32 as u32;
                cpu.write(rd, val);
                cpu.pc = next_pc;
            }
            Instruction::Lw { rd, rs1, offset } => {
                let addr = cpu.read(rs1).wrapping_add_signed(offset);
                let val = memory.load_u32(addr)?;
                cpu.write(rd, val);
                cpu.pc = next_pc;
            }
            Instruction::Lbu { rd, rs1, offset } => {
                let addr = cpu.read(rs1).wrapping_add_signed(offset);
                let val = u32::from(memory.load_u8(addr)?);
                cpu.write(rd, val);
                cpu.pc = next_pc;
            }
            Instruction::Lhu { rd, rs1, offset } => {
                let addr = cpu.read(rs1).wrapping_add_signed(offset);
                let val = u32::from(memory.load_u16(addr)?);
                cpu.write(rd, val);
                cpu.pc = next_pc;
            }
            Instruction::Sb { rs1, rs2, offset } => {
                let addr = cpu.read(rs1).wrapping_add_signed(offset);
                memory.store_u8(addr, cpu.read(rs2) as u8)?;
                cpu.pc = next_pc;
            }
            Instruction::Sh { rs1, rs2, offset } => {
                let addr = cpu.read(rs1).wrapping_add_signed(offset);
                memory.store_u16(addr, cpu.read(rs2) as u16)?;
                cpu.pc = next_pc;
            }
            Instruction::Sw { rs1, rs2, offset } => {
                let addr = cpu.read(rs1).wrapping_add_signed(offset);
                memory.store_u32(addr, cpu.read(rs2))?;
                cpu.pc = next_pc;
            }
            Instruction::Addi { rd, rs1, imm } => {
                cpu.write(rd, cpu.read(rs1).wrapping_add_signed(imm));
                cpu.pc = next_pc;
            }
            Instruction::Slti { rd, rs1, imm } => {
                let val = u32::from((cpu.read(rs1) as i32) < imm);
                cpu.write(rd, val);
                cpu.pc = next_pc;
            }
            Instruction::Sltiu { rd, rs1, imm } => {
                let lhs = cpu.read(rs1);
                let rhs = imm as u32;
                cpu.write(rd, u32::from(lhs < rhs));
                cpu.pc = next_pc;
            }
            Instruction::Xori { rd, rs1, imm } => {
                cpu.write(rd, cpu.read(rs1) ^ (imm as u32));
                cpu.pc = next_pc;
            }
            Instruction::Ori { rd, rs1, imm } => {
                cpu.write(rd, cpu.read(rs1) | (imm as u32));
                cpu.pc = next_pc;
            }
            Instruction::Andi { rd, rs1, imm } => {
                cpu.write(rd, cpu.read(rs1) & (imm as u32));
                cpu.pc = next_pc;
            }
            Instruction::Slli { rd, rs1, shamt } => {
                cpu.write(rd, cpu.read(rs1) << u32::from(shamt));
                cpu.pc = next_pc;
            }
            Instruction::Srli { rd, rs1, shamt } => {
                cpu.write(rd, cpu.read(rs1) >> u32::from(shamt));
                cpu.pc = next_pc;
            }
            Instruction::Srai { rd, rs1, shamt } => {
                let val = (cpu.read(rs1) as i32) >> i32::from(shamt);
                cpu.write(rd, val as u32);
                cpu.pc = next_pc;
            }
            Instruction::Add { rd, rs1, rs2 } => {
                cpu.write(rd, cpu.read(rs1).wrapping_add(cpu.read(rs2)));
                cpu.pc = next_pc;
            }
            Instruction::Sub { rd, rs1, rs2 } => {
                cpu.write(rd, cpu.read(rs1).wrapping_sub(cpu.read(rs2)));
                cpu.pc = next_pc;
            }
            Instruction::Sll { rd, rs1, rs2 } => {
                let shift = cpu.read(rs2) & 0x1F;
                cpu.write(rd, cpu.read(rs1) << shift);
                cpu.pc = next_pc;
            }
            Instruction::Slt { rd, rs1, rs2 } => {
                let val = u32::from((cpu.read(rs1) as i32) < (cpu.read(rs2) as i32));
                cpu.write(rd, val);
                cpu.pc = next_pc;
            }
            Instruction::Sltu { rd, rs1, rs2 } => {
                cpu.write(rd, u32::from(cpu.read(rs1) < cpu.read(rs2)));
                cpu.pc = next_pc;
            }
            Instruction::Xor { rd, rs1, rs2 } => {
                cpu.write(rd, cpu.read(rs1) ^ cpu.read(rs2));
                cpu.pc = next_pc;
            }
            Instruction::Srl { rd, rs1, rs2 } => {
                let shift = cpu.read(rs2) & 0x1F;
                cpu.write(rd, cpu.read(rs1) >> shift);
                cpu.pc = next_pc;
            }
            Instruction::Sra { rd, rs1, rs2 } => {
                let shift = cpu.read(rs2) & 0x1F;
                let val = (cpu.read(rs1) as i32) >> shift;
                cpu.write(rd, val as u32);
                cpu.pc = next_pc;
            }
            Instruction::Or { rd, rs1, rs2 } => {
                cpu.write(rd, cpu.read(rs1) | cpu.read(rs2));
                cpu.pc = next_pc;
            }
            Instruction::And { rd, rs1, rs2 } => {
                cpu.write(rd, cpu.read(rs1) & cpu.read(rs2));
                cpu.pc = next_pc;
            }
            Instruction::Mul { rd, rs1, rs2 } => {
                let result = cpu.read(rs1).wrapping_mul(cpu.read(rs2));
                cpu.write(rd, result);
                cpu.pc = next_pc;
            }
            Instruction::Mulh { rd, rs1, rs2 } => {
                let a = cpu.read(rs1) as i32 as i64;
                let b = cpu.read(rs2) as i32 as i64;
                let result = (a.wrapping_mul(b) >> 32) as u32;
                cpu.write(rd, result);
                cpu.pc = next_pc;
            }
            Instruction::Mulhsu { rd, rs1, rs2 } => {
                let a = cpu.read(rs1) as i32 as i64;
                let b = cpu.read(rs2) as u64;
                let result = (a.wrapping_mul(b as i64) >> 32) as u32;
                cpu.write(rd, result);
                cpu.pc = next_pc;
            }
            Instruction::Mulhu { rd, rs1, rs2 } => {
                let a = u64::from(cpu.read(rs1));
                let b = u64::from(cpu.read(rs2));
                let result = ((a * b) >> 32) as u32;
                cpu.write(rd, result);
                cpu.pc = next_pc;
            }
            // Division semantics follow the RISC-V "M" extension v2.0
            // (chapter 12, table 1): division by zero and signed
            // overflow are non-trapping and produce specific results.
            //   DIV[U] / 0  -> 0xFFFF_FFFF (all bits set)
            //   REM[U] / 0  -> dividend (rs1)
            //   DIV i32::MIN / -1 -> i32::MIN  (handled by wrapping_div)
            //   REM i32::MIN / -1 -> 0         (handled by wrapping_rem)
            Instruction::Div { rd, rs1, rs2 } => {
                let divisor = cpu.read(rs2) as i32;
                let dividend = cpu.read(rs1) as i32;
                let result = if divisor == 0 {
                    u32::MAX
                } else {
                    dividend.wrapping_div(divisor) as u32
                };
                cpu.write(rd, result);
                cpu.pc = next_pc;
            }
            Instruction::Divu { rd, rs1, rs2 } => {
                let dividend = cpu.read(rs1);
                let divisor = cpu.read(rs2);
                let result = if divisor == 0 {
                    u32::MAX
                } else {
                    dividend.wrapping_div(divisor)
                };
                cpu.write(rd, result);
                cpu.pc = next_pc;
            }
            Instruction::Rem { rd, rs1, rs2 } => {
                let divisor = cpu.read(rs2) as i32;
                let dividend = cpu.read(rs1) as i32;
                let result = if divisor == 0 {
                    dividend as u32
                } else {
                    dividend.wrapping_rem(divisor) as u32
                };
                cpu.write(rd, result);
                cpu.pc = next_pc;
            }
            Instruction::Remu { rd, rs1, rs2 } => {
                let dividend = cpu.read(rs1);
                let divisor = cpu.read(rs2);
                let result = if divisor == 0 {
                    dividend
                } else {
                    dividend.wrapping_rem(divisor)
                };
                cpu.write(rd, result);
                cpu.pc = next_pc;
            }
            Instruction::Ecall => {
                let syscall_code = cpu.read(17);
                let ecall_gas = crate::host::ecall_base_gas(syscall_code);
                *gas_remaining = gas_remaining.checked_sub(ecall_gas).ok_or(Trap::OutOfGas)?;
                match host.ecall(cpu, memory, gas_remaining, syscall_code)? {
                    Some(halt) => return Ok(halt),
                    None => {
                        cpu.pc = next_pc;
                    }
                }
            }
            Instruction::Ebreak => {
                return Ok(Halt::ExplicitAbort { code: 2 });
            }
            Instruction::Fence => {
                cpu.pc = next_pc;
            }
        }

        steps = steps.checked_add(1).ok_or(Trap::OutOfGas)?;
    }
}

#[cfg(test)]
#[allow(
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    clippy::cast_lossless
)]
mod tests {
    use super::*;
    use crate::cpu::Cpu;
    use crate::host::NoopHost;
    use crate::instruction::encode_test;
    use crate::memory::{Memory, Permissions};
    use alloc::vec;

    fn setup() -> (Cpu, Memory, NoopHost) {
        let mut cpu = Cpu::new();
        cpu.pc = 0x1000;
        let mut mem = Memory::new(0x2000);
        mem.add_region(0x1000, 0x1000, Permissions::RX);
        mem.add_region(0x2000, 0x1000, Permissions::RW);
        (cpu, mem, NoopHost)
    }

    fn store_insn(mem: &mut Memory, addr: u32, insn: u32) {
        mem.write_bytes(addr, &insn.to_le_bytes()).unwrap();
    }

    fn run_insn(insn: Instruction) -> Cpu {
        let (mut cpu, mut mem, mut host) = setup();
        store_insn(&mut mem, 0x1000, encode_test(&insn));
        let mut gas = 100;
        let _ = execute(&mut cpu, &mut mem, &mut host, &mut gas, 1);
        cpu
    }

    fn run_insn_with_regs(insn: Instruction, init_regs: &[(u8, u32)]) -> Cpu {
        let (mut cpu, mut mem, mut host) = setup();
        for &(r, v) in init_regs {
            cpu.write(r, v);
        }
        store_insn(&mut mem, 0x1000, encode_test(&insn));
        let mut gas = 100;
        let _ = execute(&mut cpu, &mut mem, &mut host, &mut gas, 1);
        cpu
    }

    #[test]
    fn execute_lui() {
        let cpu = run_insn(Instruction::Lui {
            rd: 1,
            imm_u20: 0x1234_5000,
        });
        assert_eq!(cpu.read(1), 0x1234_5000);
    }

    #[test]
    fn execute_auipc() {
        let cpu = run_insn(Instruction::Auipc {
            rd: 2,
            imm_u20: 0x0000_1000,
        });
        assert_eq!(cpu.read(2), 0x1000 + 0x1000);
    }

    #[test]
    fn execute_addi() {
        let cpu = run_insn_with_regs(
            Instruction::Addi {
                rd: 1,
                rs1: 2,
                imm: 42,
            },
            &[(2, 10)],
        );
        assert_eq!(cpu.read(1), 52);
    }

    #[test]
    fn execute_addi_negative_imm() {
        let cpu = run_insn_with_regs(
            Instruction::Addi {
                rd: 1,
                rs1: 2,
                imm: -1,
            },
            &[(2, 10)],
        );
        assert_eq!(cpu.read(1), 9);
    }

    #[test]
    fn execute_sub() {
        let cpu = run_insn_with_regs(
            Instruction::Sub {
                rd: 1,
                rs1: 2,
                rs2: 3,
            },
            &[(2, 20), (3, 7)],
        );
        assert_eq!(cpu.read(1), 13);
    }

    #[test]
    fn execute_branch_beq_taken() {
        let cpu = run_insn_with_regs(
            Instruction::Beq {
                rs1: 1,
                rs2: 2,
                offset: 8,
            },
            &[(1, 5), (2, 5)],
        );
        assert_eq!(cpu.pc, 0x1008);
    }

    #[test]
    fn execute_branch_beq_not_taken() {
        let cpu = run_insn_with_regs(
            Instruction::Beq {
                rs1: 1,
                rs2: 2,
                offset: 8,
            },
            &[(1, 5), (2, 7)],
        );
        assert_eq!(cpu.pc, 0x1004);
    }

    #[test]
    fn execute_slt_signed() {
        let cpu = run_insn_with_regs(
            Instruction::Slt {
                rd: 1,
                rs1: 2,
                rs2: 3,
            },
            &[(2, 0xFFFF_FFFF), (3, 0)],
        );
        assert_eq!(cpu.read(1), 1);
    }

    #[test]
    fn execute_sltu_unsigned() {
        let cpu = run_insn_with_regs(
            Instruction::Sltu {
                rd: 1,
                rs1: 2,
                rs2: 3,
            },
            &[(2, 0xFFFF_FFFF), (3, 0)],
        );
        assert_eq!(cpu.read(1), 0);
    }

    #[test]
    fn execute_mul() {
        let cpu = run_insn_with_regs(
            Instruction::Mul {
                rd: 1,
                rs1: 2,
                rs2: 3,
            },
            &[(2, 6), (3, 7)],
        );
        assert_eq!(cpu.read(1), 42);
    }

    #[test]
    fn execute_div() {
        let cpu = run_insn_with_regs(
            Instruction::Div {
                rd: 1,
                rs1: 2,
                rs2: 3,
            },
            &[(2, 42), (3, 6)],
        );
        assert_eq!(cpu.read(1), 7);
    }

    #[test]
    fn execute_div_negative() {
        let cpu = run_insn_with_regs(
            Instruction::Div {
                rd: 1,
                rs1: 2,
                rs2: 3,
            },
            &[(2, 0xFFFF_FFFBu32), (3, 2)],
        );
        assert_eq!(cpu.read(1) as i32, -2);
    }

    #[test]
    fn execute_div_by_zero_returns_minus_one() {
        // Per RV "M" spec: DIV by zero produces all-1s, no trap.
        let cpu = run_insn_with_regs(
            Instruction::Div {
                rd: 1,
                rs1: 2,
                rs2: 3,
            },
            &[(2, 0x1234_5678), (3, 0)],
        );
        assert_eq!(cpu.read(1), u32::MAX);
    }

    #[test]
    fn execute_divu_by_zero_returns_all_ones() {
        let cpu = run_insn_with_regs(
            Instruction::Divu {
                rd: 1,
                rs1: 2,
                rs2: 3,
            },
            &[(2, 100), (3, 0)],
        );
        assert_eq!(cpu.read(1), u32::MAX);
    }

    #[test]
    fn execute_rem_by_zero_returns_dividend() {
        // Per RV "M" spec: REM by zero returns the dividend, no trap.
        let cpu = run_insn_with_regs(
            Instruction::Rem {
                rd: 1,
                rs1: 2,
                rs2: 3,
            },
            &[(2, 0xDEAD_BEEF), (3, 0)],
        );
        assert_eq!(cpu.read(1), 0xDEAD_BEEF);
    }

    #[test]
    fn execute_remu_by_zero_returns_dividend() {
        let cpu = run_insn_with_regs(
            Instruction::Remu {
                rd: 1,
                rs1: 2,
                rs2: 3,
            },
            &[(2, 42), (3, 0)],
        );
        assert_eq!(cpu.read(1), 42);
    }

    #[test]
    fn execute_div_signed_overflow_returns_int_min() {
        // i32::MIN / -1 has no representable quotient; spec mandates
        // result = dividend (i32::MIN) and no trap.
        let cpu = run_insn_with_regs(
            Instruction::Div {
                rd: 1,
                rs1: 2,
                rs2: 3,
            },
            &[(2, 0x8000_0000), (3, 0xFFFF_FFFF)],
        );
        assert_eq!(cpu.read(1), 0x8000_0000);
    }

    #[test]
    fn execute_rem_signed_overflow_returns_zero() {
        // i32::MIN % -1 = 0 per spec.
        let cpu = run_insn_with_regs(
            Instruction::Rem {
                rd: 1,
                rs1: 2,
                rs2: 3,
            },
            &[(2, 0x8000_0000), (3, 0xFFFF_FFFF)],
        );
        assert_eq!(cpu.read(1), 0);
    }

    #[test]
    fn execute_rem() {
        let cpu = run_insn_with_regs(
            Instruction::Rem {
                rd: 1,
                rs1: 2,
                rs2: 3,
            },
            &[(2, 17), (3, 5)],
        );
        assert_eq!(cpu.read(1), 2);
    }

    #[test]
    fn execute_lw_sw_roundtrip() {
        let (mut cpu, mut mem, mut host) = setup();
        store_insn(
            &mut mem,
            0x1000,
            encode_test(&Instruction::Sw {
                rs1: 1,
                rs2: 2,
                offset: 0,
            }),
        );
        cpu.write(1, 0x2000);
        cpu.write(2, 0xDEAD_BEEF);
        let mut gas = 100;
        let _ = execute(&mut cpu, &mut mem, &mut host, &mut gas, 1);
        assert_eq!(mem.load_u32(0x2000).unwrap(), 0xDEAD_BEEF);
    }

    #[test]
    fn execute_lw_sw_roundtrip_full() {
        let (mut cpu, mut mem, mut host) = setup();
        store_insn(
            &mut mem,
            0x1000,
            encode_test(&Instruction::Sw {
                rs1: 1,
                rs2: 2,
                offset: 0,
            }),
        );
        store_insn(
            &mut mem,
            0x1004,
            encode_test(&Instruction::Lw {
                rd: 3,
                rs1: 1,
                offset: 0,
            }),
        );
        cpu.write(1, 0x2000);
        cpu.write(2, 0xCAFE_BABE);
        let mut gas = 100;
        let _ = execute(&mut cpu, &mut mem, &mut host, &mut gas, 2);
        assert_eq!(cpu.read(3), 0xCAFE_BABE);
    }

    #[test]
    fn execute_xori() {
        let cpu = run_insn_with_regs(
            Instruction::Xori {
                rd: 1,
                rs1: 2,
                imm: -1,
            },
            &[(2, 0x00FF_00FF)],
        );
        assert_eq!(cpu.read(1), 0xFF00_FF00);
    }

    #[test]
    fn execute_ori() {
        let cpu = run_insn_with_regs(
            Instruction::Ori {
                rd: 1,
                rs1: 2,
                imm: -1,
            },
            &[(2, 0x00FF_0000)],
        );
        assert_eq!(cpu.read(1), 0xFFFF_FFFF);
    }

    #[test]
    fn execute_andi() {
        let cpu = run_insn_with_regs(
            Instruction::Andi {
                rd: 1,
                rs1: 2,
                imm: -1,
            },
            &[(2, 0x00FF_00FF)],
        );
        assert_eq!(cpu.read(1), 0x00FF_00FF);
    }

    #[test]
    fn execute_slli() {
        let cpu = run_insn_with_regs(
            Instruction::Slli {
                rd: 1,
                rs1: 2,
                shamt: 5,
            },
            &[(2, 1)],
        );
        assert_eq!(cpu.read(1), 32);
    }

    #[test]
    fn execute_srli() {
        let cpu = run_insn_with_regs(
            Instruction::Srli {
                rd: 1,
                rs1: 2,
                shamt: 5,
            },
            &[(2, 32)],
        );
        assert_eq!(cpu.read(1), 1);
    }

    #[test]
    fn execute_srai_positive() {
        let cpu = run_insn_with_regs(
            Instruction::Srai {
                rd: 1,
                rs1: 2,
                shamt: 5,
            },
            &[(2, 0x8000_0000)],
        );
        assert_eq!(cpu.read(1), 0xFC00_0000);
    }

    #[test]
    fn execute_jal() {
        let cpu = run_insn(Instruction::Jal { rd: 1, offset: 8 });
        assert_eq!(cpu.read(1), 0x1004);
        assert_eq!(cpu.pc, 0x1008);
    }

    #[test]
    fn execute_jalr() {
        let cpu = run_insn_with_regs(
            Instruction::Jalr {
                rd: 1,
                rs1: 2,
                offset: 0,
            },
            &[(2, 0x2000)],
        );
        assert_eq!(cpu.read(1), 0x1004);
        assert_eq!(cpu.pc, 0x2000);
    }

    #[test]
    fn execute_jal_misaligned_target_traps() {
        // Offset 6 yields a target 0x1006, not 4-byte aligned.
        let (mut cpu, mut mem, mut host) = setup();
        store_insn(
            &mut mem,
            0x1000,
            encode_test(&Instruction::Jal { rd: 1, offset: 6 }),
        );
        let mut gas = 100;
        let result = execute(&mut cpu, &mut mem, &mut host, &mut gas, 1);
        assert_eq!(
            result,
            Err(Trap::InstructionAddressMisaligned { addr: 0x1006 })
        );
    }

    #[test]
    fn execute_jalr_misaligned_target_traps() {
        // JALR clears the low bit; if bit 1 of the target is set we
        // still land on a 2-mod-4 address.
        let (mut cpu, mut mem, mut host) = setup();
        store_insn(
            &mut mem,
            0x1000,
            encode_test(&Instruction::Jalr {
                rd: 1,
                rs1: 2,
                offset: 0,
            }),
        );
        cpu.write(2, 0x2002);
        let mut gas = 100;
        let result = execute(&mut cpu, &mut mem, &mut host, &mut gas, 1);
        assert_eq!(
            result,
            Err(Trap::InstructionAddressMisaligned { addr: 0x2002 })
        );
    }

    #[test]
    fn execute_ebreak_halt() {
        let (mut cpu, mut mem, mut host) = setup();
        store_insn(&mut mem, 0x1000, encode_test(&Instruction::Ebreak));
        let mut gas = 100;
        let result = execute(&mut cpu, &mut mem, &mut host, &mut gas, 1);
        assert_eq!(result, Ok(Halt::ExplicitAbort { code: 2 }));
    }

    #[test]
    fn x0_write_ignored() {
        let cpu = run_insn_with_regs(
            Instruction::Addi {
                rd: 0,
                rs1: 2,
                imm: 42,
            },
            &[(2, 0)],
        );
        assert_eq!(cpu.read(0), 0);
    }

    #[test]
    fn gas_exhausted_traps() {
        let (mut cpu, mut mem, mut host) = setup();
        store_insn(
            &mut mem,
            0x1000,
            encode_test(&Instruction::Addi {
                rd: 0,
                rs1: 0,
                imm: 0,
            }),
        );
        let mut gas = 0;
        let result = execute(&mut cpu, &mut mem, &mut host, &mut gas, 1);
        assert_eq!(result, Err(Trap::OutOfGas));
    }

    #[test]
    fn gas_decrements_per_instruction() {
        let (mut cpu, mut mem, mut host) = setup();
        store_insn(
            &mut mem,
            0x1000,
            encode_test(&Instruction::Addi {
                rd: 1,
                rs1: 2,
                imm: 42,
            }),
        );
        cpu.write(2, 10);
        let mut gas = 50;
        let _ = execute(&mut cpu, &mut mem, &mut host, &mut gas, 1);
        assert_eq!(gas, 49);
    }

    #[test]
    fn load_store_gas_cost() {
        let (mut cpu, mut mem, mut host) = setup();
        store_insn(
            &mut mem,
            0x1000,
            encode_test(&Instruction::Lw {
                rd: 3,
                rs1: 1,
                offset: 0,
            }),
        );
        cpu.write(1, 0x2000);
        let mut gas = 10;
        let _ = execute(&mut cpu, &mut mem, &mut host, &mut gas, 1);
        assert_eq!(gas, 8);
    }

    #[test]
    fn max_steps_limit() {
        let (mut cpu, mut mem, mut host) = setup();
        store_insn(
            &mut mem,
            0x1000,
            encode_test(&Instruction::Addi {
                rd: 0,
                rs1: 0,
                imm: 0,
            }),
        );
        let mut gas = 100;
        let result = execute(&mut cpu, &mut mem, &mut host, &mut gas, 0);
        assert_eq!(result, Err(Trap::OutOfGas));
    }

    #[test]
    fn all_alu_ops_deterministic() {
        let insns: [(Instruction, &[(u8, u32)], fn(&Cpu) -> u32); 5] = [
            (
                Instruction::Add {
                    rd: 1,
                    rs1: 2,
                    rs2: 3,
                },
                &[(2, 7), (3, 3)],
                |c| c.read(1),
            ),
            (
                Instruction::Sub {
                    rd: 1,
                    rs1: 2,
                    rs2: 3,
                },
                &[(2, 7), (3, 3)],
                |c| c.read(1),
            ),
            (
                Instruction::Xor {
                    rd: 1,
                    rs1: 2,
                    rs2: 3,
                },
                &[(2, 0xFF), (3, 0xF0)],
                |c| c.read(1),
            ),
            (
                Instruction::Or {
                    rd: 1,
                    rs1: 2,
                    rs2: 3,
                },
                &[(2, 0xFF), (3, 0xF0)],
                |c| c.read(1),
            ),
            (
                Instruction::And {
                    rd: 1,
                    rs1: 2,
                    rs2: 3,
                },
                &[(2, 0xFF), (3, 0xF0)],
                |c| c.read(1),
            ),
        ];
        for (insn, regs, check) in &insns {
            let val1 = {
                let (mut cpu, mut mem, mut host) = setup();
                for &(r, v) in *regs {
                    cpu.write(r, v);
                }
                store_insn(&mut mem, 0x1000, encode_test(insn));
                let mut gas = 100;
                let _ = execute(&mut cpu, &mut mem, &mut host, &mut gas, 1);
                check(&cpu)
            };
            let val2 = {
                let (mut cpu, mut mem, mut host) = setup();
                for &(r, v) in *regs {
                    cpu.write(r, v);
                }
                store_insn(&mut mem, 0x1000, encode_test(insn));
                let mut gas = 100;
                let _ = execute(&mut cpu, &mut mem, &mut host, &mut gas, 1);
                check(&cpu)
            };
            assert_eq!(val1, val2, "instruction produced different results");
        }
    }

    #[test]
    fn execution_state_identical_after_re_run() {
        let insn = Instruction::Mul {
            rd: 1,
            rs1: 2,
            rs2: 3,
        };
        let regs: &[(u8, u32)] = &[(2, 6), (3, 7)];

        let run = || -> (Cpu, u64) {
            let (mut cpu, mut mem, mut host) = setup();
            for &(r, v) in regs {
                cpu.write(r, v);
            }
            store_insn(&mut mem, 0x1000, encode_test(&insn));
            let mut gas = 100;
            let _ = execute(&mut cpu, &mut mem, &mut host, &mut gas, 1);
            (cpu, gas)
        };

        let (cpu1, gas1) = run();
        let (cpu2, gas2) = run();
        assert_eq!(cpu1.regs, cpu2.regs);
        assert_eq!(cpu1.pc, cpu2.pc);
        assert_eq!(gas1, gas2);
    }

    fn store_program(mem: &mut Memory, base: u32, insns: &[u32]) {
        for (i, &word) in insns.iter().enumerate() {
            store_insn(mem, base + u32::try_from(i * 4).unwrap(), word);
        }
    }

    #[test]
    fn program_arithmetic_sequence() {
        let (mut cpu, mut mem, mut host) = setup();
        store_program(
            &mut mem,
            0x1000,
            &[
                encode_test(&Instruction::Addi {
                    rd: 1,
                    rs1: 0,
                    imm: 10,
                }),
                encode_test(&Instruction::Addi {
                    rd: 2,
                    rs1: 0,
                    imm: 20,
                }),
                encode_test(&Instruction::Add {
                    rd: 3,
                    rs1: 1,
                    rs2: 2,
                }),
                encode_test(&Instruction::Sub {
                    rd: 4,
                    rs1: 2,
                    rs2: 1,
                }),
                encode_test(&Instruction::Ebreak),
            ],
        );

        let mut gas = 100;
        let result = execute(&mut cpu, &mut mem, &mut host, &mut gas, 10);
        assert_eq!(result, Ok(Halt::ExplicitAbort { code: 2 }));
        assert_eq!(cpu.read(1), 10);
        assert_eq!(cpu.read(2), 20);
        assert_eq!(cpu.read(3), 30);
        assert_eq!(cpu.read(4), 10);
    }

    #[test]
    fn program_countdown_loop() {
        let (mut cpu, mut mem, mut host) = setup();
        store_program(
            &mut mem,
            0x1000,
            &[
                encode_test(&Instruction::Addi {
                    rd: 5,
                    rs1: 0,
                    imm: 5,
                }),
                encode_test(&Instruction::Addi {
                    rd: 5,
                    rs1: 5,
                    imm: -1,
                }),
                encode_test(&Instruction::Bne {
                    rs1: 5,
                    rs2: 0,
                    offset: -4,
                }),
                encode_test(&Instruction::Ebreak),
            ],
        );

        let mut gas = 100;
        let result = execute(&mut cpu, &mut mem, &mut host, &mut gas, 100);
        assert_eq!(result, Ok(Halt::ExplicitAbort { code: 2 }));
        assert_eq!(cpu.read(5), 0);
        assert!(gas < 100);
    }

    #[test]
    fn program_memory_store_load_sum() {
        let (mut cpu, mut mem, mut host) = setup();
        store_program(
            &mut mem,
            0x1000,
            &[
                encode_test(&Instruction::Addi {
                    rd: 1,
                    rs1: 0,
                    imm: 42,
                }),
                encode_test(&Instruction::Addi {
                    rd: 2,
                    rs1: 0,
                    imm: 99,
                }),
                encode_test(&Instruction::Lui {
                    rd: 10,
                    imm_u20: 0x0000_2000,
                }),
                encode_test(&Instruction::Sw {
                    rs1: 10,
                    rs2: 1,
                    offset: 0,
                }),
                encode_test(&Instruction::Sw {
                    rs1: 10,
                    rs2: 2,
                    offset: 4,
                }),
                encode_test(&Instruction::Lw {
                    rd: 3,
                    rs1: 10,
                    offset: 0,
                }),
                encode_test(&Instruction::Lw {
                    rd: 4,
                    rs1: 10,
                    offset: 4,
                }),
                encode_test(&Instruction::Add {
                    rd: 5,
                    rs1: 3,
                    rs2: 4,
                }),
                encode_test(&Instruction::Ebreak),
            ],
        );

        let mut gas = 100;
        let result = execute(&mut cpu, &mut mem, &mut host, &mut gas, 10);
        assert_eq!(result, Ok(Halt::ExplicitAbort { code: 2 }));
        assert_eq!(cpu.read(5), 141);
    }

    #[test]
    fn program_jal_and_jalr() {
        let (mut cpu, mut mem, mut host) = setup();
        store_program(
            &mut mem,
            0x1000,
            &[
                encode_test(&Instruction::Jal { rd: 1, offset: 8 }),
                encode_test(&Instruction::Ebreak),
                encode_test(&Instruction::Addi {
                    rd: 9,
                    rs1: 0,
                    imm: 99,
                }),
                encode_test(&Instruction::Jalr {
                    rd: 0,
                    rs1: 1,
                    offset: 0,
                }),
            ],
        );

        let mut gas = 100;
        let result = execute(&mut cpu, &mut mem, &mut host, &mut gas, 10);
        assert_eq!(result, Ok(Halt::ExplicitAbort { code: 2 }));
        assert_eq!(cpu.read(9), 99);
        assert_eq!(cpu.read(1), 0x1004);
    }

    #[test]
    fn program_conditional_max() {
        let (mut cpu, mut mem, mut host) = setup();
        store_program(
            &mut mem,
            0x1000,
            &[
                encode_test(&Instruction::Addi {
                    rd: 1,
                    rs1: 0,
                    imm: 25,
                }),
                encode_test(&Instruction::Addi {
                    rd: 2,
                    rs1: 0,
                    imm: 17,
                }),
                encode_test(&Instruction::Bge {
                    rs1: 1,
                    rs2: 2,
                    offset: 12,
                }),
                encode_test(&Instruction::Addi {
                    rd: 3,
                    rs1: 2,
                    imm: 0,
                }),
                encode_test(&Instruction::Jal { rd: 0, offset: 8 }),
                encode_test(&Instruction::Addi {
                    rd: 3,
                    rs1: 1,
                    imm: 0,
                }),
                encode_test(&Instruction::Ebreak),
            ],
        );

        let mut gas = 100;
        let result = execute(&mut cpu, &mut mem, &mut host, &mut gas, 20);
        assert_eq!(result, Ok(Halt::ExplicitAbort { code: 2 }));
        assert_eq!(cpu.read(3), 25);
    }

    #[test]
    fn program_mul_and_mulh() {
        let (mut cpu, mut mem, mut host) = setup();
        store_program(
            &mut mem,
            0x1000,
            &[
                encode_test(&Instruction::Lui {
                    rd: 1,
                    imm_u20: 0x1234_5000,
                }),
                encode_test(&Instruction::Addi {
                    rd: 1,
                    rs1: 1,
                    imm: 0x678,
                }),
                encode_test(&Instruction::Lui {
                    rd: 2,
                    imm_u20: 0x0000_2000,
                }),
                encode_test(&Instruction::Addi {
                    rd: 2,
                    rs1: 2,
                    imm: 0x100,
                }),
                encode_test(&Instruction::Mul {
                    rd: 3,
                    rs1: 1,
                    rs2: 2,
                }),
                encode_test(&Instruction::Mulh {
                    rd: 4,
                    rs1: 1,
                    rs2: 2,
                }),
                encode_test(&Instruction::Ebreak),
            ],
        );

        let mut gas = 100;
        let result = execute(&mut cpu, &mut mem, &mut host, &mut gas, 10);
        assert_eq!(result, Ok(Halt::ExplicitAbort { code: 2 }));
        let lo = cpu.read(1).wrapping_mul(cpu.read(2));
        let hi = u32::try_from(
            i64::from(cpu.read(1) as i32).wrapping_mul(i64::from(cpu.read(2) as i32)) >> 32,
        )
        .unwrap();
        assert_eq!(cpu.read(3), lo);
        assert_eq!(cpu.read(4), hi);
    }

    #[test]
    fn deterministic_re_execution_produces_same_state() {
        let insns = [
            encode_test(&Instruction::Addi {
                rd: 1,
                rs1: 0,
                imm: 7,
            }),
            encode_test(&Instruction::Addi {
                rd: 2,
                rs1: 0,
                imm: 3,
            }),
            encode_test(&Instruction::Mul {
                rd: 3,
                rs1: 1,
                rs2: 2,
            }),
            encode_test(&Instruction::Div {
                rd: 4,
                rs1: 3,
                rs2: 2,
            }),
        ];

        let run = || -> (Cpu, u64) {
            let (mut cpu, mut mem, mut host) = setup();
            store_program(&mut mem, 0x1000, &insns);
            let mut gas = 100;
            let _ = execute(&mut cpu, &mut mem, &mut host, &mut gas, 10);
            (cpu, gas)
        };

        let (cpu1, gas1) = run();
        let (cpu2, gas2) = run();
        assert_eq!(cpu1.regs, cpu2.regs);
        assert_eq!(cpu1.pc, cpu2.pc);
        assert_eq!(gas1, gas2);
    }

    /// Test host that records every `ECALL` it observes and lets the
    /// caller script the per-call response.
    struct ScriptedHost {
        /// Responses delivered in order, one per call.
        responses: alloc::vec::Vec<Result<Option<Halt>, Trap>>,
        /// Optional per-call extra gas charge, one per call.
        extra_gas: alloc::vec::Vec<u64>,
        /// Number of dispatches observed so far.
        calls: usize,
    }

    impl crate::host::HostInterface for ScriptedHost {
        fn ecall(
            &mut self,
            _cpu: &mut Cpu,
            _memory: &mut Memory,
            gas_remaining: &mut u64,
            _code: u32,
        ) -> Result<Option<Halt>, Trap> {
            let i = self.calls;
            self.calls += 1;
            if let Some(extra) = self.extra_gas.get(i).copied() {
                *gas_remaining = gas_remaining.checked_sub(extra).ok_or(Trap::OutOfGas)?;
            }
            self.responses[i]
        }
    }

    #[test]
    fn ecall_continues_when_host_returns_none() {
        // ECALL at 0x1000 (host returns None → continue) then ADDI sets x1=42.
        let (mut cpu, mut mem, _) = setup();
        store_insn(&mut mem, 0x1000, encode_test(&Instruction::Ecall));
        store_insn(
            &mut mem,
            0x1004,
            encode_test(&Instruction::Addi {
                rd: 1,
                rs1: 0,
                imm: 42,
            }),
        );
        store_insn(&mut mem, 0x1008, encode_test(&Instruction::Ebreak));
        let mut host = ScriptedHost {
            responses: vec![Ok(None)],
            extra_gas: vec![],
            calls: 0,
        };
        let mut gas = 100;
        let result = execute(&mut cpu, &mut mem, &mut host, &mut gas, 10);
        assert_eq!(result, Ok(Halt::ExplicitAbort { code: 2 }));
        assert_eq!(cpu.read(1), 42);
        assert_eq!(host.calls, 1);
    }

    #[test]
    fn ecall_halts_when_host_returns_some_halt() {
        let (mut cpu, mut mem, _) = setup();
        store_insn(&mut mem, 0x1000, encode_test(&Instruction::Ecall));
        store_insn(
            &mut mem,
            0x1004,
            encode_test(&Instruction::Addi {
                rd: 1,
                rs1: 0,
                imm: 42,
            }),
        );
        let mut host = ScriptedHost {
            responses: vec![Ok(Some(Halt::ExplicitAbort { code: 7 }))],
            extra_gas: vec![],
            calls: 0,
        };
        let mut gas = 100;
        let result = execute(&mut cpu, &mut mem, &mut host, &mut gas, 10);
        assert_eq!(result, Ok(Halt::ExplicitAbort { code: 7 }));
        // PC should be left pointing at the ECALL instruction (host halted there).
        assert_eq!(cpu.pc, 0x1000);
        // x1 must not have been touched; control never reached the ADDI.
        assert_eq!(cpu.read(1), 0);
    }

    #[test]
    fn ecall_propagates_host_trap() {
        let (mut cpu, mut mem, _) = setup();
        store_insn(&mut mem, 0x1000, encode_test(&Instruction::Ecall));
        let mut host = ScriptedHost {
            responses: vec![Err(Trap::HostError { code: 0x99 })],
            extra_gas: vec![],
            calls: 0,
        };
        let mut gas = 100;
        let result = execute(&mut cpu, &mut mem, &mut host, &mut gas, 10);
        assert_eq!(result, Err(Trap::HostError { code: 0x99 }));
    }

    #[test]
    fn ecall_host_can_charge_extra_gas() {
        let (mut cpu, mut mem, _) = setup();
        store_insn(&mut mem, 0x1000, encode_test(&Instruction::Ecall));
        store_insn(&mut mem, 0x1004, encode_test(&Instruction::Ebreak));
        let mut host = ScriptedHost {
            responses: vec![Ok(None)],
            extra_gas: vec![50],
            calls: 0,
        };
        let mut gas = 100;
        let result = execute(&mut cpu, &mut mem, &mut host, &mut gas, 10);
        assert_eq!(result, Ok(Halt::ExplicitAbort { code: 2 }));
        // 100 - 1 (ECALL fetch) - 10 (ECALL base) - 50 (host extra) - 1 (EBREAK fetch).
        assert_eq!(gas, 38);
    }

    #[test]
    fn ecall_host_out_of_gas_traps() {
        let (mut cpu, mut mem, _) = setup();
        store_insn(&mut mem, 0x1000, encode_test(&Instruction::Ecall));
        let mut host = ScriptedHost {
            responses: vec![Ok(None)],
            extra_gas: vec![1_000_000],
            calls: 0,
        };
        let mut gas = 100;
        let result = execute(&mut cpu, &mut mem, &mut host, &mut gas, 10);
        assert_eq!(result, Err(Trap::OutOfGas));
    }

    #[test]
    fn ecall_multiple_continues_then_halt() {
        let (mut cpu, mut mem, _) = setup();
        store_insn(&mut mem, 0x1000, encode_test(&Instruction::Ecall));
        store_insn(&mut mem, 0x1004, encode_test(&Instruction::Ecall));
        store_insn(&mut mem, 0x1008, encode_test(&Instruction::Ecall));
        let mut host = ScriptedHost {
            responses: vec![
                Ok(None),
                Ok(None),
                Ok(Some(Halt::ExplicitAbort { code: 11 })),
            ],
            extra_gas: vec![],
            calls: 0,
        };
        let mut gas = 100;
        let result = execute(&mut cpu, &mut mem, &mut host, &mut gas, 10);
        assert_eq!(result, Ok(Halt::ExplicitAbort { code: 11 }));
        assert_eq!(host.calls, 3);
        assert_eq!(cpu.pc, 0x1008);
    }

    #[test]
    fn noop_host_abort_returns_halt_not_trap() {
        // NoopHost now yields a clean Halt for code 0/1 rather than a Trap.
        let (mut cpu, mut mem, mut host) = setup();
        store_insn(&mut mem, 0x1000, encode_test(&Instruction::Ecall));
        let mut gas = 100;
        let result = execute(&mut cpu, &mut mem, &mut host, &mut gas, 10);
        // a7 starts at 0 → NoopHost maps to ExplicitAbort{0}.
        assert_eq!(result, Ok(Halt::ExplicitAbort { code: 0 }));
    }

    #[test]
    fn noop_host_unknown_code_traps() {
        let (mut cpu, mut mem, mut host) = setup();
        cpu.write(17, 0xDEAD_BEEF); // a7
        store_insn(&mut mem, 0x1000, encode_test(&Instruction::Ecall));
        let mut gas = 100;
        let result = execute(&mut cpu, &mut mem, &mut host, &mut gas, 10);
        assert_eq!(result, Err(Trap::HostError { code: 0xDEAD_BEEF }));
    }
}
