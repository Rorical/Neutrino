#![allow(
    missing_docs,
    clippy::missing_const_for_fn,
    clippy::too_many_lines,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    clippy::trivially_copy_pass_by_ref
)]

use crate::Trap;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Instruction {
    Lui { rd: u8, imm_u20: u32 },
    Auipc { rd: u8, imm_u20: u32 },
    Jal { rd: u8, offset: i32 },
    Jalr { rd: u8, rs1: u8, offset: i32 },
    Beq { rs1: u8, rs2: u8, offset: i32 },
    Bne { rs1: u8, rs2: u8, offset: i32 },
    Blt { rs1: u8, rs2: u8, offset: i32 },
    Bge { rs1: u8, rs2: u8, offset: i32 },
    Bltu { rs1: u8, rs2: u8, offset: i32 },
    Bgeu { rs1: u8, rs2: u8, offset: i32 },
    Lb { rd: u8, rs1: u8, offset: i32 },
    Lh { rd: u8, rs1: u8, offset: i32 },
    Lw { rd: u8, rs1: u8, offset: i32 },
    Lbu { rd: u8, rs1: u8, offset: i32 },
    Lhu { rd: u8, rs1: u8, offset: i32 },
    Sb { rs1: u8, rs2: u8, offset: i32 },
    Sh { rs1: u8, rs2: u8, offset: i32 },
    Sw { rs1: u8, rs2: u8, offset: i32 },
    Addi { rd: u8, rs1: u8, imm: i32 },
    Slti { rd: u8, rs1: u8, imm: i32 },
    Sltiu { rd: u8, rs1: u8, imm: i32 },
    Xori { rd: u8, rs1: u8, imm: i32 },
    Ori { rd: u8, rs1: u8, imm: i32 },
    Andi { rd: u8, rs1: u8, imm: i32 },
    Slli { rd: u8, rs1: u8, shamt: u8 },
    Srli { rd: u8, rs1: u8, shamt: u8 },
    Srai { rd: u8, rs1: u8, shamt: u8 },
    Add { rd: u8, rs1: u8, rs2: u8 },
    Sub { rd: u8, rs1: u8, rs2: u8 },
    Sll { rd: u8, rs1: u8, rs2: u8 },
    Slt { rd: u8, rs1: u8, rs2: u8 },
    Sltu { rd: u8, rs1: u8, rs2: u8 },
    Xor { rd: u8, rs1: u8, rs2: u8 },
    Srl { rd: u8, rs1: u8, rs2: u8 },
    Sra { rd: u8, rs1: u8, rs2: u8 },
    Or { rd: u8, rs1: u8, rs2: u8 },
    And { rd: u8, rs1: u8, rs2: u8 },
    Mul { rd: u8, rs1: u8, rs2: u8 },
    Mulh { rd: u8, rs1: u8, rs2: u8 },
    Mulhsu { rd: u8, rs1: u8, rs2: u8 },
    Mulhu { rd: u8, rs1: u8, rs2: u8 },
    Div { rd: u8, rs1: u8, rs2: u8 },
    Divu { rd: u8, rs1: u8, rs2: u8 },
    Rem { rd: u8, rs1: u8, rs2: u8 },
    Remu { rd: u8, rs1: u8, rs2: u8 },
    Ecall,
    Ebreak,
    Fence,
}

const OP_LUI: u32 = 0b011_0111;
const OP_AUIPC: u32 = 0b001_0111;
const OP_JAL: u32 = 0b110_1111;
const OP_JALR: u32 = 0b110_0111;
const OP_BRANCH: u32 = 0b110_0011;
const OP_LOAD: u32 = 0b000_0011;
const OP_STORE: u32 = 0b010_0011;
const OP_IMM: u32 = 0b001_0011;
const OP: u32 = 0b011_0011;
const OP_FENCE: u32 = 0b000_1111;
const OP_SYSTEM: u32 = 0b111_0011;

#[inline]
fn opcode(insn: u32) -> u32 {
    insn & 0x7F
}

#[inline]
fn rd(insn: u32) -> u8 {
    ((insn >> 7) & 0x1F) as u8
}

#[inline]
fn funct3(insn: u32) -> u8 {
    ((insn >> 12) & 0x7) as u8
}

#[inline]
fn rs1(insn: u32) -> u8 {
    ((insn >> 15) & 0x1F) as u8
}

#[inline]
fn rs2(insn: u32) -> u8 {
    ((insn >> 20) & 0x1F) as u8
}

#[inline]
fn funct7(insn: u32) -> u32 {
    insn >> 25
}

#[inline]
fn imm12(insn: u32) -> i32 {
    ((insn >> 20) as i32) << 20 >> 20
}

#[inline]
fn imm_store(insn: u32) -> i32 {
    let imm = ((insn >> 7) & 0x1F) | ((insn >> 20) & 0xFE0);
    ((imm << 20) as i32) >> 20
}

#[inline]
fn imm_branch(insn: u32) -> i32 {
    let imm = ((insn >> 7) & 0x1E)
        | ((insn >> 20) & 0x7E0)
        | ((insn << 4) & 0x800)
        | ((insn >> 19) & 0x1000);
    ((imm << 19) as i32) >> 19
}

#[inline]
fn imm_jal(insn: u32) -> i32 {
    let imm = (insn & 0xFF_000)
        | ((insn >> 9) & 0x800)
        | ((insn >> 20) & 0x7FE)
        | ((insn >> 11) & 0x10_0000);
    ((imm << 11) as i32) >> 11
}

pub fn decode(insn: u32) -> Result<Instruction, Trap> {
    let op = opcode(insn);
    let f3 = funct3(insn);
    let f7 = funct7(insn);
    let rd = rd(insn);
    let rs1 = rs1(insn);
    let rs2 = rs2(insn);

    match op {
        OP_LUI => Ok(Instruction::Lui {
            rd,
            imm_u20: insn & 0xFFFF_F000,
        }),
        OP_AUIPC => Ok(Instruction::Auipc {
            rd,
            imm_u20: insn & 0xFFFF_F000,
        }),
        OP_JAL => Ok(Instruction::Jal {
            rd,
            offset: imm_jal(insn),
        }),
        OP_JALR => {
            ensure_f3(f3, 0b000, op, rs1, rd)?;
            Ok(Instruction::Jalr {
                rd,
                rs1,
                offset: imm12(insn),
            })
        }
        OP_BRANCH => {
            let offset = imm_branch(insn);
            match f3 {
                0b000 => Ok(Instruction::Beq { rs1, rs2, offset }),
                0b001 => Ok(Instruction::Bne { rs1, rs2, offset }),
                0b100 => Ok(Instruction::Blt { rs1, rs2, offset }),
                0b101 => Ok(Instruction::Bge { rs1, rs2, offset }),
                0b110 => Ok(Instruction::Bltu { rs1, rs2, offset }),
                0b111 => Ok(Instruction::Bgeu { rs1, rs2, offset }),
                _ => invalid_insn(),
            }
        }
        OP_LOAD => {
            let offset = imm12(insn);
            match f3 {
                0b000 => Ok(Instruction::Lb { rd, rs1, offset }),
                0b001 => Ok(Instruction::Lh { rd, rs1, offset }),
                0b010 => Ok(Instruction::Lw { rd, rs1, offset }),
                0b100 => Ok(Instruction::Lbu { rd, rs1, offset }),
                0b101 => Ok(Instruction::Lhu { rd, rs1, offset }),
                _ => invalid_insn(),
            }
        }
        OP_STORE => {
            let offset = imm_store(insn);
            match f3 {
                0b000 => Ok(Instruction::Sb { rs1, rs2, offset }),
                0b001 => Ok(Instruction::Sh { rs1, rs2, offset }),
                0b010 => Ok(Instruction::Sw { rs1, rs2, offset }),
                _ => invalid_insn(),
            }
        }
        OP_IMM => {
            let imm = imm12(insn);
            match f3 {
                0b000 => Ok(Instruction::Addi { rd, rs1, imm }),
                0b010 => Ok(Instruction::Slti { rd, rs1, imm }),
                0b011 => Ok(Instruction::Sltiu { rd, rs1, imm }),
                0b100 => Ok(Instruction::Xori { rd, rs1, imm }),
                0b110 => Ok(Instruction::Ori { rd, rs1, imm }),
                0b111 => Ok(Instruction::Andi { rd, rs1, imm }),
                0b001 => {
                    // RV32I: bits 31-25 must be 0000000; bit 25 set is
                    // reserved for RV64 shamt[5] and must trap in RV32.
                    if f7 != 0 {
                        return invalid_insn();
                    }
                    Ok(Instruction::Slli {
                        rd,
                        rs1,
                        shamt: ((insn >> 20) & 0x1F) as u8,
                    })
                }
                0b101 => match f7 {
                    0b000_0000 => Ok(Instruction::Srli {
                        rd,
                        rs1,
                        shamt: ((insn >> 20) & 0x1F) as u8,
                    }),
                    0b010_0000 => Ok(Instruction::Srai {
                        rd,
                        rs1,
                        shamt: ((insn >> 20) & 0x1F) as u8,
                    }),
                    _ => invalid_insn(),
                },
                _ => invalid_insn(),
            }
        }
        OP => match f7 {
            0b000_0000 => match f3 {
                0b000 => Ok(Instruction::Add { rd, rs1, rs2 }),
                0b001 => Ok(Instruction::Sll { rd, rs1, rs2 }),
                0b010 => Ok(Instruction::Slt { rd, rs1, rs2 }),
                0b011 => Ok(Instruction::Sltu { rd, rs1, rs2 }),
                0b100 => Ok(Instruction::Xor { rd, rs1, rs2 }),
                0b101 => Ok(Instruction::Srl { rd, rs1, rs2 }),
                0b110 => Ok(Instruction::Or { rd, rs1, rs2 }),
                0b111 => Ok(Instruction::And { rd, rs1, rs2 }),
                _ => invalid_insn(),
            },
            0b010_0000 => match f3 {
                0b000 => Ok(Instruction::Sub { rd, rs1, rs2 }),
                0b101 => Ok(Instruction::Sra { rd, rs1, rs2 }),
                _ => invalid_insn(),
            },
            0b000_0001 => match f3 {
                0b000 => Ok(Instruction::Mul { rd, rs1, rs2 }),
                0b001 => Ok(Instruction::Mulh { rd, rs1, rs2 }),
                0b010 => Ok(Instruction::Mulhsu { rd, rs1, rs2 }),
                0b011 => Ok(Instruction::Mulhu { rd, rs1, rs2 }),
                0b100 => Ok(Instruction::Div { rd, rs1, rs2 }),
                0b101 => Ok(Instruction::Divu { rd, rs1, rs2 }),
                0b110 => Ok(Instruction::Rem { rd, rs1, rs2 }),
                0b111 => Ok(Instruction::Remu { rd, rs1, rs2 }),
                _ => invalid_insn(),
            },
            _ => invalid_insn(),
        },
        OP_FENCE => {
            // RV32I FENCE has funct3 = 000. funct3 = 001 is FENCE.I
            // (Zifencei extension, not part of base RV32I); all other
            // funct3 values are reserved. Reject everything that isn't
            // strict base FENCE.
            if f3 != 0 {
                return invalid_insn();
            }
            Ok(Instruction::Fence)
        }
        OP_SYSTEM => {
            // Strict ECALL / EBREAK: rd and rs1 must be zero. funct12
            // distinguishes the two. Anything else under SYSTEM (CSR
            // ops, *RET, WFI, SFENCE.VMA) is not in our ISA subset.
            let f12 = insn >> 20;
            if f3 != 0 || rs1 != 0 || rd != 0 {
                return invalid_insn();
            }
            match f12 {
                0 => Ok(Instruction::Ecall),
                1 => Ok(Instruction::Ebreak),
                _ => invalid_insn(),
            }
        }
        _ => invalid_insn(),
    }
}

#[inline]
fn invalid_insn<T>() -> Result<T, Trap> {
    Err(Trap::InvalidInstruction)
}

#[inline]
fn ensure_f3(f3: u8, expected: u8, _op: u32, _rs1: u8, _rd: u8) -> Result<(), Trap> {
    if f3 == expected {
        Ok(())
    } else {
        invalid_insn()
    }
}

pub fn gas_cost(insn: &Instruction) -> u64 {
    match insn {
        Instruction::Mul { .. }
        | Instruction::Mulh { .. }
        | Instruction::Mulhsu { .. }
        | Instruction::Mulhu { .. } => 3,
        Instruction::Div { .. }
        | Instruction::Divu { .. }
        | Instruction::Rem { .. }
        | Instruction::Remu { .. } => 8,
        Instruction::Lb { .. }
        | Instruction::Lh { .. }
        | Instruction::Lw { .. }
        | Instruction::Lbu { .. }
        | Instruction::Lhu { .. }
        | Instruction::Sb { .. }
        | Instruction::Sh { .. }
        | Instruction::Sw { .. } => 2,
        _ => 1,
    }
}

#[cfg(test)]
#[allow(clippy::trivially_copy_pass_by_ref)]
pub fn encode_test(insn: &Instruction) -> u32 {
    encode_test_impl(insn)
}

#[cfg(test)]
fn encode_test_impl(insn: &Instruction) -> u32 {
    use Instruction::*;
    match insn {
        Lui { rd, imm_u20 } => enc_u(OP_LUI, *rd, *imm_u20),
        Auipc { rd, imm_u20 } => enc_u(OP_AUIPC, *rd, *imm_u20),
        Jal { rd, offset } => enc_j(OP_JAL, *rd, *offset),
        Jalr { rd, rs1, offset } => enc_i(OP_JALR, *rd, 0b000, *rs1, *offset as u32),
        Beq { rs1, rs2, offset } => enc_b(OP_BRANCH, 0b000, *rs1, *rs2, *offset),
        Bne { rs1, rs2, offset } => enc_b(OP_BRANCH, 0b001, *rs1, *rs2, *offset),
        Blt { rs1, rs2, offset } => enc_b(OP_BRANCH, 0b100, *rs1, *rs2, *offset),
        Bge { rs1, rs2, offset } => enc_b(OP_BRANCH, 0b101, *rs1, *rs2, *offset),
        Bltu { rs1, rs2, offset } => enc_b(OP_BRANCH, 0b110, *rs1, *rs2, *offset),
        Bgeu { rs1, rs2, offset } => enc_b(OP_BRANCH, 0b111, *rs1, *rs2, *offset),
        Lb { rd, rs1, offset } => enc_i(OP_LOAD, *rd, 0b000, *rs1, *offset as u32),
        Lh { rd, rs1, offset } => enc_i(OP_LOAD, *rd, 0b001, *rs1, *offset as u32),
        Lw { rd, rs1, offset } => enc_i(OP_LOAD, *rd, 0b010, *rs1, *offset as u32),
        Lbu { rd, rs1, offset } => enc_i(OP_LOAD, *rd, 0b100, *rs1, *offset as u32),
        Lhu { rd, rs1, offset } => enc_i(OP_LOAD, *rd, 0b101, *rs1, *offset as u32),
        Sb { rs1, rs2, offset } => enc_s(OP_STORE, 0b000, *rs1, *rs2, *offset as u32),
        Sh { rs1, rs2, offset } => enc_s(OP_STORE, 0b001, *rs1, *rs2, *offset as u32),
        Sw { rs1, rs2, offset } => enc_s(OP_STORE, 0b010, *rs1, *rs2, *offset as u32),
        Addi { rd, rs1, imm } => enc_i(OP_IMM, *rd, 0b000, *rs1, *imm as u32),
        Slti { rd, rs1, imm } => enc_i(OP_IMM, *rd, 0b010, *rs1, *imm as u32),
        Sltiu { rd, rs1, imm } => enc_i(OP_IMM, *rd, 0b011, *rs1, *imm as u32),
        Xori { rd, rs1, imm } => enc_i(OP_IMM, *rd, 0b100, *rs1, *imm as u32),
        Ori { rd, rs1, imm } => enc_i(OP_IMM, *rd, 0b110, *rs1, *imm as u32),
        Andi { rd, rs1, imm } => enc_i(OP_IMM, *rd, 0b111, *rs1, *imm as u32),
        Slli { rd, rs1, shamt } => enc_i(OP_IMM, *rd, 0b001, *rs1, u32::from(*shamt)),
        Srli { rd, rs1, shamt } => enc_r(OP_IMM, *rd, 0b101, *rs1, *shamt, 0b000_0000),
        Srai { rd, rs1, shamt } => enc_r(OP_IMM, *rd, 0b101, *rs1, *shamt, 0b010_0000),
        Add { rd, rs1, rs2 } => enc_r(OP, *rd, 0b000, *rs1, *rs2, 0b000_0000),
        Sub { rd, rs1, rs2 } => enc_r(OP, *rd, 0b000, *rs1, *rs2, 0b010_0000),
        Sll { rd, rs1, rs2 } => enc_r(OP, *rd, 0b001, *rs1, *rs2, 0b000_0000),
        Slt { rd, rs1, rs2 } => enc_r(OP, *rd, 0b010, *rs1, *rs2, 0b000_0000),
        Sltu { rd, rs1, rs2 } => enc_r(OP, *rd, 0b011, *rs1, *rs2, 0b000_0000),
        Xor { rd, rs1, rs2 } => enc_r(OP, *rd, 0b100, *rs1, *rs2, 0b000_0000),
        Srl { rd, rs1, rs2 } => enc_r(OP, *rd, 0b101, *rs1, *rs2, 0b000_0000),
        Sra { rd, rs1, rs2 } => enc_r(OP, *rd, 0b101, *rs1, *rs2, 0b010_0000),
        Or { rd, rs1, rs2 } => enc_r(OP, *rd, 0b110, *rs1, *rs2, 0b000_0000),
        And { rd, rs1, rs2 } => enc_r(OP, *rd, 0b111, *rs1, *rs2, 0b000_0000),
        Mul { rd, rs1, rs2 } => enc_r(OP, *rd, 0b000, *rs1, *rs2, 0b000_0001),
        Mulh { rd, rs1, rs2 } => enc_r(OP, *rd, 0b001, *rs1, *rs2, 0b000_0001),
        Mulhsu { rd, rs1, rs2 } => enc_r(OP, *rd, 0b010, *rs1, *rs2, 0b000_0001),
        Mulhu { rd, rs1, rs2 } => enc_r(OP, *rd, 0b011, *rs1, *rs2, 0b000_0001),
        Div { rd, rs1, rs2 } => enc_r(OP, *rd, 0b100, *rs1, *rs2, 0b000_0001),
        Divu { rd, rs1, rs2 } => enc_r(OP, *rd, 0b101, *rs1, *rs2, 0b000_0001),
        Rem { rd, rs1, rs2 } => enc_r(OP, *rd, 0b110, *rs1, *rs2, 0b000_0001),
        Remu { rd, rs1, rs2 } => enc_r(OP, *rd, 0b111, *rs1, *rs2, 0b000_0001),
        Ecall => 0x0000_0073,
        Ebreak => 0x0010_0073,
        Fence => 0x0000_000F,
    }
}

#[cfg(test)]
fn enc_r(op: u32, rd: u8, f3: u8, rs1: u8, rs2: u8, f7: u32) -> u32 {
    (f7 << 25)
        | (u32::from(rs2) << 20)
        | (u32::from(rs1) << 15)
        | (u32::from(f3) << 12)
        | (u32::from(rd) << 7)
        | op
}

#[cfg(test)]
fn enc_i(op: u32, rd: u8, f3: u8, rs1: u8, imm12: u32) -> u32 {
    ((imm12 & 0xFFF) << 20)
        | (u32::from(rs1) << 15)
        | (u32::from(f3) << 12)
        | (u32::from(rd) << 7)
        | op
}

#[cfg(test)]
fn enc_s(op: u32, f3: u8, rs1: u8, rs2: u8, imm12: u32) -> u32 {
    let imm = imm12 & 0xFFF;
    let upper = (imm >> 5) << 25;
    let lower = (imm & 0x1F) << 7;
    upper | (u32::from(rs2) << 20) | (u32::from(rs1) << 15) | (u32::from(f3) << 12) | lower | op
}

#[cfg(test)]
fn enc_b(op: u32, f3: u8, rs1: u8, rs2: u8, offset: i32) -> u32 {
    let off = offset as u32;
    let bit11 = (off >> 11) & 1;
    let bits4_1 = (off >> 1) & 0xF;
    let bits10_5 = (off >> 5) & 0x3F;
    let bit12 = (off >> 12) & 1;
    let upper = (bit12 << 31) | (bits10_5 << 25);
    let lower = ((bits4_1 << 1) | bit11) << 7;
    let mid = (u32::from(rs2) << 20) | (u32::from(rs1) << 15) | (u32::from(f3) << 12);
    upper | mid | lower | op
}

#[cfg(test)]
fn enc_u(op: u32, rd: u8, imm20: u32) -> u32 {
    (imm20 & 0xFFFF_F000) | (u32::from(rd) << 7) | op
}

#[cfg(test)]
fn enc_j(op: u32, rd: u8, offset: i32) -> u32 {
    let off = offset as u32;
    let bit20 = (off >> 20) & 1;
    let bits10_1 = (off >> 1) & 0x3FF;
    let bit11 = (off >> 11) & 1;
    let bits19_12 = (off >> 12) & 0xFF;
    let upper = (bit20 << 31) | (bits10_1 << 21) | (bit11 << 20) | (bits19_12 << 12);
    upper | (u32::from(rd) << 7) | op
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip(insn: Instruction) {
        let word = encode_test(&insn);
        let decoded = decode(word)
            .unwrap_or_else(|e| panic!("roundtrip decode failed for 0x{word:08X}: {e:?}"));
        assert_eq!(
            decoded, insn,
            "roundtrip failed: encoded 0x{word:08X}, decoded {decoded:?}"
        );
    }

    fn check(insn: &Instruction, word: u32) {
        let decoded =
            decode(word).unwrap_or_else(|e| panic!("failed to decode 0x{word:08X}: {e:?}"));
        assert_eq!(
            &decoded, insn,
            "decoded {decoded:?} != expected {insn:?} for word 0x{word:08X}"
        );
    }

    #[test]
    fn roundtrip_all_lui() {
        roundtrip(Instruction::Lui {
            rd: 1,
            imm_u20: 0x1234_5000,
        });
        roundtrip(Instruction::Lui {
            rd: 31,
            imm_u20: 0xFFFF_F000,
        });
    }

    #[test]
    fn roundtrip_all_auipc() {
        roundtrip(Instruction::Auipc {
            rd: 2,
            imm_u20: 0xABCD_E000,
        });
    }

    #[test]
    fn roundtrip_all_jal() {
        roundtrip(Instruction::Jal {
            rd: 1,
            offset: 0x1000,
        });
        roundtrip(Instruction::Jal { rd: 0, offset: -4 });
    }

    #[test]
    fn roundtrip_all_jalr() {
        roundtrip(Instruction::Jalr {
            rd: 1,
            rs1: 2,
            offset: 0,
        });
        roundtrip(Instruction::Jalr {
            rd: 1,
            rs1: 2,
            offset: -1,
        });
    }

    #[test]
    fn roundtrip_all_branches() {
        roundtrip(Instruction::Beq {
            rs1: 1,
            rs2: 2,
            offset: 8,
        });
        roundtrip(Instruction::Bne {
            rs1: 1,
            rs2: 2,
            offset: 8,
        });
        roundtrip(Instruction::Blt {
            rs1: 1,
            rs2: 2,
            offset: 8,
        });
        roundtrip(Instruction::Bge {
            rs1: 1,
            rs2: 2,
            offset: 8,
        });
        roundtrip(Instruction::Bltu {
            rs1: 1,
            rs2: 2,
            offset: 8,
        });
        roundtrip(Instruction::Bgeu {
            rs1: 1,
            rs2: 2,
            offset: 8,
        });
        roundtrip(Instruction::Beq {
            rs1: 1,
            rs2: 2,
            offset: -4,
        });
    }

    #[test]
    fn roundtrip_all_loads() {
        roundtrip(Instruction::Lb {
            rd: 3,
            rs1: 1,
            offset: 0,
        });
        roundtrip(Instruction::Lh {
            rd: 3,
            rs1: 1,
            offset: 0,
        });
        roundtrip(Instruction::Lw {
            rd: 3,
            rs1: 1,
            offset: 0,
        });
        roundtrip(Instruction::Lbu {
            rd: 3,
            rs1: 1,
            offset: 0,
        });
        roundtrip(Instruction::Lhu {
            rd: 3,
            rs1: 1,
            offset: 0,
        });
    }

    #[test]
    fn roundtrip_all_stores() {
        roundtrip(Instruction::Sb {
            rs1: 1,
            rs2: 2,
            offset: 0,
        });
        roundtrip(Instruction::Sh {
            rs1: 1,
            rs2: 2,
            offset: 0,
        });
        roundtrip(Instruction::Sw {
            rs1: 1,
            rs2: 2,
            offset: 0,
        });
    }

    #[test]
    fn roundtrip_all_op_imm() {
        roundtrip(Instruction::Addi {
            rd: 1,
            rs1: 2,
            imm: 42,
        });
        roundtrip(Instruction::Slti {
            rd: 1,
            rs1: 2,
            imm: 42,
        });
        roundtrip(Instruction::Sltiu {
            rd: 1,
            rs1: 2,
            imm: 42,
        });
        roundtrip(Instruction::Xori {
            rd: 1,
            rs1: 2,
            imm: 42,
        });
        roundtrip(Instruction::Ori {
            rd: 1,
            rs1: 2,
            imm: 42,
        });
        roundtrip(Instruction::Andi {
            rd: 1,
            rs1: 2,
            imm: 42,
        });
        roundtrip(Instruction::Slli {
            rd: 1,
            rs1: 2,
            shamt: 5,
        });
        roundtrip(Instruction::Srli {
            rd: 1,
            rs1: 2,
            shamt: 5,
        });
        roundtrip(Instruction::Srai {
            rd: 1,
            rs1: 2,
            shamt: 5,
        });
    }

    #[test]
    fn roundtrip_all_op_reg() {
        roundtrip(Instruction::Add {
            rd: 1,
            rs1: 2,
            rs2: 3,
        });
        roundtrip(Instruction::Sub {
            rd: 1,
            rs1: 2,
            rs2: 3,
        });
        roundtrip(Instruction::Sll {
            rd: 1,
            rs1: 2,
            rs2: 3,
        });
        roundtrip(Instruction::Slt {
            rd: 1,
            rs1: 2,
            rs2: 3,
        });
        roundtrip(Instruction::Sltu {
            rd: 1,
            rs1: 2,
            rs2: 3,
        });
        roundtrip(Instruction::Xor {
            rd: 1,
            rs1: 2,
            rs2: 3,
        });
        roundtrip(Instruction::Srl {
            rd: 1,
            rs1: 2,
            rs2: 3,
        });
        roundtrip(Instruction::Sra {
            rd: 1,
            rs1: 2,
            rs2: 3,
        });
        roundtrip(Instruction::Or {
            rd: 1,
            rs1: 2,
            rs2: 3,
        });
        roundtrip(Instruction::And {
            rd: 1,
            rs1: 2,
            rs2: 3,
        });
    }

    #[test]
    fn roundtrip_all_m_extension() {
        roundtrip(Instruction::Mul {
            rd: 1,
            rs1: 2,
            rs2: 3,
        });
        roundtrip(Instruction::Mulh {
            rd: 1,
            rs1: 2,
            rs2: 3,
        });
        roundtrip(Instruction::Mulhsu {
            rd: 1,
            rs1: 2,
            rs2: 3,
        });
        roundtrip(Instruction::Mulhu {
            rd: 1,
            rs1: 2,
            rs2: 3,
        });
        roundtrip(Instruction::Div {
            rd: 1,
            rs1: 2,
            rs2: 3,
        });
        roundtrip(Instruction::Divu {
            rd: 1,
            rs1: 2,
            rs2: 3,
        });
        roundtrip(Instruction::Rem {
            rd: 1,
            rs1: 2,
            rs2: 3,
        });
        roundtrip(Instruction::Remu {
            rd: 1,
            rs1: 2,
            rs2: 3,
        });
    }

    #[test]
    fn roundtrip_system() {
        roundtrip(Instruction::Ecall);
        roundtrip(Instruction::Ebreak);
    }

    #[test]
    fn roundtrip_fence() {
        roundtrip(Instruction::Fence);
    }

    #[test]
    fn known_words_decode_correctly() {
        check(
            &Instruction::Lui {
                rd: 1,
                imm_u20: 0x1234_5000,
            },
            0x1234_50B7,
        );
        check(
            &Instruction::Add {
                rd: 1,
                rs1: 2,
                rs2: 3,
            },
            0x0031_00B3,
        );
        check(
            &Instruction::Lw {
                rd: 3,
                rs1: 1,
                offset: 0,
            },
            0x0000_A183,
        );
        check(
            &Instruction::Sw {
                rs1: 1,
                rs2: 2,
                offset: 0,
            },
            0x0020_A023,
        );
        check(&Instruction::Jal { rd: 0, offset: 0 }, 0x0000_006F);
    }

    #[test]
    fn decode_invalid_opcode() {
        assert!(decode(0x0000_007F).is_err());
        assert!(decode(0x0000_005F).is_err());
    }

    #[test]
    fn decode_invalid_funct3() {
        assert!(decode(0x0000_7003).is_err());
        assert!(decode(0x0000_3023).is_err());
        assert!(decode(0x0400_00B3).is_err());
        assert!(decode(0x0600_00B3).is_err());
    }

    #[test]
    fn decode_invalid_system_funct12() {
        assert!(decode(0x0020_0073).is_err());
        assert!(decode(0xFFF0_0073).is_err());
    }

    #[test]
    fn decode_slli_rejects_nonzero_funct7() {
        // SLLI x1, x0, 0 with funct7 = 0x20 (bit 30 set). In RV32I that
        // bit is reserved for RV64 shamt[5], so a strict decoder must
        // refuse it. Encoding: opcode=0x13, rd=1 (<<7), f3=001 (<<12),
        // rs1=0, shamt=0, funct7=0x20 (<<25).
        let bad = 0x4000_1093u32;
        assert!(
            decode(bad).is_err(),
            "SLLI with funct7=0x20 should be illegal in RV32I"
        );

        // A well-formed SLLI x1, x0, 0 with funct7=0 still decodes.
        let good = 0x0000_1093u32;
        assert!(decode(good).is_ok());
    }

    #[test]
    fn decode_fence_rejects_nonzero_funct3() {
        // FENCE.I (funct3 = 001) is Zifencei; this ISA subset rejects
        // it. Other funct3 values are reserved.
        for f3 in 1u32..8 {
            let word = 0x0000_000Fu32 | (f3 << 12);
            assert!(
                decode(word).is_err(),
                "FENCE with funct3={f3:#b} should be illegal"
            );
        }
    }

    #[test]
    fn decode_ecall_rejects_nonzero_rs1() {
        // ECALL with rs1 != 0 must be illegal.
        let bad = 0x0000_0073u32 | (1 << 15);
        assert!(decode(bad).is_err());
    }

    #[test]
    fn decode_ecall_rejects_nonzero_rd() {
        // ECALL with rd != 0 must be illegal.
        let bad = 0x0000_0073u32 | (1 << 7);
        assert!(decode(bad).is_err());
    }

    #[test]
    fn decode_ebreak_rejects_nonzero_rs1() {
        // EBREAK with rs1 != 0 must be illegal.
        let bad = 0x0010_0073u32 | (1 << 15);
        assert!(decode(bad).is_err());
    }

    #[test]
    fn decode_ebreak_rejects_nonzero_rd() {
        let bad = 0x0010_0073u32 | (1 << 7);
        assert!(decode(bad).is_err());
    }

    #[test]
    fn decode_all_instructions_deterministic() {
        for word in [0x0000_0013, 0x0041_0113, 0x0FF1_0113] {
            let a = decode(word);
            let b = decode(word);
            assert_eq!(a, b);
        }
    }

    #[test]
    fn gas_cost_basics() {
        assert_eq!(
            gas_cost(&Instruction::Addi {
                rd: 1,
                rs1: 2,
                imm: 0
            }),
            1
        );
        assert_eq!(
            gas_cost(&Instruction::Add {
                rd: 1,
                rs1: 2,
                rs2: 3
            }),
            1
        );
        assert_eq!(
            gas_cost(&Instruction::Mul {
                rd: 1,
                rs1: 2,
                rs2: 3
            }),
            3
        );
        assert_eq!(
            gas_cost(&Instruction::Div {
                rd: 1,
                rs1: 2,
                rs2: 3
            }),
            8
        );
        assert_eq!(
            gas_cost(&Instruction::Lw {
                rd: 3,
                rs1: 1,
                offset: 0
            }),
            2
        );
        assert_eq!(
            gas_cost(&Instruction::Sw {
                rs1: 1,
                rs2: 2,
                offset: 0
            }),
            2
        );
        assert_eq!(gas_cost(&Instruction::Ecall), 1);
        assert_eq!(gas_cost(&Instruction::Fence), 1);
    }
}
