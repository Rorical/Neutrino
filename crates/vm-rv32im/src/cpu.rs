//! RV32IM register file and program counter.
#![allow(clippy::missing_const_for_fn)]
#[derive(Debug, Clone)]
pub struct Cpu {
    /// 32 general-purpose registers (x0…x31). x0 is hardwired to zero.
    pub regs: [u32; 32],
    /// Program counter.
    pub pc: u32,
}

impl Default for Cpu {
    fn default() -> Self {
        Self::new()
    }
}

impl Cpu {
    /// Creates a new CPU with all registers zero and PC at 0.
    #[must_use]
    pub fn new() -> Self {
        Self {
            regs: [0; 32],
            pc: 0,
        }
    }

    /// Reads the value of register `index`. x0 always returns 0.
    pub fn read(&self, index: u8) -> u32 {
        self.regs[usize::from(index)]
    }

    /// Writes `value` to register `index`. Writes to x0 are silently ignored.
    pub fn write(&mut self, index: u8, value: u32) {
        if index != 0 {
            self.regs[usize::from(index)] = value;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn x0_always_reads_zero() {
        let mut cpu = Cpu::new();
        cpu.write(0, 42);
        assert_eq!(cpu.read(0), 0);
    }

    #[test]
    fn register_read_write() {
        let mut cpu = Cpu::new();
        cpu.write(1, 0xDEAD_BEEF);
        assert_eq!(cpu.read(1), 0xDEAD_BEEF);
    }

    #[test]
    fn pc_tracks_value() {
        let mut cpu = Cpu::new();
        cpu.pc = 0x1000;
        assert_eq!(cpu.pc, 0x1000);
    }

    #[test]
    fn all_registers_independent() {
        let mut cpu = Cpu::new();
        for i in 1u8..32 {
            cpu.write(i, u32::from(i) * 100);
        }
        for i in 1u8..32 {
            assert_eq!(cpu.read(i), u32::from(i) * 100);
        }
    }
}
