#![allow(missing_docs, clippy::missing_const_for_fn)]

use crate::Trap;

/// Memory region access permissions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Permissions {
    pub read: bool,
    pub write: bool,
    pub execute: bool,
}

impl Permissions {
    pub const R: Self = Self {
        read: true,
        write: false,
        execute: false,
    };
    pub const RW: Self = Self {
        read: true,
        write: true,
        execute: false,
    };
    pub const RX: Self = Self {
        read: true,
        write: false,
        execute: true,
    };
    pub const RWX: Self = Self {
        read: true,
        write: true,
        execute: true,
    };
}

/// A contiguous range of guest memory with associated permissions.
#[derive(Debug, Clone)]
pub struct MemoryRegion {
    pub start: u32,
    pub len: u32,
    pub permissions: Permissions,
}

impl MemoryRegion {
    #[must_use]
    pub fn contains(&self, addr: u32) -> bool {
        addr >= self.start && addr < self.start.saturating_add(self.len)
    }

    #[must_use]
    pub fn contains_range(&self, addr: u32, size: u32) -> bool {
        let end = addr.saturating_add(size);
        addr >= self.start && end <= self.start.saturating_add(self.len)
    }
}

/// Guest memory with byte-level access and permission enforcement.
#[derive(Debug, Clone)]
pub struct Memory {
    data: Vec<u8>,
    regions: Vec<MemoryRegion>,
}

impl Memory {
    #[must_use]
    pub fn new(size: u32) -> Self {
        Self {
            data: vec![0; usize::try_from(size).unwrap_or(0)],
            regions: Vec::new(),
        }
    }

    pub fn add_region(&mut self, start: u32, len: u32, permissions: Permissions) {
        let end = start.saturating_add(len);
        let needed = end as usize;
        if needed > self.data.len() {
            self.data.resize(needed, 0);
        }
        self.regions.push(MemoryRegion {
            start,
            len,
            permissions,
        });
    }

    #[must_use]
    pub fn len(&self) -> u32 {
        u32::try_from(self.data.len()).unwrap_or(u32::MAX)
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    pub fn write_bytes(&mut self, addr: u32, bytes: &[u8]) -> Result<(), Trap> {
        let end = usize::try_from(addr)
            .ok()
            .and_then(|a| a.checked_add(bytes.len()))
            .ok_or(Trap::MemoryFault { addr })?;
        if end > self.data.len() {
            return Err(Trap::MemoryFault { addr });
        }
        self.data[addr as usize..end].copy_from_slice(bytes);
        Ok(())
    }

    fn check_region_access(&self, addr: u32, size: u32, needs: Permissions) -> Result<(), Trap> {
        let end = addr.checked_add(size).ok_or(Trap::MemoryFault { addr })?;
        if end > self.len() {
            return Err(Trap::MemoryFault { addr });
        }
        for region in &self.regions {
            if region.contains_range(addr, size) {
                let ok = match (needs.read, needs.write, needs.execute) {
                    (true, false, false) => region.permissions.read,
                    (false, true, false) => region.permissions.write,
                    (true, true, false) => region.permissions.read && region.permissions.write,
                    (true, false, true) => region.permissions.read && region.permissions.execute,
                    (false, true, true) => region.permissions.write && region.permissions.execute,
                    (true, true, true) => {
                        region.permissions.read
                            && region.permissions.write
                            && region.permissions.execute
                    }
                    (false, false, true) => region.permissions.execute,
                    (false, false, false) => true,
                };
                return if ok {
                    Ok(())
                } else {
                    Err(Trap::MemoryFault { addr })
                };
            }
        }
        Err(Trap::MemoryFault { addr })
    }

    /// Data accesses are natural-aligned (2-byte for `u16`, 4-byte for
    /// `u32`). This is an EEI decision — the spec leaves misaligned
    /// loads/stores up to the execution environment. We forbid them so
    /// the proof witness can canonically encode each access as a
    /// `(addr, size)` pair without per-byte striping.
    pub fn load_u8(&self, addr: u32) -> Result<u8, Trap> {
        self.check_region_access(addr, 1, Permissions::R)?;
        Ok(self.data[usize::try_from(addr).map_err(|_| Trap::MemoryFault { addr })?])
    }

    pub fn load_u16(&self, addr: u32) -> Result<u16, Trap> {
        if addr & 0x1 != 0 {
            return Err(Trap::MemoryFault { addr });
        }
        self.check_region_access(addr, 2, Permissions::R)?;
        let base = usize::try_from(addr).map_err(|_| Trap::MemoryFault { addr })?;
        Ok(u16::from_le_bytes([self.data[base], self.data[base + 1]]))
    }

    pub fn load_u32(&self, addr: u32) -> Result<u32, Trap> {
        if addr & 0x3 != 0 {
            return Err(Trap::MemoryFault { addr });
        }
        self.check_region_access(addr, 4, Permissions::R)?;
        let base = usize::try_from(addr).map_err(|_| Trap::MemoryFault { addr })?;
        Ok(u32::from_le_bytes([
            self.data[base],
            self.data[base + 1],
            self.data[base + 2],
            self.data[base + 3],
        ]))
    }

    pub fn store_u8(&mut self, addr: u32, value: u8) -> Result<(), Trap> {
        self.check_region_access(
            addr,
            1,
            Permissions {
                read: false,
                write: true,
                execute: false,
            },
        )?;
        let idx = usize::try_from(addr).map_err(|_| Trap::MemoryFault { addr })?;
        self.data[idx] = value;
        Ok(())
    }

    pub fn store_u16(&mut self, addr: u32, value: u16) -> Result<(), Trap> {
        if addr & 0x1 != 0 {
            return Err(Trap::MemoryFault { addr });
        }
        self.check_region_access(
            addr,
            2,
            Permissions {
                read: false,
                write: true,
                execute: false,
            },
        )?;
        let base = usize::try_from(addr).map_err(|_| Trap::MemoryFault { addr })?;
        let bytes = value.to_le_bytes();
        self.data[base] = bytes[0];
        self.data[base + 1] = bytes[1];
        Ok(())
    }

    pub fn store_u32(&mut self, addr: u32, value: u32) -> Result<(), Trap> {
        if addr & 0x3 != 0 {
            return Err(Trap::MemoryFault { addr });
        }
        self.check_region_access(
            addr,
            4,
            Permissions {
                read: false,
                write: true,
                execute: false,
            },
        )?;
        let base = usize::try_from(addr).map_err(|_| Trap::MemoryFault { addr })?;
        let bytes = value.to_le_bytes();
        self.data[base] = bytes[0];
        self.data[base + 1] = bytes[1];
        self.data[base + 2] = bytes[2];
        self.data[base + 3] = bytes[3];
        Ok(())
    }

    /// Fetch a 4-byte instruction word at `addr`. The PC must be
    /// 4-byte aligned (no `C` extension support); misalignment surfaces
    /// as a distinct `InstructionAddressMisaligned` trap so the host
    /// can distinguish a bad fetch from a malformed opcode.
    pub fn load_insn(&self, addr: u32) -> Result<u32, Trap> {
        if addr & 0x3 != 0 {
            return Err(Trap::InstructionAddressMisaligned { addr });
        }
        self.check_region_access(addr, 4, Permissions::RX)?;
        let base = usize::try_from(addr).map_err(|_| Trap::MemoryFault { addr })?;
        Ok(u32::from_le_bytes([
            self.data[base],
            self.data[base + 1],
            self.data[base + 2],
            self.data[base + 3],
        ]))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_rw_memory(size: u32) -> Memory {
        let mut mem = Memory::new(size);
        mem.add_region(0, size, Permissions::RW);
        mem
    }

    #[test]
    fn add_region_grows_memory() {
        let mut mem = Memory::new(256);
        mem.add_region(0, 512, Permissions::RW);
        assert!(mem.len() >= 512);
    }

    #[test]
    fn load_store_u8_roundtrip() {
        let mut mem = make_rw_memory(1024);
        mem.store_u8(100, 0xAB).unwrap();
        assert_eq!(mem.load_u8(100).unwrap(), 0xAB);
    }

    #[test]
    fn load_store_u16_roundtrip() {
        let mut mem = make_rw_memory(1024);
        mem.store_u16(100, 0xBEEF).unwrap();
        assert_eq!(mem.load_u16(100).unwrap(), 0xBEEF);
    }

    #[test]
    fn load_store_u32_roundtrip() {
        let mut mem = make_rw_memory(1024);
        mem.store_u32(100, 0xDEAD_BEEF).unwrap();
        assert_eq!(mem.load_u32(100).unwrap(), 0xDEAD_BEEF);
    }

    #[test]
    fn load_out_of_bounds_traps() {
        let mem = make_rw_memory(16);
        assert!(mem.load_u8(16).is_err());
        assert!(mem.load_u16(15).is_err());
        assert!(mem.load_u32(13).is_err());
    }

    #[test]
    fn store_out_of_bounds_traps() {
        let mut mem = make_rw_memory(16);
        assert!(mem.store_u8(16, 0).is_err());
        assert!(mem.store_u16(15, 0).is_err());
        assert!(mem.store_u32(13, 0).is_err());
    }

    #[test]
    fn unmapped_region_traps() {
        let mut mem = Memory::new(1024);
        mem.add_region(0, 16, Permissions::RW);
        assert!(mem.load_u8(100).is_err());
        assert!(mem.store_u8(100, 0).is_err());
    }

    #[test]
    fn write_to_read_only_region_traps() {
        let mut mem = Memory::new(1024);
        mem.add_region(0, 256, Permissions::R);
        assert!(mem.store_u8(50, 0).is_err());
        assert!(mem.load_u8(50).is_ok());
    }

    #[test]
    fn execute_from_non_exec_region_traps() {
        let mut mem = Memory::new(1024);
        mem.add_region(0, 256, Permissions::RW);
        assert!(mem.load_insn(0).is_err());
    }

    #[test]
    fn execute_from_exec_region_succeeds() {
        let mut mem = Memory::new(1024);
        mem.add_region(0, 256, Permissions::RX);
        mem.write_bytes(0, &0x0000_0013u32.to_le_bytes()).unwrap();
        assert_eq!(mem.load_insn(0).unwrap(), 0x0000_0013);
    }

    #[test]
    fn unaligned_instruction_fetch_traps() {
        let mut mem = Memory::new(1024);
        mem.add_region(0, 256, Permissions::RX);
        assert_eq!(
            mem.load_insn(2),
            Err(Trap::InstructionAddressMisaligned { addr: 2 })
        );
    }

    #[test]
    fn unaligned_load_u16_traps() {
        let mem = make_rw_memory(1024);
        assert_eq!(mem.load_u16(1), Err(Trap::MemoryFault { addr: 1 }));
        assert_eq!(mem.load_u16(3), Err(Trap::MemoryFault { addr: 3 }));
        // Aligned (any even address) still works.
        assert!(mem.load_u16(2).is_ok());
        assert!(mem.load_u16(4).is_ok());
    }

    #[test]
    fn unaligned_load_u32_traps() {
        let mem = make_rw_memory(1024);
        for bad in [1u32, 2, 3, 5, 6, 7] {
            assert_eq!(mem.load_u32(bad), Err(Trap::MemoryFault { addr: bad }));
        }
        assert!(mem.load_u32(0).is_ok());
        assert!(mem.load_u32(4).is_ok());
    }

    #[test]
    fn unaligned_store_u16_traps() {
        let mut mem = make_rw_memory(1024);
        assert_eq!(mem.store_u16(1, 0xBEEF), Err(Trap::MemoryFault { addr: 1 }));
        assert!(mem.store_u16(2, 0xBEEF).is_ok());
    }

    #[test]
    fn unaligned_store_u32_traps() {
        let mut mem = make_rw_memory(1024);
        for bad in [1u32, 2, 3] {
            assert_eq!(
                mem.store_u32(bad, 0xDEAD_BEEF),
                Err(Trap::MemoryFault { addr: bad })
            );
        }
        assert!(mem.store_u32(0, 0xDEAD_BEEF).is_ok());
        assert!(mem.store_u32(4, 0xDEAD_BEEF).is_ok());
    }

    #[test]
    fn region_contains_range_exact() {
        let region = MemoryRegion {
            start: 0x100,
            len: 0x100,
            permissions: Permissions::RW,
        };
        assert!(region.contains_range(0x100, 0x100));
        assert!(!region.contains_range(0x100, 0x101));
        assert!(!region.contains_range(0x0FF, 1));
    }

    #[test]
    fn zero_size_memory_ok_for_empty_regions() {
        let mem = Memory::new(0);
        assert!(mem.is_empty());
        assert_eq!(mem.len(), 0);
    }
}
