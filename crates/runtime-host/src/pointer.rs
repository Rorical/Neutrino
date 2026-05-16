//! Buffer transfer helpers between the host and guest memory.
//!
//! Every ABI syscall that passes a buffer hands the host a `(ptr, len)`
//! pair into guest memory. The host must validate that the entire
//! requested span lies inside a mapped region with the right permission
//! before copying any bytes; otherwise a malicious or buggy runtime
//! could read uninitialised host memory or trigger out-of-bounds
//! accesses.
//!
//! Validation is performed by reusing [`Memory::load_u8`] and
//! [`Memory::store_u8`], both of which check region permissions on every
//! byte. This is O(len) but correct; the alternative would require a
//! `Memory::check_range_access` accessor on `vm-rv32im`. For M2 the
//! per-byte cost is negligible compared to trie work and crypto.
//!
//! All helpers return `Trap` directly so the dispatcher can propagate
//! the trap to the executor without reshaping.

use neutrino_vm_rv32im::Trap;
use neutrino_vm_rv32im::memory::Memory;

/// Copy `len` bytes starting at `addr` out of guest memory into a fresh
/// `Vec`. Returns [`Trap::MemoryFault`] on the first byte that fails
/// region or permission checks, with the faulting address attached.
///
/// Returns an empty `Vec` for `len == 0` regardless of `addr` to match
/// the ABI contract that a zero-length buffer never accesses memory.
pub fn read_bytes(memory: &Memory, addr: u32, len: u32) -> Result<Vec<u8>, Trap> {
    if len == 0 {
        return Ok(Vec::new());
    }
    let len_us = len as usize;
    let mut out = vec![0u8; len_us];
    for (i, slot) in out.iter_mut().enumerate() {
        let i_u32 = u32::try_from(i).map_err(|_| Trap::MemoryFault { addr })?;
        let cur = addr.checked_add(i_u32).ok_or(Trap::MemoryFault { addr })?;
        *slot = memory.load_u8(cur)?;
    }
    Ok(out)
}

/// Write `bytes` into guest memory starting at `addr`. Returns
/// [`Trap::MemoryFault`] on the first byte that fails region or
/// permission checks.
///
/// A zero-length slice is a no-op even for an otherwise invalid `addr`.
pub fn write_bytes(memory: &mut Memory, addr: u32, bytes: &[u8]) -> Result<(), Trap> {
    if bytes.is_empty() {
        return Ok(());
    }
    for (i, &byte) in bytes.iter().enumerate() {
        let i_u32 = u32::try_from(i).map_err(|_| Trap::MemoryFault { addr })?;
        let cur = addr.checked_add(i_u32).ok_or(Trap::MemoryFault { addr })?;
        memory.store_u8(cur, byte)?;
    }
    Ok(())
}

/// Validate that the range `[addr, addr + len)` is fully readable
/// without copying any bytes. Useful for size-only checks (e.g. when
/// reporting `BufferTooSmall`).
pub fn validate_readable(memory: &Memory, addr: u32, len: u32) -> Result<(), Trap> {
    if len == 0 {
        return Ok(());
    }
    for i in 0..len {
        let cur = addr.checked_add(i).ok_or(Trap::MemoryFault { addr })?;
        memory.load_u8(cur)?;
    }
    Ok(())
}

/// Returns `true` if the byte ranges `[a_ptr, a_ptr+a_len)` and
/// `[b_ptr, b_ptr+b_len)` share any address.
///
/// The runtime ABI forbids overlap between an input and an output
/// buffer in the same syscall: it would let the runtime observe
/// partial-write state and complicate witness recording. Zero-length
/// buffers never overlap with anything.
#[must_use]
pub const fn buffers_overlap(a_ptr: u32, a_len: u32, b_ptr: u32, b_len: u32) -> bool {
    if a_len == 0 || b_len == 0 {
        return false;
    }
    let a_end = a_ptr.saturating_add(a_len);
    let b_end = b_ptr.saturating_add(b_len);
    a_ptr < b_end && b_ptr < a_end
}

#[cfg(test)]
mod tests {
    use super::*;
    use neutrino_vm_rv32im::memory::{Memory, Permissions};

    fn rw_memory(len: u32) -> Memory {
        let mut mem = Memory::new(len);
        mem.add_region(0, len, Permissions::RW);
        mem
    }

    #[test]
    fn read_bytes_returns_exact_payload() {
        let mut mem = rw_memory(64);
        for i in 0..8u8 {
            mem.store_u8(u32::from(i), i).unwrap();
        }
        let got = read_bytes(&mem, 0, 8).unwrap();
        assert_eq!(got, vec![0, 1, 2, 3, 4, 5, 6, 7]);
    }

    #[test]
    fn read_zero_len_succeeds_even_on_unmapped_addr() {
        let mem = Memory::new(0);
        assert_eq!(read_bytes(&mem, 0xDEAD_BEEF, 0).unwrap(), Vec::<u8>::new());
    }

    #[test]
    fn read_out_of_bounds_traps() {
        let mem = rw_memory(16);
        let err = read_bytes(&mem, 12, 8).unwrap_err();
        assert!(matches!(err, Trap::MemoryFault { .. }));
    }

    #[test]
    fn read_unmapped_traps() {
        let mut mem = Memory::new(64);
        mem.add_region(0, 16, Permissions::RW);
        let err = read_bytes(&mem, 32, 4).unwrap_err();
        assert!(matches!(err, Trap::MemoryFault { .. }));
    }

    #[test]
    fn write_round_trips() {
        let mut mem = rw_memory(32);
        write_bytes(&mut mem, 4, &[0xDE, 0xAD, 0xBE, 0xEF]).unwrap();
        assert_eq!(mem.load_u8(4).unwrap(), 0xDE);
        assert_eq!(mem.load_u8(5).unwrap(), 0xAD);
        assert_eq!(mem.load_u8(6).unwrap(), 0xBE);
        assert_eq!(mem.load_u8(7).unwrap(), 0xEF);
    }

    #[test]
    fn write_to_readonly_traps() {
        let mut mem = Memory::new(64);
        mem.add_region(0, 32, Permissions::R);
        let err = write_bytes(&mut mem, 0, &[1, 2, 3]).unwrap_err();
        assert!(matches!(err, Trap::MemoryFault { .. }));
    }

    #[test]
    fn validate_readable_passes_for_mapped() {
        let mem = rw_memory(64);
        assert!(validate_readable(&mem, 0, 64).is_ok());
    }

    #[test]
    fn validate_readable_traps_for_out_of_bounds() {
        let mem = rw_memory(16);
        assert!(matches!(
            validate_readable(&mem, 14, 4),
            Err(Trap::MemoryFault { .. })
        ));
    }

    #[test]
    fn overlap_detection() {
        // Disjoint.
        assert!(!buffers_overlap(0, 4, 4, 4));
        // Touching at boundary still disjoint.
        assert!(!buffers_overlap(0, 4, 4, 4));
        // Overlapping by one byte.
        assert!(buffers_overlap(0, 5, 4, 4));
        // Identical range.
        assert!(buffers_overlap(10, 4, 10, 4));
        // a inside b.
        assert!(buffers_overlap(10, 2, 8, 10));
        // b inside a.
        assert!(buffers_overlap(8, 10, 10, 2));
        // Zero-length never overlaps.
        assert!(!buffers_overlap(0, 0, 0, 4));
        assert!(!buffers_overlap(0, 4, 2, 0));
    }
}
