//! Cryptographic syscalls (0x40..=0x4F).
//!
//! All hash and signature primitives are dispatched to
//! [`neutrino_crypto`]. Output buffers are written byte-by-byte through
//! the [`crate::pointer`] helpers to enforce region permissions; the
//! per-syscall gas cost follows the table in
//! `docs/design/04-host-abi.md`.

use neutrino_crypto::{bls, ed25519, hash, secp256k1};
use neutrino_runtime_abi::gas;
use neutrino_runtime_abi::status::Status;
use neutrino_vm_rv32im::cpu::Cpu;
use neutrino_vm_rv32im::memory::Memory;
use neutrino_vm_rv32im::{Halt, Trap};

use crate::pointer;

use super::set_status;

/// Common shape for hash syscalls: read `in_len` bytes from `in_ptr`,
/// hash them with `f`, write the 32-byte digest to `out_ptr`.
fn hash_into<F>(
    cpu: &mut Cpu,
    memory: &mut Memory,
    gas_cost: u64,
    gas_remaining: &mut u64,
    f: F,
) -> Result<Option<Halt>, Trap>
where
    F: FnOnce(&[u8]) -> [u8; 32],
{
    *gas_remaining = gas_remaining.checked_sub(gas_cost).ok_or(Trap::OutOfGas)?;

    let in_ptr = cpu.read(10);
    let in_len = cpu.read(11);
    let out_ptr = cpu.read(12);

    let input = pointer::read_bytes(memory, in_ptr, in_len)?;
    let digest = f(&input);
    pointer::write_bytes(memory, out_ptr, &digest)?;
    set_status(cpu, Status::Ok);
    Ok(None)
}

/// `hash_sha256(in_ptr, in_len, out_ptr) -> status` — `0x40`.
pub fn hash_sha256(
    cpu: &mut Cpu,
    memory: &mut Memory,
    gas_remaining: &mut u64,
) -> Result<Option<Halt>, Trap> {
    let in_len = cpu.read(11);
    let cost = gas::hash_fast(u64::from(in_len));
    hash_into(cpu, memory, cost, gas_remaining, hash::sha256)
}

/// `hash_blake3(in_ptr, in_len, out_ptr) -> status` — `0x41`.
pub fn hash_blake3(
    cpu: &mut Cpu,
    memory: &mut Memory,
    gas_remaining: &mut u64,
) -> Result<Option<Halt>, Trap> {
    let in_len = cpu.read(11);
    let cost = gas::hash_fast(u64::from(in_len));
    hash_into(cpu, memory, cost, gas_remaining, hash::blake3_256)
}

/// `hash_keccak256(in_ptr, in_len, out_ptr) -> status` — `0x42`.
pub fn hash_keccak256(
    cpu: &mut Cpu,
    memory: &mut Memory,
    gas_remaining: &mut u64,
) -> Result<Option<Halt>, Trap> {
    let in_len = cpu.read(11);
    let cost = gas::hash_keccak256(u64::from(in_len));
    hash_into(cpu, memory, cost, gas_remaining, hash::keccak256)
}

/// `verify_ed25519(msg_ptr, msg_len, sig_ptr, pub_ptr) -> bool` — `0x43`.
///
/// Returns `1` in `a0` if the signature verifies under `pub_ptr` over
/// the message at `(msg_ptr, msg_len)`, `0` otherwise. Malformed
/// public keys or signatures return `0` (not a trap): callers can
/// validate or fall through to a status path of their choice.
pub fn verify_ed25519(
    cpu: &mut Cpu,
    memory: &mut Memory,
    gas_remaining: &mut u64,
) -> Result<Option<Halt>, Trap> {
    *gas_remaining = gas_remaining
        .checked_sub(gas::verify_ed25519())
        .ok_or(Trap::OutOfGas)?;

    let msg_ptr = cpu.read(10);
    let msg_len = cpu.read(11);
    let sig_ptr = cpu.read(12);
    let pub_ptr = cpu.read(13);

    let msg = pointer::read_bytes(memory, msg_ptr, msg_len)?;
    let sig_bytes_vec = pointer::read_bytes(memory, sig_ptr, 64)?;
    let pub_bytes_vec = pointer::read_bytes(memory, pub_ptr, 32)?;

    let mut sig_bytes = [0_u8; 64];
    sig_bytes.copy_from_slice(&sig_bytes_vec);
    let mut pub_bytes = [0_u8; 32];
    pub_bytes.copy_from_slice(&pub_bytes_vec);

    let ok = ed25519::PublicKey::from_bytes(&pub_bytes)
        .ok()
        .is_some_and(|pk| pk.verify(&msg, &sig_bytes).is_ok());
    cpu.write(10, u32::from(ok));
    cpu.write(11, 0);
    Ok(None)
}

/// `verify_secp256k1(msg_hash_ptr, sig_ptr, pub_ptr) -> bool` — `0x44`.
///
/// The runtime supplies a pre-hashed 32-byte message digest; the
/// underlying ECDSA verifier hashes the same way bridges expect (SHA-256
/// of the original payload).
pub fn verify_secp256k1(
    cpu: &mut Cpu,
    memory: &mut Memory,
    gas_remaining: &mut u64,
) -> Result<Option<Halt>, Trap> {
    *gas_remaining = gas_remaining
        .checked_sub(gas::verify_secp256k1())
        .ok_or(Trap::OutOfGas)?;

    let msg_hash_ptr = cpu.read(10);
    let sig_ptr = cpu.read(11);
    let pub_ptr = cpu.read(12);

    let msg_hash = pointer::read_bytes(memory, msg_hash_ptr, 32)?;
    let sig_bytes_vec = pointer::read_bytes(memory, sig_ptr, 65)?;
    let pub_bytes_vec = pointer::read_bytes(memory, pub_ptr, 33)?;

    let mut sig_bytes = [0_u8; 65];
    sig_bytes.copy_from_slice(&sig_bytes_vec);
    let mut pub_bytes = [0_u8; 33];
    pub_bytes.copy_from_slice(&pub_bytes_vec);

    let ok = secp256k1::PublicKey::from_bytes(&pub_bytes)
        .ok()
        .is_some_and(|pk| pk.verify(&msg_hash, &sig_bytes).is_ok());
    cpu.write(10, u32::from(ok));
    cpu.write(11, 0);
    Ok(None)
}

/// `verify_bls(msg_ptr, msg_len, sig_ptr, pub_ptr) -> bool` — `0x45`.
pub fn verify_bls(
    cpu: &mut Cpu,
    memory: &mut Memory,
    gas_remaining: &mut u64,
) -> Result<Option<Halt>, Trap> {
    *gas_remaining = gas_remaining
        .checked_sub(gas::verify_bls())
        .ok_or(Trap::OutOfGas)?;

    let msg_ptr = cpu.read(10);
    let msg_len = cpu.read(11);
    let sig_ptr = cpu.read(12);
    let pub_ptr = cpu.read(13);

    let msg = pointer::read_bytes(memory, msg_ptr, msg_len)?;
    let sig_vec = pointer::read_bytes(memory, sig_ptr, 96)?;
    let pub_vec = pointer::read_bytes(memory, pub_ptr, 48)?;

    let mut sig_bytes = [0_u8; 96];
    sig_bytes.copy_from_slice(&sig_vec);
    let mut pub_bytes = [0_u8; 48];
    pub_bytes.copy_from_slice(&pub_vec);

    let ok = bls::Signature::from_bytes(&sig_bytes)
        .ok()
        .zip(bls::PublicKey::from_bytes(&pub_bytes).ok())
        .is_some_and(|(sig, pk)| pk.verify(&msg, &sig).is_ok());
    cpu.write(10, u32::from(ok));
    cpu.write(11, 0);
    Ok(None)
}

/// `verify_bls_aggregate(msg_ptr, msg_len, sig_ptr, pubs_ptr, n_pubs) -> bool` — `0x46`.
///
/// Verifies a single 96-byte aggregate signature against `n_pubs`
/// public keys (48 bytes each, packed back-to-back at `pubs_ptr`) all
/// signing the same message at `(msg_ptr, msg_len)`.
pub fn verify_bls_aggregate(
    cpu: &mut Cpu,
    memory: &mut Memory,
    gas_remaining: &mut u64,
) -> Result<Option<Halt>, Trap> {
    let msg_ptr = cpu.read(10);
    let msg_len = cpu.read(11);
    let sig_ptr = cpu.read(12);
    let pubs_ptr = cpu.read(13);
    let n_pubs = cpu.read(14);

    *gas_remaining = gas_remaining
        .checked_sub(gas::verify_bls_aggregate(u64::from(n_pubs)))
        .ok_or(Trap::OutOfGas)?;

    let msg = pointer::read_bytes(memory, msg_ptr, msg_len)?;
    let sig_vec = pointer::read_bytes(memory, sig_ptr, 96)?;
    let mut sig_bytes = [0_u8; 96];
    sig_bytes.copy_from_slice(&sig_vec);

    // 48 bytes per BLS public key.
    let Some(pubs_total_len) = n_pubs.checked_mul(48) else {
        return Err(Trap::MemoryFault { addr: pubs_ptr });
    };
    let pubs_bytes = pointer::read_bytes(memory, pubs_ptr, pubs_total_len)?;

    let mut pks_owned: Vec<bls::PublicKey> = Vec::with_capacity(n_pubs as usize);
    let mut decode_ok = true;
    for i in 0..(n_pubs as usize) {
        let start = i * 48;
        let mut buf = [0_u8; 48];
        buf.copy_from_slice(&pubs_bytes[start..start + 48]);
        if let Ok(pk) = bls::PublicKey::from_bytes(&buf) {
            pks_owned.push(pk);
        } else {
            decode_ok = false;
            break;
        }
    }

    let mut ok = false;
    if decode_ok && !pks_owned.is_empty() {
        if let Ok(sig) = bls::Signature::from_bytes(&sig_bytes) {
            let pk_refs: Vec<&bls::PublicKey> = pks_owned.iter().collect();
            ok = bls::fast_aggregate_verify(&pk_refs, &msg, &sig).is_ok();
        }
    }

    cpu.write(10, u32::from(ok));
    cpu.write(11, 0);
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use neutrino_vm_rv32im::memory::Permissions;

    fn rw_memory(len: u32) -> Memory {
        let mut mem = Memory::new(len);
        mem.add_region(0, len, Permissions::RW);
        mem
    }

    fn store(mem: &mut Memory, addr: u32, bytes: &[u8]) {
        for (i, &b) in bytes.iter().enumerate() {
            mem.store_u8(addr + u32::try_from(i).unwrap(), b).unwrap();
        }
    }

    fn load_bytes(mem: &Memory, addr: u32, len: usize) -> Vec<u8> {
        (0..len)
            .map(|i| mem.load_u8(addr + u32::try_from(i).unwrap()).unwrap())
            .collect()
    }

    #[test]
    fn blake3_matches_reference() {
        let mut cpu = Cpu::new();
        let mut mem = rw_memory(256);
        store(&mut mem, 0, b"abc");
        cpu.write(10, 0);
        cpu.write(11, 3);
        cpu.write(12, 100);
        let mut gas = 10_000_u64;
        let _ = hash_blake3(&mut cpu, &mut mem, &mut gas).unwrap();
        let digest = load_bytes(&mem, 100, 32);
        let expected = neutrino_crypto::blake3_256(b"abc");
        assert_eq!(&digest[..], &expected[..]);
    }

    #[test]
    fn sha256_matches_reference() {
        let mut cpu = Cpu::new();
        let mut mem = rw_memory(256);
        store(&mut mem, 0, b"abc");
        cpu.write(10, 0);
        cpu.write(11, 3);
        cpu.write(12, 100);
        let mut gas = 10_000_u64;
        let _ = hash_sha256(&mut cpu, &mut mem, &mut gas).unwrap();
        let digest = load_bytes(&mem, 100, 32);
        let expected = neutrino_crypto::sha256(b"abc");
        assert_eq!(&digest[..], &expected[..]);
    }

    #[test]
    fn keccak256_matches_reference() {
        let mut cpu = Cpu::new();
        let mut mem = rw_memory(256);
        store(&mut mem, 0, b"abc");
        cpu.write(10, 0);
        cpu.write(11, 3);
        cpu.write(12, 100);
        let mut gas = 10_000_u64;
        let _ = hash_keccak256(&mut cpu, &mut mem, &mut gas).unwrap();
        let digest = load_bytes(&mem, 100, 32);
        let expected = neutrino_crypto::keccak256(b"abc");
        assert_eq!(&digest[..], &expected[..]);
    }

    #[test]
    fn hash_out_of_gas_traps() {
        let mut cpu = Cpu::new();
        let mut mem = rw_memory(256);
        cpu.write(10, 0);
        cpu.write(11, 100);
        cpu.write(12, 200);
        let mut gas = 50_u64;
        let result = hash_blake3(&mut cpu, &mut mem, &mut gas);
        assert_eq!(result, Err(Trap::OutOfGas));
    }

    #[test]
    fn verify_ed25519_returns_zero_on_invalid_pubkey() {
        let mut cpu = Cpu::new();
        let mut mem = rw_memory(512);
        cpu.write(10, 0);
        cpu.write(11, 8);
        cpu.write(12, 8);
        cpu.write(13, 72);
        let mut gas = 1_000_000_u64;
        let _ = verify_ed25519(&mut cpu, &mut mem, &mut gas).unwrap();
        assert_eq!(cpu.read(10), 0);
    }

    #[test]
    fn verify_bls_aggregate_zero_pubkeys_returns_false() {
        let mut cpu = Cpu::new();
        let mut mem = rw_memory(512);
        cpu.write(10, 0);
        cpu.write(11, 8);
        cpu.write(12, 16);
        cpu.write(13, 200);
        cpu.write(14, 0);
        let mut gas = 1_000_000_u64;
        let _ = verify_bls_aggregate(&mut cpu, &mut mem, &mut gas).unwrap();
        assert_eq!(cpu.read(10), 0);
    }
}
