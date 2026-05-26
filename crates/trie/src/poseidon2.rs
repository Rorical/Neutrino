//! Poseidon2-backed trie hasher.
//!
//! This is the SP1-precompile-aligned trie hash. Inside the SP1 Guest
//! (`target_os = "zkvm"`) each permutation maps to a single
//! `syscall_poseidon2` precompile call (~100 prover cycles); outside
//! the guest we run a software implementation built on `p3-poseidon2`
//! + `p3-koala-bear` that produces byte-identical digests.
//!
//! # Parameters
//!
//! Matches SP1's canonical KoalaBear Poseidon2 instance
//! (`slop-koala-bear::my_kb_16_perm`):
//!
//! - Field: `KoalaBear`, modulus `p = 2^31 - 2^24 + 1 = 0x7F000001`
//! - Width 16, S-box `x^3` (`D = 3`)
//! - 8 external full rounds + 20 internal partial rounds
//! - External constants: `RC16_RAW[0..4]` and `RC16_RAW[24..28]`
//! - Internal constants: column 0 of `RC16_RAW[4..24]`
//!
//! # Byte hashing convention
//!
//! Matches `sp1-lib::poseidon2::Poseidon2ByteHash::hash`:
//!
//! 1. Absorb a length-prefix block first (`u64_le(input.len()` packed
//!    into the first 24-byte block, zero-padded).  Using `u64` rather
//!    than `usize` keeps the digest target-independent — the high
//!    bytes are zero for any practical input so the resulting block
//!    matches the 32-bit guest's `u32_le` encoding byte-for-byte for
//!    inputs under 4 GiB.
//! 2. Absorb every full 24-byte block (3 bytes per field element,
//!    little-endian into the low 24 bits, 8 field elements per
//!    block = the sponge rate).
//! 3. Absorb the final partial block with zero padding (no length
//!    delimiter — the leading length-prefix is sufficient).
//! 4. Output the first 8 state elements (the rate portion), packed
//!    as 4 little-endian bytes per element = 32-byte digest.
//!
//! Each KoalaBear element fits in 31 bits, so the top bit of every
//! 4th output byte is always zero.  Effective digest entropy is
//! `8 * 31 = 248 bits`, well above the 128-bit safety floor for
//! collision resistance.
//!
//! # Domain separation
//!
//! `Hasher::hash_node` prepends [`TRIE_NODE_DOMAIN_POSEIDON2`] (16
//! bytes, disjoint from the BLAKE3 variant's `TRIE_NODE_DOMAIN`) so a
//! chain that ran on the BLAKE3 trie and a chain that ran on the
//! Poseidon2 trie cannot share a node digest by accident, even if
//! they happened to share initial state.
//! `Hasher::hash_value` hashes value bytes directly without a domain
//! tag — values are content-addressed and the column they live in is
//! disjoint from the node column.

extern crate alloc;

use neutrino_primitives::Hash;

use crate::hasher::Hasher;

// Software-impl imports.  The SP1 Guest (`target_os = "zkvm"`) calls
// the precompile via `sp1-lib`; the master cdylib's `wasm32-unknown-
// unknown` build never executes the hash function at runtime (state
// roots are supplied by host imports), so we link a panic-stub there
// to avoid pulling the `getrandom`-bearing `p3-poseidon2` dep into the
// wasm cdylib build.
#[cfg(not(any(target_os = "zkvm", target_arch = "wasm32")))]
use alloc::boxed::Box;
#[cfg(not(any(target_os = "zkvm", target_arch = "wasm32")))]
use once_cell::race::OnceBox;
#[cfg(not(any(target_os = "zkvm", target_arch = "wasm32")))]
use p3_field::{AbstractField, PrimeField32};
#[cfg(not(any(target_os = "zkvm", target_arch = "wasm32")))]
use p3_koala_bear::{DiffusionMatrixKoalaBear, KoalaBear};
#[cfg(not(any(target_os = "zkvm", target_arch = "wasm32")))]
use p3_poseidon2::{Poseidon2, Poseidon2ExternalMatrixGeneral};
#[cfg(not(any(target_os = "zkvm", target_arch = "wasm32")))]
use p3_symmetric::Permutation;

/// 16-byte domain tag prepended to every Poseidon2 trie-node hash.
/// Disjoint from the BLAKE3 variant's
/// [`crate::TRIE_NODE_DOMAIN`] so the two hash families cannot
/// alias on the same input.
pub const TRIE_NODE_DOMAIN_POSEIDON2: [u8; 16] = *b"NTRO_TR_NODE_P2_";

/// Sponge rate — 8 elements per absorb (`24` bytes of byte-input
/// per absorb).  Matches `sp1-lib::poseidon2::RATE`.  Used by every
/// code path that produces a digest (host software, zkvm precompile)
/// to drive the output-packing loop; only the wasm32 panic-stub
/// doesn't reference it.
#[cfg(not(target_arch = "wasm32"))]
const RATE: usize = 8;

/// Sponge width, byte-block size, and Poseidon2 round counts —
/// software-impl only.  The SP1 Guest reaches the precompile via
/// `sp1-lib` (which carries its own copies of these constants
/// internally), and the master `wasm32-unknown-unknown` cdylib
/// never executes the trie's hash function at runtime, so neither
/// target needs these baked in.
#[cfg(not(any(target_os = "zkvm", target_arch = "wasm32")))]
const WIDTH: usize = 16;
#[cfg(not(any(target_os = "zkvm", target_arch = "wasm32")))]
const BYTE_BLOCK_SIZE: usize = RATE * 3;
#[cfg(not(any(target_os = "zkvm", target_arch = "wasm32")))]
const ROUNDS_F_HALF: usize = 4;
#[cfg(not(any(target_os = "zkvm", target_arch = "wasm32")))]
const ROUNDS_P: usize = 20;
#[cfg(not(any(target_os = "zkvm", target_arch = "wasm32")))]
const D: u64 = 3;

/// The Poseidon2 permutation type, identical to SP1's
/// `slop-koala-bear::KoalaPerm`.  Software-impl-only — the SP1 Guest
/// reaches the precompile via
/// `sp1-lib::poseidon2::Poseidon2ByteHash::hash`, and the master
/// `wasm32-unknown-unknown` cdylib never instantiates this at
/// runtime (host imports own state-root computation).
#[cfg(not(any(target_os = "zkvm", target_arch = "wasm32")))]
type KoalaPerm =
    Poseidon2<KoalaBear, Poseidon2ExternalMatrixGeneral, DiffusionMatrixKoalaBear, WIDTH, D>;

/// SP1's canonical KoalaBear Poseidon2 round constants for width 16.
///
/// Software-impl-only — the SP1 Guest goes through the precompile
/// and never reads these.  Gated to keep the guest ELF smaller and
/// to keep the master cdylib's wasm32-unknown-unknown build free
/// of the `p3-poseidon2`/`getrandom` chain (the cdylib doesn't
/// execute trie hashing at runtime; host imports own that).
#[cfg(not(any(target_os = "zkvm", target_arch = "wasm32")))]
///
/// Layout (matching `slop-koala-bear::koala_bear_poseidon2`):
///
/// - Rows `0..4`: beginning external (full) round constants.
/// - Rows `4..24`: internal (partial) round constants — only column
///   `0` of each row is used; the remaining 15 columns are zero
///   filler so the table is rectangular.
/// - Rows `24..28`: ending external (full) round constants.
///
/// Bit-identical to `slop-koala-bear-6.2.1::koala_bear_poseidon2::RC16`
/// after `KoalaBear::from_canonical_u64(u64::from_str_radix(...))`.
/// Each value is `< 2^31` so `KoalaBear::from_canonical_u32` accepts
/// them without reduction.
#[allow(clippy::unreadable_literal)]
const RC16_RAW: [[u32; 16]; 28] = [
    // 4 beginning full rounds
    [
        0x7ee56a48, 0x11367045, 0x12e41941, 0x7ebbc12b, 0x1970b7d5, 0x662b60e8, 0x3e4990c6,
        0x679f91f5, 0x350813bb, 0x00874ad4, 0x28a0081a, 0x18fa5872, 0x5f25b071, 0x5e5d5998,
        0x5e6fd3e7, 0x5b2e2660,
    ],
    [
        0x6f1837bf, 0x3fe6182b, 0x1edd7ac5, 0x57470d00, 0x43d486d5, 0x1982c70f, 0x0ea53af9,
        0x61d6165b, 0x51639c00, 0x2dec352c, 0x2950e531, 0x2d2cb947, 0x08256cef, 0x1a0109f6,
        0x1f51faf3, 0x5cef1c62,
    ],
    [
        0x3d65e50e, 0x33d91626, 0x133d5a1e, 0x0ff49b0d, 0x38900cd1, 0x2c22cc3f, 0x28852bb2,
        0x06c65a02, 0x7b2cf7bc, 0x68016e1a, 0x15e16bc0, 0x5248149a, 0x6dd212a0, 0x18d6830a,
        0x5001be82, 0x64dac34e,
    ],
    [
        0x5902b287, 0x426583a0, 0x0c921632, 0x3fe028a5, 0x245f8e49, 0x43bb297e, 0x7873dbd9,
        0x3cc987df, 0x286bb4ce, 0x640a8dcd, 0x512a8e36, 0x03a4cf55, 0x481837a2, 0x03d6da84,
        0x73726ac7, 0x760e7fdf,
    ],
    // 20 partial rounds (only column 0 used)
    [0x54dfeb5d, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    [0x7d40afd6, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    [0x722cb316, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    [0x106a4573, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    [0x45a7ccdb, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    [0x44061375, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    [0x154077a5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    [0x45744faa, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    [0x4eb5e5ee, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    [0x3794e83f, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    [0x47c7093c, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    [0x5694903c, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    [0x69cb6299, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    [0x373df84c, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    [0x46a0df58, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    [0x46b8758a, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    [0x3241ebcb, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    [0x0b09d233, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    [0x1af42357, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    [0x1e66cec2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    // 4 ending full rounds
    [
        0x43e7dc24, 0x259a5d61, 0x27e85a3b, 0x1b9133fa, 0x343e5628, 0x485cd4c2, 0x16e269f5,
        0x165b60c6, 0x25f683d9, 0x124f81f9, 0x174331f9, 0x77344dc5, 0x5a821dba, 0x5fc4177f,
        0x54153bf5, 0x5e3f1194,
    ],
    [
        0x3bdbf191, 0x088c84a3, 0x68256c9b, 0x3c90bbc6, 0x6846166a, 0x03f4238d, 0x463335fb,
        0x5e3d3551, 0x6e59ae6f, 0x32d06cc0, 0x596293f3, 0x6c87edb2, 0x08fc60b5, 0x34bcca80,
        0x24f007f3, 0x62731c6f,
    ],
    [
        0x1e1db6c6, 0x0ca409bb, 0x585c1e78, 0x56e94edc, 0x16d22734, 0x18e11467, 0x7b2c3730,
        0x770075e4, 0x35d1b18c, 0x22be3db5, 0x4fb1fbb7, 0x477cb3ed, 0x7d5311c6, 0x5b62ae7d,
        0x559c5fa8, 0x77f15048,
    ],
    [
        0x3211570b, 0x490fef6a, 0x77ec311f, 0x2247171b, 0x4e0ac711, 0x2edf69c9, 0x3b5a8850,
        0x65809421, 0x5619b4aa, 0x362019a7, 0x6bf9d4ed, 0x5b413dff, 0x617e181e, 0x5e7ab57b,
        0x33ad7833, 0x3466c7ca,
    ],
];

/// Lazily-constructed Poseidon2 permutation singleton.  Built once on
/// first use from [`RC16_RAW`]; subsequent uses are O(1).  no_std +
/// alloc compatible via [`OnceBox`].
#[cfg(not(any(target_os = "zkvm", target_arch = "wasm32")))]
fn perm_instance() -> &'static KoalaPerm {
    static INSTANCE: OnceBox<KoalaPerm> = OnceBox::new();
    INSTANCE.get_or_init(|| Box::new(build_perm()))
}

/// Build the canonical Poseidon2 permutation from the hardcoded
/// [`RC16_RAW`] table.  Equivalent to
/// `slop-koala-bear::my_kb_16_perm()` at runtime.
#[cfg(not(any(target_os = "zkvm", target_arch = "wasm32")))]
fn build_perm() -> KoalaPerm {
    let to_field = |row: &[u32; 16]| -> [KoalaBear; WIDTH] {
        let mut out = [KoalaBear::zero(); WIDTH];
        for (i, &v) in row.iter().enumerate() {
            out[i] = KoalaBear::from_canonical_u32(v);
        }
        out
    };

    let mut external_constants = alloc::vec::Vec::with_capacity(2 * ROUNDS_F_HALF);
    for row in &RC16_RAW[0..ROUNDS_F_HALF] {
        external_constants.push(to_field(row));
    }
    for row in &RC16_RAW[ROUNDS_F_HALF + ROUNDS_P..] {
        external_constants.push(to_field(row));
    }

    let mut internal_constants = alloc::vec::Vec::with_capacity(ROUNDS_P);
    for row in &RC16_RAW[ROUNDS_F_HALF..ROUNDS_F_HALF + ROUNDS_P] {
        internal_constants.push(KoalaBear::from_canonical_u32(row[0]));
    }

    KoalaPerm::new(
        2 * ROUNDS_F_HALF,
        external_constants,
        Poseidon2ExternalMatrixGeneral,
        ROUNDS_P,
        internal_constants,
        DiffusionMatrixKoalaBear,
    )
}

/// Inside the SP1 Guest, dispatch straight to the precompile-backed
/// [`sp1_lib::poseidon2::Poseidon2ByteHash::hash`].  Each absorbed
/// block costs ~100 prover cycles instead of the ~1.5 M cycles a
/// software BLAKE3 invocation would take in emulated RISC-V.
#[cfg(target_os = "zkvm")]
fn poseidon2_byte_hash(bytes: &[u8]) -> Hash {
    let output: [u32; RATE] = sp1_lib::poseidon2::Poseidon2ByteHash::hash(bytes);
    let mut digest = [0u8; 32];
    for i in 0..RATE {
        digest[i * 4..(i + 1) * 4].copy_from_slice(&output[i].to_le_bytes());
    }
    digest
}

/// `wasm32-unknown-unknown` panic-stub.  The master cdylib delegates
/// every state-root computation to host imports
/// (`pre_state_root` / `post_state_root`) and never instantiates the
/// trie's hash function at runtime — so the only purpose of this
/// stub is to keep the crate's dead code linking cleanly without
/// pulling the `p3-poseidon2` → `rand` → `getrandom` chain into the
/// wasm cdylib's dep graph.  A live call here indicates a regression
/// in the WASM ABI surface; failing loudly is the right behaviour.
#[cfg(target_arch = "wasm32")]
fn poseidon2_byte_hash(_bytes: &[u8]) -> Hash {
    panic!(
        "neutrino-trie's Poseidon2 software impl is not compiled into \
         the wasm32-unknown-unknown cdylib build; host imports own \
         state-root computation"
    )
}

/// Absorb a single 24-byte block into the sponge state, using SP1's
/// 3-bytes-per-element little-endian packing.  Software-impl only —
/// the guest path is `sp1-lib::poseidon2::Poseidon2ByteHash::hash`
/// (which uses the same convention internally) and the wasm32 cdylib
/// path is a panic-stub.
#[cfg(not(any(target_os = "zkvm", target_arch = "wasm32")))]
fn absorb_byte_block(state: &mut [u32; WIDTH], block: &[u8; BYTE_BLOCK_SIZE]) {
    for (i, slot) in state.iter_mut().take(RATE).enumerate() {
        let start = 3 * i;
        *slot = u32::from(block[start])
            | (u32::from(block[start + 1]) << 8)
            | (u32::from(block[start + 2]) << 16);
    }
    // Convert sponge state to field elements, permute, convert back.
    let mut field_state: [KoalaBear; WIDTH] = [KoalaBear::zero(); WIDTH];
    for (i, &v) in state.iter().enumerate() {
        field_state[i] = KoalaBear::from_canonical_u32(v);
    }
    perm_instance().permute_mut(&mut field_state);
    for (i, slot) in state.iter_mut().enumerate() {
        *slot = field_state[i].as_canonical_u32();
    }
}

/// Length-prefixed sponge hash, matching
/// `sp1-lib::poseidon2::Poseidon2ByteHash::hash` byte-for-byte for
/// inputs under 4 GiB.  Returns a 32-byte digest formed by packing
/// the first [`RATE`] state elements as 4 little-endian bytes each.
///
/// Software-impl path; the SP1 Guest goes through the
/// precompile-backed `poseidon2_byte_hash` defined above and the
/// master `wasm32-unknown-unknown` cdylib uses a panic-stub since
/// it never executes the trie's hash function at runtime.
#[cfg(not(any(target_os = "zkvm", target_arch = "wasm32")))]
fn poseidon2_byte_hash(bytes: &[u8]) -> Hash {
    let mut state = [0u32; WIDTH];

    // Block 0: length prefix.  Using u64 explicitly keeps the digest
    // identical between 32-bit and 64-bit hosts (the high 4 bytes
    // are zero for any input under 4 GiB).
    let len_bytes = (bytes.len() as u64).to_le_bytes();
    let mut len_block = [0u8; BYTE_BLOCK_SIZE];
    len_block[..len_bytes.len()].copy_from_slice(&len_bytes);
    absorb_byte_block(&mut state, &len_block);

    // Full input blocks.
    let chunks = bytes.chunks_exact(BYTE_BLOCK_SIZE);
    let remainder = chunks.remainder();
    for chunk in chunks {
        // `try_into()` on a slice of known length is infallible.
        let block: &[u8; BYTE_BLOCK_SIZE] = chunk
            .try_into()
            .expect("chunks_exact produces fixed-size slices");
        absorb_byte_block(&mut state, block);
    }

    // Final partial block, zero-padded.
    if !remainder.is_empty() {
        let mut last_block = [0u8; BYTE_BLOCK_SIZE];
        last_block[..remainder.len()].copy_from_slice(remainder);
        absorb_byte_block(&mut state, &last_block);
    }

    // Output: first RATE elements, packed as 4 LE bytes each.
    let mut digest = [0u8; 32];
    for i in 0..RATE {
        digest[i * 4..(i + 1) * 4].copy_from_slice(&state[i].to_le_bytes());
    }
    digest
}

/// Poseidon2-backed [`Hasher`].
///
/// Inside the SP1 Guest this maps to a `POSEIDON2` precompile call
/// per absorbed block — ~100 prover cycles vs ~1.5M for BLAKE3 in
/// software-emulated RISC-V.  Outside the guest the software fallback
/// produces byte-identical digests.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Poseidon2Hasher;

impl Hasher for Poseidon2Hasher {
    fn hash_node(encoded_node: &[u8]) -> Hash {
        let mut buf =
            alloc::vec::Vec::with_capacity(TRIE_NODE_DOMAIN_POSEIDON2.len() + encoded_node.len());
        buf.extend_from_slice(&TRIE_NODE_DOMAIN_POSEIDON2);
        buf.extend_from_slice(encoded_node);
        poseidon2_byte_hash(&buf)
    }

    fn hash_value(value: &[u8]) -> Hash {
        poseidon2_byte_hash(value)
    }
}

// Tests run on the host toolchain (which is neither the SP1 Guest
// `target_os = "zkvm"` nor a wasm32 target).  Gating to "software
// impl available" keeps the `perm_instance` test reachable while
// avoiding `unused`-warnings under the gated-out targets.
#[cfg(all(test, not(any(target_os = "zkvm", target_arch = "wasm32"))))]
mod tests {
    use super::*;

    #[test]
    fn permutation_singleton_is_idempotent() {
        // OnceBox guarantee — two calls return the same reference.
        let a = core::ptr::from_ref::<KoalaPerm>(perm_instance());
        let b = core::ptr::from_ref::<KoalaPerm>(perm_instance());
        assert_eq!(a, b, "perm_instance must return the same singleton");
    }

    #[test]
    fn empty_input_hashes_to_well_defined_non_zero_digest() {
        // Empty input is the length-prefix block (all zeros after the
        // 8-byte len = 0) plus an absorb-output.  The result must be
        // non-zero and deterministic.
        let h = poseidon2_byte_hash(&[]);
        assert_ne!(h, [0u8; 32]);
        assert_eq!(h, poseidon2_byte_hash(&[]), "deterministic across calls");
    }

    #[test]
    fn distinct_inputs_have_distinct_digests() {
        // Trivial collision-resistance smoke check.
        let a = poseidon2_byte_hash(b"alpha");
        let b = poseidon2_byte_hash(b"beta");
        assert_ne!(a, b);
    }

    #[test]
    fn length_prefix_prevents_zero_extension_collision() {
        // Without the length-prefix block, "a" and "a\0" would
        // produce the same digest because the second is just a
        // zero-padded version of the first inside the same 24-byte
        // block.  The length prefix splits them.
        let a = poseidon2_byte_hash(b"a");
        let ab = poseidon2_byte_hash(b"a\0");
        assert_ne!(a, ab, "length-prefixed sponge must distinguish them");
    }

    #[test]
    fn node_and_value_hashes_are_disjoint_namespaces() {
        // The same input bytes hash differently under hash_node vs
        // hash_value because hash_node prepends
        // TRIE_NODE_DOMAIN_POSEIDON2 first.
        let bytes = b"collision attempt";
        let n = <Poseidon2Hasher as Hasher>::hash_node(bytes);
        let v = <Poseidon2Hasher as Hasher>::hash_value(bytes);
        assert_ne!(n, v);
    }

    #[test]
    fn poseidon2_domain_is_exactly_sixteen_bytes() {
        assert_eq!(TRIE_NODE_DOMAIN_POSEIDON2.len(), 16);
    }

    #[test]
    fn output_top_bit_of_each_element_is_zero() {
        // Each output element is a KoalaBear field element with value
        // < 2^31, so when packed as little-endian u32 the top bit of
        // bytes 3, 7, 11, 15, 19, 23, 27, 31 must be zero.  This is a
        // sanity check that the host-side software path didn't smuggle
        // a value >= modulus through `as_canonical_u32()`.
        let digest = poseidon2_byte_hash(b"sanity check input");
        for i in 0..8 {
            let top_byte = digest[i * 4 + 3];
            assert!(
                top_byte < 0x80,
                "byte {} = 0x{:02x} has the top bit set; element {} would be >= 2^31",
                i * 4 + 3,
                top_byte,
                i,
            );
        }
    }
}
