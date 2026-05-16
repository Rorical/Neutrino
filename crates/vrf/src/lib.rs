#![cfg_attr(not(feature = "std"), no_std)]
#![deny(unsafe_code)]
#![allow(clippy::doc_markdown)]

//! BLS-VRF message construction and eligibility helpers.

extern crate alloc;

use alloc::vec::Vec;

use neutrino_primitives::{ChainId, DOMAIN_VRF, Seed, Slot};

/// Builds the canonical BLS-VRF message.
pub fn vrf_message(chain_id: ChainId, finalized_seed: &Seed, slot: Slot) -> Vec<u8> {
    let mut message = Vec::with_capacity(16 + 8 + 32 + 8);
    message.extend_from_slice(&DOMAIN_VRF);
    message.extend_from_slice(&chain_id.to_le_bytes());
    message.extend_from_slice(finalized_seed);
    message.extend_from_slice(&slot.to_le_bytes());
    message
}
