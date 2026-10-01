#![no_std]
#![deny(unsafe_code)]
#![allow(clippy::doc_markdown)]

//! Deterministic validation shared by native and SP1 chunk proof paths.
//!
//! Validation alone does not verify the inner SP1 proofs. The guest must
//! recursively verify each block proof and commit the validated statement.

extern crate alloc;
#[cfg(feature = "std")]
extern crate std;

pub mod bls;
pub mod body;
pub mod consensus;
pub mod evidence;
pub mod execution;
pub mod finality;
pub mod history;
#[cfg(feature = "sp1-verification")]
pub mod proof_verification;
pub mod proposer;
pub mod rotation;
pub mod slashing;
