#![deny(unsafe_code)]
#![allow(clippy::doc_markdown)]

//! Block-proof backend scaffold.

/// Block prover marker.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct BlockProver;
