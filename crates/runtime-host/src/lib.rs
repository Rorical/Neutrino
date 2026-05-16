#![deny(unsafe_code)]
#![allow(clippy::doc_markdown)]

//! Host-side runtime executor scaffold.

/// Host runtime implementation marker.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RuntimeHost;
