//! Per-block scratch buffer.
//!
//! The runtime ABI passes the entrypoint's input through syscall
//! `host_input(out_ptr, out_cap)` and collects its output via
//! `host_output(ptr, len)`. Both buffers live host-side; the guest
//! ferries bytes across the boundary as needed. This decouples the
//! input/output payload size from the guest's memory layout.

/// Per-block scratch carrying the entrypoint's input and output.
///
/// The runtime ferries bytes through `host_input` / `host_output`; both
/// buffers live host-side as plain `Vec<u8>`. M2 has no upper bound;
/// a future engine pass can cap them via `gas_limit` and per-byte
/// costs.
#[derive(Debug, Default, Clone)]
pub struct Scratch {
    /// Bytes the host will hand out to `host_input`.
    pub input: Vec<u8>,
    /// Bytes the runtime has written via `host_output`.
    pub output: Vec<u8>,
}

impl Scratch {
    /// Construct a new scratch with the given input payload and an
    /// empty output buffer.
    #[must_use]
    pub const fn with_input(input: Vec<u8>) -> Self {
        Self {
            input,
            output: Vec::new(),
        }
    }

    /// Length of the staged input in bytes.
    #[must_use]
    pub fn input_len(&self) -> u32 {
        u32::try_from(self.input.len()).unwrap_or(u32::MAX)
    }

    /// Length of the recorded output in bytes.
    #[must_use]
    pub fn output_len(&self) -> u32 {
        u32::try_from(self.output.len()).unwrap_or(u32::MAX)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_empty() {
        let s = Scratch::default();
        assert!(s.input.is_empty());
        assert!(s.output.is_empty());
        assert_eq!(s.input_len(), 0);
        assert_eq!(s.output_len(), 0);
    }

    #[test]
    fn with_input_records_payload() {
        let s = Scratch::with_input(vec![1, 2, 3, 4]);
        assert_eq!(s.input, vec![1, 2, 3, 4]);
        assert!(s.output.is_empty());
        assert_eq!(s.input_len(), 4);
    }
}
