//! Helpers for runtime authors implementing `_neutrino_query`.
//!
//! The host invokes the query entrypoint with a borsh-encoded
//! `QueryRequest` in `host_input` and expects a borsh-encoded
//! `QueryResponse` written via `host_output`. The wire envelope is
//! narrow — a UTF-8 method name plus opaque argument bytes in, a
//! status code plus opaque payload bytes out — so a runtime author
//! does not need an allocator to implement it.
//!
//! [`parse_query_request`] decodes the envelope without allocating,
//! exposing the method name as `&str` and the argument bytes as
//! `&[u8]`. [`encode_query_response_header`] writes the response code
//! plus payload length in place into a caller-supplied buffer.
//! [`query_dispatch`] (RV32-only) ties both together: it issues the
//! `host_input` / `host_output` syscalls and lets the runtime author
//! focus on per-method dispatch.

use neutrino_runtime_abi::QueryStatus;

/// Errors produced by [`parse_query_request`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QueryParseError {
    /// The payload was shorter than the borsh envelope requires.
    Truncated,
    /// The method-name bytes were not valid UTF-8.
    InvalidMethodName,
}

/// Errors produced by [`encode_query_response_header`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QueryEncodeError {
    /// The caller-supplied output buffer was smaller than `8 + payload_len`.
    BufferTooSmall {
        /// Required total buffer length.
        required: usize,
        /// Actual buffer length.
        available: usize,
    },
}

/// Parse a borsh-encoded [`QueryRequest`](neutrino_runtime_abi::QueryRequest)
/// out of `payload` without allocating.
///
/// Returns the UTF-8 method name and a slice referencing the argument
/// bytes inside `payload`. The returned references borrow from
/// `payload`; the caller is expected to hold it for the duration of
/// the dispatch.
pub fn parse_query_request(payload: &[u8]) -> Result<(&str, &[u8]), QueryParseError> {
    if payload.len() < 4 {
        return Err(QueryParseError::Truncated);
    }
    let method_len = u32::from_le_bytes(
        payload[..4]
            .try_into()
            .map_err(|_| QueryParseError::Truncated)?,
    ) as usize;
    let method_end = 4_usize
        .checked_add(method_len)
        .ok_or(QueryParseError::Truncated)?;
    if payload.len() < method_end + 4 {
        return Err(QueryParseError::Truncated);
    }
    let method_bytes = &payload[4..method_end];
    let method =
        core::str::from_utf8(method_bytes).map_err(|_| QueryParseError::InvalidMethodName)?;

    let args_len = u32::from_le_bytes(
        payload[method_end..method_end + 4]
            .try_into()
            .map_err(|_| QueryParseError::Truncated)?,
    ) as usize;
    let args_off = method_end + 4;
    let args_end = args_off
        .checked_add(args_len)
        .ok_or(QueryParseError::Truncated)?;
    if payload.len() < args_end {
        return Err(QueryParseError::Truncated);
    }
    Ok((method, &payload[args_off..args_end]))
}

/// Write the borsh `QueryResponse` header into the first eight bytes
/// of `output_buf`: `code:u32 LE || payload_len:u32 LE`. The caller
/// must have already written `payload_len` bytes starting at
/// `output_buf[8..]`. Returns the total number of bytes the host
/// should be told to read (`8 + payload_len`).
pub fn encode_query_response_header(
    output_buf: &mut [u8],
    code: u32,
    payload_len: usize,
) -> Result<usize, QueryEncodeError> {
    let total = 8_usize
        .checked_add(payload_len)
        .ok_or(QueryEncodeError::BufferTooSmall {
            required: usize::MAX,
            available: output_buf.len(),
        })?;
    if output_buf.len() < total {
        return Err(QueryEncodeError::BufferTooSmall {
            required: total,
            available: output_buf.len(),
        });
    }
    output_buf[0..4].copy_from_slice(&code.to_le_bytes());
    let payload_len_u32 =
        u32::try_from(payload_len).map_err(|_| QueryEncodeError::BufferTooSmall {
            required: total,
            available: output_buf.len(),
        })?;
    output_buf[4..8].copy_from_slice(&payload_len_u32.to_le_bytes());
    Ok(total)
}

/// Convenience: drive an entire `_neutrino_query` invocation through
/// the SDK syscall stubs.
///
/// The caller provides two fixed-size buffers — one for the borsh
/// request bytes, one for the borsh response — plus a dispatcher
/// closure that writes the response payload directly into
/// `response_payload` and returns `(code, payload_len)`. The helper
/// reads the request via `host_input`, parses it (returning
/// [`QueryStatus::InvalidArguments`] on a malformed envelope),
/// invokes the dispatcher, fills in the response header, and writes
/// the result via `host_output`.
///
/// On an unrecoverable encoder failure (output buffer too small for
/// the requested payload length) the runtime aborts with code
/// `0xBADD_5500 + status` so the host can surface a deterministic
/// failure. Runtimes that want softer behaviour should size their
/// output buffer generously enough.
#[cfg(target_arch = "riscv32")]
pub fn query_dispatch<F>(input_buf: &mut [u8], output_buf: &mut [u8], dispatcher: F)
where
    F: FnOnce(&str, &[u8], &mut [u8]) -> (u32, usize),
{
    use neutrino_runtime_abi::status::Status;

    let input_cap = u32::try_from(input_buf.len()).unwrap_or(u32::MAX);
    let (status, input_len) = crate::syscalls::host_input(input_buf.as_mut_ptr() as u32, input_cap);

    let (code, payload_len) = if status == Status::Ok.as_u32() {
        let len = (input_len as usize).min(input_buf.len());
        let payload = &input_buf[..len];
        match parse_query_request(payload) {
            Ok((method, args)) => {
                // The dispatcher writes into the response payload area
                // (bytes 8 onward). We pass it the slice so it cannot
                // accidentally clobber the header.
                let header_len = 8;
                if output_buf.len() < header_len {
                    crate::syscalls::abort(0xBADD_5501);
                }
                let (_, rest) = output_buf.split_at_mut(header_len);
                dispatcher(method, args, rest)
            }
            Err(_) => (QueryStatus::InvalidArguments.as_u32(), 0),
        }
    } else {
        (QueryStatus::InvalidArguments.as_u32(), 0)
    };

    let total = match encode_query_response_header(output_buf, code, payload_len) {
        Ok(n) => n,
        Err(_) => crate::syscalls::abort(0xBADD_5502),
    };

    let total_u32 = u32::try_from(total).unwrap_or_else(|_| crate::syscalls::abort(0xBADD_5503));
    crate::syscalls::host_output(output_buf.as_ptr() as u32, total_u32);
}

#[cfg(test)]
mod tests {
    use super::*;
    extern crate alloc;
    use alloc::vec::Vec;

    fn encode_request(method: &str, args: &[u8]) -> Vec<u8> {
        let mut bytes = Vec::new();
        let method_bytes = method.as_bytes();
        bytes.extend_from_slice(&u32::try_from(method_bytes.len()).unwrap().to_le_bytes());
        bytes.extend_from_slice(method_bytes);
        bytes.extend_from_slice(&u32::try_from(args.len()).unwrap().to_le_bytes());
        bytes.extend_from_slice(args);
        bytes
    }

    #[test]
    fn parse_round_trips_method_and_args() {
        let encoded = encode_request("account_get", &[1, 2, 3]);
        let (method, args) = parse_query_request(&encoded).unwrap();
        assert_eq!(method, "account_get");
        assert_eq!(args, &[1, 2, 3]);
    }

    #[test]
    fn parse_returns_truncated_on_short_payload() {
        assert_eq!(
            parse_query_request(&[0, 0, 0]),
            Err(QueryParseError::Truncated)
        );
    }

    #[test]
    fn parse_returns_truncated_when_method_overruns_buffer() {
        // method_len = 10 but no method bytes present.
        let mut encoded = Vec::new();
        encoded.extend_from_slice(&10u32.to_le_bytes());
        assert_eq!(
            parse_query_request(&encoded),
            Err(QueryParseError::Truncated)
        );
    }

    #[test]
    fn parse_returns_truncated_when_args_overrun_buffer() {
        let mut encoded = encode_request("m", &[]);
        // Set args_len to 99 without supplying the bytes.
        let args_len_off = 4 + 1;
        encoded[args_len_off..args_len_off + 4].copy_from_slice(&99u32.to_le_bytes());
        assert_eq!(
            parse_query_request(&encoded),
            Err(QueryParseError::Truncated)
        );
    }

    #[test]
    fn parse_returns_invalid_method_name_on_non_utf8() {
        // 0xFF is not valid in UTF-8.
        let mut encoded = Vec::new();
        encoded.extend_from_slice(&1u32.to_le_bytes());
        encoded.push(0xFF);
        encoded.extend_from_slice(&0u32.to_le_bytes());
        assert_eq!(
            parse_query_request(&encoded),
            Err(QueryParseError::InvalidMethodName)
        );
    }

    #[test]
    fn encode_header_writes_code_and_length() {
        let mut buf = [0u8; 32];
        // Pretend payload is bytes 8..14
        buf[8..14].copy_from_slice(b"hello!");
        let total = encode_query_response_header(&mut buf, 42, 6).unwrap();
        assert_eq!(total, 14);
        assert_eq!(&buf[0..4], &42u32.to_le_bytes());
        assert_eq!(&buf[4..8], &6u32.to_le_bytes());
        assert_eq!(&buf[8..14], b"hello!");
    }

    #[test]
    fn encode_header_returns_buffer_too_small() {
        let mut buf = [0u8; 4];
        let err = encode_query_response_header(&mut buf, 0, 10).unwrap_err();
        assert!(matches!(err, QueryEncodeError::BufferTooSmall { .. }));
    }
}
