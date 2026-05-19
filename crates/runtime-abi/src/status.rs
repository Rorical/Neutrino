//! Stable ABI status codes for the runtime host contract.
//!
//! Status codes are part of the guest/host wire contract: they never
//! change semantics across ABI minor versions. A successful operation
//! returns [`Status::Ok`]; any other variant indicates the host refused
//! the call and the runtime should treat the operation as having no
//! effect.

use core::fmt;

/// Stable ABI status code returned by every fallible runtime operation.
///
/// The numeric discriminants match the values in
/// `docs/design/04-host-abi.md` exactly and are consensus-critical.
#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum Status {
    /// The operation succeeded.
    Ok = 0,
    /// Caller-provided output buffer was too small; `a1` holds the
    /// required size.
    BufferTooSmall = 1,
    /// Caller passed an invalid argument (pointer, length, or value).
    InvalidArgument = 2,
    /// Requested item was not found.
    NotFound = 3,
    /// Operation was not permitted in the current host context.
    PermissionDenied = 4,
    /// Runtime ran out of gas.
    OutOfGas = 5,
    /// Host encountered an internal error not attributable to the
    /// guest. Never expected; indicates a host bug.
    InternalError = 6,
}

impl Status {
    /// Returns the canonical wire encoding of the status code.
    #[must_use]
    pub const fn as_u32(self) -> u32 {
        self as u32
    }

    /// Returns `true` when the status indicates a successful operation.
    #[must_use]
    pub const fn is_ok(self) -> bool {
        matches!(self, Self::Ok)
    }

    /// Returns the short stable name used in diagnostics and logs.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Ok => "Ok",
            Self::BufferTooSmall => "BufferTooSmall",
            Self::InvalidArgument => "InvalidArgument",
            Self::NotFound => "NotFound",
            Self::PermissionDenied => "PermissionDenied",
            Self::OutOfGas => "OutOfGas",
            Self::InternalError => "InternalError",
        }
    }
}

impl fmt::Display for Status {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

impl From<Status> for u32 {
    fn from(status: Status) -> Self {
        status.as_u32()
    }
}

/// Error returned when a `u32` does not correspond to any ABI status code.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct UnknownStatus(pub u32);

impl fmt::Display for UnknownStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "unknown ABI status code {:#x}", self.0)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for UnknownStatus {}

impl TryFrom<u32> for Status {
    type Error = UnknownStatus;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Ok),
            1 => Ok(Self::BufferTooSmall),
            2 => Ok(Self::InvalidArgument),
            3 => Ok(Self::NotFound),
            4 => Ok(Self::PermissionDenied),
            5 => Ok(Self::OutOfGas),
            6 => Ok(Self::InternalError),
            other => Err(UnknownStatus(other)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALL: &[Status] = &[
        Status::Ok,
        Status::BufferTooSmall,
        Status::InvalidArgument,
        Status::NotFound,
        Status::PermissionDenied,
        Status::OutOfGas,
        Status::InternalError,
    ];

    #[test]
    fn discriminants_match_design_doc() {
        assert_eq!(Status::Ok.as_u32(), 0);
        assert_eq!(Status::BufferTooSmall.as_u32(), 1);
        assert_eq!(Status::InvalidArgument.as_u32(), 2);
        assert_eq!(Status::NotFound.as_u32(), 3);
        assert_eq!(Status::PermissionDenied.as_u32(), 4);
        assert_eq!(Status::OutOfGas.as_u32(), 5);
        assert_eq!(Status::InternalError.as_u32(), 6);
    }

    #[test]
    fn round_trip_through_u32() {
        for &status in ALL {
            let encoded: u32 = status.into();
            assert_eq!(Status::try_from(encoded), Ok(status));
        }
    }

    #[test]
    fn unknown_codes_are_rejected() {
        for code in [7_u32, 8, 42, u32::MAX] {
            assert_eq!(Status::try_from(code), Err(UnknownStatus(code)));
        }
    }

    #[test]
    fn only_ok_is_ok() {
        for &status in ALL {
            assert_eq!(status.is_ok(), matches!(status, Status::Ok));
        }
    }

    #[test]
    fn display_matches_name() {
        use alloc::string::ToString;

        for &status in ALL {
            assert_eq!(status.to_string(), status.name());
        }
    }
}
