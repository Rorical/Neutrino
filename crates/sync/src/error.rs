//! Error types produced by [`SyncDriver`](crate::SyncDriver).

use thiserror::Error;

/// Errors surfaced by [`SyncDriver`](crate::SyncDriver) construction or
/// shutdown.
#[derive(Debug, Error)]
pub enum SyncDriverError {
    /// The network command channel closed before the driver finished
    /// initialising.
    #[error("network command channel closed unexpectedly")]
    NetworkChannelClosed,
    /// The network event stream closed unexpectedly.
    #[error("network event stream closed unexpectedly")]
    NetworkEventStreamClosed,
}
