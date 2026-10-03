//! Bounded asynchronous history proving requests and completion notifications.

use serde::{Deserialize, Serialize};

use crate::types::HashHex;

/// Public lifecycle of a persisted range-proving job.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HistoryJobStatus {
    /// Persisted and waiting for a worker.
    Queued,
    /// Proving outside the engine mutex.
    Running,
    /// Verified proof persisted and available by its pinned endpoints.
    Completed,
    /// Failed without changing the trusted boundary; intermediate proofs survive.
    Failed,
    /// Explicitly cancelled or expired.
    Cancelled,
}

impl HistoryJobStatus {
    /// Whether a subscription should close after this event.
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Completed | Self::Failed | Self::Cancelled)
    }
}

/// Stable request endpoints and observable completion state.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct HistoryJobInfo {
    /// Domain-separated deterministic request identity.
    pub id: HashHex,
    /// Exact locally known incoming checkpoint hash.
    pub start: HashHex,
    /// Exact locally known outgoing checkpoint hash.
    pub end: HashHex,
    /// Current job state.
    pub status: HistoryJobStatus,
    /// Operational failure reason, if any.
    pub error: Option<String>,
}
