/// Why a pairing attempt failed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PairError {
    /// The code or SAS did not match, or key confirmation failed.
    #[error("the code did not match")]
    Mismatch,
    /// The window was open longer than [`crate::PAIRING_TTL`].
    #[error("the pairing window expired")]
    Expired,
    /// The window was already used by an earlier attempt.
    #[error("this pairing window was already used")]
    Consumed,
    /// The peer sent something malformed.
    #[error("protocol error: {0}")]
    Protocol(String),
    /// The transport failed.
    #[error("network error: {0}")]
    Network(String),
}
