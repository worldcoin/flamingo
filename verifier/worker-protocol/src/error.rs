/// A bounded CBOR serialization failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum WorkerProtocolError {
    /// Payload exceeds its configured byte budget.
    #[error("worker payload exceeds its configured limit")]
    TooLarge,
    /// Payload limit is zero.
    #[error("invalid worker payload limit")]
    InvalidLimit,
    /// Serialization failed.
    #[error("worker message encoding failed")]
    Encoding,
    /// Payload is not exactly one valid message.
    #[error("worker message is malformed")]
    Malformed,
}
