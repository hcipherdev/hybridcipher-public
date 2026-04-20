//! Error types for message operations

use thiserror::Error;

/// Message processing errors
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum MessageError {
    /// Serialization error
    #[error("Serialization failed: {0}")]
    Serialization(String),

    /// Deserialization error
    #[error("Deserialization failed: {0}")]
    Deserialization(String),

    /// Invalid message format
    #[error("Invalid message format: {0}")]
    InvalidFormat(String),

    /// Cryptographic error from underlying crypto operations
    #[error("Crypto error: {0}")]
    Crypto(#[from] hybridcipher_crypto::error::CryptoError),

    /// Direct cryptographic error
    #[error("Crypto error: {0}")]
    CryptoError(String),

    /// Serialization error for CBOR encoding/decoding
    #[error("Serialization error: {0}")]
    SerializationError(String),

    /// Signature verification error
    #[error("Signature error: {0}")]
    SignatureError(String),

    /// Timestamp-related error
    #[error("Timestamp error: {0}")]
    TimestampError(String),

    /// Expired card or message
    #[error("Expired: {0}")]
    ExpiredCard(String),
}

/// Result type for message operations
pub type MessageResult<T> = Result<T, MessageError>;
