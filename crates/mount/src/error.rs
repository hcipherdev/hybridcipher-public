//! Error types for the mount crate

use thiserror::Error;

/// Mount operation errors
#[derive(Error, Debug)]
pub enum MountError {
    #[error("FUSE operation failed: {0}")]
    FuseError(String),

    #[error("File system error: {0}")]
    FileSystemError(String),

    #[error("Cache error: {0}")]
    CacheError(String),

    #[error("Migration error: {0}")]
    MigrationError(String),

    #[error("Platform error: {0}")]
    PlatformError(String),

    #[error("Client error: {0}")]
    Client(#[from] hybridcipher_client::ClientError),

    #[error("Decryption error: {0}")]
    Decryption(String),

    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("Other error: {0}")]
    Other(#[from] anyhow::Error),
}

/// Result type for mount operations
pub type Result<T> = std::result::Result<T, MountError>;
