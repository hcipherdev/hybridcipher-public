use crate::security::server_identity::ServerIdentityError;
use hybridcipher_client::errors::ErrorCode;
use thiserror::Error;

/// Comprehensive CLI error types with user-friendly messages and recovery guidance
#[derive(Error, Debug)]
pub enum CliError {
    #[error("Authentication failed: {message}")]
    Authentication { message: String },

    #[error("Session error: {message}")]
    Session { message: String },

    #[error("Migration error: {message}")]
    Migration { message: String },

    #[error("Coverage error: {message}")]
    Coverage { message: String },

    #[error("File operation failed: {message}")]
    FileOperation { message: String },

    #[error("Member management error: {message}")]
    MemberManagement { message: String },

    #[error("Mount/filesystem error: {message}")]
    Mount { message: String },

    #[error("Configuration error: {message}")]
    Configuration { message: String },

    #[error("Network error: {message}")]
    Network { message: String },

    #[error("Cryptographic error: {message}")]
    Cryptographic { message: String },

    #[error("Permission denied: {message}")]
    Permission { message: String },

    #[error("Invalid input: {message}")]
    InvalidInput { message: String },

    #[error("Validation failed: {message}")]
    Validation { message: String },

    #[error("Resource not found: {message}")]
    NotFound { message: String },

    #[error("Operation cancelled by user")]
    Cancelled,

    #[error("Internal error: {message}")]
    Internal { message: String },

    #[error("Key pinning error: {0}")]
    PinningFailed(String),

    #[error("User not authenticated: {0}")]
    NotAuthenticated(String),

    #[error("I/O operation failed: {0}")]
    Io(String),

    #[error("Storage error: {message}")]
    Storage { message: String },

    #[error("Encryption error: {message}")]
    Encryption { message: String },

    #[error("Decryption error: {message}")]
    Decryption { message: String },

    #[error("Format error: {message}")]
    Format { message: String },

    #[error("Operation failed: {message}")]
    Operation { message: String },
}

impl CliError {
    /// Create an authentication error with context
    pub fn authentication<S: Into<String>>(message: S) -> Self {
        Self::Authentication {
            message: message.into(),
        }
    }

    /// Create a session error with context
    pub fn session<S: Into<String>>(message: S) -> Self {
        Self::Session {
            message: message.into(),
        }
    }

    /// Create a migration error with context
    pub fn migration<S: Into<String>>(message: S) -> Self {
        Self::Migration {
            message: message.into(),
        }
    }

    /// Create a coverage error with context
    pub fn coverage<S: Into<String>>(message: S) -> Self {
        Self::Coverage {
            message: message.into(),
        }
    }

    /// Create a file operation error with context
    pub fn file_operation<S: Into<String>>(message: S) -> Self {
        Self::FileOperation {
            message: message.into(),
        }
    }

    /// Create a member management error with context
    pub fn member_management<S: Into<String>>(message: S) -> Self {
        Self::MemberManagement {
            message: message.into(),
        }
    }

    /// Create a mount/filesystem error with context
    pub fn mount<S: Into<String>>(message: S) -> Self {
        Self::Mount {
            message: message.into(),
        }
    }

    /// Create a configuration error with context
    pub fn configuration<S: Into<String>>(message: S) -> Self {
        Self::Configuration {
            message: message.into(),
        }
    }

    /// Create a network error with context
    pub fn network<S: Into<String>>(message: S) -> Self {
        Self::Network {
            message: message.into(),
        }
    }

    /// Create a cryptographic error with context
    pub fn cryptographic<S: Into<String>>(message: S) -> Self {
        Self::Cryptographic {
            message: message.into(),
        }
    }

    /// Create a permission error with context
    pub fn permission<S: Into<String>>(message: S) -> Self {
        Self::Permission {
            message: message.into(),
        }
    }

    /// Create an invalid input error with context
    pub fn invalid_input<S: Into<String>>(message: S) -> Self {
        Self::InvalidInput {
            message: message.into(),
        }
    }

    /// Create a validation error with context
    pub fn validation<S: Into<String>>(message: S) -> Self {
        Self::Validation {
            message: message.into(),
        }
    }

    /// Create a not found error with context
    pub fn not_found<S: Into<String>>(message: S) -> Self {
        Self::NotFound {
            message: message.into(),
        }
    }

    /// Create an I/O error with context
    pub fn io<S: Into<String>>(message: S) -> Self {
        Self::Io(message.into())
    }

    /// Create an internal error with context
    pub fn internal<S: Into<String>>(message: S) -> Self {
        Self::Internal {
            message: message.into(),
        }
    }

    /// Create a storage error with context
    pub fn storage<S: Into<String>>(message: S) -> Self {
        Self::Storage {
            message: message.into(),
        }
    }

    /// Create an encryption error with context
    pub fn encryption<S: Into<String>>(message: S) -> Self {
        Self::Encryption {
            message: message.into(),
        }
    }

    /// Create a decryption error with context
    pub fn decryption<S: Into<String>>(message: S) -> Self {
        Self::Decryption {
            message: message.into(),
        }
    }

    /// Create a format error with context
    pub fn format<S: Into<String>>(message: S) -> Self {
        Self::Format {
            message: message.into(),
        }
    }

    /// Create an operation error with context
    pub fn operation<S: Into<String>>(message: S) -> Self {
        Self::Operation {
            message: message.into(),
        }
    }

    /// Create an invalid state error with context
    pub fn invalid_state<S: Into<String>>(message: S) -> Self {
        Self::Validation {
            message: message.into(),
        }
    }

    /// Create a cancelled error
    pub fn cancelled() -> Self {
        Self::Cancelled
    }

    /// Get recovery suggestions for this error
    pub fn recovery_suggestions(&self) -> Vec<&'static str> {
        match self {
            Self::Authentication { .. } => vec![
                "Check your username and password",
                "Ensure you have network connectivity",
                "Try registering if you haven't created an account",
                "Contact your group administrator if the problem persists",
            ],
            Self::Session { .. } => vec![
                "Try logging out and logging back in",
                "Check if your session has expired",
                "Ensure proper file permissions on config directory",
                "Clear session data with 'hybridcipher logout'",
            ],
            Self::Migration { .. } => vec![
                "Stream the live dashboard with 'hybridcipher rekey status --watch'",
                "Ensure all devices remain online to report heartbeats",
                "Contact the group administrator if migration is stuck after the grace window",
                "Review policy metrics to confirm quorum and coverage thresholds",
            ],
            Self::Coverage { .. } => vec![
                "Run 'hybridcipher coverage audit' to check system state",
                "Verify network connectivity to the server",
                "Check if a migration is in progress",
                "Contact administrator if coverage logs are corrupted",
            ],
            Self::FileOperation { .. } => vec![
                "Check file permissions and disk space",
                "Ensure the file path exists and is accessible",
                "Verify you have the correct epoch key",
                "Check if a migration is affecting file access",
            ],
            Self::MemberManagement { .. } => vec![
                "Verify you have administrator privileges",
                "Check that the user ID is correct",
                "Ensure the target user exists in the system",
                "Complete any pending migrations before member changes",
            ],
            Self::Configuration { .. } => vec![
                "Check the configuration file syntax",
                "Ensure proper file permissions",
                "Reset to default configuration if corrupted",
                "Check the configuration file path",
            ],
            Self::Network { .. } => vec![
                "Check your internet connection",
                "Verify the server URL is correct",
                "Check firewall and proxy settings",
                "Try again in a few moments",
            ],
            Self::Cryptographic { .. } => vec![
                "This indicates a serious security issue",
                "Do not proceed with the operation",
                "Contact your security administrator immediately",
                "Preserve logs for forensic analysis",
            ],
            Self::Permission { .. } => vec![
                "Check file and directory permissions",
                "Ensure you have the necessary privileges",
                "Run with appropriate user permissions",
                "Contact your system administrator",
            ],
            Self::InvalidInput { .. } => vec![
                "Check the command syntax and arguments",
                "Use 'hybridcipher help' for usage information",
                "Ensure all required parameters are provided",
                "Check file paths and user IDs for validity",
            ],
            Self::NotFound { .. } => vec![
                "Verify the resource exists",
                "Check the path or identifier",
                "Ensure you have access permissions",
                "Refresh your session if needed",
            ],
            Self::Cancelled => vec![
                "Operation was cancelled by user request",
                "No action is needed",
            ],
            Self::Internal { .. } => vec![
                "This is an unexpected error",
                "Please report this as a bug",
                "Include the full error message and steps to reproduce",
                "Try restarting the application",
            ],
            Self::Validation { .. } => vec![
                "Check system prerequisites and configuration",
                "Ensure all required services are running",
                "Verify system state is consistent",
                "Address any validation failures before proceeding",
            ],
            Self::PinningFailed(_) => vec![
                "Verify the fingerprint or safety number is correct",
                "Check that the device identity keys match",
                "Try rescanning the QR code if using QR verification",
                "Contact the other user to verify key information",
            ],
            Self::NotAuthenticated(_) => vec![
                "Log in with 'hybridcipher login <username>'",
                "Check your authentication status",
                "Verify your session hasn't expired",
                "Register if you don't have an account",
            ],
            Self::Io(_) => vec![
                "Check file and directory permissions",
                "Ensure sufficient disk space",
                "Verify the file path is correct",
                "Check system resource availability",
            ],
            Self::Storage { .. } => vec![
                "Check file and directory permissions",
                "Ensure sufficient disk space",
                "Verify the storage path is accessible",
                "Check for filesystem errors",
            ],
            Self::Encryption { .. } => vec![
                "Verify the encryption keys are valid",
                "Check that the data format is correct",
                "Ensure proper key derivation",
                "Contact support if encryption consistently fails",
            ],
            Self::Decryption { .. } => vec![
                "Verify you have the correct decryption keys",
                "Check that the encrypted data hasn't been corrupted",
                "Ensure you're using the right epoch key",
                "Verify the file format is correct",
            ],
            Self::Format { .. } => vec![
                "Check the input data format",
                "Verify the file structure is correct",
                "Ensure proper encoding is used",
                "Check for data corruption",
            ],
            Self::Operation { .. } => vec![
                "Check the operation prerequisites",
                "Verify system state is correct",
                "Ensure proper permissions",
                "Try the operation again",
            ],
            Self::Mount { .. } => vec![
                "Check mount point permissions",
                "Verify filesystem support",
                "Ensure mount point is available",
                "Check system mount capabilities",
            ],
        }
    }
}

pub fn map_missing_welcome_error(message: String) -> String {
    let lower = message.to_lowercase();
    let missing_welcome = lower.contains("welcome message")
        || lower.contains("pending-welcome")
        || lower.contains("pending welcome")
        || lower.contains("pending approval")
        || lower.contains("epoch key")
        || lower.contains("epoch keys")
        || lower.contains("active epoch is unavailable")
        || lower.contains("no active epoch")
        || lower.contains("needs epoch keys");
    let has_guidance = lower.contains("issue-welcome")
        || lower.contains("process-welcome-messages")
        || lower.contains("recovery fetch")
        || lower.contains("hybridcipher issue-welcome")
        || lower.contains("hybridcipher process-welcome-messages");
    let is_signing_key_error = lower.contains("welcome signing key");

    if missing_welcome && !has_guidance && !is_signing_key_error {
        format!(
            "{message}\n\nThis device does not have the required Welcome message or epoch keys yet.\n\
To fix:\n\
1) Ask a group admin (or a trusted device) to run: hybridcipher issue-welcome --device <DEVICE_ID>\n\
2) On this device, run: hybridcipher process-welcome-messages\n\
3) If you have a recovery backup, run: hybridcipher recovery fetch\n\
Find this device ID with: hybridcipher current-user"
        )
    } else {
        message
    }
}

impl From<ServerIdentityError> for CliError {
    fn from(err: ServerIdentityError) -> Self {
        match err {
            ServerIdentityError::KeyMismatch {
                server_url,
                expected,
                received,
            } => CliError::PinningFailed(format!(
                "Server public key mismatch for {server_url}. Expected {expected}, received {received}"
            )),
            ServerIdentityError::SigningKeyMismatch {
                server_url,
                expected,
                received,
            } => CliError::PinningFailed(format!(
                "Welcome signing key mismatch for {server_url}. Expected {expected}, received {received}. Install the latest HybridCipher client or verify the rotation bulletin before proceeding."
            )),
            ServerIdentityError::InvalidKey(server) => CliError::PinningFailed(format!(
                "Received empty server public key for {server}"
            )),
            ServerIdentityError::UnknownServer(server) => CliError::PinningFailed(format!(
                "No pinned server identity for {server}. Run 'hybridcipher login' to establish trust first."
            )),
            ServerIdentityError::InvalidEncoding(err) => {
                CliError::PinningFailed(format!("Invalid server identity encoding: {err}"))
            }
            ServerIdentityError::Io(e) => CliError::Storage {
                message: format!("Failed to persist server identities: {e}"),
            },
            ServerIdentityError::Serialization(e) => CliError::Storage {
                message: format!("Failed to parse server identities: {e}"),
            },
        }
    }
}

// Convert ClientError to CliError
impl From<hybridcipher_client::ClientError> for CliError {
    fn from(err: hybridcipher_client::ClientError) -> Self {
        match err {
            hybridcipher_client::ClientError::NetworkError { context, .. } => {
                if context.code == ErrorCode::NetworkAuthentication {
                    CliError::Authentication {
                        message: format!(
                            "{} Please login again with 'hybridcipher login <username>'.",
                            context.message
                        ),
                    }
                } else {
                    CliError::Network {
                        message: context.message,
                    }
                }
            }
            hybridcipher_client::ClientError::Unauthorized(msg) => {
                CliError::Permission { message: msg }
            }
            hybridcipher_client::ClientError::InvalidInput(msg) => {
                CliError::InvalidInput { message: msg }
            }
            hybridcipher_client::ClientError::InvalidState(msg) => CliError::Internal {
                message: map_missing_welcome_error(msg),
            },
            hybridcipher_client::ClientError::SecurityViolation(msg) => {
                CliError::Cryptographic { message: msg }
            }
            hybridcipher_client::ClientError::PinningRequired(msg) => CliError::PinningFailed(msg),
            _ => CliError::Internal {
                message: format!("Client error: {}", err),
            },
        }
    }
}
