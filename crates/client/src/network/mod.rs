use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use thiserror::Error;

pub mod mock;

pub use mock::MockNetwork;

/// Network communication abstraction with Byzantine fault tolerance
///
/// The Network trait provides secure, authenticated communication for
/// distributed group coordination with comprehensive fault tolerance.
///
/// ## Security Properties
/// - All messages are encrypted using HybridKEM + ChaCha20-Poly1305
/// - Message authenticity verified using Ed25519 signatures
/// - Replay protection using sequence numbers and timestamps
/// - Rate limiting prevents DoS attacks on message processing
///
/// ## Fault Tolerance
/// - Network partitions handled gracefully with timeout/retry
/// - Message loss detection and automatic retransmission
/// - Byzantine behavior detection and mitigation
/// - Consensus mechanisms for critical operations
#[async_trait]
pub trait Network: Send + Sync + Clone + 'static {
    /// Send message to specific group member
    ///
    /// # Arguments
    /// * `recipient` - Target member's public key
    /// * `message` - Message to send
    ///
    /// # Security
    /// Message is encrypted using HybridKEM with recipient's public key
    /// and signed with sender's device identity key.
    ///
    /// # Reliability
    /// Returns Ok only after message delivery confirmation.
    /// Automatically retries on transient network failures.
    async fn send_message(
        &self,
        recipient: &[u8; 32],
        message: &NetworkMessage,
    ) -> Result<(), NetworkError>;

    /// Broadcast message to all group members
    ///
    /// # Arguments
    /// * `members` - List of group member public keys
    /// * `message` - Message to broadcast
    ///
    /// # Reliability
    /// Uses reliable broadcast protocol to ensure all members
    /// receive the message despite network failures.
    ///
    /// # Performance
    /// Optimizes delivery using gossip protocol for large groups.
    async fn broadcast_message(
        &self,
        members: &[[u8; 32]],
        message: &NetworkMessage,
    ) -> Result<BroadcastResult, NetworkError>;

    /// Receive next message from the network
    ///
    /// # Returns
    /// Next authenticated message or None if no messages available
    ///
    /// # Validation
    /// All received messages are:
    /// - Decrypted and authenticated
    /// - Validated for proper formatting
    /// - Checked for replay attacks
    /// - Rate limited to prevent DoS
    async fn receive_message(&self) -> Result<Option<ReceivedMessage>, NetworkError>;

    /// Distribute JoinCard invitation to potential new member
    ///
    /// # Arguments
    /// * `join_card` - Signed invitation with expiration
    /// * `contact_info` - How to reach the invitee
    ///
    /// # Security
    /// JoinCard contains invitation-specific keys and expiration.
    /// Distribution method depends on out-of-band communication.
    async fn distribute_join_card(
        &self,
        join_card: &hybridcipher_messages::join_card::JoinCard,
        contact_info: &ContactInfo,
    ) -> Result<(), NetworkError>;

    /// Broadcast coverage update to group
    ///
    /// # Arguments
    /// * `coverage_update` - Coverage log update with Merkle proof
    /// * `members` - Group members to notify
    ///
    /// # Consistency
    /// Coverage updates are ordered and applied atomically.
    /// Conflicts are resolved using deterministic ordering.
    async fn broadcast_coverage_update(
        &self,
        coverage_update: &hybridcipher_messages::file_metadata::CoverageUpdate,
        members: &[[u8; 32]],
    ) -> Result<BroadcastResult, NetworkError>;

    /// Coordinate cutover operation with group consensus
    ///
    /// # Arguments
    /// * `cutover_msg` - Cutover coordination message
    /// * `members` - Group members participating in cutover
    ///
    /// # Consensus
    /// Implements Byzantine-fault-tolerant consensus for cutover.
    /// Requires supermajority agreement to proceed.
    ///
    /// # Timeout
    /// Cutover coordination has strict timeout to prevent deadlock.
    async fn coordinate_cutover(
        &self,
        cutover_msg: &hybridcipher_messages::cutover::Cutover,
        members: &[[u8; 32]],
    ) -> Result<CutoverResult, NetworkError>;

    /// Get current network connectivity status
    ///
    /// # Returns
    /// Network status including connectivity and peer information
    async fn get_network_status(&self) -> Result<NetworkStatus, NetworkError>;

    /// Configure network parameters and policies
    ///
    /// # Arguments
    /// * `config` - Network configuration parameters
    ///
    /// # Parameters
    /// - Message timeouts and retry policies
    /// - Rate limiting thresholds
    /// - Consensus algorithm parameters
    /// - Security policy settings
    async fn configure(&self, config: &NetworkConfig) -> Result<(), NetworkError>;

    /// Start network listener on specified address
    ///
    /// # Arguments
    /// * `bind_address` - Local address to bind to
    ///
    /// # Security
    /// Listener accepts only authenticated connections.
    /// Uses TLS 1.3 for transport security.
    async fn start_listener(&self, bind_address: &str) -> Result<(), NetworkError>;

    /// Connect to peer at specified address
    ///
    /// # Arguments
    /// * `peer_address` - Remote peer address
    /// * `peer_public_key` - Expected peer public key for authentication
    ///
    /// # Security
    /// Connection is authenticated using public key verification.
    /// Prevents man-in-the-middle attacks.
    async fn connect_peer(
        &self,
        peer_address: &str,
        peer_public_key: &[u8; 32],
    ) -> Result<(), NetworkError>;

    /// Disconnect from specific peer
    ///
    /// # Arguments
    /// * `peer_public_key` - Peer to disconnect from
    async fn disconnect_peer(&self, peer_public_key: &[u8; 32]) -> Result<(), NetworkError>;

    /// Get list of currently connected peers
    ///
    /// # Returns
    /// List of connected peer information
    async fn list_peers(&self) -> Result<Vec<PeerInfo>, NetworkError>;
}

/// Network message container with encryption and authentication
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkMessage {
    /// Message type identifier
    pub message_type: MessageType,

    /// Encrypted message payload
    pub encrypted_payload: Vec<u8>,

    /// Sender's public key
    pub sender_public_key: [u8; 32],

    /// Message signature for authentication (serialized as Vec<u8>)
    #[serde(with = "signature_serde")]
    pub signature: [u8; 64],

    /// Message timestamp for replay protection
    pub timestamp: DateTime<Utc>,

    /// Sequence number for ordering
    pub sequence_number: u64,

    /// Message priority for delivery ordering
    pub priority: MessagePriority,
}

// Custom serialization for 64-byte signatures
mod signature_serde {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S>(signature: &[u8; 64], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        signature.to_vec().serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 64], D::Error>
    where
        D: Deserializer<'de>,
    {
        let vec: Vec<u8> = Vec::deserialize(deserializer)?;
        if vec.len() != 64 {
            return Err(serde::de::Error::custom(format!(
                "Expected 64 bytes, got {}",
                vec.len()
            )));
        }
        let mut array = [0u8; 64];
        array.copy_from_slice(&vec);
        Ok(array)
    }
}

/// Types of network messages
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum MessageType {
    /// Join card invitation
    JoinCard,

    /// Welcome message with epoch secrets
    Welcome,

    /// Group membership update
    GroupUpdate,

    /// File metadata update
    FileMetadata,

    /// Coverage log update
    CoverageUpdate,

    /// Cutover coordination message
    Cutover,

    /// Transparency log request
    TransparencyRequest,

    /// Heartbeat for connectivity checking
    Heartbeat,

    /// Acknowledgment message
    Acknowledgment,
}

/// Message delivery priority
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum MessagePriority {
    /// Low priority - background synchronization
    Low,

    /// Normal priority - regular operations
    Normal,

    /// High priority - time-sensitive operations
    High,

    /// Critical priority - emergency operations
    Critical,
}

/// Received message with metadata
#[derive(Debug, Clone)]
pub struct ReceivedMessage {
    /// Decrypted message content
    pub message: NetworkMessage,

    /// Sender information
    pub sender: PeerInfo,

    /// Reception timestamp
    pub received_at: DateTime<Utc>,

    /// Message validation result
    pub validation: MessageValidation,
}

/// Message validation result
#[derive(Debug, Clone, PartialEq)]
pub enum MessageValidation {
    /// Message is valid and authenticated
    Valid,

    /// Message signature is invalid
    InvalidSignature,

    /// Message is a replay attack
    ReplayAttack,

    /// Message timestamp is too old or future
    InvalidTimestamp,

    /// Message format is malformed
    Malformed,

    /// Sender is not authorized
    Unauthorized,
}

/// Contact information for invitation distribution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContactInfo {
    /// Contact method (email, SMS, etc.)
    pub method: ContactMethod,

    /// Contact address (email address, phone number, etc.)
    pub address: String,

    /// Optional message to include with invitation
    pub message: Option<String>,
}

/// Contact delivery methods
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ContactMethod {
    /// Email delivery
    Email,

    /// SMS delivery
    Sms,

    /// Direct network delivery
    Network,

    /// QR code for manual transfer
    QrCode,

    /// File-based transfer
    File,
}

/// Broadcast operation result
#[derive(Debug, Clone)]
pub struct BroadcastResult {
    /// Number of members successfully reached
    pub successful_deliveries: usize,

    /// Number of delivery failures
    pub failed_deliveries: usize,

    /// Members that couldn't be reached
    pub unreachable_members: Vec<[u8; 32]>,

    /// Total broadcast duration
    pub duration_ms: u64,
}

/// Cutover coordination result
#[derive(Debug, Clone)]
pub struct CutoverResult {
    /// Whether cutover achieved consensus
    pub consensus_reached: bool,

    /// Members that voted for cutover
    pub votes_for: Vec<[u8; 32]>,

    /// Members that voted against cutover
    pub votes_against: Vec<[u8; 32]>,

    /// Members that didn't respond
    pub no_response: Vec<[u8; 32]>,

    /// Consensus timestamp
    pub consensus_time: Option<DateTime<Utc>>,
}

/// Network connectivity status
#[derive(Debug, Clone)]
pub struct NetworkStatus {
    /// Whether network is connected
    pub is_connected: bool,

    /// Number of active peer connections
    pub connected_peers: usize,

    /// Network latency to peers (milliseconds)
    pub peer_latencies: HashMap<[u8; 32], u64>,

    /// Recent message throughput (messages per second)
    pub message_throughput: f64,

    /// Network error rate (0.0 to 1.0)
    pub error_rate: f64,

    /// Last successful communication timestamp
    pub last_activity: DateTime<Utc>,
}

/// Network configuration parameters
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConfig {
    /// Message timeout in milliseconds
    pub message_timeout_ms: u64,

    /// Maximum retry attempts for failed messages
    pub max_retries: u32,

    /// Rate limit: messages per second
    pub rate_limit_per_second: u32,

    /// Maximum concurrent connections
    pub max_connections: u32,

    /// Consensus timeout in milliseconds
    pub consensus_timeout_ms: u64,

    /// Heartbeat interval in milliseconds
    pub heartbeat_interval_ms: u64,

    /// Maximum message size in bytes
    pub max_message_size: u64,

    /// Connection keepalive timeout
    pub keepalive_timeout_ms: u64,
}

/// Peer connection information
#[derive(Debug, Clone)]
pub struct PeerInfo {
    /// Peer's public key identifier
    pub public_key: [u8; 32],

    /// Peer's network address
    pub address: String,

    /// Connection status
    pub status: PeerStatus,

    /// Connection establishment time
    pub connected_at: DateTime<Utc>,

    /// Last activity timestamp
    pub last_activity: DateTime<Utc>,

    /// Round-trip latency in milliseconds
    pub latency_ms: u64,

    /// Protocol version supported by peer
    pub protocol_version: String,
}

/// Peer connection status
#[derive(Debug, Clone, PartialEq)]
pub enum PeerStatus {
    /// Connected and active
    Connected,

    /// Connection being established
    Connecting,

    /// Temporarily disconnected
    Disconnected,

    /// Connection failed
    Failed,

    /// Peer is unreachable
    Unreachable,
}

/// Network operation errors
#[derive(Debug, Error)]
pub enum NetworkError {
    #[error("Connection error: {0}")]
    Connection(String),

    #[error("Authentication failed: {0}")]
    Authentication(String),

    #[error("Message encryption/decryption error: {0}")]
    Encryption(String),

    #[error("Message timeout: {0}")]
    Timeout(String),

    #[error("Network unreachable: {0}")]
    Unreachable(String),

    #[error("Rate limit exceeded")]
    RateLimit,

    #[error("Message too large: {0} bytes")]
    MessageTooLarge(u64),

    #[error("Invalid message format: {0}")]
    InvalidMessage(String),

    #[error("Consensus failed: {0}")]
    ConsensusFailure(String),

    #[error("Protocol error: {0}")]
    Protocol(String),

    #[error("Configuration error: {0}")]
    Configuration(String),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            message_timeout_ms: 30_000, // 30 seconds
            max_retries: 3,
            rate_limit_per_second: 100,
            max_connections: 1000,
            consensus_timeout_ms: 60_000,  // 60 seconds
            heartbeat_interval_ms: 10_000, // 10 seconds
            max_message_size: 1_048_576,   // 1 MB
            keepalive_timeout_ms: 300_000, // 5 minutes
        }
    }
}

impl Default for MessagePriority {
    fn default() -> Self {
        MessagePriority::Normal
    }
}
