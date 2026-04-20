use crate::network::{
    BroadcastResult, ContactInfo, CutoverResult, MessagePriority, Network, NetworkConfig,
    NetworkError, NetworkMessage, NetworkStatus, PeerInfo, PeerStatus, ReceivedMessage,
};
use async_trait::async_trait;
use chrono::Utc;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Mock network implementation for testing
///
/// Provides in-memory message simulation with all network trait functionality
/// for comprehensive testing without external network dependencies.
#[derive(Debug, Clone)]
pub struct MockNetwork {
    /// Simulated network state
    state: Arc<RwLock<MockNetworkState>>,
}

#[derive(Debug, Default)]
struct MockNetworkState {
    /// Messages waiting to be received
    message_queue: Vec<ReceivedMessage>,

    /// Connected peers
    peers: HashMap<[u8; 32], PeerInfo>,

    /// Network configuration
    config: NetworkConfig,

    /// Simulated network status
    is_connected: bool,

    /// Message delivery simulation
    delivery_success_rate: f64,

    /// Simulated latency in milliseconds
    simulated_latency_ms: u64,

    /// Total messages sent (for testing)
    messages_sent: u64,

    /// Total messages received (for testing)
    messages_received: u64,
}

impl MockNetwork {
    /// Create new mock network instance
    pub fn new() -> Self {
        Self {
            state: Arc::new(RwLock::new(MockNetworkState {
                message_queue: Vec::new(),
                peers: HashMap::new(),
                config: NetworkConfig::default(),
                is_connected: true,
                delivery_success_rate: 1.0, // 100% success by default
                simulated_latency_ms: 50,
                messages_sent: 0,
                messages_received: 0,
            })),
        }
    }

    /// Set simulated delivery success rate (0.0 to 1.0)
    pub async fn set_delivery_success_rate(&self, rate: f64) {
        let mut state = self.state.write().await;
        state.delivery_success_rate = rate.clamp(0.0, 1.0);
    }

    /// Set simulated network latency
    pub async fn set_latency(&self, latency_ms: u64) {
        let mut state = self.state.write().await;
        state.simulated_latency_ms = latency_ms;
    }

    /// Simulate network disconnection
    pub async fn disconnect(&self) {
        let mut state = self.state.write().await;
        state.is_connected = false;
    }

    /// Simulate network reconnection
    pub async fn reconnect(&self) {
        let mut state = self.state.write().await;
        state.is_connected = true;
    }

    /// Inject message into receive queue for testing
    pub async fn inject_message(&self, message: ReceivedMessage) {
        let mut state = self.state.write().await;
        state.message_queue.push(message);
        state.messages_received += 1;
    }

    /// Get number of messages sent (for testing)
    pub async fn messages_sent(&self) -> u64 {
        let state = self.state.read().await;
        state.messages_sent
    }

    /// Get number of messages received (for testing)
    pub async fn messages_received(&self) -> u64 {
        let state = self.state.read().await;
        state.messages_received
    }

    /// Clear all queued messages
    pub async fn clear_messages(&self) {
        let mut state = self.state.write().await;
        state.message_queue.clear();
    }

    /// Add mock peer for testing
    pub async fn add_peer(&self, public_key: [u8; 32], address: String) {
        let mut state = self.state.write().await;
        let peer = PeerInfo {
            public_key,
            address,
            status: PeerStatus::Connected,
            connected_at: Utc::now(),
            last_activity: Utc::now(),
            latency_ms: state.simulated_latency_ms,
            protocol_version: "1.0.0".to_string(),
        };
        state.peers.insert(public_key, peer);
    }
}

#[async_trait]
impl Network for MockNetwork {
    async fn send_message(
        &self,
        recipient: &[u8; 32],
        _message: &NetworkMessage,
    ) -> Result<(), NetworkError> {
        let mut state = self.state.write().await;

        // Check if network is connected
        if !state.is_connected {
            return Err(NetworkError::Unreachable(
                "Network disconnected".to_string(),
            ));
        }

        // Check if recipient peer exists
        if !state.peers.contains_key(recipient) {
            return Err(NetworkError::Unreachable("Recipient not found".to_string()));
        }

        // Simulate delivery failure based on success rate
        let success = rand::random::<f64>() < state.delivery_success_rate;
        if !success {
            return Err(NetworkError::Timeout("Message delivery failed".to_string()));
        }

        // Simulate latency
        if state.simulated_latency_ms > 0 {
            tokio::time::sleep(tokio::time::Duration::from_millis(
                state.simulated_latency_ms,
            ))
            .await;
        }

        state.messages_sent += 1;
        Ok(())
    }

    async fn broadcast_message(
        &self,
        members: &[[u8; 32]],
        _message: &NetworkMessage,
    ) -> Result<BroadcastResult, NetworkError> {
        let mut state = self.state.write().await;

        if !state.is_connected {
            return Err(NetworkError::Unreachable(
                "Network disconnected".to_string(),
            ));
        }

        let mut successful_deliveries = 0;
        let mut failed_deliveries = 0;
        let mut unreachable_members = Vec::new();

        let start_time = std::time::Instant::now();

        for member in members {
            if state.peers.contains_key(member) {
                let success = rand::random::<f64>() < state.delivery_success_rate;
                if success {
                    successful_deliveries += 1;
                } else {
                    failed_deliveries += 1;
                    unreachable_members.push(*member);
                }
            } else {
                failed_deliveries += 1;
                unreachable_members.push(*member);
            }
        }

        // Simulate broadcast latency
        if state.simulated_latency_ms > 0 {
            tokio::time::sleep(tokio::time::Duration::from_millis(
                state.simulated_latency_ms,
            ))
            .await;
        }

        state.messages_sent += successful_deliveries as u64;

        Ok(BroadcastResult {
            successful_deliveries,
            failed_deliveries,
            unreachable_members,
            duration_ms: start_time.elapsed().as_millis() as u64,
        })
    }

    async fn receive_message(&self) -> Result<Option<ReceivedMessage>, NetworkError> {
        let mut state = self.state.write().await;

        if !state.is_connected {
            return Err(NetworkError::Unreachable(
                "Network disconnected".to_string(),
            ));
        }

        Ok(state.message_queue.pop())
    }

    async fn distribute_join_card(
        &self,
        _join_card: &hybridcipher_messages::join_card::JoinCard,
        _contact_info: &ContactInfo,
    ) -> Result<(), NetworkError> {
        let mut state = self.state.write().await;

        if !state.is_connected {
            return Err(NetworkError::Unreachable(
                "Network disconnected".to_string(),
            ));
        }

        // Simulate join card distribution
        state.messages_sent += 1;
        Ok(())
    }

    async fn broadcast_coverage_update(
        &self,
        _coverage_update: &hybridcipher_messages::file_metadata::CoverageUpdate,
        members: &[[u8; 32]],
    ) -> Result<BroadcastResult, NetworkError> {
        // Use the same logic as broadcast_message
        let dummy_message = NetworkMessage {
            message_type: crate::network::MessageType::CoverageUpdate,
            encrypted_payload: Vec::new(),
            sender_public_key: [0u8; 32],
            signature: [0u8; 64],
            timestamp: Utc::now(),
            sequence_number: 0,
            priority: MessagePriority::Normal,
        };

        self.broadcast_message(members, &dummy_message).await
    }

    async fn coordinate_cutover(
        &self,
        _cutover_msg: &hybridcipher_messages::cutover::Cutover,
        members: &[[u8; 32]],
    ) -> Result<CutoverResult, NetworkError> {
        let state = self.state.read().await;

        if !state.is_connected {
            return Err(NetworkError::Unreachable(
                "Network disconnected".to_string(),
            ));
        }

        // Simulate consensus voting
        let mut votes_for = Vec::new();
        let mut votes_against = Vec::new();
        let mut no_response = Vec::new();

        for member in members {
            if state.peers.contains_key(member) {
                let responds = rand::random::<f64>() < state.delivery_success_rate;
                if responds {
                    // Simulate vote (80% vote for, 20% against)
                    if rand::random::<f64>() < 0.8 {
                        votes_for.push(*member);
                    } else {
                        votes_against.push(*member);
                    }
                } else {
                    no_response.push(*member);
                }
            } else {
                no_response.push(*member);
            }
        }

        // Consensus requires supermajority (2/3)
        let total_responses = votes_for.len() + votes_against.len();
        let consensus_reached = total_responses > 0 && votes_for.len() * 3 >= total_responses * 2;

        Ok(CutoverResult {
            consensus_reached,
            votes_for,
            votes_against,
            no_response,
            consensus_time: if consensus_reached {
                Some(Utc::now())
            } else {
                None
            },
        })
    }

    async fn get_network_status(&self) -> Result<NetworkStatus, NetworkError> {
        let state = self.state.read().await;

        let peer_latencies: HashMap<[u8; 32], u64> = state
            .peers
            .iter()
            .map(|(key, peer)| (*key, peer.latency_ms))
            .collect();

        Ok(NetworkStatus {
            is_connected: state.is_connected,
            connected_peers: state.peers.len(),
            peer_latencies,
            message_throughput: 100.0, // Mock throughput
            error_rate: 1.0 - state.delivery_success_rate,
            last_activity: Utc::now(),
        })
    }

    async fn configure(&self, config: &NetworkConfig) -> Result<(), NetworkError> {
        let mut state = self.state.write().await;
        state.config = config.clone();
        Ok(())
    }

    async fn start_listener(&self, _bind_address: &str) -> Result<(), NetworkError> {
        let mut state = self.state.write().await;
        state.is_connected = true;
        Ok(())
    }

    async fn connect_peer(
        &self,
        peer_address: &str,
        peer_public_key: &[u8; 32],
    ) -> Result<(), NetworkError> {
        let mut state = self.state.write().await;

        let peer = PeerInfo {
            public_key: *peer_public_key,
            address: peer_address.to_string(),
            status: PeerStatus::Connected,
            connected_at: Utc::now(),
            last_activity: Utc::now(),
            latency_ms: state.simulated_latency_ms,
            protocol_version: "1.0.0".to_string(),
        };

        state.peers.insert(*peer_public_key, peer);
        Ok(())
    }

    async fn disconnect_peer(&self, peer_public_key: &[u8; 32]) -> Result<(), NetworkError> {
        let mut state = self.state.write().await;

        if let Some(peer) = state.peers.get_mut(peer_public_key) {
            peer.status = PeerStatus::Disconnected;
        }

        Ok(())
    }

    async fn list_peers(&self) -> Result<Vec<PeerInfo>, NetworkError> {
        let state = self.state.read().await;
        Ok(state.peers.values().cloned().collect())
    }
}

impl Default for MockNetwork {
    fn default() -> Self {
        Self::new()
    }
}
