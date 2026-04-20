use std::{sync::Arc, time::Duration};

use crate::{
    coverage::current_transparency_config, network::Network, transparency::TransparencyClient,
};
use async_trait::async_trait;
use hybridcipher_coverage::{
    CoverageManagerError, CoveragePublication, CoveragePublisher, CoverageTransparencyRecord,
    CoverageTransparencyVerifier,
};
use hybridcipher_messages::transparency::{
    TransparencyConfig, TransparencyEntry, TransparencyOperation,
};
use tokio::{runtime::Handle, time::sleep};

/// Publishes coverage snapshots to the transparency log.
pub struct TransparencyCoveragePublisher<N: Network> {
    client: Arc<TransparencyClient<N>>,
}

impl<N: Network> TransparencyCoveragePublisher<N> {
    /// Create a new publisher backed by a transparency client.
    pub fn new(client: Arc<TransparencyClient<N>>) -> Self {
        Self { client }
    }
}

impl<N: Network> std::fmt::Debug for TransparencyCoveragePublisher<N> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TransparencyCoveragePublisher")
            .finish_non_exhaustive()
    }
}

/// Retrieves transparency inclusion proofs for coverage snapshots.
pub struct TransparencyCoverageVerifier<N: Network> {
    client: Arc<TransparencyClient<N>>,
}

impl<N: Network> TransparencyCoverageVerifier<N> {
    /// Create a new verifier backed by a transparency client.
    pub fn new(client: Arc<TransparencyClient<N>>) -> Self {
        Self { client }
    }
}

#[async_trait]
impl<N: Network> CoverageTransparencyVerifier for TransparencyCoverageVerifier<N> {
    async fn fetch_inclusion_proof(
        &self,
        merkle_root: &[u8; 32],
    ) -> Result<CoverageTransparencyRecord, CoverageManagerError> {
        let root = *merkle_root;
        let proof = self
            .client
            .get_inclusion_proof(&root)
            .await
            .map_err(|err| CoverageManagerError::Generic(err.to_string()))?;

        Ok(CoverageTransparencyRecord { proof })
    }
}

impl<N: Network> std::fmt::Debug for TransparencyCoverageVerifier<N> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TransparencyCoverageVerifier")
            .finish_non_exhaustive()
    }
}

impl<N: Network> CoveragePublisher for TransparencyCoveragePublisher<N> {
    fn publish(&self, publication: CoveragePublication) -> Result<(), CoverageManagerError> {
        let handle = Handle::try_current().map_err(|e| {
            CoverageManagerError::Generic(format!("No Tokio runtime available: {e}"))
        })?;

        let client = Arc::clone(&self.client);
        let snapshot = Arc::new(publication.snapshot);
        let epoch_id = publication.epoch_id;
        let file_count = publication.total_files;

        handle.spawn(async move {
            let operation = TransparencyOperation::CoverageSnapshot {
                merkle_root: snapshot.merkle_root,
                epoch_id,
                file_count,
                signing_key_id: snapshot.signing_key_id.clone(),
                verifying_key: snapshot.verifying_key,
            };

            let entry = Arc::new(TransparencyEntry::new(
                0,
                snapshot.merkle_root,
                operation,
                snapshot.signature.clone(),
            ));

            const MAX_ATTEMPTS: usize = 5;
            let mut attempt = 0usize;
            let mut delay = Duration::from_secs(1);

            loop {
                match client.submit_entry(entry.as_ref()).await {
                    Ok(sequence) => {
                        log::info!(
                            "Published coverage snapshot for epoch {} ({} files) to transparency log, sequence {}",
                            epoch_id,
                            file_count,
                            sequence
                        );
                        break;
                    }
                    Err(err) => {
                        attempt += 1;
                        if attempt >= MAX_ATTEMPTS {
                            log::error!(
                                "Failed to publish coverage snapshot for epoch {} after {} attempts: {}",
                                epoch_id,
                                attempt,
                                err
                            );
                            break;
                        }

                        log::warn!(
                            "Coverage transparency publish attempt {} failed for epoch {}: {}. Retrying in {:?}",
                            attempt,
                            epoch_id,
                            err,
                            delay
                        );
                        sleep(delay).await;
                        delay = (delay * 2).min(Duration::from_secs(60));
                    }
                }
            }
        });

        Ok(())
    }
}

/// Combined transparency publisher and verifier handles.
#[derive(Debug)]
pub struct TransparencyCoverageHandles {
    pub publisher: Arc<dyn CoveragePublisher>,
    pub verifier: Arc<dyn CoverageTransparencyVerifier>,
}

/// Attempt to construct transparency publisher/verifier handles using configured settings.
pub fn try_build_transparency_handles<N: Network>(
    network: Arc<N>,
) -> Option<TransparencyCoverageHandles> {
    let config = current_transparency_config()?;
    if !config.enabled {
        return None;
    }

    build_handles_from_config(network, config)
}

/// Attempt to construct a transparency-backed coverage publisher using configured settings.
pub fn try_build_transparency_publisher<N: Network>(
    network: Arc<N>,
) -> Option<Arc<dyn CoveragePublisher>> {
    try_build_transparency_handles(network).map(|handles| handles.publisher)
}

fn build_handles_from_config<N: Network>(
    network: Arc<N>,
    config: TransparencyConfig,
) -> Option<TransparencyCoverageHandles> {
    let log_url = match config.log_server_url.as_ref() {
        Some(url) if !url.is_empty() => url.trim().to_string(),
        _ => {
            log::warn!(
                "Transparency coverage integration enabled but no log_url configured; disabling transparency handles"
            );
            return None;
        }
    };

    if config.trusted_signing_keys.is_empty() {
        log::warn!(
            "Transparency coverage integration enabled but trusted signing keys are empty; disabling transparency handles"
        );
        return None;
    }

    let key_ids: Vec<String> = config
        .trusted_signing_keys
        .iter()
        .map(|k| k.key_id.clone())
        .collect();

    let network_clone = (*network).clone();
    let normalized = normalize_config(config.clone(), log_url.clone());
    let client = Arc::new(TransparencyClient::new(
        network_clone,
        log_url.clone(),
        normalized,
    ));

    log::info!(
        "Transparency coverage integration enabled; log_url={}, signing_keys={:?}",
        log_url,
        key_ids
    );

    let publisher: Arc<dyn CoveragePublisher> =
        Arc::new(TransparencyCoveragePublisher::new(client.clone()));
    let verifier: Arc<dyn CoverageTransparencyVerifier> =
        Arc::new(TransparencyCoverageVerifier::new(client));

    Some(TransparencyCoverageHandles {
        publisher,
        verifier,
    })
}

fn normalize_config(mut config: TransparencyConfig, log_url: String) -> TransparencyConfig {
    config.log_server_url = Some(log_url);
    config
}
