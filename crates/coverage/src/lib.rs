use std::collections::HashMap;
use std::sync::Arc;
use std::time::SystemTime;

use async_trait::async_trait;
use hybridcipher_crypto::signatures::{
    self, Signature, SigningKey, VerifyingKey, VERIFYING_KEY_LEN,
};
use hybridcipher_merkle::{InclusionProof as MerkleInclusionProof, MerkleTree};
use hybridcipher_messages::transparency::{
    InclusionProof as TransparencyInclusionProof, TransparencyOperation,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::sync::Mutex;

/// Result type for coverage operations
pub type CoverageResult = f64;

/// Errors for coverage manager operations
#[derive(Debug, Error)]
pub enum CoverageManagerError {
    #[error("coverage error: {0}")]
    Generic(String),
}

/// Alias for backward compatibility
pub type CoverageError = CoverageManagerError;

/// Entry mapping a file to an epoch with proof of inclusion
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileEpochEntry {
    pub file_id: String,
    pub epoch_id: u64,
    pub proof: MerkleInclusionProof,
    pub merkle_root: [u8; 32],
    #[serde(default)]
    pub signature: Vec<u8>,
    #[serde(default = "default_verifying_key")]
    pub verifying_key: [u8; VERIFYING_KEY_LEN],
    #[serde(default)]
    pub signing_key_id: Option<String>,
}

fn default_verifying_key() -> [u8; VERIFYING_KEY_LEN] {
    [0u8; VERIFYING_KEY_LEN]
}

/// Coverage log storing file→epoch assignments
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoverageLog {
    entries: HashMap<String, u64>,
    #[serde(default)]
    latest_root: Option<[u8; 32]>,
    #[serde(default)]
    latest_signature: Option<Vec<u8>>,
    #[serde(default)]
    verifying_key: Option<[u8; VERIFYING_KEY_LEN]>,
    #[serde(default)]
    signing_key_id: Option<String>,
    #[serde(default)]
    latest_epoch: Option<u64>,
}

/// Aggregate counts used for coarse coverage reporting.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct CoverageCounts {
    pub total_items: u64,
    pub rewrapped_items: u64,
}

/// Signed Merkle root snapshot suitable for transparency publication.
#[derive(Debug, Clone)]
pub struct CoverageRootSnapshot {
    pub merkle_root: [u8; 32],
    pub signature: Vec<u8>,
    pub verifying_key: [u8; VERIFYING_KEY_LEN],
    pub signing_key_id: Option<String>,
}

/// Coverage publication payload emitted after log updates.
#[derive(Debug, Clone)]
pub struct CoveragePublication {
    /// Snapshot of the signed Merkle root.
    pub snapshot: CoverageRootSnapshot,
    /// Epoch associated with the most recent update.
    pub epoch_id: u64,
    /// Total number of tracked files.
    pub total_files: u64,
    /// Timestamp when the publication was generated.
    pub updated_at: SystemTime,
}

/// Transparency inclusion proof bundle used for verification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoverageTransparencyRecord {
    /// Inclusion proof confirming the snapshot is anchored in the transparency log.
    pub proof: TransparencyInclusionProof,
}

/// Extracted transparency metadata suitable for wiring through client/server flows.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CoverageTransparencyMetadata {
    /// Global sequence number assigned by the transparency log.
    pub sequence_number: u64,
    /// Size of the transparency log at the time of inclusion.
    pub log_size: u64,
    /// Leaf index corresponding to the published entry.
    pub leaf_index: u64,
    /// Timestamp attached to the transparency entry.
    pub entry_timestamp: u64,
}

impl CoverageTransparencyMetadata {
    #[must_use]
    pub fn from_record(record: &CoverageTransparencyRecord) -> Self {
        Self {
            sequence_number: record.proof.entry.sequence_number,
            log_size: record.proof.log_size,
            leaf_index: record.proof.leaf_index,
            entry_timestamp: record.proof.entry.timestamp,
        }
    }
}

/// Verifier capable of retrieving transparency inclusion proofs for coverage snapshots.
#[async_trait]
pub trait CoverageTransparencyVerifier: Send + Sync + std::fmt::Debug {
    async fn fetch_inclusion_proof(
        &self,
        merkle_root: &[u8; 32],
    ) -> Result<CoverageTransparencyRecord, CoverageManagerError>;
}

/// Publisher invoked whenever a new signed root is produced.
pub trait CoveragePublisher: Send + Sync + std::fmt::Debug {
    fn publish(&self, publication: CoveragePublication) -> Result<(), CoverageManagerError>;
}

/// Abstract signer used to authenticate coverage log roots.
#[async_trait]
pub trait CoverageSigner: Send + Sync + std::fmt::Debug {
    /// Sign the provided message bytes.
    async fn sign(&self, message: &[u8]) -> Result<Vec<u8>, CoverageManagerError>;

    /// Return the Ed25519 verifying key associated with this signer.
    fn verifying_key(&self) -> [u8; VERIFYING_KEY_LEN];

    /// Optional identifier for the signing key (e.g., KMS resource).
    fn key_id(&self) -> Option<String> {
        None
    }
}

/// In-memory Ed25519 signer backed by [`SigningKey`].
#[derive(Debug)]
pub struct Ed25519CoverageSigner {
    signing_key: SigningKey,
    verifying_key: [u8; VERIFYING_KEY_LEN],
    signing_key_id: Option<String>,
}

impl Ed25519CoverageSigner {
    /// Create a new coverage signer from an Ed25519 signing key.
    ///
    /// # Panics
    /// Panics if deriving the verifying key fails (should be infallible for valid keys).
    #[must_use]
    pub fn new(signing_key: SigningKey, signing_key_id: Option<String>) -> Self {
        let verifying_key = signing_key.verifying_key().to_bytes();
        Self {
            signing_key,
            verifying_key,
            signing_key_id,
        }
    }
}

#[async_trait]
impl CoverageSigner for Ed25519CoverageSigner {
    async fn sign(&self, message: &[u8]) -> Result<Vec<u8>, CoverageManagerError> {
        signatures::sign(&self.signing_key, message)
            .map(|sig| sig.to_bytes().to_vec())
            .map_err(|e| CoverageManagerError::Generic(format!("signing failed: {e}")))
    }

    fn verifying_key(&self) -> [u8; VERIFYING_KEY_LEN] {
        self.verifying_key
    }

    fn key_id(&self) -> Option<String> {
        self.signing_key_id.clone()
    }
}

impl CoverageLog {
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
            latest_root: None,
            latest_signature: None,
            verifying_key: None,
            signing_key_id: None,
            latest_epoch: None,
        }
    }

    /// Add a file-epoch entry to the log
    pub fn add_entry(&mut self, entry: FileEpochEntry) {
        self.entries.insert(entry.file_id.clone(), entry.epoch_id);
        self.latest_root = Some(entry.merkle_root);
        self.latest_epoch = Some(entry.epoch_id);

        if !entry.signature.is_empty() {
            self.latest_signature = Some(entry.signature.clone());
        }

        if entry.verifying_key != default_verifying_key() {
            self.verifying_key = Some(entry.verifying_key);
        }

        if let Some(key_id) = entry.signing_key_id.clone() {
            if !key_id.is_empty() {
                self.signing_key_id = Some(key_id);
            }
        }
    }

    /// Get an entry for a specific file ID
    pub fn get_entry(&self, file_id: &str) -> Option<u64> {
        self.entries.get(file_id).copied()
    }

    /// Verify the overall coverage integrity using only local state.
    pub async fn verify_coverage(&self) -> Result<(), CoverageManagerError> {
        self.verify_coverage_internal(None).await.map(|_| ())
    }

    /// Replace an existing entry while preserving the latest signature metadata.
    ///
    /// This is primarily used when a file is rewrapped into a new epoch and the
    /// previous epoch-specific identifier needs to be removed to keep counts
    /// accurate.
    pub fn replace_entry(&mut self, old_file_id: &str, entry: FileEpochEntry) {
        self.entries.remove(old_file_id);
        self.add_entry(entry);
    }

    /// Verify coverage integrity using transparency inclusion proofs and return the proof bundle.
    pub async fn verify_coverage_with_transparency(
        &self,
        verifier: &dyn CoverageTransparencyVerifier,
    ) -> Result<CoverageTransparencyRecord, CoverageManagerError> {
        self.verify_coverage_internal(Some(verifier))
            .await?
            .ok_or_else(|| {
                CoverageManagerError::Generic(
                    "transparency verifier did not return inclusion proof".into(),
                )
            })
    }

    async fn verify_coverage_internal(
        &self,
        transparency_verifier: Option<&dyn CoverageTransparencyVerifier>,
    ) -> Result<Option<CoverageTransparencyRecord>, CoverageManagerError> {
        if self.entries.is_empty() {
            return Err(CoverageManagerError::Generic(
                "coverage log is empty; nothing to verify".into(),
            ));
        }

        let recorded_root = self
            .latest_root
            .ok_or_else(|| CoverageManagerError::Generic("coverage root not recorded".into()))?;
        let signature_bytes = self.latest_signature.as_ref().ok_or_else(|| {
            CoverageManagerError::Generic("coverage root signature missing".into())
        })?;
        let verifying_key_bytes = self.verifying_key.ok_or_else(|| {
            CoverageManagerError::Generic("coverage verifying key missing".into())
        })?;

        let signing_key_id = self.signing_key_id.clone();
        let (mut tree, items) = self.build_tree();
        let total_files = items.len() as u64;
        let computed_root = tree.root().map_err(|e| {
            CoverageManagerError::Generic(format!("failed to compute Merkle root: {e}"))
        })?;

        if computed_root != recorded_root {
            return Err(CoverageManagerError::Generic(
                "computed Merkle root does not match recorded root".into(),
            ));
        }

        let verifying_key = VerifyingKey::from_bytes(&verifying_key_bytes).map_err(|e| {
            CoverageManagerError::Generic(format!("invalid verifying key bytes: {e}"))
        })?;
        let signature = Signature::from_bytes(signature_bytes).map_err(|e| {
            CoverageManagerError::Generic(format!("invalid coverage signature bytes: {e}"))
        })?;

        signatures::verify(&verifying_key, &computed_root, &signature).map_err(|e| {
            CoverageManagerError::Generic(format!("coverage signature verification failed: {e}"))
        })?;

        for (index, (file_id, epoch_id)) in items.iter().enumerate() {
            let proof = tree.generate_proof(index).map_err(|e| {
                CoverageManagerError::Generic(format!(
                    "failed to generate inclusion proof for {file_id}: {e}"
                ))
            })?;
            let leaf = format!("{file_id}:{epoch_id}");
            let proof_valid = hybridcipher_merkle::verify_inclusion_proof(
                &proof,
                &computed_root,
                leaf.as_bytes(),
            )
            .map_err(|e| {
                CoverageManagerError::Generic(format!(
                    "error validating inclusion proof for {file_id}: {e}"
                ))
            })?;
            if !proof_valid {
                return Err(CoverageManagerError::Generic(format!(
                    "inclusion proof invalid for file {file_id}"
                )));
            }
        }

        if let Some(verifier) = transparency_verifier {
            let transparency = verifier
                .fetch_inclusion_proof(&computed_root)
                .await
                .map_err(|e| {
                    CoverageManagerError::Generic(format!("transparency verification failed: {e}"))
                })?;

            let proof = &transparency.proof;

            let proof_valid = proof.verify().map_err(|e| {
                CoverageManagerError::Generic(format!(
                    "transparency inclusion verification failed: {e}"
                ))
            })?;
            if !proof_valid {
                return Err(CoverageManagerError::Generic(
                    "transparency inclusion proof invalid".into(),
                ));
            }

            if proof.entry.join_card_hash != computed_root {
                return Err(CoverageManagerError::Generic(
                    "transparency join_card_hash does not match coverage root".into(),
                ));
            }

            let latest_epoch = self
                .latest_epoch
                .or_else(|| items.iter().map(|(_, epoch)| *epoch).max())
                .ok_or_else(|| {
                    CoverageManagerError::Generic(
                        "unable to determine latest epoch for coverage verification".into(),
                    )
                })?;

            match &proof.entry.operation {
                TransparencyOperation::CoverageSnapshot {
                    merkle_root,
                    epoch_id,
                    file_count,
                    signing_key_id: entry_key_id,
                    verifying_key: entry_verifying_key,
                } => {
                    if merkle_root != &computed_root {
                        return Err(CoverageManagerError::Generic(
                            "transparency coverage snapshot does not reference the expected root"
                                .into(),
                        ));
                    }

                    if *file_count != total_files {
                        return Err(CoverageManagerError::Generic(format!(
                            "transparency coverage snapshot file count mismatch: expected {}, got {}",
                            total_files, file_count
                        )));
                    }

                    if *epoch_id != latest_epoch {
                        return Err(CoverageManagerError::Generic(format!(
                            "transparency coverage snapshot epoch mismatch: expected {}, got {}",
                            latest_epoch, epoch_id
                        )));
                    }

                    if entry_verifying_key != &verifying_key_bytes {
                        return Err(CoverageManagerError::Generic(
                            "transparency coverage snapshot verifying key mismatch".into(),
                        ));
                    }

                    match (&signing_key_id, entry_key_id) {
                        (Some(expected), Some(recorded)) if expected == recorded => {}
                        (Some(expected), Some(recorded)) => {
                            return Err(CoverageManagerError::Generic(format!(
                                "transparency coverage snapshot signing key mismatch: expected {}, got {}",
                                expected, recorded
                            )))
                        }
                        (Some(expected), None) => {
                            return Err(CoverageManagerError::Generic(format!(
                                "transparency coverage snapshot missing signing key identifier (expected {})",
                                expected
                            )))
                        }
                        (None, Some(recorded)) => {
                            return Err(CoverageManagerError::Generic(format!(
                                "transparency coverage snapshot unexpectedly contains signing key identifier {}",
                                recorded
                            )))
                        }
                        (None, None) => {}
                    }
                }
                other => {
                    return Err(CoverageManagerError::Generic(format!(
                    "transparency entry operation mismatch: expected coverage snapshot, got {:?}",
                    other
                )))
                }
            }
            Ok(Some(transparency))
        } else {
            Ok(None)
        }
    }

    /// Get the Merkle root for the coverage log
    pub fn get_merkle_root(&self) -> Result<String, CoverageManagerError> {
        let root = self.merkle_root()?;
        Ok(hex::encode(root))
    }

    /// Return the most recent signed coverage root, if available.
    pub fn latest_snapshot(&self) -> Option<CoverageRootSnapshot> {
        let merkle_root = self.latest_root?;
        let signature = self.latest_signature.clone()?;
        let verifying_key = self.verifying_key?;
        Some(CoverageRootSnapshot {
            merkle_root,
            signature,
            verifying_key,
            signing_key_id: self.signing_key_id.clone(),
        })
    }

    fn insert(&mut self, file_id: String, epoch_id: u64) {
        self.entries.insert(file_id, epoch_id);
    }

    /// Attach a signed snapshot (root + signature + verifying key) to the coverage log.
    ///
    /// This is primarily used when restoring coverage state from an existing snapshot so
    /// that integrity verification can succeed even though per-entry proofs were not
    /// replayed.
    #[allow(clippy::needless_pass_by_value)]
    pub fn apply_signed_snapshot(
        &mut self,
        merkle_root: [u8; 32],
        signature: Vec<u8>,
        verifying_key: [u8; VERIFYING_KEY_LEN],
        signing_key_id: Option<String>,
    ) {
        self.latest_root = Some(merkle_root);
        self.latest_signature = Some(signature);
        self.verifying_key = Some(verifying_key);
        self.signing_key_id = signing_key_id;
    }

    fn build_tree(&self) -> (MerkleTree, Vec<(String, u64)>) {
        let mut tree = MerkleTree::new();
        let mut items: Vec<(String, u64)> =
            self.entries.iter().map(|(k, v)| (k.clone(), *v)).collect();
        items.sort_by(|a, b| a.0.cmp(&b.0));
        for (fid, epoch) in &items {
            let leaf = format!("{fid}:{epoch}");
            tree.insert_leaf(leaf.as_bytes());
        }
        (tree, items)
    }

    fn merkle_root(&self) -> Result<[u8; 32], CoverageManagerError> {
        let (mut tree, _) = self.build_tree();
        tree.root()
            .map_err(|e| CoverageManagerError::Generic(format!("{e}")))
    }

    fn inclusion_proof(
        &self,
        file_id: &str,
    ) -> Result<(MerkleInclusionProof, [u8; 32]), CoverageManagerError> {
        let (mut tree, items) = self.build_tree();
        let index = items
            .iter()
            .position(|(f, _)| f == file_id)
            .ok_or_else(|| CoverageManagerError::Generic("file not found".into()))?;
        let root = tree
            .root()
            .map_err(|e| CoverageManagerError::Generic(format!("{e}")))?;
        let proof = tree
            .generate_proof(index)
            .map_err(|e| CoverageManagerError::Generic(format!("{e}")))?;
        Ok((proof, root))
    }

    /// Count total items and those rewrapped into the target epoch identifier.
    pub fn counts_for_epoch(&self, epoch_id: u64) -> CoverageCounts {
        let total_items = self.entries.len() as u64;
        let rewrapped_items = self
            .entries
            .values()
            .filter(|&&entry_epoch| entry_epoch == epoch_id)
            .count() as u64;

        CoverageCounts {
            total_items,
            rewrapped_items,
        }
    }

    /// Get all file IDs currently in the coverage log
    pub fn get_all_file_ids(&self) -> Vec<String> {
        self.entries.keys().cloned().collect()
    }

    /// Remove an entry from the coverage log
    pub fn remove_entry(&mut self, file_id: &str) {
        self.entries.remove(file_id);
    }
}

impl Default for CoverageLog {
    fn default() -> Self {
        Self::new()
    }
}

/// Coverage manager maintaining log and signing roots
#[derive(Debug)]
pub struct CoverageManager<S> {
    _storage: Arc<S>,
    log: Arc<Mutex<CoverageLog>>,
    signer: Arc<dyn CoverageSigner>,
    verifying_key: [u8; VERIFYING_KEY_LEN],
    signing_key_id: Option<String>,
    publisher: Option<Arc<dyn CoveragePublisher>>,
    transparency_verifier: Option<Arc<dyn CoverageTransparencyVerifier>>,
    latest_transparency: Arc<Mutex<Option<CoverageTransparencyMetadata>>>,
}

impl<S> CoverageManager<S> {
    pub fn new(storage: Arc<S>, signer: Arc<dyn CoverageSigner>) -> Self {
        Self::with_log(storage, CoverageLog::new(), signer, None)
    }

    pub fn new_with_signing_key(storage: Arc<S>, signing_key: SigningKey) -> Self {
        Self::new_with_signing_key_and_id(storage, signing_key, None)
    }

    pub fn new_with_signing_key_and_id(
        storage: Arc<S>,
        signing_key: SigningKey,
        signing_key_id: Option<String>,
    ) -> Self {
        let signer = Arc::new(Ed25519CoverageSigner::new(signing_key, signing_key_id));
        Self::with_log(storage, CoverageLog::new(), signer, None)
    }

    pub fn new_with_signer_and_log(
        storage: Arc<S>,
        log: CoverageLog,
        signer: Arc<dyn CoverageSigner>,
    ) -> Self {
        Self::with_log(storage, log, signer, None)
    }

    pub fn new_standalone(storage: Arc<S>, log: CoverageLog, signing_key: SigningKey) -> Self {
        Self::new_standalone_with_id(storage, log, signing_key, None)
    }

    pub fn new_standalone_with_id(
        storage: Arc<S>,
        log: CoverageLog,
        signing_key: SigningKey,
        signing_key_id: Option<String>,
    ) -> Self {
        let signer = Arc::new(Ed25519CoverageSigner::new(signing_key, signing_key_id));
        Self::with_log(storage, log, signer, None)
    }

    pub fn with_publisher(mut self, publisher: Arc<dyn CoveragePublisher>) -> Self {
        self.publisher = Some(publisher);
        self
    }

    /// Attach a transparency verifier that can fetch inclusion proofs for snapshots.
    pub fn with_transparency_verifier(
        mut self,
        verifier: Arc<dyn CoverageTransparencyVerifier>,
    ) -> Self {
        self.transparency_verifier = Some(verifier);
        self
    }

    fn with_log(
        storage: Arc<S>,
        log: CoverageLog,
        signer: Arc<dyn CoverageSigner>,
        publisher: Option<Arc<dyn CoveragePublisher>>,
    ) -> Self {
        let verifying_key = signer.verifying_key();
        let signing_key_id = signer.key_id();
        Self {
            _storage: storage,
            log: Arc::new(Mutex::new(log)),
            signer,
            verifying_key,
            signing_key_id,
            publisher,
            transparency_verifier: None,
            latest_transparency: Arc::new(Mutex::new(None)),
        }
    }

    /// Record a file's epoch and return signed entry with proof
    pub async fn log_file_epoch(
        &self,
        file_id: &str,
        epoch_id: u64,
    ) -> Result<FileEpochEntry, CoverageManagerError> {
        let (entry, snapshot, total_files) = {
            let mut log = self.log.lock().await;
            log.insert(file_id.to_string(), epoch_id);
            let (proof, root) = log.inclusion_proof(file_id)?;
            let signature = self.signer.sign(&root).await?;
            let entry = FileEpochEntry {
                file_id: file_id.to_string(),
                epoch_id,
                proof,
                merkle_root: root,
                signature,
                verifying_key: self.verifying_key,
                signing_key_id: self.signing_key_id.clone(),
            };
            log.add_entry(entry.clone());
            let snapshot = log.latest_snapshot();
            let total_files = log.entries.len() as u64;
            (entry, snapshot, total_files)
        };
        {
            let mut latest = self.latest_transparency.lock().await;
            *latest = None;
        }
        if let Some(publisher) = &self.publisher {
            if let Some(snapshot) = snapshot {
                let publication = CoveragePublication {
                    snapshot,
                    epoch_id,
                    total_files,
                    updated_at: SystemTime::now(),
                };
                publisher.publish(publication)?;
            }
        }
        Ok(entry)
    }

    /// Insert multiple file epochs without generating per-entry proofs.
    pub fn insert_entries<I>(&self, entries: I)
    where
        I: IntoIterator<Item = (String, u64)>,
    {
        let mut log = self.log.blocking_lock();
        let mut latest_epoch = log.latest_epoch.unwrap_or(0);
        let mut have_epoch = log.latest_epoch.is_some();

        for (file_id, epoch_id) in entries {
            log.insert(file_id, epoch_id);
            if !have_epoch {
                latest_epoch = epoch_id;
                have_epoch = true;
            } else if epoch_id > latest_epoch {
                latest_epoch = epoch_id;
            }
        }

        if have_epoch {
            log.latest_epoch = Some(latest_epoch);
        }

        let mut latest = self.latest_transparency.blocking_lock();
        *latest = None;
    }

    /// Sign and store a Merkle root snapshot without per-entry proofs.
    pub async fn apply_signed_snapshot(
        &self,
        merkle_root: [u8; 32],
    ) -> Result<CoverageRootSnapshot, CoverageManagerError> {
        let signature = self.signer.sign(&merkle_root).await?;
        {
            let mut log = self.log.lock().await;
            log.apply_signed_snapshot(
                merkle_root,
                signature.clone(),
                self.verifying_key,
                self.signing_key_id.clone(),
            );
        }
        let mut latest = self.latest_transparency.lock().await;
        *latest = None;

        Ok(CoverageRootSnapshot {
            merkle_root,
            signature,
            verifying_key: self.verifying_key,
            signing_key_id: self.signing_key_id.clone(),
        })
    }

    /// Get current Merkle root of coverage log
    pub fn get_merkle_root(&self) -> Result<[u8; 32], CoverageManagerError> {
        self.log
            .try_lock()
            .map_err(|_| CoverageManagerError::Generic("coverage log is busy".to_string()))?
            .merkle_root()
    }

    /// Return the most recent signed Merkle root snapshot, if available.
    pub fn latest_root_snapshot(&self) -> Option<CoverageRootSnapshot> {
        self.log
            .try_lock()
            .map(|log| log.latest_snapshot())
            .unwrap_or(None)
    }

    pub async fn get_migration_progress(
        &self,
        _from: u64,
        to: u64,
    ) -> Result<CoverageResult, CoverageManagerError> {
        let log = self.log.lock().await;
        if log.entries.is_empty() {
            return Ok(0.0);
        }
        let total = log.entries.len();
        let migrated = log.entries.values().filter(|&&epoch| epoch >= to).count();
        Ok(migrated as f64 / total as f64)
    }

    pub async fn get_coverage_status(&self) -> Result<CoverageResult, CoverageManagerError> {
        let log = self.log.lock().await;
        if log.entries.is_empty() {
            return Ok(0.0);
        }
        let max_epoch = *log.entries.values().max().unwrap();
        let total = log.entries.len();
        let up_to_date = log
            .entries
            .values()
            .filter(|&&epoch| epoch == max_epoch)
            .count();
        Ok(up_to_date as f64 / total as f64)
    }

    pub async fn get_coverage_log(&self) -> Result<CoverageLog, CoverageManagerError> {
        let log = self.log.lock().await;
        Ok(log.clone())
    }

    /// Verify the integrity of the coverage log, including transparency if configured.
    pub async fn verify_integrity(&self) -> Result<(), CoverageManagerError> {
        if let Some(verifier) = &self.transparency_verifier {
            let log = self.log.lock().await.clone();
            let record = log
                .verify_coverage_with_transparency(verifier.as_ref())
                .await?;
            let metadata = CoverageTransparencyMetadata::from_record(&record);
            let mut latest = self.latest_transparency.lock().await;
            *latest = Some(metadata);
            Ok(())
        } else {
            let log = self.log.lock().await.clone();
            log.verify_coverage().await
        }
    }

    /// Return the most recent transparency metadata captured during verification, if any.
    pub fn latest_transparency_metadata(&self) -> Option<CoverageTransparencyMetadata> {
        self.latest_transparency
            .try_lock()
            .map(|metadata| metadata.clone())
            .unwrap_or(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use std::sync::Arc;

    #[tokio::test]
    async fn test_merkle_root_and_proof() {
        let signing_key = SigningKey::from_bytes(&[1u8; 32]).unwrap();
        let manager =
            CoverageManager::new_standalone(Arc::new(()), CoverageLog::new(), signing_key);

        let e1 = manager.log_file_epoch("file1", 1).await.unwrap();
        let root1 = e1.merkle_root;
        assert!(
            hybridcipher_merkle::verify_inclusion_proof(&e1.proof, &root1, b"file1:1").unwrap()
        );

        let e2 = manager.log_file_epoch("file2", 2).await.unwrap();
        assert_ne!(root1, e2.merkle_root);
        assert!(hybridcipher_merkle::verify_inclusion_proof(
            &e2.proof,
            &e2.merkle_root,
            b"file2:2"
        )
        .unwrap());

        let log = manager.log.lock().await.clone();
        log.verify_coverage().await.unwrap();
    }

    #[tokio::test]
    async fn test_migration_progress_and_status() {
        let signing_key = SigningKey::from_bytes(&[1u8; 32]).unwrap();
        let manager =
            CoverageManager::new_standalone(Arc::new(()), CoverageLog::new(), signing_key);

        manager.log_file_epoch("file1", 1).await.unwrap();
        manager.log_file_epoch("file2", 1).await.unwrap();

        let progress = manager.get_migration_progress(1, 2).await.unwrap();
        assert_eq!(progress, 0.0);

        manager.log_file_epoch("file1", 2).await.unwrap();
        let progress = manager.get_migration_progress(1, 2).await.unwrap();
        assert_eq!(progress, 0.5);

        let status = manager.get_coverage_status().await.unwrap();
        assert_eq!(status, 0.5);

        manager.log_file_epoch("file2", 2).await.unwrap();
        let status = manager.get_coverage_status().await.unwrap();
        assert_eq!(status, 1.0);
    }

    #[tokio::test]
    async fn counts_for_epoch_reports_totals() {
        let signing_key = SigningKey::from_bytes(&[2u8; 32]).unwrap();
        let manager =
            CoverageManager::new_standalone(Arc::new(()), CoverageLog::new(), signing_key);

        manager.log_file_epoch("file1", 5).await.unwrap();
        manager.log_file_epoch("file2", 5).await.unwrap();
        manager.log_file_epoch("file3", 4).await.unwrap();

        let counts = manager.log.lock().await.counts_for_epoch(5);
        assert_eq!(counts.total_items, 3);
        assert_eq!(counts.rewrapped_items, 2);

        let other = manager.log.lock().await.counts_for_epoch(7);
        assert_eq!(other.total_items, 3);
        assert_eq!(other.rewrapped_items, 0);
    }

    #[tokio::test]
    async fn verify_coverage_fails_with_invalid_signature() {
        let signing_key = SigningKey::from_bytes(&[9u8; 32]).unwrap();
        let manager =
            CoverageManager::new_standalone(Arc::new(()), CoverageLog::new(), signing_key);

        manager.log_file_epoch("file-invalid", 42).await.unwrap();

        {
            let mut log = manager.log.lock().await;
            log.latest_signature = Some(vec![0u8; hybridcipher_crypto::signatures::SIGNATURE_LEN]);
        }

        let log = manager.log.lock().await.clone();
        assert!(log.verify_coverage().await.is_err());
    }

    #[derive(Debug)]
    struct RecordingPublisher {
        records: Arc<std::sync::Mutex<Vec<CoveragePublication>>>,
    }

    impl RecordingPublisher {
        fn new() -> (
            Arc<dyn CoveragePublisher>,
            Arc<std::sync::Mutex<Vec<CoveragePublication>>>,
        ) {
            let records = Arc::new(std::sync::Mutex::new(Vec::new()));
            let publisher: Arc<dyn CoveragePublisher> = Arc::new(Self {
                records: Arc::clone(&records),
            });
            (publisher, records)
        }
    }

    impl CoveragePublisher for RecordingPublisher {
        fn publish(&self, publication: CoveragePublication) -> Result<(), CoverageManagerError> {
            self.records.lock().unwrap().push(publication);
            Ok(())
        }
    }

    #[derive(Clone, Debug)]
    struct MockTransparencyVerifier {
        record: CoverageTransparencyRecord,
    }

    #[async_trait]
    impl CoverageTransparencyVerifier for MockTransparencyVerifier {
        async fn fetch_inclusion_proof(
            &self,
            merkle_root: &[u8; 32],
        ) -> Result<CoverageTransparencyRecord, CoverageManagerError> {
            if merkle_root != &self.record.proof.entry.join_card_hash {
                return Err(CoverageManagerError::Generic(
                    "unexpected transparency root".to_string(),
                ));
            }
            Ok(self.record.clone())
        }
    }

    #[tokio::test]
    async fn publisher_receives_snapshots() {
        let signing_key = SigningKey::from_bytes(&[7u8; 32]).unwrap();
        let (publisher, records) = RecordingPublisher::new();

        let manager =
            CoverageManager::new_standalone(Arc::new(()), CoverageLog::new(), signing_key)
                .with_publisher(publisher);

        manager.log_file_epoch("file-publish", 11).await.unwrap();

        let stored = records.lock().unwrap();
        assert_eq!(stored.len(), 1);
        let publication = &stored[0];
        assert_eq!(publication.epoch_id, 11);
        assert_eq!(publication.total_files, 1);
        assert_eq!(publication.snapshot.merkle_root.len(), 32);
    }

    #[tokio::test]
    async fn verify_integrity_with_transparency() {
        let signing_key = SigningKey::from_bytes(&[3u8; 32]).unwrap();
        let manager =
            CoverageManager::new_standalone(Arc::new(()), CoverageLog::new(), signing_key);

        manager
            .log_file_epoch("file-transparency", 8)
            .await
            .unwrap();

        let snapshot = manager
            .latest_root_snapshot()
            .expect("snapshot should be available");

        let operation = TransparencyOperation::CoverageSnapshot {
            merkle_root: snapshot.merkle_root,
            epoch_id: 8,
            file_count: 1,
            signing_key_id: snapshot.signing_key_id.clone(),
            verifying_key: snapshot.verifying_key,
        };

        let entry = hybridcipher_messages::transparency::TransparencyEntry::new(
            1,
            snapshot.merkle_root,
            operation,
            snapshot.signature.clone(),
        );

        let proof = TransparencyInclusionProof {
            entry: entry.clone(),
            leaf_index: 0,
            proof_path: Vec::new(),
            log_size: 1,
            log_root: entry.hash(),
        };

        let record = CoverageTransparencyRecord { proof };
        let expected_metadata = CoverageTransparencyMetadata::from_record(&record);

        let verifier: Arc<dyn CoverageTransparencyVerifier> = Arc::new(MockTransparencyVerifier {
            record: record.clone(),
        });

        let manager = manager.with_transparency_verifier(verifier);

        assert!(manager.verify_integrity().await.is_ok());
        let metadata = manager
            .latest_transparency_metadata()
            .expect("metadata should be recorded");
        assert_eq!(metadata, expected_metadata);
    }

    #[tokio::test]
    async fn verify_integrity_with_transparency_detects_mismatch() {
        let signing_key = SigningKey::from_bytes(&[4u8; 32]).unwrap();
        let manager =
            CoverageManager::new_standalone(Arc::new(()), CoverageLog::new(), signing_key);

        manager
            .log_file_epoch("file-transparency-bad", 12)
            .await
            .unwrap();

        let snapshot = manager
            .latest_root_snapshot()
            .expect("snapshot should be available");

        let bad_operation = TransparencyOperation::CoverageSnapshot {
            merkle_root: snapshot.merkle_root,
            epoch_id: 12,
            file_count: 99, // incorrect file count should trigger failure
            signing_key_id: snapshot.signing_key_id.clone(),
            verifying_key: snapshot.verifying_key,
        };

        let entry = hybridcipher_messages::transparency::TransparencyEntry::new(
            2,
            snapshot.merkle_root,
            bad_operation,
            snapshot.signature.clone(),
        );

        let proof = TransparencyInclusionProof {
            entry: entry.clone(),
            leaf_index: 0,
            proof_path: Vec::new(),
            log_size: 1,
            log_root: entry.hash(),
        };

        let verifier: Arc<dyn CoverageTransparencyVerifier> = Arc::new(MockTransparencyVerifier {
            record: CoverageTransparencyRecord { proof },
        });

        let manager = manager.with_transparency_verifier(verifier);
        assert!(manager.verify_integrity().await.is_err());
        assert!(manager.latest_transparency_metadata().is_none());
    }
}
