// Exact schema-2 representation. Verify its checksum before introducing new fields.
use super::*;
#[derive(Debug, Clone, Serialize, Deserialize)]
struct Schema2Record {
    pub id: Uuid,
    #[serde(default)]
    pub sequence: u64,
    pub kind: CloudMutationKind,
    pub root_id: Uuid,
    pub relative_path: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_relative_path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub plaintext_path: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_plaintext_path: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity: Option<hybridcipher_provider_core::FileIdentityV1>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_version: Option<ProviderContentVersion>,
    #[serde(default)]
    pub attempts: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
struct Schema2Journal {
    pub root_id: Uuid,
    #[serde(default)]
    pub generation: u64,
    #[serde(default)]
    pub next_sequence: u64,
    #[serde(default)]
    pub records: Vec<Schema2Record>,
    pub updated_at: DateTime<Utc>,
}
#[derive(Deserialize)]
struct Schema2Envelope {
    schema_version: u16,
    generation: u64,
    checksum_hex: String,
    journal: Schema2Journal,
}

pub(super) fn decode(data: &[u8], root_id: Uuid) -> Result<CloudMutationJournal> {
    let old: Schema2Envelope = serde_json::from_slice(data)?;
    let checksum = format!("{:x}", Sha256::digest(serde_json::to_vec(&old.journal)?));
    if old.schema_version != 2
        || old.generation != old.journal.generation
        || old.journal.root_id != root_id
        || old.checksum_hex != checksum
    {
        return Err(CloudProviderError::Callback(
            "Schema-2 mutation journal checksum or generation mismatch".into(),
        ));
    }
    Ok(serde_json::from_value(serde_json::to_value(old.journal)?)?)
}

#[cfg(any(test, feature = "native-verification"))]
pub(super) fn fixture(journal: &CloudMutationJournal) -> Vec<u8> {
    let old: Schema2Journal =
        serde_json::from_value(serde_json::to_value(journal).unwrap()).unwrap();
    let checksum = format!("{:x}", Sha256::digest(serde_json::to_vec(&old).unwrap()));
    serde_json::to_vec_pretty(&serde_json::json!({"schema_version": 2, "generation": old.generation, "checksum_hex": checksum, "journal": old})).unwrap()
}
