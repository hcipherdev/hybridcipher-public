//! Which device keys may sign Welcome messages for a group.
//!
//! A Welcome carries its signer's public key, so a valid signature alone proves nothing
//! against a server that writes Welcomes of its own. Each device therefore keeps, per
//! group, the keys it trusts to sign them. The set is seeded once from the group's
//! approved devices (trust on first use) and afterwards only grows through
//! introductions: when a trusted device approves another, it signs "key K may sign
//! Welcomes for group G", and every Welcome carries the introductions its sender knows.

use chrono::{DateTime, Utc};
use hybridcipher_crypto::signatures::{Ed25519KeyPair, Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use uuid::Uuid;

/// A device's signed statement that `identity_key` may sign Welcomes for `group_id`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignerIntroduction {
    pub group_id: Uuid,
    /// Hex Ed25519 identity key being introduced.
    pub identity_key: String,
    /// Hex Ed25519 identity key of the introducing device.
    pub introduced_by: String,
    pub created_at: DateTime<Utc>,
    /// Hex Ed25519 signature by `introduced_by` over the introduction payload.
    pub signature: String,
}

impl SignerIntroduction {
    /// `introducer` vouches that `identity_key` may sign Welcomes for `group_id`.
    pub fn new(introducer: &Ed25519KeyPair, group_id: Uuid, identity_key: &[u8]) -> Self {
        let mut introduction = Self {
            group_id,
            identity_key: hex::encode(identity_key),
            introduced_by: hex::encode(introducer.public_key_bytes()),
            created_at: Utc::now(),
            signature: String::new(),
        };
        introduction.signature = hex::encode(introducer.sign(&introduction.signing_payload()));
        introduction
    }

    fn signing_payload(&self) -> Vec<u8> {
        let mut bytes = b"hybridcipher/welcome-signer-introduction/v1\n".to_vec();
        bytes.extend(self.group_id.as_bytes());
        for part in [&self.identity_key, &self.introduced_by] {
            bytes.extend((part.len() as u64).to_be_bytes());
            bytes.extend(part.as_bytes());
        }
        bytes.extend(self.created_at.timestamp_micros().to_be_bytes());
        bytes
    }

    /// Whether `introduced_by` really signed this introduction.
    pub fn is_authentic(&self) -> bool {
        let (Ok(key), Ok(signature)) = (
            hex::decode(&self.introduced_by),
            hex::decode(&self.signature),
        ) else {
            return false;
        };
        let (Ok(key), Ok(signature)) = (
            VerifyingKey::from_bytes(&key),
            Signature::from_bytes(&signature),
        ) else {
            return false;
        };
        key.verify(&self.signing_payload(), &signature).is_ok()
    }
}

/// Keys this device trusts to sign Welcomes for one group, plus the introductions it
/// accepted, which it forwards in the Welcomes it sends.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GroupSignerTrust {
    pub group_id: Uuid,
    trusted: BTreeSet<String>,
    introductions: Vec<SignerIntroduction>,
}

impl GroupSignerTrust {
    /// Trust exactly `keys` for `group_id`.
    pub fn seeded<'a>(group_id: Uuid, keys: impl IntoIterator<Item = &'a [u8]>) -> Self {
        Self {
            group_id,
            trusted: keys.into_iter().map(hex::encode).collect(),
            introductions: Vec::new(),
        }
    }

    pub fn trusts(&self, key: &[u8]) -> bool {
        self.trusted.contains(&hex::encode(key))
    }

    pub fn introductions(&self) -> &[SignerIntroduction] {
        &self.introductions
    }

    /// Accept every authentic introduction for this group whose introducer is trusted,
    /// repeating until nothing changes so chains of introductions are followed.
    /// Returns whether anything was added.
    pub fn absorb(&mut self, introductions: &[SignerIntroduction]) -> bool {
        let mut changed = false;
        loop {
            let mut progressed = false;
            for introduction in introductions {
                if introduction.group_id != self.group_id
                    || !self.trusted.contains(&introduction.introduced_by)
                    || self.introductions.contains(introduction)
                    || !introduction.is_authentic()
                {
                    continue;
                }
                self.trusted.insert(introduction.identity_key.clone());
                self.introductions.push(introduction.clone());
                progressed = true;
            }
            if !progressed {
                return changed;
            }
            changed = true;
        }
    }

    /// Have `introducer` (a trusted key) vouch for `key`, unless it is already trusted.
    /// Returns whether anything was added.
    pub fn introduce(&mut self, introducer: &Ed25519KeyPair, key: &[u8]) -> bool {
        if self.trusts(key) || !self.trusts(&introducer.public_key_bytes()) {
            return false;
        }
        let introduction = SignerIntroduction::new(introducer, self.group_id, key);
        self.trusted.insert(introduction.identity_key.clone());
        self.introductions.push(introduction);
        true
    }
}

#[cfg(test)]
#[path = "../tests/device_security/test_welcome_signers.rs"]
mod tests;
