//! Client state management
//!
//! This module provides state management capabilities for the HybridCipher client,
//! including epoch tracking, migration coordination, and persistence.

pub mod client;
pub mod migration;

pub use client::{
    AddMemberResult, Client, EncryptedFileMetadata, MemberCapabilities, MigrationPhase,
    MigrationState, RekeyPlan, RemoveMemberResult,
};
pub use migration::{MigrationManager, MigrationProgress, MigrationStatistics};

/// State validation result
#[derive(Debug, Clone, PartialEq)]
pub enum StateValidation {
    /// State is valid and consistent
    Valid,

    /// State has warnings but is functional
    Warning(String),

    /// State has errors that need correction
    Error(String),

    /// State is corrupted and needs recovery
    Corrupted(String),
}

/// State synchronization result
#[derive(Debug, Clone)]
pub struct SyncResult {
    /// Whether synchronization was successful
    pub success: bool,

    /// Number of updates applied
    pub updates_applied: u64,

    /// Number of conflicts resolved
    pub conflicts_resolved: u64,

    /// Synchronization duration
    pub duration_ms: u64,

    /// Any errors encountered
    pub errors: Vec<String>,
}
