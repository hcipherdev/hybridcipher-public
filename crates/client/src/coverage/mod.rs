//! Coverage management integration for client
//!
//! This module provides integration between the client and coverage tracking system.

mod folders;
mod log;

use once_cell::sync::Lazy;
use std::sync::RwLock;

use hybridcipher_messages::transparency::TransparencyConfig;

// Re-export from hybridcipher_coverage for convenience
pub use hybridcipher_coverage::{
    CoverageLog, CoverageManager, CoverageManagerError, CoveragePublication, CoveragePublisher,
    CoverageResult, CoverageRootSnapshot, CoverageTransparencyMetadata, CoverageTransparencyRecord,
    CoverageTransparencyVerifier,
};

pub use folders::{
    CoverageRoot, CoverageRootKind, CoverageRootState, FileCoverageState, FileIndexEntry,
    FileOrphanKind,
};
pub use log::{
    TransparencyCoverageHandles, TransparencyCoveragePublisher, TransparencyCoverageVerifier,
};

static TRANSPARENCY_CONFIG: Lazy<RwLock<Option<TransparencyConfig>>> =
    Lazy::new(|| RwLock::new(None));

/// Update the transparency configuration used for coverage publishing.
pub fn set_transparency_config(config: TransparencyConfig) {
    let mut guard = TRANSPARENCY_CONFIG
        .write()
        .expect("coverage transparency config lock poisoned");
    *guard = Some(config);
}

/// Retrieve the currently configured transparency settings, if any.
pub fn current_transparency_config() -> Option<TransparencyConfig> {
    TRANSPARENCY_CONFIG
        .read()
        .expect("coverage transparency config lock poisoned")
        .clone()
}

/// Attempt to construct a transparency publisher using the stored configuration.
pub fn try_build_transparency_publisher<N: crate::network::Network>(
    network: std::sync::Arc<N>,
) -> Option<std::sync::Arc<dyn CoveragePublisher>> {
    log::try_build_transparency_publisher(network)
}

/// Attempt to construct transparency handles (publisher + verifier) using the stored configuration.
pub fn try_build_transparency_handles<N: crate::network::Network>(
    network: std::sync::Arc<N>,
) -> Option<TransparencyCoverageHandles> {
    log::try_build_transparency_handles(network)
}
