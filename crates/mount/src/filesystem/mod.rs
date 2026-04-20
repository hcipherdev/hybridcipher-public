//! FUSE filesystem implementation with migration support
//!
//! This module provides the core FUSE filesystem implementation with
//! dual-epoch access, migration awareness, and performance optimization.

pub mod attr;
pub mod decrypt;
pub mod hybridcipher;
pub mod lookup;
pub mod performance;
pub mod read;

pub use decrypt::{
    AccessPattern, DecryptedChunk, DecryptionContext, DecryptionManager, DecryptionMetrics,
};
pub use hybridcipher::HybridCipher;
pub use lookup::{LookupManager, LookupResult, MigrationStatus};
pub use performance::{
    MemoryPressureMonitor, MetricsCollector, PerformanceManager, PerformanceSnapshot,
    PrefetchCoordinator,
};
pub use read::{ReadManager, ReadResult};
