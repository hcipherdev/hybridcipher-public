//! Migration tracking and coordination for FUSE operations
//!
//! This module provides comprehensive migration tracking capabilities
//! including progress monitoring, opportunistic rewrapping, and
//! migration status overlay functionality.

pub mod overlay;
pub mod rewrap;
pub mod tracker;

pub use overlay::OverlayFile;
pub use rewrap::OpportunisticRewrapper;
pub use tracker::MigrationTracker;
