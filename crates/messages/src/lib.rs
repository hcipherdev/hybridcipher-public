//! HybridCipher Message Types and Serialization
//!
//! This crate defines the message types used for communication in the HybridCipher
//! secure file-sharing system, including serialization and validation.

#![deny(missing_docs)]
#![warn(clippy::all, clippy::pedantic, clippy::cargo, clippy::nursery)]
#![allow(clippy::multiple_crate_versions)]

pub mod cutover;
pub mod error;
pub mod file_metadata;
pub mod group_update;
pub mod join_card;
pub mod transparency;
pub mod welcome;
