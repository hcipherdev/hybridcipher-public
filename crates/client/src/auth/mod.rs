//! Authentication module for OPAQUE-PAKE and device registration
//!
//! This module provides secure password-based authentication using OPAQUE-PAKE
//! protocol, which is resistant to offline dictionary attacks and provides
//! forward secrecy.

pub mod opaque;
pub mod registration;

pub use opaque::{OpaqueAuth, OpaqueError, OpaqueLoginResult};
pub use registration::{LoginFlow, RegistrationFlow};
