//! Public, versioned dashboard contract authority and shared white dashboard.
//!
//! The [`contracts`] module remains the edition-neutral C0 authority. Runtime
//! projections and embedded assets consume that authority without adding host
//! enforcement, private matrices, policy decisions, or evaluation results.

pub mod assets;
pub mod claims;
pub mod community;
pub mod contract;
pub mod token_usage;
pub mod versions;
