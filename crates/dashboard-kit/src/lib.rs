//! Public, versioned dashboard contract authority and shared white dashboard.
//!
//! [`contract`] is the edition-neutral C0 authority and [`contract_docs`] embeds
//! the v1 documents this crate owns, so a downstream build validates against the
//! exact bytes of the revision it pins instead of its own copy. Runtime
//! projections and embedded assets consume that authority without adding host
//! enforcement, private matrices, policy decisions, or evaluation results.

pub mod assets;
pub mod claims;
pub mod community;
pub mod contract;
pub mod contract_docs;
pub mod token_usage;
pub mod versions;
