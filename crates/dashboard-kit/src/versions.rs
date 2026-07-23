//! Immutable identifiers shared by fixtures, producers and consumers.

use crate::contract::{Canonicalization, VersionRef};

pub const SCHEMA_VERSION: &str = "innerwarden.dashboard.v1";
pub const COMMUNITY_JOURNEY_CONTRACT_ID: &str = "CJC-090";
pub const COMMUNITY_JOURNEY_CONTRACT: &str = "CJC-090-v1";
pub const COMMUNITY_BASELINE_COMMIT: &str = "de484c34c47164a159f012c863b91cd9f1b001d3";
pub const COMMUNITY_JOURNEY_CONTRACT_DIGEST: &str =
    "sha256:d9f4fdd94ff1bb238e049fcf2fbed96acc24c32f7c821bc34c366949f7feab87";
pub const ASSURANCE_MATRIX: &str = "AM-090-v1";
pub const AUTHORIZATION_MATRIX: &str = "PAAM-090-v1";

pub fn community_journey_contract() -> VersionRef {
    VersionRef {
        id: COMMUNITY_JOURNEY_CONTRACT_ID.into(),
        version: COMMUNITY_JOURNEY_CONTRACT.into(),
        canonicalization: Canonicalization::RawUtf8BytesSha256,
        digest: COMMUNITY_JOURNEY_CONTRACT_DIGEST.into(),
    }
}
