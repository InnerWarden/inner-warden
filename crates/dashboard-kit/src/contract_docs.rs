//! The v1 contract documents this crate owns, embedded so a downstream crate
//! can validate against the exact bytes a pinned revision ships.
//!
//! The Enterprise dashboard is built from these documents plus its own
//! (assurance matrix, privileged actions, the full proof report). Its
//! conformance suite has to read BOTH halves, and the obvious way to give it the
//! shared half -- copying these files into the other repository -- creates two
//! copies of a contract that must not disagree. That is the same fork that left
//! an unstyled screen and a stranded UI fix behind the last time it happened
//! here, and a contract is a worse thing to fork than a stylesheet.
//!
//! So the shared half is read from the dependency, at the revision `Cargo.toml`
//! pins, and only the Enterprise-only documents live downstream.

/// `dashboard-common-v1.schema.json` -- the shared vocabulary every other v1
/// document refers to.
pub const DASHBOARD_COMMON_SCHEMA: &str =
    include_str!("../contracts/v1/dashboard-common-v1.schema.json");

/// `community-journey-contract-v1.schema.json` -- the schema the CJC is
/// validated against.
pub const COMMUNITY_JOURNEY_CONTRACT_SCHEMA: &str =
    include_str!("../contracts/v1/community-journey-contract-v1.schema.json");

/// `dashboard-core-v1.openapi.yaml` -- the API surface both editions serve.
pub const DASHBOARD_CORE_OPENAPI: &str =
    include_str!("../contracts/v1/dashboard-core-v1.openapi.yaml");

/// `CJC-090-v1.yaml` -- the Community Journey Contract itself.
pub const COMMUNITY_JOURNEY_CONTRACT: &str = include_str!("../contracts/v1/CJC-090-v1.yaml");

/// `enterprise-proof-report-v1.schema.json` as it exists HERE: a placeholder.
///
/// The real schema belongs to Active Defence, and this stub exists only so the
/// shared OpenAPI document still resolves in the Community build. Exposed so a
/// consumer can assert it is looking at the stub rather than silently validating
/// against an empty object.
pub const ENTERPRISE_PROOF_REPORT_PLACEHOLDER: &str =
    include_str!("../contracts/v1/enterprise-proof-report-v1.schema.json");

/// `CJC-090-compatibility.md` -- the CJC compatibility record.
pub const COMMUNITY_JOURNEY_COMPATIBILITY: &str =
    include_str!("../contracts/v1/CJC-090-compatibility.md");

/// `C1-contract-compatibility.md` -- the C1-prototype-to-C0 compatibility map.
pub const C1_CONTRACT_COMPATIBILITY: &str =
    include_str!("../contracts/v1/C1-contract-compatibility.md");

/// Look a shared document up by the file name the contracts directory uses.
///
/// Returns `None` for a document this crate does not own -- notably the
/// Enterprise assurance-matrix and privileged-actions schemas, which is the
/// point: a downstream conformance suite must not be able to silently fall back
/// to a Community stand-in for a document that only exists downstream.
pub fn shared_document(name: &str) -> Option<&'static str> {
    match name {
        "dashboard-common-v1.schema.json" => Some(DASHBOARD_COMMON_SCHEMA),
        "community-journey-contract-v1.schema.json" => Some(COMMUNITY_JOURNEY_CONTRACT_SCHEMA),
        "dashboard-core-v1.openapi.yaml" => Some(DASHBOARD_CORE_OPENAPI),
        "CJC-090-v1.yaml" => Some(COMMUNITY_JOURNEY_CONTRACT),
        "CJC-090-compatibility.md" => Some(COMMUNITY_JOURNEY_COMPATIBILITY),
        "C1-contract-compatibility.md" => Some(C1_CONTRACT_COMPATIBILITY),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_shared_document_is_embedded_and_parses() {
        for name in [
            "dashboard-common-v1.schema.json",
            "community-journey-contract-v1.schema.json",
        ] {
            let raw = shared_document(name).expect("document must be embedded");
            serde_json::from_str::<serde_json::Value>(raw)
                .unwrap_or_else(|error| panic!("{name} must be valid JSON: {error}"));
        }
        for name in ["dashboard-core-v1.openapi.yaml", "CJC-090-v1.yaml"] {
            let raw = shared_document(name).expect("document must be embedded");
            serde_yaml::from_str::<serde_yaml::Value>(raw)
                .unwrap_or_else(|error| panic!("{name} must be valid YAML: {error}"));
        }
        for name in ["CJC-090-compatibility.md", "C1-contract-compatibility.md"] {
            assert!(
                !shared_document(name)
                    .expect("document must be embedded")
                    .is_empty(),
                "{name} must not be empty"
            );
        }
    }

    /// The Enterprise-only documents must NOT resolve here. A downstream suite
    /// that asked for one and got a Community answer would report conformance
    /// against a document the product does not actually serve.
    #[test]
    fn enterprise_only_documents_do_not_resolve_to_a_community_stand_in() {
        for name in [
            "assurance-matrix-v1.schema.json",
            "privileged-actions-v1.schema.json",
        ] {
            assert!(
                shared_document(name).is_none(),
                "{name} is Enterprise-only and must not be answered from this crate"
            );
        }
    }

    /// The proof-report schema here is a placeholder, and saying so is the whole
    /// reason it exists. If it ever grows a real `properties` block, the split
    /// has leaked and the Enterprise contract is being published publicly.
    #[test]
    fn the_proof_report_schema_here_is_still_only_a_placeholder() {
        let document: serde_json::Value =
            serde_json::from_str(ENTERPRISE_PROOF_REPORT_PLACEHOLDER).expect("valid JSON");
        assert!(
            document.get("properties").is_none(),
            "the Community copy of the proof-report schema has gained a real body; \
             the Enterprise contract belongs in Active Defence"
        );
        assert!(
            shared_document("enterprise-proof-report-v1.schema.json").is_none(),
            "the placeholder must never be served as the shared answer for this name"
        );
    }
}
