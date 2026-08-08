use std::collections::BTreeSet;

use serde_yaml::Value;

const CONTRACT: &str = include_str!("../contracts/v1/CJC-090-v1.yaml");
const FOUNDATION: &str = include_str!("../contracts/v1/dashboard-core-v1.openapi.yaml");

const JOURNEY_EVIDENCE: [(&str, &str, &str); 12] = [
    (
        "CJC-090-J001",
        "crates/dashboard-kit/web/tests/community/j001-posture.spec.ts",
        include_str!("../web/tests/community/j001-posture.spec.ts"),
    ),
    (
        "CJC-090-J002",
        "crates/dashboard-kit/web/tests/community/j002-decision.spec.ts",
        include_str!("../web/tests/community/j002-decision.spec.ts"),
    ),
    (
        "CJC-090-J003",
        "crates/dashboard-kit/web/tests/community/j003-sessions.spec.ts",
        include_str!("../web/tests/community/j003-sessions.spec.ts"),
    ),
    (
        "CJC-090-J004",
        "crates/dashboard-kit/web/tests/community/j004-activity.spec.ts",
        include_str!("../web/tests/community/j004-activity.spec.ts"),
    ),
    (
        "CJC-090-J005",
        "crates/dashboard-kit/web/tests/community/j005-navigation.spec.ts",
        include_str!("../web/tests/community/j005-navigation.spec.ts"),
    ),
    (
        "CJC-090-J006",
        "crates/dashboard-kit/tests/cjc_j006_allow_mute.rs",
        include_str!("cjc_j006_allow_mute.rs"),
    ),
    (
        "CJC-090-J007",
        "crates/dashboard-kit/tests/cjc_j007_ai_jail.rs",
        include_str!("cjc_j007_ai_jail.rs"),
    ),
    (
        "CJC-090-J008",
        "crates/dashboard-kit/web/tests/community/j008-agents.spec.ts",
        include_str!("../web/tests/community/j008-agents.spec.ts"),
    ),
    (
        "CJC-090-J009",
        "crates/dashboard-kit/tests/cjc_j009_watcher.rs",
        include_str!("cjc_j009_watcher.rs"),
    ),
    (
        "CJC-090-J010",
        "crates/dashboard-kit/web/tests/community/j010-tokens.spec.ts",
        include_str!("../web/tests/community/j010-tokens.spec.ts"),
    ),
    (
        "CJC-090-J011",
        "crates/dashboard-kit/web/tests/community/j011-graph.spec.ts",
        include_str!("../web/tests/community/j011-graph.spec.ts"),
    ),
    (
        "CJC-090-J012",
        "crates/dashboard-kit/tests/cjc_j012_notifications.rs",
        include_str!("cjc_j012_notifications.rs"),
    ),
];

fn mapping<'a>(value: &'a Value, key: &str) -> &'a serde_yaml::Mapping {
    value
        .get(key)
        .and_then(Value::as_mapping)
        .unwrap_or_else(|| panic!("{key} must be a mapping"))
}

#[test]
fn frozen_contract_keeps_the_pinned_community_baseline() {
    let contract: Value = serde_yaml::from_str(CONTRACT).expect("CJC must be valid YAML");
    assert_eq!(
        contract["contract_schema"].as_str(),
        Some("innerwarden.community-journey-contract.v1")
    );
    assert_eq!(contract["contract_id"].as_str(), Some("CJC-090"));
    assert_eq!(contract["version"].as_str(), Some("CJC-090-v1"));
    assert_eq!(contract["status"].as_str(), Some("frozen"));
    assert_eq!(contract["immutable"].as_bool(), Some(true));

    let baseline = mapping(&contract, "baseline");
    assert_eq!(
        baseline["git_commit"].as_str(),
        Some(innerwarden_dashboard_kit::versions::COMMUNITY_BASELINE_COMMIT)
    );
    assert_eq!(baseline["edition"].as_str(), Some("community"));
}

#[test]
fn all_twelve_journeys_are_unique_and_have_acceptance_ids() {
    let contract: Value = serde_yaml::from_str(CONTRACT).expect("CJC must be valid YAML");
    let journeys = contract["journeys"]
        .as_sequence()
        .expect("journeys must be a sequence");
    assert_eq!(journeys.len(), 12);

    let mut journey_ids = BTreeSet::new();
    let mut acceptance_ids = BTreeSet::new();
    for journey in journeys {
        let id = journey["id"].as_str().expect("journey id");
        let acceptance_id = journey["acceptance"]["id"].as_str().expect("acceptance id");
        assert!(
            journey_ids.insert(id.to_owned()),
            "duplicate journey id {id}"
        );
        assert!(
            acceptance_ids.insert(acceptance_id.to_owned()),
            "duplicate acceptance id {acceptance_id}"
        );
    }

    assert_eq!(
        journey_ids,
        (1..=12)
            .map(|index| format!("CJC-090-J{index:03}"))
            .collect::<BTreeSet<_>>()
    );
    assert_eq!(
        acceptance_ids,
        (1..=12)
            .map(|index| format!("CJC-090-AT-{index:03}"))
            .collect::<BTreeSet<_>>()
    );
}

#[test]
fn all_twelve_journeys_have_exact_executable_evidence_locators() {
    let contract: Value = serde_yaml::from_str(CONTRACT).expect("CJC must be valid YAML");
    let contract_ids = contract["journeys"]
        .as_sequence()
        .expect("journeys must be a sequence")
        .iter()
        .filter_map(|journey| journey["id"].as_str())
        .collect::<BTreeSet<_>>();
    let evidence_ids = JOURNEY_EVIDENCE
        .iter()
        .map(|(journey_id, _, _)| *journey_id)
        .collect::<BTreeSet<_>>();

    assert_eq!(evidence_ids, contract_ids);
    assert_eq!(JOURNEY_EVIDENCE.len(), 12);
    for (journey_id, locator, source) in JOURNEY_EVIDENCE {
        assert!(
            !locator.trim().is_empty() && !source.trim().is_empty(),
            "{journey_id} evidence locator must resolve to a non-empty tracked source"
        );
        assert!(
            locator.starts_with("crates/dashboard-kit/"),
            "{journey_id} evidence must remain within dashboard-kit"
        );
        let short_id = journey_id
            .rsplit('-')
            .next()
            .expect("journey suffix")
            .to_ascii_lowercase();
        assert!(
            locator.to_ascii_lowercase().contains(&short_id),
            "{journey_id} locator must name its own journey, got {locator}"
        );
        let executable_marker = if locator.ends_with(".rs") {
            "#[test]"
        } else {
            "test("
        };
        assert!(
            source.contains(executable_marker),
            "{journey_id} evidence must contain an executable test marker"
        );
        if locator.ends_with(".spec.ts") {
            assert!(
                source.contains(journey_id),
                "{journey_id} browser evidence must declare the full journey id"
            );
        }
    }
}

#[test]
fn bootstrap_digest_pins_the_exact_frozen_contract_bytes() {
    // Rendered through the crate's own `content_sha256` so the digest string
    // compared here is produced by the exact code path that renders every other
    // `sha256:` identity in this crate. A private copy of the hex formatting
    // could drift from the real one and this test would not notice.
    let actual = innerwarden_dashboard_kit::assets::content_sha256(CONTRACT.as_bytes());
    assert_eq!(
        actual,
        innerwarden_dashboard_kit::versions::COMMUNITY_JOURNEY_CONTRACT_DIGEST
    );
    let reference = innerwarden_dashboard_kit::versions::community_journey_contract();
    assert_eq!(reference.id, "CJC-090");
    assert_eq!(reference.version, "CJC-090-v1");
    assert_eq!(reference.digest, actual);
}

#[test]
fn contract_preserves_the_non_claim_and_read_only_invariants() {
    let contract: Value = serde_yaml::from_str(CONTRACT).expect("CJC must be valid YAML");
    let invariants = contract["global_invariants"]
        .as_sequence()
        .expect("global invariants")
        .iter()
        .filter_map(Value::as_str)
        .collect::<Vec<_>>()
        .join("\n");

    assert!(invariants.contains("Community dashboard HTTP surface remains read-only"));
    assert!(invariants.contains("deny recommendation is not a verified block"));
    assert!(invariants.contains("Missing numeric history is null or unavailable"));
    assert!(invariants.contains("independent post-compromise host or kernel boundary"));
}

#[test]
fn tracked_core_keeps_the_two_community_foundation_routes_read_only() {
    let openapi: Value = serde_yaml::from_str(FOUNDATION).expect("OpenAPI must be valid YAML");
    let paths = openapi["paths"].as_mapping().expect("OpenAPI paths");
    for path in ["/bootstrap", "/posture"] {
        let operations = paths[path].as_mapping().expect("path operations");
        assert!(operations.contains_key("get"));
        assert_eq!(operations.len(), 1, "{path} must stay read-only");
    }
}

#[test]
fn platform_candidate_name_matches_the_serialized_rust_contract() {
    use innerwarden_dashboard_kit::contract::PlatformStatus;

    let wire = serde_json::to_value(PlatformStatus {
        os: "linux".into(),
        architecture: "x86_64".into(),
        enterprise_candidate: true,
        reason_code: None,
    })
    .expect("serialize platform");
    assert_eq!(wire["enterprise_candidate"], true);
    assert!(wire.get("enterprise_eligible").is_none());

    let openapi: Value = serde_yaml::from_str(FOUNDATION).expect("OpenAPI must be valid YAML");
    let platform = &openapi["components"]["schemas"]["PlatformStatus"];
    let properties = platform["properties"]
        .as_mapping()
        .expect("platform properties");
    assert!(properties.contains_key("enterprise_candidate"));
    assert!(!properties.contains_key("enterprise_eligible"));
}

#[test]
fn active_claim_records_pin_the_full_matrix_and_layers_carry_claims() {
    let openapi: Value = serde_yaml::from_str(FOUNDATION).expect("OpenAPI must be valid YAML");
    let schemas = &openapi["components"]["schemas"];

    assert_eq!(
        schemas["ClaimRecord"]["$ref"].as_str(),
        Some("./dashboard-common-v1.schema.json#/$defs/ClaimRecord")
    );

    let capability_required = schemas["CapabilityStatus"]["required"]
        .as_sequence()
        .expect("CapabilityStatus.required")
        .iter()
        .filter_map(Value::as_str)
        .collect::<BTreeSet<_>>();
    assert!(capability_required.contains("claims"));

    let layer_required = schemas["ProtectionLayer"]["required"]
        .as_sequence()
        .expect("ProtectionLayer.required")
        .iter()
        .filter_map(Value::as_str)
        .collect::<BTreeSet<_>>();
    assert!(layer_required.contains("evidence"));
}
