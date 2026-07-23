use serde_yaml::Value;

const CJC: &str = include_str!("../contracts/v1/CJC-090-v1.yaml");
const FOUNDATION: &str = include_str!("../contracts/v1/dashboard-core-v1.openapi.yaml");

fn journey<'a>(contract: &'a Value, id: &str) -> &'a Value {
    contract["journeys"]
        .as_sequence()
        .expect("journeys")
        .iter()
        .find(|journey| journey["id"].as_str() == Some(id))
        .expect("pinned journey")
}

#[test]
fn suppression_remains_a_local_cli_policy_not_a_dashboard_control_plane() {
    let contract: Value = serde_yaml::from_str(CJC).expect("valid CJC");
    let j006 = journey(&contract, "CJC-090-J006");
    assert_eq!(j006["baseline_channels"]["cli"].as_str(), Some("expected"));
    assert_eq!(
        j006["baseline_channels"]["white_dashboard"].as_str(),
        Some("unsupported")
    );

    let non_claims = j006["must_not_claim"]
        .as_sequence()
        .expect("J006 non-claims")
        .iter()
        .filter_map(Value::as_str)
        .collect::<Vec<_>>()
        .join("\n");
    assert!(non_claims.contains("Mute is a broad allowlist"));
    assert!(non_claims.contains("UI acknowledgement changed effective policy"));

    let openapi: Value = serde_yaml::from_str(FOUNDATION).expect("valid OpenAPI");
    for (path, operations) in openapi["paths"].as_mapping().expect("dashboard paths") {
        let operations = operations.as_mapping().expect("path operations");
        let path = path.as_str().expect("path name");
        assert!(!path.contains("allow") && !path.contains("mute"));
        for (method, operation) in operations {
            if method.as_str() != Some("get") {
                assert_eq!(
                    operation["x-innerwarden-auth-profile"].as_str(),
                    Some("enterprise-read-write")
                );
                assert_ne!(
                    operation["x-innerwarden-community-loopback-read-exception"].as_bool(),
                    Some(true)
                );
            }
        }
    }
}
