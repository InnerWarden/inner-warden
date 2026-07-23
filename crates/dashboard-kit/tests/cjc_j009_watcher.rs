use serde_yaml::Value;

const CJC: &str = include_str!("../contracts/v1/CJC-090-v1.yaml");

#[test]
fn watcher_contract_keeps_policy_availability_separate_from_detection() {
    let contract: Value = serde_yaml::from_str(CJC).expect("valid CJC");
    let j009 = contract["journeys"]
        .as_sequence()
        .expect("journeys")
        .iter()
        .find(|journey| journey["id"].as_str() == Some("CJC-090-J009"))
        .expect("J009");

    let unavailable = j009["state_cases"]
        .as_sequence()
        .expect("state cases")
        .iter()
        .find(|case| case["state"].as_str() == Some("null"))
        .expect("unavailable policy state");
    let result = unavailable["result"].as_str().expect("state result");
    assert!(result.contains("unavailable"));
    assert!(result.contains("no configuration change"));

    let non_claims = j009["must_not_claim"]
        .as_sequence()
        .expect("non-claims")
        .iter()
        .filter_map(Value::as_str)
        .collect::<Vec<_>>()
        .join("\n");
    assert!(non_claims.contains("merely because an agent was detected"));
    assert!(non_claims.contains("prior configured mode"));
}
