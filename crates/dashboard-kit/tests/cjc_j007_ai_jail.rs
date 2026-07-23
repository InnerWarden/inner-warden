use innerwarden_dashboard_kit::community::{build_bootstrap, CommunityProjectionInput};
use innerwarden_dashboard_kit::contract::{Availability, EffectiveMode, HealthState, SupportLevel};

fn input(os: &str) -> CommunityProjectionInput {
    CommunityProjectionInput {
        generated_at: "2026-07-18T12:00:00.000Z".into(),
        generated_at_ms: 1_768_564_800_000,
        product_version: "0.16.4-rc.1".into(),
        platform_os: os.into(),
        platform_architecture: "x86_64".into(),
        exposed: false,
        configured_guardrail_mode: EffectiveMode::Disabled,
        guarded_agents: 0,
        discovery_availability: Availability::Unavailable,
        discovery_observed_at_ms: None,
        discovery_freshness_budget_seconds: 65,
        token_availability: Availability::Unavailable,
        token_observed_at_ms: None,
        token_freshness_budget_seconds: 660,
        local_record_availability: Availability::Unavailable,
        local_record_observed_at_ms: None,
        local_record_freshness_budget_seconds: 30,
    }
}

#[test]
fn dashboard_never_turns_platform_support_into_a_jailed_runtime_claim() {
    for os in ["linux", "macos"] {
        let bootstrap = build_bootstrap(&input(os));
        let jail = bootstrap
            .capabilities
            .iter()
            .find(|capability| capability.id == "community.ai_jail")
            .expect("AI Jail capability");
        assert_eq!(jail.support, SupportLevel::Supported);
        assert_eq!(jail.availability, Availability::Unknown);
        assert_eq!(jail.effective_mode, EffectiveMode::Unknown);
        assert_eq!(jail.health, HealthState::Unknown);
        assert!(jail.last_evidence.is_none());
        assert!(jail.claims.is_empty());
    }
}

#[test]
fn unsupported_platform_is_explicit_without_becoming_disabled_or_healthy() {
    let bootstrap = build_bootstrap(&input("windows"));
    let jail = bootstrap
        .capabilities
        .iter()
        .find(|capability| capability.id == "community.ai_jail")
        .expect("AI Jail capability");
    assert_eq!(jail.support, SupportLevel::Unsupported);
    assert_eq!(jail.availability, Availability::Unknown);
    assert_eq!(jail.effective_mode, EffectiveMode::Unknown);
    assert_eq!(jail.health, HealthState::Unknown);
    assert!(jail.claims.is_empty());
}
