use innerwarden_dashboard_kit::community::{build_bootstrap, CommunityProjectionInput};
use innerwarden_dashboard_kit::contract::{Availability, EffectiveMode, HealthState, StageAnswer};

fn input() -> CommunityProjectionInput {
    CommunityProjectionInput {
        generated_at: "2026-07-18T12:00:00.000Z".into(),
        generated_at_ms: 1_768_564_800_000,
        product_version: "0.16.4-rc.1".into(),
        platform_os: "linux".into(),
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
fn notification_delivery_is_explicitly_unavailable_to_the_read_only_dashboard() {
    let bootstrap = build_bootstrap(&input());
    let notifications = bootstrap
        .capabilities
        .iter()
        .find(|capability| capability.id == "community.notifications")
        .expect("notification capability");

    assert_eq!(notifications.availability, Availability::Unavailable);
    assert_eq!(notifications.effective_mode, EffectiveMode::Unknown);
    assert_eq!(notifications.health, HealthState::Unknown);
    assert_eq!(
        notifications.convergence.running.state,
        StageAnswer::Unknown
    );
    assert!(notifications.last_evidence.is_none());
    assert!(notifications.claims.is_empty());
}
