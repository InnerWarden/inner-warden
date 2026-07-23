//! Active Defence gate + upsell (Model A).
//!
//! The Community binary IS the single `innerwarden` CLI. When a HOST command (`get`,
//! `action`, `exec-gate`, ...) - which only Active Defence provides - is typed:
//!   - if Active Defence is installed on this machine, the command is DELEGATED to
//!     its CLI transparently (so the one `innerwarden` command does everything);
//!   - if not, the attempt becomes a CALL TO ACQUIRE Active Defence instead of an
//!     "unknown command" - the Community CLI is the funnel.
//!
//! The upsell text is centralized + OVERRIDABLE (env `IW_AD_MESSAGE`, else
//! `~/.config/innerwarden/ad-message.txt`) so a promo / trial offer can be
//! swapped WITHOUT a rebuild. The pure bits (the host-command set, the default
//! message) are unit-tested; the process delegation is the thin I/O.

/// The host commands Active Defence provides. Typing one on a machine without AD
/// shows the upsell; with AD it delegates. Kept in sync with the Active Defence ctl's
/// top-level host verbs (a curated set of the ones a user reaches for first).
pub const HOST_COMMANDS: &[&str] = &[
    "get",       // incidents / decisions / status / metrics
    "action",    // block / unblock an IP
    "trust",     // trusted entities + suppression
    "stream",    // live incidents/events
    "rule",      // detection rules
    "system",    // doctor / harden / test / export / backup
    "exec-gate", // the in-kernel execution gate
    "scan",      // host security audit
    "harden",    // apply host hardening
];

/// True when `cmd` is a host command the Community binary gates. Pure.
pub fn is_host_command(cmd: &str) -> bool {
    HOST_COMMANDS.contains(&cmd)
}

/// The default upsell message shown when a host command runs without Active
/// Defence. `prog` is the invoked name, `command` the host verb attempted. Pure.
pub fn default_message(prog: &str, command: &str) -> String {
    format!(
        "\n  🛡  `{prog} {command}` is part of InnerWarden Active Defence - the licensed host layer:\n\
        \x20     host telemetry + response · incident triage · on Linux: kernel eBPF + execution gate.\n\
        \n\
        \x20 Not active on this machine - you're running {community}, which keeps\n\
        \x20 screening your agent's commands. Active Defence adds host EDR + response; on Linux, kernel enforcement.\n\
        \n\
        \x20 → Get Active Defence:  https://innerwarden.com/defend\n",
        community = crate::COMMUNITY_NAME,
    )
}

/// The upsell text: an override (env `IW_AD_MESSAGE`, else the override file's
/// contents) if set, otherwise the default. The override is how a promo / trial
/// offer changes the pitch without a rebuild. `read_file` is injected so this is
/// pure/testable; the real caller reads `~/.config/innerwarden/ad-message.txt`.
pub fn message(
    prog: &str,
    command: &str,
    env: impl Fn(&str) -> Option<String>,
    read_file: impl Fn() -> Option<String>,
) -> String {
    if let Some(m) = env("IW_AD_MESSAGE") {
        let m = m.trim();
        if !m.is_empty() {
            return m.to_string();
        }
    }
    if let Some(m) = read_file() {
        let m = m.trim();
        if !m.is_empty() {
            return m.to_string();
        }
    }
    default_message(prog, command)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_commands_are_gated_but_community_verbs_are_not() {
        assert!(is_host_command("get") && is_host_command("exec-gate"));
        // Community verbs are NOT host commands (they must never upsell)
        for community in [
            "check",
            "agents",
            "setup",
            "notify",
            "dashboard",
            "graph",
            "proxy",
        ] {
            assert!(!is_host_command(community), "{community} must not be gated");
        }
    }

    #[test]
    fn default_message_pitches_active_defence_with_a_cta() {
        let m = default_message("innerwarden", "get");
        assert!(m.contains("innerwarden get"));
        assert!(m.contains("Active Defence"));
        assert!(m.contains(crate::COMMUNITY_NAME));
        assert!(m.contains("innerwarden.com/defend"), "has a call to action");
    }

    #[test]
    fn env_and_file_override_the_default() {
        // env wins
        let m = message(
            "iw",
            "get",
            |k| (k == "IW_AD_MESSAGE").then(|| "PROMO!".into()),
            || None,
        );
        assert_eq!(m, "PROMO!");
        // file used when env is unset/blank
        let m = message("iw", "get", |_| None, || Some("  trial offer  ".into()));
        assert_eq!(m, "trial offer");
        // blank override falls through to default
        let m = message("iw", "get", |_| Some("   ".into()), || None);
        assert!(m.contains("Active Defence"));
    }
}
