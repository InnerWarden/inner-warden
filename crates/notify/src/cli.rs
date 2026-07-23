//! innerwarden's thin notification driver over the shared `innerwarden-notify` crate.
//!
//! The DECISION logic, resolve the config (env overrides a config file), then
//! build the per-channel requests for a verdict, lives in `plan()`, which is
//! pure (env + file content are injected) and fully unit-tested. Only the actual
//! env/file read and the `ureq` POST are I/O, and they are best-effort: a failed
//! notify never changes the guard's verdict or exit code.

use crate::{verdict_requests, NotifyConfig, NotifyFile, Request};
use serde_json::Value;

/// Parse `innerwarden notify` setter flags into (channel updates, run-a-test?). A
/// flag with no following value, or an unknown flag, is an error. Pure/tested;
/// the file read/write + test send are the thin I/O in `cmd`.
pub fn parse_set_args(args: &[String]) -> Result<(NotifyFile, bool), String> {
    let mut f = NotifyFile::default();
    let mut test = false;
    let mut i = 0;
    while i < args.len() {
        let flag = args[i].as_str();
        let mut value = || -> Result<String, String> {
            i += 1;
            args.get(i)
                .cloned()
                .ok_or_else(|| format!("{flag} needs a value"))
        };
        match flag {
            "--telegram-token" => f.telegram_token = Some(value()?),
            "--telegram-chat" => f.telegram_chat = Some(value()?),
            "--slack-webhook" => f.slack_webhook = Some(value()?),
            "--discord-webhook" => f.discord_webhook = Some(value()?),
            "--webhook-url" => f.webhook_url = Some(value()?),
            "--notify-review" => f.notify_review = Some(true),
            "--test" => test = true,
            other => return Err(format!("unknown flag `{other}`")),
        }
        i += 1;
    }
    Ok((f, test))
}

/// One-line status of which channels a resolved config has wired. Pure/tested.
pub fn status_line(cfg: &NotifyConfig) -> String {
    let mut on = Vec::new();
    if cfg.telegram.is_some() {
        on.push("telegram");
    }
    if cfg.slack_webhook.is_some() {
        on.push("slack");
    }
    if cfg.discord_webhook.is_some() {
        on.push("discord");
    }
    if cfg.webhook_url.is_some() {
        on.push("webhook");
    }
    if on.is_empty() {
        "no channels configured".to_string()
    } else {
        let review = if cfg.notify_review { " (+review)" } else { "" };
        format!("channels: {}{review}", on.join(", "))
    }
}

/// Resolve the config (env over an optional TOML file) and build the outbound
/// requests for `verdict`. Pure, the env getter and file content are injected,
/// so config precedence + request fan-out are tested without touching the disk.
pub fn plan(
    get_env: impl Fn(&str) -> Option<String>,
    file: Option<&str>,
    command: &str,
    verdict: &Value,
) -> Vec<Request> {
    let cfg = crate::resolved(get_env, file);
    verdict_requests(&cfg, command, verdict)
}

/// The synthetic verdict `--test` sends: a `deny` so every configured channel
/// fires, labelled as a test. Pure.
fn test_verdict() -> Value {
    serde_json::json!({
        "recommendation": "deny", "risk_score": 0,
        "explanation": "test alert from `innerwarden notify --test`"
    })
}

/// What `cmd` must do, computed purely from the setter args + existing file
/// content + env. This holds ALL of `cmd`'s branching (status vs set vs bad-flag
/// vs test) so it is unit-testable with no disk/env/network; `cmd` is then a thin
/// dispatch of the resulting I/O.
#[derive(Debug, PartialEq)]
pub enum Action {
    /// No args: print this one-line channel status.
    Status(String),
    /// Bad args: print this error to stderr, exit 2.
    Error(String),
    /// Set/test: write `write` (when `Some`) to the config file, then send `tests`.
    Apply {
        write: Option<String>,
        tests: Vec<Request>,
    },
}

/// Pure core of `cmd`. `existing_file` is the current config-file content (if any)
/// and `get_env` the environment getter, both injected so config precedence,
/// merge-on-set, and the `--test` fan-out are fully deterministic in tests.
pub fn compute(
    rest: &[String],
    existing_file: Option<&str>,
    get_env: impl Fn(&str) -> Option<String>,
) -> Action {
    if rest.is_empty() {
        let cfg = crate::resolved(&get_env, existing_file);
        return Action::Status(status_line(&cfg));
    }
    let (updates, test) = match parse_set_args(rest) {
        Ok(x) => x,
        Err(e) => return Action::Error(e),
    };
    let write = if updates.is_empty() {
        None
    } else {
        let existing = existing_file
            .and_then(|s| NotifyFile::parse(s).ok())
            .unwrap_or_default();
        Some(existing.overlay(updates).to_toml())
    };
    let tests = if test {
        plan(
            &get_env,
            existing_file,
            "innerwarden --test",
            &test_verdict(),
        )
    } else {
        Vec::new()
    };
    Action::Apply { write, tests }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn env<'a>(pairs: &'a [(&'a str, &'a str)]) -> impl Fn(&str) -> Option<String> + 'a {
        move |k| {
            pairs
                .iter()
                .find(|(kk, _)| *kk == k)
                .map(|(_, v)| v.to_string())
        }
    }

    #[test]
    fn plan_from_env_only_on_deny() {
        let reqs = plan(
            env(&[("IW_SLACK_WEBHOOK", "https://s")]),
            None,
            "rm -rf /",
            &json!({"recommendation":"deny","risk_score":90}),
        );
        assert_eq!(reqs.len(), 1);
        assert_eq!(reqs[0].url, "https://s"); // slack posts to the webhook URL as-is
    }

    #[test]
    fn plan_allow_is_empty() {
        let reqs = plan(
            env(&[("IW_SLACK_WEBHOOK", "https://s")]),
            None,
            "ls",
            &json!({"recommendation":"allow"}),
        );
        assert!(reqs.is_empty());
    }

    #[test]
    fn plan_env_overrides_file_and_file_fills_gaps() {
        let file = r#"slack_webhook = "https://file-slack"
                      discord_webhook = "https://file-discord""#;
        let reqs = plan(
            env(&[("IW_SLACK_WEBHOOK", "https://env-slack")]),
            Some(file),
            "rm -rf /",
            &json!({"recommendation":"deny"}),
        );
        // slack from env, discord from file -> 2 channels
        assert_eq!(reqs.len(), 2);
        assert!(reqs.iter().any(|r| r.url == "https://env-slack"));
        assert!(reqs.iter().any(|r| r.url == "https://file-discord"));
    }

    #[test]
    fn plan_file_only() {
        let reqs = plan(
            env(&[]),
            Some(r#"webhook_url = "https://w""#),
            "rm -rf /",
            &json!({"recommendation":"deny"}),
        );
        assert_eq!(reqs.len(), 1);
        assert_eq!(reqs[0].url, "https://w");
    }

    #[test]
    fn plan_review_needs_flag() {
        let base = "slack_webhook = \"https://s\"";
        assert!(plan(
            env(&[]),
            Some(base),
            "x",
            &json!({"recommendation":"review"})
        )
        .is_empty());
        let with_flag = "slack_webhook = \"https://s\"\nnotify_review = true";
        assert_eq!(
            plan(
                env(&[]),
                Some(with_flag),
                "x",
                &json!({"recommendation":"review"})
            )
            .len(),
            1
        );
    }

    #[test]
    fn plan_nothing_configured_is_empty() {
        assert!(plan(
            env(&[]),
            None,
            "rm -rf /",
            &json!({"recommendation":"deny"})
        )
        .is_empty());
        // a malformed file is ignored (treated as no file), not a panic
        assert!(plan(
            env(&[]),
            Some("== bad =="),
            "rm -rf /",
            &json!({"recommendation":"deny"})
        )
        .is_empty());
    }

    fn args(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn parse_set_args_all_channels() {
        let (f, test) = parse_set_args(&args(&[
            "--telegram-token",
            "t",
            "--telegram-chat",
            "c",
            "--slack-webhook",
            "https://s",
            "--discord-webhook",
            "https://d",
            "--webhook-url",
            "https://w",
            "--notify-review",
            "--test",
        ]))
        .unwrap();
        assert_eq!(f.telegram_token.as_deref(), Some("t"));
        assert_eq!(f.telegram_chat.as_deref(), Some("c"));
        assert_eq!(f.slack_webhook.as_deref(), Some("https://s"));
        assert_eq!(f.discord_webhook.as_deref(), Some("https://d"));
        assert_eq!(f.webhook_url.as_deref(), Some("https://w"));
        assert_eq!(f.notify_review, Some(true));
        assert!(test);
    }

    #[test]
    fn parse_set_args_partial_leaves_rest_none() {
        let (f, test) = parse_set_args(&args(&["--slack-webhook", "https://s"])).unwrap();
        assert_eq!(f.slack_webhook.as_deref(), Some("https://s"));
        assert!(f.telegram_token.is_none() && f.webhook_url.is_none());
        assert!(!test);
    }

    #[test]
    fn parse_set_args_errors() {
        assert!(parse_set_args(&args(&["--slack-webhook"])).is_err()); // value missing
        assert!(parse_set_args(&args(&["--bogus"])).is_err()); // unknown flag
    }

    #[test]
    fn status_line_reports_channels() {
        let cfg = NotifyConfig::resolve(env(&[
            ("IW_SLACK_WEBHOOK", "https://s"),
            ("IW_TELEGRAM_TOKEN", "t"),
            ("IW_TELEGRAM_CHAT", "c"),
            ("IW_NOTIFY_REVIEW", "1"),
        ]));
        let s = status_line(&cfg);
        assert!(s.contains("telegram") && s.contains("slack") && s.contains("+review"));
        assert_eq!(
            status_line(&NotifyConfig::default()),
            "no channels configured"
        );
    }

    #[test]
    fn compute_no_args_is_status_resolving_env_over_file() {
        // env slack + file discord -> status reports both channels.
        let a = compute(
            &[],
            Some(r#"discord_webhook = "https://d""#),
            env(&[("IW_SLACK_WEBHOOK", "https://s")]),
        );
        match a {
            Action::Status(s) => assert!(s.contains("slack") && s.contains("discord")),
            other => panic!("expected Status, got {other:?}"),
        }
    }

    #[test]
    fn compute_no_args_no_config_reports_none() {
        assert_eq!(
            compute(&[], None, env(&[])),
            Action::Status("no channels configured".into())
        );
    }

    #[test]
    fn compute_bad_flag_is_error() {
        match compute(&args(&["--bogus"]), None, env(&[])) {
            Action::Error(e) => assert!(e.contains("--bogus")),
            other => panic!("expected Error, got {other:?}"),
        }
    }

    #[test]
    fn compute_set_writes_merged_toml_keeping_existing() {
        // Existing file has discord; setting slack must KEEP discord and add slack.
        let a = compute(
            &args(&["--slack-webhook", "https://new-slack"]),
            Some(r#"discord_webhook = "https://keep-d""#),
            env(&[]),
        );
        match a {
            Action::Apply { write, tests } => {
                let toml = write.expect("a write");
                assert!(toml.contains("https://new-slack"), "slack set");
                assert!(toml.contains("https://keep-d"), "discord preserved");
                assert!(tests.is_empty(), "no --test -> no requests");
            }
            other => panic!("expected Apply, got {other:?}"),
        }
    }

    #[test]
    fn compute_test_only_sends_no_write() {
        // --test with a configured channel (from env) -> tests non-empty, no write.
        let a = compute(
            &args(&["--test"]),
            None,
            env(&[("IW_SLACK_WEBHOOK", "https://s")]),
        );
        match a {
            Action::Apply { write, tests } => {
                assert!(write.is_none(), "no channel set -> no write");
                assert_eq!(tests.len(), 1, "one configured channel -> one test request");
                assert_eq!(tests[0].url, "https://s");
            }
            other => panic!("expected Apply, got {other:?}"),
        }
    }

    #[test]
    fn compute_set_and_test_from_file_fires_the_just_set_channel() {
        // Set slack AND --test: the test fan-out reads the SAME existing file, so a
        // channel already in the file fires. (The just-written slack is not yet in
        // `existing_file`, mirroring cmd's read-before-write; the file webhook is.)
        let a = compute(
            &args(&["--slack-webhook", "https://s", "--test"]),
            Some(r#"webhook_url = "https://w""#),
            env(&[]),
        );
        match a {
            Action::Apply { write, tests } => {
                assert!(write.unwrap().contains("https://s"));
                assert_eq!(tests.len(), 1);
                assert_eq!(tests[0].url, "https://w");
            }
            other => panic!("expected Apply, got {other:?}"),
        }
    }

    #[test]
    fn test_verdict_is_a_deny() {
        assert_eq!(test_verdict()["recommendation"], "deny");
    }
}
