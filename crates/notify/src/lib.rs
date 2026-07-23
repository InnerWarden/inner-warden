//! Shared user-feedback notification layer for InnerWarden.
//!
//! This crate is PURE, it resolves the notification config, builds the
//! per-channel HTTP payloads, and formats the message text. It does NOT send
//! anything: each product owns its transport (Community's `innerwarden` sends with
//! a blocking `ureq` client; Active Defence sends with its async `reqwest`
//! client). Sharing the config + payload logic here preserves notifications
//! across an upgrade: both products resolve the SAME channels (Telegram / Slack /
//! Discord / webhook) from the SAME config, so a user who configured Telegram
//! once for Community's guardrail alerts also receives Active Defence incident
//! alerts on that exact channel.
//!
//! Config precedence: environment variables override a config-file (TOML) value,
//! so an operator can set a token in a file and still override it per-process.
//!
//! Environment variables (canonical, shared by both products):
//!   IW_TELEGRAM_TOKEN + IW_TELEGRAM_CHAT   Telegram bot sendMessage
//!   IW_SLACK_WEBHOOK                        Slack incoming webhook URL
//!   IW_DISCORD_WEBHOOK                      Discord webhook URL
//!   IW_WEBHOOK_URL                          generic JSON POST
//!   IW_NOTIFY_REVIEW=1                      also notify on `review` (not only `deny`)

/// The `notify` CLI logic (flag parsing + the set/status action), shared so the
/// Community's `innerwarden notify` and Active Defence's `innerwarden notify`
/// behave identically.
pub mod cli;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

/// A single outbound notification request: where to POST and the body to send.
/// Concrete (not a live client) so the whole fan-out is testable without a network.
#[derive(Debug, Clone, PartialEq)]
pub struct Request {
    pub url: String,
    pub body: String,
    /// Always `application/json` for these channels; kept explicit for the sender.
    pub json: bool,
}

/// The resolved notification config: which channels are wired.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct NotifyConfig {
    pub telegram: Option<(String, String)>, // (bot token, chat id)
    pub slack_webhook: Option<String>,
    pub discord_webhook: Option<String>,
    pub webhook_url: Option<String>,
    /// Notify on `review` too, not only `deny`.
    pub notify_review: bool,
}

/// The TOML shape of a notify config file (all fields optional). Also the
/// setter model for `innerwarden notify --telegram-token …`: a `None` field means
/// "leave as-is", a `Some` field means "set to this".
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct NotifyFile {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub telegram_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub telegram_chat: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub slack_webhook: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub discord_webhook: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub webhook_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notify_review: Option<bool>,
}

impl NotifyFile {
    /// Parse an existing config file (empty string = empty config).
    pub fn parse(s: &str) -> Result<Self, toml::de::Error> {
        toml::from_str(s)
    }

    /// Overlay `updates` onto `self`: every `Some` field in `updates` replaces
    /// the corresponding field; `None` in `updates` keeps `self`'s value. This is
    /// how `innerwarden notify --slack-webhook X` sets one channel without wiping the
    /// others already in the file.
    pub fn overlay(self, updates: NotifyFile) -> Self {
        NotifyFile {
            telegram_token: updates.telegram_token.or(self.telegram_token),
            telegram_chat: updates.telegram_chat.or(self.telegram_chat),
            slack_webhook: updates.slack_webhook.or(self.slack_webhook),
            discord_webhook: updates.discord_webhook.or(self.discord_webhook),
            webhook_url: updates.webhook_url.or(self.webhook_url),
            notify_review: updates.notify_review.or(self.notify_review),
        }
    }

    /// Serialize back to TOML (omitting unset fields).
    pub fn to_toml(&self) -> String {
        toml::to_string_pretty(self).unwrap_or_default()
    }

    /// True when no field is set.
    pub fn is_empty(&self) -> bool {
        *self == NotifyFile::default()
    }
}

fn clean(v: Option<String>) -> Option<String> {
    v.filter(|s| !s.trim().is_empty())
}

impl NotifyConfig {
    /// Resolve from an environment getter (injected so tests are deterministic).
    pub fn resolve(get: impl Fn(&str) -> Option<String>) -> Self {
        let telegram = match (
            clean(get("IW_TELEGRAM_TOKEN")),
            clean(get("IW_TELEGRAM_CHAT")),
        ) {
            (Some(t), Some(c)) => Some((t, c)),
            _ => None,
        };
        NotifyConfig {
            telegram,
            slack_webhook: clean(get("IW_SLACK_WEBHOOK")),
            discord_webhook: clean(get("IW_DISCORD_WEBHOOK")),
            webhook_url: clean(get("IW_WEBHOOK_URL")),
            notify_review: get("IW_NOTIFY_REVIEW")
                .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
                .unwrap_or(false),
        }
    }

    /// Parse a TOML config file into a config. Empty string / no keys = empty config.
    pub fn from_toml_str(s: &str) -> Result<Self, toml::de::Error> {
        let f: NotifyFile = toml::from_str(s)?;
        let telegram = match (clean(f.telegram_token), clean(f.telegram_chat)) {
            (Some(t), Some(c)) => Some((t, c)),
            _ => None,
        };
        Ok(NotifyConfig {
            telegram,
            slack_webhook: clean(f.slack_webhook),
            discord_webhook: clean(f.discord_webhook),
            webhook_url: clean(f.webhook_url),
            notify_review: f.notify_review.unwrap_or(false),
        })
    }

    /// Fill any channel left `None` on `self` from `fallback`. Used to layer env
    /// (higher precedence, `self`) over a config file (`fallback`). `notify_review`
    /// is OR-ed so either source can enable it.
    pub fn or_else(mut self, fallback: NotifyConfig) -> Self {
        self.telegram = self.telegram.or(fallback.telegram);
        self.slack_webhook = self.slack_webhook.or(fallback.slack_webhook);
        self.discord_webhook = self.discord_webhook.or(fallback.discord_webhook);
        self.webhook_url = self.webhook_url.or(fallback.webhook_url);
        self.notify_review = self.notify_review || fallback.notify_review;
        self
    }

    /// True when at least one channel is configured.
    pub fn any(&self) -> bool {
        self.telegram.is_some()
            || self.slack_webhook.is_some()
            || self.discord_webhook.is_some()
            || self.webhook_url.is_some()
    }
}

/// The shared notify config-file path, resolved purely from an env getter: the
/// override `IW_NOTIFY_CONFIG`, else `$HOME/.config/innerwarden/notify.toml`. This
/// is the ONE place the path is defined so Community and Active Defence
/// read the SAME file. Returns `None` when neither is set (no `HOME`).
pub fn config_path(get: impl Fn(&str) -> Option<String>) -> Option<std::path::PathBuf> {
    if let Some(p) = clean(get("IW_NOTIFY_CONFIG")) {
        return Some(std::path::PathBuf::from(p));
    }
    clean(get("HOME")).map(|h| std::path::PathBuf::from(h).join(".config/innerwarden/notify.toml"))
}

/// Resolve the effective config: environment variables win, an optional config
/// file (its TOML contents) fills the gaps. Pure, both inputs injected, so the
/// precedence is identical and tested for both products. This is the single resolver
/// Community and Active Defence both call.
pub fn resolved(get_env: impl Fn(&str) -> Option<String>, file: Option<&str>) -> NotifyConfig {
    let env_cfg = NotifyConfig::resolve(get_env);
    match file.and_then(|s| NotifyConfig::from_toml_str(s).ok()) {
        Some(f) => env_cfg.or_else(f), // env wins, file fills the gaps
        None => env_cfg,
    }
}

/// Should this verdict be notified? `deny` always; `review` only when opted in.
pub fn should_notify(recommendation: &str, notify_review: bool) -> bool {
    recommendation == "deny" || (notify_review && recommendation == "review")
}

/// The `recommendation` string of a verdict, defaulting to "allow" when absent.
pub fn recommendation_of(verdict: &Value) -> &str {
    verdict
        .get("recommendation")
        .and_then(|r| r.as_str())
        .unwrap_or("allow")
}

/// A short, human-readable one-line summary of a guardrail verdict for a chat
/// message. Truncates the command so a runaway payload cannot flood the channel.
pub fn format_verdict(command: &str, verdict: &Value) -> String {
    let rec = recommendation_of(verdict);
    let icon = match rec {
        "deny" => "🚫",
        "review" => "⚠️",
        _ => "✓",
    };
    let mut msg = format!(
        "{icon} InnerWarden guardrail: {} `{}`",
        rec.to_uppercase(),
        truncate(command, 200)
    );
    if let Some(r) = verdict.get("risk_score").and_then(|r| r.as_i64()) {
        msg.push_str(&format!(" (risk {r})"));
    }
    let reason = verdict
        .get("explanation")
        .and_then(|e| e.as_str())
        .unwrap_or("")
        .trim();
    if !reason.is_empty() {
        msg.push_str(&format!("\n{}", truncate(reason, 300)));
    }
    msg
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let mut out: String = s.chars().take(max).collect();
        out.push('…');
        out
    }
}

// ── Per-channel request builders (pure) ──────────────────────────────────────

/// Telegram Bot API sendMessage. Text goes in the JSON body (never the URL) so a
/// secret/command cannot leak into a logged query string.
pub fn telegram_request(token: &str, chat: &str, text: &str) -> Request {
    Request {
        url: format!("https://api.telegram.org/bot{token}/sendMessage"),
        body: json!({ "chat_id": chat, "text": text, "disable_web_page_preview": true })
            .to_string(),
        json: true,
    }
}

/// Slack incoming webhook, `{ "text": ... }`.
pub fn slack_request(webhook: &str, text: &str) -> Request {
    Request {
        url: webhook.to_string(),
        body: json!({ "text": text }).to_string(),
        json: true,
    }
}

/// Discord webhook, `{ "content": ... }`.
pub fn discord_request(webhook: &str, text: &str) -> Request {
    Request {
        url: webhook.to_string(),
        body: json!({ "content": text }).to_string(),
        json: true,
    }
}

/// Generic webhook with a caller-supplied JSON payload (structured, machine-readable).
pub fn webhook_request(url: &str, payload: Value) -> Request {
    Request {
        url: url.to_string(),
        body: payload.to_string(),
        json: true,
    }
}

/// Build a request for each TEXT channel (Telegram / Slack / Discord) for a given
/// message. Either product can call this with its own formatted text.
pub fn text_requests(cfg: &NotifyConfig, text: &str) -> Vec<Request> {
    let mut out = Vec::new();
    if let Some((token, chat)) = &cfg.telegram {
        out.push(telegram_request(token, chat, text));
    }
    if let Some(w) = &cfg.slack_webhook {
        out.push(slack_request(w, text));
    }
    if let Some(w) = &cfg.discord_webhook {
        out.push(discord_request(w, text));
    }
    out
}

/// Community Edition's fan-out: for a deny verdict (and optionally review), notify every text
/// channel with a human summary AND the generic webhook with the structured
/// verdict. Empty when nothing is configured or the verdict should not notify.
pub fn verdict_requests(cfg: &NotifyConfig, command: &str, verdict: &Value) -> Vec<Request> {
    if !should_notify(recommendation_of(verdict), cfg.notify_review) {
        return Vec::new();
    }
    let mut out = text_requests(cfg, &format_verdict(command, verdict));
    if let Some(u) = &cfg.webhook_url {
        out.push(webhook_request(
            u,
            json!({
                "source": "innerwarden",
                "command": command,
                "recommendation": recommendation_of(verdict),
                "verdict": verdict,
            }),
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env<'a>(pairs: &'a [(&'a str, &'a str)]) -> impl Fn(&str) -> Option<String> + 'a {
        move |k| {
            pairs
                .iter()
                .find(|(kk, _)| *kk == k)
                .map(|(_, v)| v.to_string())
        }
    }

    #[test]
    fn resolve_reads_each_channel() {
        let c = NotifyConfig::resolve(env(&[
            ("IW_TELEGRAM_TOKEN", "abc"),
            ("IW_TELEGRAM_CHAT", "42"),
            ("IW_SLACK_WEBHOOK", "https://s"),
            ("IW_DISCORD_WEBHOOK", "https://d"),
            ("IW_WEBHOOK_URL", "https://w"),
            ("IW_NOTIFY_REVIEW", "1"),
        ]));
        assert_eq!(c.telegram, Some(("abc".into(), "42".into())));
        assert_eq!(c.slack_webhook.as_deref(), Some("https://s"));
        assert_eq!(c.discord_webhook.as_deref(), Some("https://d"));
        assert_eq!(c.webhook_url.as_deref(), Some("https://w"));
        assert!(c.notify_review && c.any());
    }

    #[test]
    fn resolve_empty_and_blank() {
        assert_eq!(NotifyConfig::resolve(env(&[])), NotifyConfig::default());
        let blank =
            NotifyConfig::resolve(env(&[("IW_SLACK_WEBHOOK", "  "), ("IW_WEBHOOK_URL", "")]));
        assert!(!blank.any());
    }

    #[test]
    fn telegram_needs_both_parts() {
        assert!(NotifyConfig::resolve(env(&[("IW_TELEGRAM_TOKEN", "a")]))
            .telegram
            .is_none());
        assert!(NotifyConfig::resolve(env(&[("IW_TELEGRAM_CHAT", "1")]))
            .telegram
            .is_none());
    }

    #[test]
    fn notify_review_flag_variants() {
        for v in ["1", "true", "TRUE"] {
            assert!(NotifyConfig::resolve(env(&[("IW_NOTIFY_REVIEW", v)])).notify_review);
        }
        for v in ["0", "false", "", "no"] {
            assert!(!NotifyConfig::resolve(env(&[("IW_NOTIFY_REVIEW", v)])).notify_review);
        }
    }

    #[test]
    fn from_toml_str_parses_and_ignores_blank() {
        let c = NotifyConfig::from_toml_str(
            r#"
            telegram_token = "tok"
            telegram_chat = "99"
            slack_webhook = "https://s"
            webhook_url = ""
            notify_review = true
            "#,
        )
        .unwrap();
        assert_eq!(c.telegram, Some(("tok".into(), "99".into())));
        assert_eq!(c.slack_webhook.as_deref(), Some("https://s"));
        assert!(c.webhook_url.is_none()); // blank ignored
        assert!(c.notify_review);
    }

    #[test]
    fn from_toml_str_empty_is_default() {
        assert_eq!(
            NotifyConfig::from_toml_str("").unwrap(),
            NotifyConfig::default()
        );
    }

    #[test]
    fn from_toml_str_invalid_errors() {
        assert!(NotifyConfig::from_toml_str("not = = valid").is_err());
    }

    #[test]
    fn notifyfile_overlay_sets_only_given_keeps_rest() {
        let existing = NotifyFile::parse(
            r#"slack_webhook = "https://s"
                                            telegram_token = "keep""#,
        )
        .unwrap();
        let updates = NotifyFile {
            slack_webhook: Some("https://new".into()),
            ..Default::default()
        };
        let merged = existing.overlay(updates);
        assert_eq!(merged.slack_webhook.as_deref(), Some("https://new")); // updated
        assert_eq!(merged.telegram_token.as_deref(), Some("keep")); // untouched
    }

    #[test]
    fn notifyfile_to_toml_roundtrips_and_omits_unset() {
        let f = NotifyFile {
            slack_webhook: Some("https://s".into()),
            notify_review: Some(true),
            ..Default::default()
        };
        let s = f.to_toml();
        assert!(s.contains("slack_webhook") && s.contains("notify_review"));
        assert!(!s.contains("telegram")); // unset omitted
        assert_eq!(NotifyFile::parse(&s).unwrap(), f);
    }

    #[test]
    fn notifyfile_is_empty() {
        assert!(NotifyFile::default().is_empty());
        assert!(!NotifyFile {
            webhook_url: Some("https://w".into()),
            ..Default::default()
        }
        .is_empty());
    }

    #[test]
    fn or_else_layers_env_over_file() {
        let file = NotifyConfig::from_toml_str(
            r#"slack_webhook = "https://file-slack"
               discord_webhook = "https://file-discord""#,
        )
        .unwrap();
        let env_cfg = NotifyConfig::resolve(env(&[("IW_SLACK_WEBHOOK", "https://env-slack")]));
        let merged = env_cfg.or_else(file);
        // env wins on slack, file fills discord
        assert_eq!(merged.slack_webhook.as_deref(), Some("https://env-slack"));
        assert_eq!(
            merged.discord_webhook.as_deref(),
            Some("https://file-discord")
        );
    }

    #[test]
    fn or_else_notify_review_is_or() {
        let a = NotifyConfig {
            notify_review: false,
            ..Default::default()
        };
        let b = NotifyConfig {
            notify_review: true,
            ..Default::default()
        };
        assert!(a.or_else(b).notify_review);
    }

    #[test]
    fn should_notify_rules() {
        assert!(should_notify("deny", false));
        assert!(should_notify("review", true));
        assert!(!should_notify("review", false));
        assert!(!should_notify("allow", true));
    }

    #[test]
    fn recommendation_of_defaults_allow() {
        assert_eq!(recommendation_of(&json!({"recommendation":"deny"})), "deny");
        assert_eq!(recommendation_of(&json!({})), "allow");
        assert_eq!(recommendation_of(&json!({"recommendation":7})), "allow");
    }

    #[test]
    fn format_verdict_full_and_minimal() {
        let m = format_verdict(
            "curl x | bash",
            &json!({"recommendation":"deny","risk_score":90,"explanation":"pipe to shell"}),
        );
        assert!(
            m.contains("🚫")
                && m.contains("DENY")
                && m.contains("curl x | bash")
                && m.contains("risk 90")
                && m.contains("pipe to shell")
        );
        let min = format_verdict("ls", &json!({"recommendation":"deny"}));
        assert!(min.contains("DENY") && min.contains("ls") && !min.contains("risk"));
        assert!(format_verdict("x", &json!({"recommendation":"review"})).contains("⚠️"));
        assert!(format_verdict("x", &json!({"recommendation":"allow"})).contains("✓"));
    }

    #[test]
    fn format_verdict_truncates() {
        let m = format_verdict(&"a".repeat(500), &json!({"recommendation":"deny"}));
        assert!(m.contains('…'));
    }

    #[test]
    fn channel_request_shapes() {
        let t = telegram_request("TOK", "9", "hi");
        assert_eq!(t.url, "https://api.telegram.org/botTOK/sendMessage");
        assert!(!t.url.contains("hi")); // text not in URL
        assert_eq!(
            serde_json::from_str::<Value>(&t.body).unwrap()["text"],
            "hi"
        );
        assert_eq!(
            serde_json::from_str::<Value>(&slack_request("https://s", "hi").body).unwrap()["text"],
            "hi"
        );
        assert_eq!(
            serde_json::from_str::<Value>(&discord_request("https://d", "hi").body).unwrap()
                ["content"],
            "hi"
        );
        let w = webhook_request("https://w", json!({"a":1}));
        assert_eq!(serde_json::from_str::<Value>(&w.body).unwrap()["a"], 1);
    }

    #[test]
    fn text_requests_fans_out_configured_only() {
        let cfg = NotifyConfig::resolve(env(&[
            ("IW_SLACK_WEBHOOK", "https://s"),
            ("IW_TELEGRAM_TOKEN", "t"),
            ("IW_TELEGRAM_CHAT", "c"),
        ]));
        let r = text_requests(&cfg, "hey");
        assert_eq!(r.len(), 2); // telegram + slack; no discord/webhook
    }

    #[test]
    fn verdict_requests_all_channels_on_deny() {
        let cfg = NotifyConfig::resolve(env(&[
            ("IW_TELEGRAM_TOKEN", "t"),
            ("IW_TELEGRAM_CHAT", "c"),
            ("IW_SLACK_WEBHOOK", "https://s"),
            ("IW_DISCORD_WEBHOOK", "https://d"),
            ("IW_WEBHOOK_URL", "https://w"),
        ]));
        assert_eq!(
            verdict_requests(
                &cfg,
                "rm -rf /",
                &json!({"recommendation":"deny","risk_score":90})
            )
            .len(),
            4
        );
    }

    #[test]
    fn verdict_requests_empty_on_allow_and_ungated_review() {
        let cfg = NotifyConfig::resolve(env(&[("IW_SLACK_WEBHOOK", "https://s")]));
        assert!(verdict_requests(&cfg, "ls", &json!({"recommendation":"allow"})).is_empty());
        assert!(verdict_requests(&cfg, "x", &json!({"recommendation":"review"})).is_empty());
        let cfg2 = NotifyConfig::resolve(env(&[
            ("IW_SLACK_WEBHOOK", "https://s"),
            ("IW_NOTIFY_REVIEW", "1"),
        ]));
        assert_eq!(
            verdict_requests(&cfg2, "x", &json!({"recommendation":"review"})).len(),
            1
        );
    }

    #[test]
    fn verdict_requests_empty_when_unconfigured() {
        assert!(verdict_requests(
            &NotifyConfig::default(),
            "rm -rf /",
            &json!({"recommendation":"deny"})
        )
        .is_empty());
    }

    #[test]
    fn config_path_prefers_override_then_home_then_none() {
        assert_eq!(
            config_path(env(&[("IW_NOTIFY_CONFIG", "/etc/iw/notify.toml")])),
            Some(std::path::PathBuf::from("/etc/iw/notify.toml"))
        );
        assert_eq!(
            config_path(env(&[("HOME", "/home/x")])),
            Some(std::path::PathBuf::from(
                "/home/x/.config/innerwarden/notify.toml"
            ))
        );
        // override wins over HOME
        assert_eq!(
            config_path(env(&[("IW_NOTIFY_CONFIG", "/o.toml"), ("HOME", "/home/x")])),
            Some(std::path::PathBuf::from("/o.toml"))
        );
        assert_eq!(config_path(env(&[])), None);
        // blank values are ignored, not treated as a path
        assert_eq!(config_path(env(&[("IW_NOTIFY_CONFIG", "  ")])), None);
    }

    #[test]
    fn resolved_env_over_file() {
        let file = r#"slack_webhook = "https://file-slack"
                      discord_webhook = "https://file-discord""#;
        let cfg = resolved(
            env(&[("IW_SLACK_WEBHOOK", "https://env-slack")]),
            Some(file),
        );
        assert_eq!(cfg.slack_webhook.as_deref(), Some("https://env-slack")); // env wins
        assert_eq!(cfg.discord_webhook.as_deref(), Some("https://file-discord"));
        // file fills gap
    }

    #[test]
    fn resolved_file_only_and_env_only() {
        let file = r#"webhook_url = "https://w""#;
        assert_eq!(
            resolved(env(&[]), Some(file)).webhook_url.as_deref(),
            Some("https://w")
        );
        assert_eq!(
            resolved(env(&[("IW_WEBHOOK_URL", "https://e")]), None)
                .webhook_url
                .as_deref(),
            Some("https://e")
        );
        assert!(!resolved(env(&[]), None).any());
    }
}
