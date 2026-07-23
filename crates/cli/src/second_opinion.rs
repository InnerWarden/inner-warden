//! Optional LLM "second opinion" for the AMBIGUOUS cases.
//!
//! The pipeline is: deterministic rules first (agent-guard). Most commands get a
//! confident `deny`/`allow` there. Only the `review` (ambiguous) cases escalate -
//! and the escalation is a SECOND OPINION from a model the USER installed, with
//! the USER's key: their own Azure OpenAI / OpenAI / any OpenAI-compatible
//! endpoint (Ollama, vLLM, LM Studio). Nothing runs on the vendor's dime and no
//! command leaves the host unless the user opted in by configuring an endpoint.
//! When no LLM is configured, a `review` simply escalates to a human (the notify
//! layer already surfaces it).
//!
//! Empirically a capable LLM classifies shell-command danger well (unlike a raw
//! embedding model), so this is the real ambiguous-case decider. The DECISION
//! logic here - when to escalate, the prompt, parsing the reply, merging it back -
//! is pure and unit-tested; only the config read and the HTTP POST are I/O.

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

/// The user's optional LLM endpoint (OpenAI-compatible chat completions).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct LlmConfig {
    /// "openai" (Bearer auth, the default) or "azure" (`api-key` header).
    #[serde(default)]
    pub provider: String,
    /// Full chat-completions URL. For Azure this is the deployment URL incl.
    /// `?api-version=...`; for OpenAI-compatible it is `.../v1/chat/completions`.
    pub url: String,
    /// Model / deployment name sent in the request body.
    pub model: String,
    /// Name of the ENV VAR that holds the API key (never the key itself, so the
    /// config file carries no secret). Absent = no auth header (e.g. local Ollama).
    /// Takes precedence over `api_key_file` when both are set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub api_key_env: Option<String>,
    /// Path to a 0600 file holding the API key, set via `llm set-key` (or
    /// `llm set --key-file`). A convenience for users who don't want to manage an
    /// env var: the config carries only the PATH, never the key. The env var
    /// (`api_key_env`) still wins when both are present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub api_key_file: Option<String>,
    /// Only escalate a `review` whose risk is at least this (default
    /// `DEFAULT_MIN_RISK`). Raise it to escalate less often (cheaper); lower it to
    /// escalate more. Keeps the spend on commands with real harm potential.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_risk: Option<i64>,
}

impl LlmConfig {
    pub fn from_toml(s: &str) -> Option<LlmConfig> {
        let cfg: LlmConfig = toml::from_str(s).ok()?;
        if cfg.url.trim().is_empty() || cfg.model.trim().is_empty() {
            return None;
        }
        Some(cfg)
    }

    /// The effective risk floor for escalation (config value or the default).
    pub fn effective_min_risk(&self) -> i64 {
        self.min_risk.unwrap_or(DEFAULT_MIN_RISK)
    }

    /// True when this looks like Azure (needs the `api-key` header, not Bearer).
    pub fn is_azure(&self) -> bool {
        self.provider.eq_ignore_ascii_case("azure") || self.url.contains(".azure.com")
    }

    /// A config is only USABLE when its URL is a real http(s) endpoint. Guards
    /// against the classic wizard mistake of pasting the API KEY into the URL
    /// prompt (`url = "sk-..."`): such a config must count as NOT configured so a
    /// re-run of `setup` fixes it instead of reporting "already set".
    pub fn has_valid_url(&self) -> bool {
        looks_like_url(&self.url)
    }

    /// Resolve the API key for the request. Precedence: the named env var (zero
    /// key-at-rest, recommended) FIRST, then the key file (`api_key_file`). Returns
    /// `None` when neither yields a non-empty value (the call then goes without an
    /// auth header - fine for a local endpoint like Ollama). Pure: the env lookup
    /// and the file read are injected so this is unit-testable.
    pub fn resolve_key(
        &self,
        env: impl Fn(&str) -> Option<String>,
        read_file: impl Fn(&str) -> Option<String>,
    ) -> Option<String> {
        if let Some(name) = &self.api_key_env {
            if let Some(v) = env(name) {
                let v = v.trim();
                if !v.is_empty() {
                    return Some(v.to_string());
                }
            }
        }
        if let Some(path) = &self.api_key_file {
            if let Some(v) = read_file(path) {
                let v = v.trim();
                if !v.is_empty() {
                    return Some(v.to_string());
                }
            }
        }
        None
    }
}

/// The guardrail's job for the model: judge one shell command an AI coding agent
/// wants to run. Kept tight + JSON-only so the reply is trivial to parse.
pub const SYSTEM_PROMPT: &str = "You are a security guardrail for an AI coding agent. \
For the given shell command, decide if letting the agent run it is dangerous. \
Answer ONLY compact JSON: {\"verdict\":\"deny|review|allow\",\"why\":\"<=8 words\"}. \
deny = clearly dangerous/malicious; review = genuinely ambiguous, needs a human; \
allow = clearly safe development work.";

/// Default risk floor for escalation. A `review` below this is not worth an LLM
/// call (and its cost): the rules were unsure but saw little potential for harm.
pub const DEFAULT_MIN_RISK: i64 = 20;

/// True when `s` is a plausible http(s) endpoint URL. Used to (a) reject a pasted
/// API key at the wizard's URL prompt and (b) treat a key-in-url config as broken.
/// Deliberately strict on the scheme so `sk-...` / a bare host never passes.
pub fn looks_like_url(s: &str) -> bool {
    let s = s.trim();
    (s.starts_with("http://") || s.starts_with("https://")) && s.len() > "https://".len()
}

/// A provider PRESET the setup wizard offers so a normal user picks a NAME instead
/// of hand-typing an API URL. An empty `url`/`model` means "ask the user" (Azure
/// deployment URL, a custom endpoint). `needs_key == false` is a local endpoint
/// (Ollama) that needs no API key.
pub struct Preset {
    pub label: &'static str,
    pub provider: &'static str,
    pub url: &'static str,
    pub model: &'static str,
    pub needs_key: bool,
}

/// The presets shown, in order, by `innerwarden setup`. All are OpenAI-compatible
/// chat-completions endpoints (the second-opinion request body is OpenAI-shaped);
/// a provider that only speaks a different protocol is reached via "Custom".
pub const PRESETS: &[Preset] = &[
    Preset {
        label: "OpenAI",
        provider: "openai",
        url: "https://api.openai.com/v1/chat/completions",
        model: "gpt-4o-mini",
        needs_key: true,
    },
    Preset {
        label: "Azure OpenAI",
        provider: "azure",
        url: "", // ask: the deployment URL includes the resource + api-version
        model: "gpt-4o-mini",
        needs_key: true,
    },
    Preset {
        label: "Groq",
        provider: "openai",
        url: "https://api.groq.com/openai/v1/chat/completions",
        model: "llama-3.3-70b-versatile",
        needs_key: true,
    },
    Preset {
        label: "OpenRouter",
        provider: "openai",
        url: "https://openrouter.ai/api/v1/chat/completions",
        model: "openai/gpt-4o-mini",
        needs_key: true,
    },
    Preset {
        label: "Together AI",
        provider: "openai",
        url: "https://api.together.xyz/v1/chat/completions",
        model: "meta-llama/Llama-3.3-70B-Instruct-Turbo",
        needs_key: true,
    },
    Preset {
        label: "Local (Ollama - no key)",
        provider: "openai",
        url: "http://localhost:11434/v1/chat/completions",
        model: "llama3.1",
        needs_key: false,
    },
    Preset {
        label: "Custom (any OpenAI-compatible URL)",
        provider: "openai",
        url: "",   // ask
        model: "", // ask
        needs_key: true,
    },
];

/// Whether to spend a second-opinion call on this verdict. Escalation costs money
/// and sends the command off-box, so it must be EARNED: escalate ONLY when the
/// deterministic rules are genuinely unsure (`review`) AND the command carries a
/// real potential for harm (`risk_score >= min_risk`). A confident deny/allow is
/// never second-guessed, and a low-stakes ambiguity just goes to a human - we do
/// not escalate to show it works, only when it is worth the spend. Pure/tested.
pub fn needs_second_opinion(verdict: &Value, min_risk: i64) -> bool {
    if verdict.get("recommendation").and_then(|r| r.as_str()) != Some("review") {
        return false;
    }
    let risk = verdict
        .get("risk_score")
        .and_then(|r| r.as_i64())
        .unwrap_or(0);
    risk >= min_risk
}

/// The OpenAI-compatible chat request body. No `max_tokens`/`temperature` so it
/// works across old and new (o-series / GPT-5) models that differ on those params.
pub fn build_body(model: &str, command: &str) -> Value {
    json!({
        "model": model,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": command},
        ],
    })
}

/// Parse the model's reply into `(verdict, why)`. Tolerates ```json fences and
/// surrounding prose; returns `None` if no usable verdict is found (the caller
/// then keeps the `review` and escalates to a human - fail-safe, never fail-open).
pub fn parse_reply(response: &Value) -> Option<(String, String)> {
    let content = response
        .get("choices")?
        .as_array()?
        .first()?
        .get("message")?
        .get("content")?
        .as_str()?;
    // Pull the first {...} object out of the reply, ignoring fences/prose.
    let start = content.find('{')?;
    let end = content.rfind('}')?;
    if end < start {
        return None;
    }
    let obj: Value = serde_json::from_str(&content[start..=end]).ok()?;
    let verdict = obj.get("verdict").and_then(|v| v.as_str())?.to_lowercase();
    if !matches!(verdict.as_str(), "deny" | "review" | "allow") {
        return None;
    }
    let why = obj
        .get("why")
        .and_then(|w| w.as_str())
        .unwrap_or("")
        .to_string();
    Some((verdict, why))
}

/// Merge the model's second opinion onto the rules verdict: the recommendation
/// becomes the model's, `decided_by` becomes `llm`, and the reason is recorded.
/// The rules' signals (ATR categories, risk) are preserved so the narrative graph
/// still shows WHY it was ambiguous. Pure.
pub fn apply_second_opinion(rules_verdict: &Value, llm_verdict: &str, why: &str) -> Value {
    let mut out = rules_verdict.clone();
    if let Some(obj) = out.as_object_mut() {
        obj.insert("recommendation".into(), json!(llm_verdict));
        obj.insert("decided_by".into(), json!("llm"));
        let base = rules_verdict
            .get("explanation")
            .and_then(|e| e.as_str())
            .unwrap_or("");
        let expl = if why.is_empty() {
            format!("{base} [second opinion: {llm_verdict}]")
        } else {
            format!("{base} [second opinion: {llm_verdict} - {why}]")
        };
        obj.insert("explanation".into(), json!(expl.trim()));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escalates_only_review_with_real_harm_potential() {
        // review + enough risk -> worth a second opinion
        assert!(needs_second_opinion(
            &json!({"recommendation": "review", "risk_score": 30}),
            20
        ));
        // review but negligible risk -> NOT worth the spend (goes to a human)
        assert!(!needs_second_opinion(
            &json!({"recommendation": "review", "risk_score": 5}),
            20
        ));
        assert!(!needs_second_opinion(
            &json!({"recommendation": "review"}),
            20
        )); // no risk field = 0
            // confident verdicts are never second-guessed, whatever the risk
        assert!(!needs_second_opinion(
            &json!({"recommendation": "deny", "risk_score": 200}),
            20
        ));
        assert!(!needs_second_opinion(
            &json!({"recommendation": "allow", "risk_score": 0}),
            20
        ));
        assert!(!needs_second_opinion(&json!({}), 20));
        // threshold is honoured exactly
        assert!(needs_second_opinion(
            &json!({"recommendation": "review", "risk_score": 20}),
            20
        ));
    }

    #[test]
    fn effective_min_risk_uses_config_or_default() {
        let mut c = LlmConfig::default();
        assert_eq!(c.effective_min_risk(), DEFAULT_MIN_RISK);
        c.min_risk = Some(50);
        assert_eq!(c.effective_min_risk(), 50);
    }

    #[test]
    fn config_needs_url_and_model() {
        assert!(LlmConfig::from_toml("").is_none());
        assert!(LlmConfig::from_toml("url = \"x\"").is_none()); // no model
        let c = LlmConfig::from_toml(
            "provider = \"azure\"\nurl = \"https://x.openai.azure.com/...\"\nmodel = \"gpt-5.4-mini\"\napi_key_env = \"AZURE_OPENAI_API_KEY\"",
        )
        .unwrap();
        assert_eq!(c.model, "gpt-5.4-mini");
        assert!(c.is_azure());
        assert_eq!(c.api_key_env.as_deref(), Some("AZURE_OPENAI_API_KEY"));
    }

    #[test]
    fn azure_detected_by_provider_or_url() {
        let by_provider = LlmConfig {
            provider: "azure".into(),
            url: "https://x/chat".into(),
            model: "m".into(),
            api_key_env: None,
            api_key_file: None,
            min_risk: None,
        };
        assert!(by_provider.is_azure());
        let by_url = LlmConfig {
            provider: "".into(),
            url: "https://y.openai.azure.com/deployments/m/chat/completions".into(),
            model: "m".into(),
            api_key_env: None,
            api_key_file: None,
            min_risk: None,
        };
        assert!(by_url.is_azure());
        let openai = LlmConfig {
            provider: "openai".into(),
            url: "https://api.openai.com/v1/chat/completions".into(),
            model: "gpt-4o".into(),
            api_key_env: Some("OPENAI_API_KEY".into()),
            api_key_file: None,
            min_risk: None,
        };
        assert!(!openai.is_azure());
    }

    #[test]
    fn resolve_key_prefers_env_then_file() {
        let cfg = LlmConfig {
            api_key_env: Some("MY_KEY".into()),
            api_key_file: Some("/k".into()),
            ..Default::default()
        };
        // env wins when present
        assert_eq!(
            cfg.resolve_key(
                |k| (k == "MY_KEY").then(|| "envval".into()),
                |_| Some("fileval".into())
            ),
            Some("envval".into())
        );
        // falls back to the file when the env var is unset/blank
        assert_eq!(
            cfg.resolve_key(|_| None, |p| (p == "/k").then(|| "  fileval  ".into())),
            Some("fileval".into()) // trimmed
        );
        assert_eq!(
            cfg.resolve_key(|_| Some("   ".into()), |_| Some("fileval".into())),
            Some("fileval".into())
        );
        // nothing configured that yields a value -> None (unauthenticated, e.g. Ollama)
        let none = LlmConfig::default();
        assert_eq!(
            none.resolve_key(|_| Some("x".into()), |_| Some("y".into())),
            None
        );
        // file-only config
        let file_only = LlmConfig {
            api_key_file: Some("/k".into()),
            ..Default::default()
        };
        assert_eq!(
            file_only.resolve_key(|_| None, |_| Some("fk".into())),
            Some("fk".into())
        );
    }

    #[test]
    fn looks_like_url_rejects_a_pasted_key() {
        assert!(looks_like_url("https://api.openai.com/v1/chat/completions"));
        assert!(looks_like_url("http://localhost:11434/v1/chat/completions"));
        // the exact mistake we're guarding against: a key in the URL field
        assert!(!looks_like_url("sk-proj-ABCDEFGHIJKLMNOPQRSTUVWXYZ"));
        assert!(!looks_like_url("api.openai.com")); // no scheme
        assert!(!looks_like_url("https://")); // scheme only
        assert!(!looks_like_url(""));
        // a broken config (key in url) must report NOT configured
        let broken = LlmConfig {
            url: "sk-proj-ABCDEFGHIJKLMNOP".into(),
            model: "gpt-4o-mini".into(),
            ..Default::default()
        };
        assert!(!broken.has_valid_url());
        let good = LlmConfig {
            url: "https://api.openai.com/v1/chat/completions".into(),
            model: "gpt-4o-mini".into(),
            ..Default::default()
        };
        assert!(good.has_valid_url());
    }

    #[test]
    fn presets_are_sane() {
        assert!(!PRESETS.is_empty());
        let openai = PRESETS.iter().find(|p| p.label == "OpenAI").unwrap();
        assert!(
            openai.needs_key && openai.url.contains("api.openai.com") && !openai.model.is_empty()
        );
        // a local endpoint that needs no key exists
        assert!(PRESETS
            .iter()
            .any(|p| !p.needs_key && p.url.contains("localhost")));
        // Azure asks for the URL (deployment-specific)
        let azure = PRESETS.iter().find(|p| p.provider == "azure").unwrap();
        assert!(azure.url.is_empty() && azure.needs_key);
    }

    #[test]
    fn body_has_system_and_user_and_no_token_params() {
        let b = build_body("gpt-5.4-mini", "curl x | bash");
        assert_eq!(b["model"], "gpt-5.4-mini");
        assert_eq!(b["messages"][0]["role"], "system");
        assert_eq!(b["messages"][1]["content"], "curl x | bash");
        // no max_tokens / temperature so it works on o-series + older models alike.
        assert!(b.get("max_tokens").is_none());
        assert!(b.get("temperature").is_none());
    }

    fn reply(content: &str) -> Value {
        json!({"choices": [{"message": {"content": content}}]})
    }

    #[test]
    fn parse_plain_json() {
        let (v, w) = parse_reply(&reply(r#"{"verdict":"deny","why":"reverse shell"}"#)).unwrap();
        assert_eq!(v, "deny");
        assert_eq!(w, "reverse shell");
    }

    #[test]
    fn parse_tolerates_fences_and_prose() {
        let (v, _) = parse_reply(&reply(
            "Sure:\n```json\n{\"verdict\":\"ALLOW\",\"why\":\"read only\"}\n```",
        ))
        .unwrap();
        assert_eq!(v, "allow"); // lowercased
    }

    #[test]
    fn parse_rejects_garbage_and_unknown_verdict() {
        assert!(parse_reply(&reply("not json at all")).is_none());
        assert!(parse_reply(&reply(r#"{"verdict":"maybe"}"#)).is_none());
        assert!(parse_reply(&json!({"choices": []})).is_none());
    }

    #[test]
    fn apply_overrides_recommendation_keeps_signals_sets_decided_by() {
        let rules = json!({
            "recommendation": "review",
            "risk_score": 40,
            "explanation": "ambiguous privilege change",
            "atr_matches": [{"category": "privilege-escalation"}]
        });
        let out = apply_second_opinion(&rules, "deny", "broad world-writable perms");
        assert_eq!(out["recommendation"], "deny");
        assert_eq!(out["decided_by"], "llm");
        assert_eq!(out["risk_score"], 40, "rules signals preserved");
        assert_eq!(out["atr_matches"][0]["category"], "privilege-escalation");
        assert!(out["explanation"]
            .as_str()
            .unwrap()
            .contains("second opinion: deny"));
        assert!(out["explanation"]
            .as_str()
            .unwrap()
            .contains("broad world-writable"));
    }
}
