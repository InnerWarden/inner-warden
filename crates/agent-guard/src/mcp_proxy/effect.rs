//! What a tool does, read from its definition, and where the values that
//! steer it came from: the policy table that decides a call to a tool that
//! moves money, sends something out, shares, or deletes.
//!
//! An ATR rule that matches a tool by its name (ATR-2026-098 refuses every
//! `send_money`, ATR-2026-040 every `delete_file`) or by the name of an
//! argument (`"recipient":`) refuses the user's own payment as it refuses an
//! injected one: measured on AgentDojo's benign tasks, 25 of 339 calls the
//! user asked for were refused that way, every one of them for a name. The
//! name says what the tool can do, not who wanted it done.
//!
//! What separates the two is where the value that matters came from: the
//! account a payment goes to, the address a message goes to, the file a
//! delete removes. An injected order hands the model that value inside a tool
//! result; the user's own request does not. So:
//!
//! 1. **Effect class, once per tool, at `tools/list`** ([`EffectClass::of_tool`]):
//!    from the input schema's slot names, the MCP annotations
//!    (`readOnlyHint`, `destructiveHint`) and the words of the tool's name as a
//!    hint. A tool not listed is classed at its call, from its name and the
//!    call's argument names. Each class names its **sensitive slots**
//!    ([`EffectClass::is_sensitive_slot`]).
//! 2. **Provenance of each sensitive value** ([`SeenText`]): did it appear in
//!    anything a server said this session (a tool result, a resource, a
//!    listing), or nowhere? A value found nowhere was written by the model or
//!    the person. The proxy does not see the person's request (no agent hands
//!    it the prompt), so "the user asked for it" and "the model wrote it" are
//!    one row here; the table gives both the same verdict.
//! 3. **The table** ([`apply_table`]): a call that moves money, sends, shares or
//!    deletes, whose every sensitive value came from nowhere, is allowed and
//!    recorded: an ATR rule that matched only the tool's name or an
//!    argument's name stays in the alert as a label and no longer refuses.
//!    Any sensitive value found in what a server said keeps the verdict the
//!    call had (an ATR refusal, `AG-TAINT`), so nothing that was refused before
//!    passes when the value came from a result.
//!
//! What never changes here: an alert that is not an ATR rule, an ATR
//! condition that reads an argument's value (a `DROP TABLE`, a `--privileged`),
//! a shell or process tool (its command line is judged as the line it runs),
//! and a call to any other class. A session whose server text could not all
//! be kept ([`SEEN_TEXT_BUDGET`]) or was read only in part can no longer say
//! "nowhere", so no call in it is lowered: the cautious side.

use serde_json::Value;

use crate::mcp::{Verdict, VerdictAlert};
use crate::rules::{AtrContext, RuleEngine};

/// The rule an allowed-and-recorded call is reported under.
pub const EFFECT_RULE: &str = "AG-EFFECT";

/// How much of what servers said in one session is kept to answer "did this
/// value appear before". Past it the session can no longer say a value came
/// from nowhere, and no call is lowered for the rest of it.
pub(crate) const SEEN_TEXT_BUDGET: usize = 2 * 1024 * 1024;

/// A value at least this long is also looked for with every character but
/// letters and digits taken out of both sides: an account number written
/// `GB29 NWBK 6016` in a result and `GB29NWBK6016` in the call is the same value.
const SQUEEZED_MIN_LEN: usize = 6;

/// What a tool does to the world, as far as its definition says.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EffectClass {
    /// Pays, transfers, schedules or changes a transaction.
    MoneyMovement,
    /// Sends a message, a mail or a post to someone or somewhere.
    SendExternal,
    /// Shares something with, or invites, someone.
    Share,
    /// Deletes or removes something.
    Delete,
    /// Reads a credential.
    ReadSecret,
    /// Fetches a URL.
    FetchUrl,
    /// Reads and changes nothing.
    ReadOnly,
    /// Anything else, or not known.
    Other,
}

/// Words of a tool name that make it a reader whatever else it names
/// (`get_scheduled_transactions`, `search_emails`), when they come first.
const READ_VERBS: &[&str] = &[
    "get", "list", "search", "read", "find", "query", "show", "view", "lookup", "describe",
    "count", "check", "retrieve", "fetch", "download", "browse", "open", "load", "inspect",
];
const MONEY_WORDS: &[&str] = &[
    "pay",
    "payment",
    "transfer",
    "transaction",
    "money",
    "wire",
    "remit",
    "withdraw",
    "withdrawal",
    "refund",
    "purchase",
    "checkout",
    "charge",
    "payout",
];
const DELETE_WORDS: &[&str] = &[
    "delete", "remove", "rm", "drop", "purge", "erase", "destroy", "unlink", "wipe", "trash",
];
const SHARE_WORDS: &[&str] = &["share", "invite"];
const SEND_WORDS: &[&str] = &[
    "send", "email", "mail", "message", "post", "reply", "forward", "notify", "sms", "publish",
    "tweet", "dm", "comment", "submit",
];
const SECRET_WORDS: &[&str] = &[
    "password",
    "passwd",
    "secret",
    "credential",
    "token",
    "apikey",
    "key",
];
/// Slot words that name where something goes or who gets it.
const DESTINATION_SLOTS: &[&str] = &[
    "to",
    "cc",
    "bcc",
    "recipient",
    "address",
    "email",
    "phone",
    "user",
    "username",
    "member",
    "participant",
    "attendee",
    "invitee",
    "contact",
    "channel",
    "destination",
    "url",
    "link",
    "webhook",
    "target",
    "receiver",
];
/// Slot words that name where money goes, or how much.
const MONEY_SLOTS: &[&str] = &[
    "recipient",
    "iban",
    "account",
    "payee",
    "beneficiary",
    "wallet",
    "bic",
    "swift",
    "routing",
    "to",
    "destination",
    "receiver",
    "amount",
];
/// Slot words a share adds to [`DESTINATION_SLOTS`].
const SHARE_SLOTS: &[&str] = &["role", "permission"];

/// The lower-case words of a name: split on anything but letters and
/// digits, and where a lower-case letter meets an upper-case one
/// (`sendMoney` is `send`, `money`). A trailing plural `s` is dropped from a
/// word longer than three letters.
fn words(name: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut word = String::new();
    let mut prev_lower = false;
    for c in name.chars() {
        if !c.is_alphanumeric() {
            prev_lower = false;
            if !word.is_empty() {
                out.push(std::mem::take(&mut word));
            }
            continue;
        }
        if c.is_uppercase() && prev_lower && !word.is_empty() {
            out.push(std::mem::take(&mut word));
        }
        prev_lower = c.is_lowercase() || c.is_ascii_digit();
        word.extend(c.to_lowercase());
    }
    if !word.is_empty() {
        out.push(word);
    }
    for w in &mut out {
        if w.len() > 3 && w.ends_with('s') && !w.ends_with("ss") {
            w.pop();
        }
    }
    out
}

fn any_in(words: &[String], set: &[&str]) -> bool {
    words.iter().any(|w| set.contains(&w.as_str()))
}

impl EffectClass {
    /// The name said in an alert.
    pub fn label(self) -> &'static str {
        match self {
            EffectClass::MoneyMovement => "money-movement",
            EffectClass::SendExternal => "send-external",
            EffectClass::Share => "share",
            EffectClass::Delete => "delete",
            EffectClass::ReadSecret => "read-secret",
            EffectClass::FetchUrl => "fetch-url",
            EffectClass::ReadOnly => "read-only",
            EffectClass::Other => "other",
        }
    }

    /// Whether the table decides a call of this class by the provenance of
    /// its sensitive values.
    pub fn acts(self) -> bool {
        matches!(
            self,
            EffectClass::MoneyMovement
                | EffectClass::SendExternal
                | EffectClass::Share
                | EffectClass::Delete
        )
    }

    /// The class of one `tools/list` entry: its name, its annotations and the
    /// names of its input schema's properties.
    pub fn of_tool(tool: &Value) -> Self {
        let name = tool.get("name").and_then(Value::as_str).unwrap_or("");
        let slots: Vec<&str> = tool
            .get("inputSchema")
            .and_then(|s| s.get("properties"))
            .and_then(Value::as_object)
            .map(|p| p.keys().map(String::as_str).collect())
            .unwrap_or_default();
        Self::of(name, tool.get("annotations"), &slots)
    }

    /// The class of a tool from its name, its MCP annotations and its slot
    /// names. A server that declares a tool read-only is believed: the class
    /// that lowers nothing.
    pub fn of(name: &str, annotations: Option<&Value>, slots: &[&str]) -> Self {
        let hint = |key: &str| {
            annotations
                .and_then(|a| a.get(key))
                .and_then(Value::as_bool)
        };
        if hint("readOnlyHint") == Some(true) {
            return EffectClass::ReadOnly;
        }
        let w = words(name);
        let slot_words: Vec<Vec<String>> = slots.iter().map(|s| words(s)).collect();
        let has_slot = |set: &[&str]| slot_words.iter().any(|sw| any_in(sw, set));
        if w.first()
            .is_some_and(|first| READ_VERBS.contains(&first.as_str()))
        {
            if any_in(&w, SECRET_WORDS) {
                return EffectClass::ReadSecret;
            }
            if has_slot(&["url", "uri", "link"]) || any_in(&w, &["webpage", "url", "page", "http"])
            {
                return EffectClass::FetchUrl;
            }
            return EffectClass::ReadOnly;
        }
        let money_slots = has_slot(&["amount"])
            && has_slot(&[
                "recipient",
                "iban",
                "account",
                "payee",
                "beneficiary",
                "wallet",
            ]);
        if any_in(&w, MONEY_WORDS) || money_slots {
            return EffectClass::MoneyMovement;
        }
        if any_in(&w, DELETE_WORDS) || hint("destructiveHint") == Some(true) {
            return EffectClass::Delete;
        }
        if any_in(&w, SHARE_WORDS) {
            return EffectClass::Share;
        }
        if any_in(&w, SEND_WORDS) {
            return EffectClass::SendExternal;
        }
        EffectClass::Other
    }

    /// Whether a top-level argument named `slot` holds a value whose origin
    /// decides a call of this class: where money goes and how much, who a
    /// message or a share goes to, what a delete removes (every argument).
    pub fn is_sensitive_slot(self, slot: &str) -> bool {
        let w = words(slot);
        match self {
            EffectClass::MoneyMovement => any_in(&w, MONEY_SLOTS),
            EffectClass::SendExternal => any_in(&w, DESTINATION_SLOTS),
            EffectClass::Share => any_in(&w, DESTINATION_SLOTS) || any_in(&w, SHARE_SLOTS),
            EffectClass::Delete => true,
            _ => false,
        }
    }
}

/// What servers said this session, lower-cased, to answer whether a value a
/// call carries appeared in any of it.
#[derive(Debug)]
pub(crate) struct SeenText {
    text: String,
    /// The same with every character but letters and digits taken out.
    squeezed: String,
    /// Everything said this session is in `text`, read whole.
    whole: bool,
}

impl Default for SeenText {
    fn default() -> Self {
        Self {
            text: String::new(),
            squeezed: String::new(),
            whole: true,
        }
    }
}

impl SeenText {
    /// Keep what a server said. Past [`SEEN_TEXT_BUDGET`] nothing more is kept and
    /// the session is no longer whole.
    pub(crate) fn record(&mut self, said: &str) {
        if !self.whole {
            return;
        }
        if self.text.len() + said.len() + 1 > SEEN_TEXT_BUDGET {
            self.whole = false;
            self.text = String::new();
            self.squeezed = String::new();
            return;
        }
        let lower = said.to_lowercase();
        self.text.push('\n');
        self.text.push_str(&lower);
        self.squeezed.push('\n');
        self.squeezed
            .extend(lower.chars().filter(|c| c.is_alphanumeric()));
    }

    /// A server said something that was not read whole (an answer cut at the
    /// scan limit): what lies past the cut is not known.
    pub(crate) fn note_unread(&mut self) {
        self.whole = false;
        self.text = String::new();
        self.squeezed = String::new();
    }

    /// Whether every server text of the session is kept, so a value not in
    /// it came from nowhere.
    pub(crate) fn is_whole(&self) -> bool {
        self.whole
    }

    /// Whether `value` appeared in what servers said: as a whole word
    /// (no letter or digit right before or after it), or, for a value of at
    /// least [`SQUEEZED_MIN_LEN`] letters and digits, with everything else taken
    /// out of both.
    pub(crate) fn contains_value(&self, value: &str) -> bool {
        let value = value.trim().to_lowercase();
        if value.is_empty() {
            return false;
        }
        let is_word = |c: Option<char>| c.is_some_and(char::is_alphanumeric);
        let mut from = 0;
        while let Some(at) = self.text[from..].find(&value) {
            let start = from + at;
            let end = start + value.len();
            if !is_word(self.text[..start].chars().next_back())
                && !is_word(self.text[end..].chars().next())
            {
                return true;
            }
            from = start + value.chars().next().map_or(1, char::len_utf8);
        }
        let squeezed: String = value.chars().filter(|c| c.is_alphanumeric()).collect();
        squeezed.chars().count() >= SQUEEZED_MIN_LEN && self.squeezed.contains(&squeezed)
    }
}

/// The values a call's sensitive slots carry: every string and number under
/// a top-level argument the class names sensitive.
fn sensitive_values(class: EffectClass, args: &Value) -> Vec<(String, String)> {
    fn walk(slot: &str, v: &Value, out: &mut Vec<(String, String)>) {
        match v {
            Value::String(s) => out.push((slot.to_string(), s.clone())),
            Value::Number(n) => {
                out.push((slot.to_string(), n.to_string()));
                if let Some(f) = n.as_f64() {
                    if f.fract() == 0.0 && f.abs() < 1e15 {
                        out.push((slot.to_string(), format!("{}", f as i64)));
                    }
                }
            }
            Value::Array(items) => items.iter().for_each(|i| walk(slot, i, out)),
            Value::Object(map) => map.values().for_each(|i| walk(slot, i, out)),
            _ => {}
        }
    }
    let mut out = Vec::new();
    if let Value::Object(map) = args {
        for (slot, value) in map {
            if class.is_sensitive_slot(slot) {
                walk(slot, value, &mut out);
            }
        }
    }
    out
}

/// The call's arguments with every key renamed (`k0`, `k1`...), values kept: what
/// an ATR condition still matches here it matched on a value.
fn without_key_names(v: &Value) -> Value {
    match v {
        Value::Object(map) => Value::Object(
            map.values()
                .enumerate()
                .map(|(i, v)| (format!("k{i}"), without_key_names(v)))
                .collect(),
        ),
        Value::Array(items) => Value::Array(items.iter().map(without_key_names).collect()),
        other => other.clone(),
    }
}

/// Apply the table to the verdict of one `tools/call` (see the module docs).
/// Lowers, to a label, each blocking ATR alert that matched only the tool's
/// name or an argument's name, when the call's class acts and every
/// sensitive value came from nowhere; adds an [`EFFECT_RULE`] record when it
/// lowers one. Anything else is left as it was.
pub(crate) fn apply_table(
    tool: &str,
    args: &Value,
    class: EffectClass,
    seen: &SeenText,
    engine: Option<&RuleEngine>,
    verdict: &mut Verdict,
) {
    let Some(engine) = engine else { return };
    if !class.acts()
        || crate::mcp::names_a_shell_tool(tool)
        || crate::mcp::names_a_process_tool(tool)
        || !seen.is_whole()
    {
        return;
    }
    if !verdict
        .alerts
        .iter()
        .any(|a| a.block && a.rule.starts_with("ATR-"))
    {
        return;
    }
    let values = sensitive_values(class, args);
    if values.iter().any(|(_, value)| seen.contains_value(value)) {
        return;
    }
    let neutral = without_key_names(args).to_string();
    let kept: Vec<String> = engine
        .check_context(AtrContext {
            tool_name: None,
            ..AtrContext::tool_call(tool, &neutral)
        })
        .into_iter()
        .map(|m| m.rule_id)
        .collect();
    let mut slots: Vec<&str> = values.iter().map(|(slot, _)| slot.as_str()).collect();
    slots.dedup();
    let origin = if slots.is_empty() {
        "it carries no sensitive value".to_string()
    } else {
        format!(
            "its {} came from no tool result this session",
            slots
                .iter()
                .map(|s| format!("`{s}`"))
                .collect::<Vec<_>>()
                .join(", ")
        )
    };
    let mut lowered: Vec<String> = Vec::new();
    for alert in verdict.alerts.iter_mut() {
        if alert.block && alert.rule.starts_with("ATR-") && !kept.contains(&alert.rule) {
            alert.block = false;
            alert.detail.push_str(&format!(
                " [a label, not a refusal: a {} call and {origin}]",
                class.label()
            ));
            if !lowered.contains(&alert.rule) {
                lowered.push(alert.rule.clone());
            }
        }
    }
    if lowered.is_empty() {
        return;
    }
    verdict.alerts.push(VerdictAlert::builtin(
        EFFECT_RULE,
        format!(
            "{} call allowed and recorded: {origin} (written by the model or the person); \
             {} matched only a name and is kept as a label",
            class.label(),
            lowered.join(", ")
        ),
        false,
    ));
    verdict.allowed = !verdict.alerts.iter().any(|a| a.block);
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn a_tool_is_classed_by_its_verb_and_its_slots() {
        for (name, slots, class) in [
            (
                "send_money",
                &["recipient", "amount"][..],
                EffectClass::MoneyMovement,
            ),
            (
                "schedule_transaction",
                &["recipient", "amount"][..],
                EffectClass::MoneyMovement,
            ),
            (
                "update_scheduled_transaction",
                &["id", "amount"][..],
                EffectClass::MoneyMovement,
            ),
            (
                "make_it_so",
                &["iban", "amount"][..],
                EffectClass::MoneyMovement,
            ),
            ("get_scheduled_transactions", &[][..], EffectClass::ReadOnly),
            ("search_emails", &["query"][..], EffectClass::ReadOnly),
            (
                "send_email",
                &["recipients", "body"][..],
                EffectClass::SendExternal,
            ),
            (
                "sendDirectMessage",
                &["recipient", "body"][..],
                EffectClass::SendExternal,
            ),
            (
                "post_webpage",
                &["url", "content"][..],
                EffectClass::SendExternal,
            ),
            ("delete_file", &["file_id"][..], EffectClass::Delete),
            ("remove_user_from_slack", &["user"][..], EffectClass::Delete),
            (
                "invite_user_to_slack",
                &["user", "user_email"][..],
                EffectClass::Share,
            ),
            ("share_file", &["file_id", "email"][..], EffectClass::Share),
            ("get_webpage", &["url"][..], EffectClass::FetchUrl),
            ("get_api_key", &[][..], EffectClass::ReadSecret),
            ("create_calendar_event", &["title"][..], EffectClass::Other),
        ] {
            assert_eq!(EffectClass::of(name, None, slots), class, "{name}");
        }
    }

    #[test]
    fn annotations_are_read_and_read_only_wins() {
        let ro = json!({"readOnlyHint": true});
        assert_eq!(
            EffectClass::of("send_money", Some(&ro), &["recipient"]),
            EffectClass::ReadOnly
        );
        let destructive = json!({"destructiveHint": true});
        assert_eq!(
            EffectClass::of("archive_thing", Some(&destructive), &["id"]),
            EffectClass::Delete
        );
        let tool =
            json!({"name": "transmit", "inputSchema": {"properties": {"iban": {}, "amount": {}}}});
        assert_eq!(EffectClass::of_tool(&tool), EffectClass::MoneyMovement);
    }

    #[test]
    fn sensitive_slots_follow_the_class() {
        assert!(EffectClass::MoneyMovement.is_sensitive_slot("recipient"));
        assert!(EffectClass::MoneyMovement.is_sensitive_slot("amount"));
        assert!(!EffectClass::MoneyMovement.is_sensitive_slot("subject"));
        assert!(EffectClass::SendExternal.is_sensitive_slot("recipients"));
        assert!(EffectClass::SendExternal.is_sensitive_slot("cc"));
        assert!(!EffectClass::SendExternal.is_sensitive_slot("body"));
        assert!(EffectClass::Delete.is_sensitive_slot("file_id"));
        assert!(EffectClass::Share.is_sensitive_slot("permission"));
        assert!(!EffectClass::ReadOnly.is_sensitive_slot("path"));
    }

    #[test]
    fn a_value_is_seen_as_a_word_or_squeezed() {
        let mut seen = SeenText::default();
        seen.record("Please delete the file with ID '13'. Pay GB29 NWBK 6016 1331 9268 19 now.");
        assert!(seen.contains_value("13"));
        assert!(!seen.contains_value("3"));
        assert!(!seen.contains_value("130"));
        assert!(seen.contains_value("GB29NWBK60161331926819"));
        assert!(!seen.contains_value("GB29NWBK60161331920000"));
        assert!(seen.is_whole());
        seen.note_unread();
        assert!(!seen.is_whole());
    }

    #[test]
    fn past_its_budget_the_session_is_no_longer_whole() {
        let mut seen = SeenText::default();
        let chunk = "a".repeat(SEEN_TEXT_BUDGET / 2);
        seen.record(&chunk);
        assert!(seen.is_whole());
        seen.record(&chunk);
        seen.record("x");
        assert!(!seen.is_whole());
    }
}
