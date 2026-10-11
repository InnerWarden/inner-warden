//! JSON-RPC 2.0 envelope types and line framing for the MCP stdio proxy.
//!
//! MCP over stdio is newline-delimited JSON-RPC 2.0: one JSON message per
//! line. The 2025-06-18 revision allows only single objects; clients of the
//! 2025-03-26 revision may also send a batch (a JSON array of messages), so a
//! batch is read element by element rather than passed through unread.
//!
//! A line is read the way the server reading it will: as a JSON value, where
//! the LAST of two equal keys wins (what JavaScript's `JSON.parse` and
//! Python's `json` do). A typed struct would refuse the duplicate instead, and
//! the line it refused used to travel on unread, so a `tools/call` with a
//! harmless `params` followed by a second, hostile one was never inspected.
//!
//! These types model just enough of the envelope to ROUTE and INSPECT a
//! message (`id` / `method` / `params` / `result` / `error`); unknown
//! top-level fields (e.g. `_meta`) are intentionally NOT captured, because
//! pass-through messages are forwarded as their original raw bytes and never
//! re-serialized, which is the only way to guarantee byte fidelity (no key
//! reordering, no `1` vs `1.0` number drift). [`serialize_line`] is used ONLY
//! for messages the proxy synthesizes itself (e.g. a denial), which have no
//! unknown fields to preserve.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// A parsed JSON-RPC 2.0 message envelope, the fields the proxy inspects.
///
/// One struct covers all three message kinds:
/// - request: `method` + `id` (+ optional `params`)
/// - notification: `method`, no `id`
/// - response: `id` + (`result` xor `error`), no `method`
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct JsonRpcEnvelope {
    pub jsonrpc: String,
    /// Request/response correlation id: a string or integer (never null for a
    /// request). Kept as a raw [`Value`] so it echoes back verbatim in a
    /// synthesized response, with no integer/float reinterpretation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub params: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<Value>,
}

impl JsonRpcEnvelope {
    /// True when this envelope carries a `method` (a request or notification).
    pub fn is_call(&self) -> bool {
        self.method.is_some()
    }

    /// True when this envelope is a response (has `result` or `error` and no
    /// `method`).
    pub fn is_response(&self) -> bool {
        self.method.is_none() && (self.result.is_some() || self.error.is_some())
    }
}

/// Classification of one input line read from a stdio stream.
#[derive(Debug, Clone, PartialEq)]
pub enum ParsedLine {
    /// Blank / whitespace-only line: skip, do not forward.
    Empty,
    /// A JSON object, read as a message the proxy can inspect. The version is
    /// not required to be `2.0`: a server that does not check it would act on
    /// the message all the same, so it is inspected all the same.
    Message(JsonRpcEnvelope),
    /// A JSON array: a batch. Each element is one message (or something a
    /// server ignores), in order.
    Batch(Vec<Value>),
    /// JSON, but a scalar (`42`, `"x"`, `null`): nothing a server acts on.
    Opaque(String),
    /// Not JSON at all (or JSON this parser cannot read, such as nesting past
    /// its depth limit).
    NotJson(String),
}

/// Parse one line (newline already stripped) into a [`ParsedLine`].
///
/// Never panics. Duplicate keys resolve as the server resolves them: the last
/// one wins.
pub fn parse_line(line: &str) -> ParsedLine {
    if line.trim().is_empty() {
        return ParsedLine::Empty;
    }
    match parse_value(line) {
        Ok(Value::Array(items)) => ParsedLine::Batch(items),
        Ok(value) => match envelope_of(&value) {
            Some(envelope) => ParsedLine::Message(envelope),
            None => ParsedLine::Opaque(line.to_string()),
        },
        Err(_) => ParsedLine::NotJson(line.to_string()),
    }
}

/// One line read as a JSON value, the way [`parse_line`] reads it.
///
/// JSON allows an escaped lone surrogate (`"\ud800"`), and a JavaScript client
/// produces one when it cuts a string between the halves of an emoji; this
/// parser refuses it. The line is then read with each one as U+FFFD, which
/// inspects the same, rather than refuse a line the server accepts.
pub fn parse_value(line: &str) -> Result<Value, serde_json::Error> {
    serde_json::from_str::<Value>(line).or_else(|error| {
        replace_lone_surrogates(line)
            .ok_or(error)
            .and_then(|fixed| serde_json::from_str::<Value>(&fixed))
    })
}

/// `line` with every escaped lone surrogate (`\uD800` to `\uDFFF` not in a
/// high-low pair) written as `\uFFFD`; `None` when there is none. Other
/// escapes, including an escaped backslash before `u`, are copied as they are.
fn replace_lone_surrogates(line: &str) -> Option<String> {
    fn unit_at(bytes: &[u8], at: usize) -> Option<u32> {
        if bytes.get(at) != Some(&b'\\') || bytes.get(at + 1) != Some(&b'u') {
            return None;
        }
        let hex = std::str::from_utf8(bytes.get(at + 2..at + 6)?).ok()?;
        u32::from_str_radix(hex, 16).ok()
    }
    let bytes = line.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut changed = false;
    let mut at = 0;
    while at < bytes.len() {
        if bytes[at] != b'\\' {
            out.push(bytes[at]);
            at += 1;
            continue;
        }
        match unit_at(bytes, at) {
            Some(0xD800..=0xDBFF)
                if unit_at(bytes, at + 6).is_some_and(|low| (0xDC00..=0xDFFF).contains(&low)) =>
            {
                out.extend_from_slice(&bytes[at..at + 12]);
                at += 12;
            }
            Some(0xD800..=0xDFFF) => {
                out.extend_from_slice(b"\\uFFFD");
                changed = true;
                at += 6;
            }
            Some(_) => {
                out.extend_from_slice(&bytes[at..at + 6]);
                at += 6;
            }
            // Any other escape is two bytes; copying both keeps `\\u` an
            // escaped backslash followed by a plain `u`.
            None => {
                out.extend_from_slice(&bytes[at..(at + 2).min(bytes.len())]);
                at += 2;
            }
        }
    }
    changed.then(|| String::from_utf8(out).ok()).flatten()
}

/// The envelope of one JSON object, or `None` when `value` is not an object.
/// A `null` field reads as absent, as it did through the typed envelope.
pub fn envelope_of(value: &Value) -> Option<JsonRpcEnvelope> {
    let object = value.as_object()?;
    let field = |name: &str| object.get(name).filter(|value| !value.is_null()).cloned();
    Some(JsonRpcEnvelope {
        jsonrpc: object
            .get("jsonrpc")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string(),
        id: field("id"),
        method: object
            .get("method")
            .and_then(Value::as_str)
            .map(str::to_string),
        params: field("params"),
        result: field("result"),
        error: field("error"),
    })
}

/// Whether any JSON object in `line` repeats a key. A conforming peer never
/// does; a line that does is forwarded as the proxy read it (last key wins),
/// so a server whose parser keeps the FIRST key cannot be handed a value the
/// proxy never inspected.
///
/// Read from the same text [`parse_value`] reads (a lone surrogate written as
/// U+FFFD), and `true` when that cannot be read at all: a line whose keys
/// could not be checked is forwarded as inspected, never as it came.
pub fn has_duplicate_keys(line: &str) -> bool {
    use serde::de::DeserializeSeed;
    let walk = |text: &str| {
        let mut deserializer = serde_json::Deserializer::from_str(text);
        DuplicateKeys.deserialize(&mut deserializer)
    };
    walk(line)
        .or_else(|error| {
            replace_lone_surrogates(line)
                .ok_or(error)
                .and_then(|fixed| walk(&fixed))
        })
        .unwrap_or(true)
}

/// Walks a JSON value and answers whether any object in it repeats a key.
#[derive(Clone, Copy)]
struct DuplicateKeys;

impl<'de> serde::de::DeserializeSeed<'de> for DuplicateKeys {
    type Value = bool;

    fn deserialize<D: serde::Deserializer<'de>>(self, deserializer: D) -> Result<bool, D::Error> {
        deserializer.deserialize_any(self)
    }
}

impl<'de> serde::de::Visitor<'de> for DuplicateKeys {
    type Value = bool;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("any JSON value")
    }

    fn visit_bool<E>(self, _: bool) -> Result<bool, E> {
        Ok(false)
    }

    fn visit_i64<E>(self, _: i64) -> Result<bool, E> {
        Ok(false)
    }

    fn visit_u64<E>(self, _: u64) -> Result<bool, E> {
        Ok(false)
    }

    fn visit_f64<E>(self, _: f64) -> Result<bool, E> {
        Ok(false)
    }

    fn visit_str<E>(self, _: &str) -> Result<bool, E> {
        Ok(false)
    }

    fn visit_unit<E>(self) -> Result<bool, E> {
        Ok(false)
    }

    fn visit_seq<A: serde::de::SeqAccess<'de>>(self, mut seq: A) -> Result<bool, A::Error> {
        let mut found = false;
        while let Some(inner) = seq.next_element_seed(self)? {
            found |= inner;
        }
        Ok(found)
    }

    fn visit_map<A: serde::de::MapAccess<'de>>(self, mut map: A) -> Result<bool, A::Error> {
        let mut seen = std::collections::HashSet::new();
        let mut found = false;
        while let Some(key) = map.next_key::<String>()? {
            found |= !seen.insert(key);
            found |= map.next_value_seed(self)?;
        }
        Ok(found)
    }
}

/// Serialize an envelope to a single newline-terminated line.
///
/// Used ONLY for messages the proxy synthesizes (denials), never for
/// pass-through (which forwards raw bytes). [`serde_json::to_string`] escapes
/// embedded newlines and never pretty-prints, so the one-object-per-line
/// invariant holds even if a string field contains `\n`.
pub fn serialize_line(env: &JsonRpcEnvelope) -> String {
    // An envelope built from valid `Value`s cannot fail to serialize; the
    // fallback exists only so this never panics.
    let mut s = serde_json::to_string(env).unwrap_or_else(|_| {
        String::from(
            "{\"jsonrpc\":\"2.0\",\"error\":{\"code\":-32603,\"message\":\"serialize error\"}}",
        )
    });
    s.push('\n');
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn parses_a_request() {
        let line = r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"get_weather","arguments":{"location":"NYC"}}}"#;
        let ParsedLine::Message(env) = parse_line(line) else {
            panic!("expected Message")
        };
        assert_eq!(env.method.as_deref(), Some("tools/call"));
        assert_eq!(env.id, Some(json!(2)));
        assert!(env.is_call());
        assert!(!env.is_response());
        assert_eq!(env.params.unwrap()["arguments"]["location"], json!("NYC"));
    }

    #[test]
    fn parses_a_result_response() {
        let line = r#"{"jsonrpc":"2.0","id":2,"result":{"content":[{"type":"text","text":"hi"}],"isError":false}}"#;
        let ParsedLine::Message(env) = parse_line(line) else {
            panic!("expected Message")
        };
        assert!(env.method.is_none());
        assert!(env.is_response());
        assert!(!env.is_call());
        assert_eq!(env.result.unwrap()["isError"], json!(false));
    }

    #[test]
    fn parses_an_error_response() {
        let line =
            r#"{"jsonrpc":"2.0","id":2,"error":{"code":-32602,"message":"Unknown tool: x"}}"#;
        let ParsedLine::Message(env) = parse_line(line) else {
            panic!("expected Message")
        };
        assert!(env.is_response());
        assert_eq!(env.error.unwrap()["code"], json!(-32602));
    }

    #[test]
    fn parses_a_notification() {
        let line = r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#;
        let ParsedLine::Message(env) = parse_line(line) else {
            panic!("expected Message")
        };
        assert_eq!(env.method.as_deref(), Some("notifications/initialized"));
        assert!(env.id.is_none());
        assert!(env.is_call());
        assert!(!env.is_response());
    }

    #[test]
    fn blank_and_whitespace_lines_are_empty() {
        assert_eq!(parse_line(""), ParsedLine::Empty);
        assert_eq!(parse_line("   "), ParsedLine::Empty);
        assert_eq!(parse_line("\t  "), ParsedLine::Empty);
    }

    /// A batch is read, not passed through: clients of the 2025-03-26
    /// revision send them, and each element is a message the server acts on.
    #[test]
    fn top_level_array_is_a_batch() {
        let line = r#"[{"jsonrpc":"2.0","id":1,"method":"ping"},{"jsonrpc":"2.0","method":"notifications/initialized"}]"#;
        let ParsedLine::Batch(items) = parse_line(line) else {
            panic!("expected Batch")
        };
        assert_eq!(items.len(), 2);
        assert_eq!(
            envelope_of(&items[0]).and_then(|env| env.method),
            Some("ping".to_string())
        );
    }

    #[test]
    fn non_json_lines_are_not_json_and_never_panic() {
        for line in &[
            "not json at all",
            "{ broken",
            "{\"a\":1} trailing",
            "{\"a\":1}{\"b\":2}",
        ] {
            assert_eq!(parse_line(line), ParsedLine::NotJson(line.to_string()));
        }
    }

    /// A lone surrogate escape is valid JSON a JavaScript client produces;
    /// the line is read, not refused, and a real pair is left alone.
    #[test]
    fn a_lone_surrogate_escape_is_read_not_refused() {
        let line = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"x","arguments":{"t":"cut \ud83d","u":"\udc00 x","ok":"\ud83d\ude00","lit":"\\ud800"}}}"#;
        let ParsedLine::Message(env) = parse_line(line) else {
            panic!("a lone surrogate must not make the line unreadable")
        };
        let args = &env.params.unwrap()["arguments"];
        assert_eq!(args["t"], json!("cut \u{FFFD}"));
        assert_eq!(args["u"], json!("\u{FFFD} x"));
        assert_eq!(args["ok"], json!("\u{1F600}"));
        assert_eq!(args["lit"], json!("\\ud800"));
        assert_eq!(replace_lone_surrogates(r#"{"a":"\ud83d\ude00"}"#), None);
    }

    #[test]
    fn json_scalars_are_opaque() {
        for line in &["42", "\"a string\"", "true", "null"] {
            assert_eq!(parse_line(line), ParsedLine::Opaque(line.to_string()));
        }
    }

    /// A message without `jsonrpc: "2.0"` is inspected all the same: a server
    /// that does not check the version acts on it.
    #[test]
    fn wrong_or_missing_version_is_still_read_as_a_message() {
        for line in [
            r#"{"jsonrpc":"1.0","id":1,"method":"tools/call"}"#,
            r#"{"id":1,"method":"tools/call"}"#,
        ] {
            let ParsedLine::Message(env) = parse_line(line) else {
                panic!("{line} must be inspected")
            };
            assert_eq!(env.method.as_deref(), Some("tools/call"));
        }
    }

    /// The last of two equal keys is the one read, as the server reads it.
    ///
    /// FAILS ON REVERT: parse into the typed envelope again and the line is
    /// refused as a duplicate field, which used to mean forwarded unread.
    #[test]
    fn the_last_duplicate_key_wins_as_it_does_for_the_server() {
        let line = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/tmp/a"}},"params":{"name":"write_file","arguments":{"path":"/etc/sudoers"}}}"#;
        let ParsedLine::Message(env) = parse_line(line) else {
            panic!("a duplicate key must not make the line unreadable")
        };
        assert_eq!(env.params.unwrap()["name"], json!("write_file"));
        assert!(has_duplicate_keys(line));
        assert!(has_duplicate_keys(r#"[{"a":{"b":1,"b":2}}]"#));
        assert!(has_duplicate_keys(r#"{"a":1,"\u0061":2}"#));
        assert!(!has_duplicate_keys(
            r#"{"jsonrpc":"2.0","id":1,"params":{"a":{"a":1}},"result":[{"a":1},{"a":2}]}"#
        ));
        // Keys that cannot be checked are not taken for unique ones.
        assert!(has_duplicate_keys("not json"));
    }

    /// A lone surrogate made the duplicate check fail to read the line, and a
    /// line it could not read was taken to have no duplicate: the raw line,
    /// with the FIRST `params` that a first-key server runs, went through.
    ///
    /// FAILS ON REVERT: check the raw line only (`unwrap_or(false)`) and the
    /// duplicate is missed.
    #[test]
    fn a_duplicate_key_beside_a_lone_surrogate_is_still_seen() {
        let line = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"write_file","arguments":{"path":"/etc/sudoers"}},"params":{"name":"read_file","arguments":{"path":"/tmp/a","x":"\ud800"}}}"#;
        assert!(has_duplicate_keys(line));
        let ParsedLine::Message(env) = parse_line(line) else {
            panic!("read with the surrogate as U+FFFD")
        };
        assert_eq!(env.params.unwrap()["name"], json!("read_file"));
        assert!(!has_duplicate_keys(r#"{"a":"\ud800","b":1}"#));
    }

    #[test]
    fn a_null_field_reads_as_absent() {
        let ParsedLine::Message(env) =
            parse_line(r#"{"jsonrpc":"2.0","id":null,"method":"x","params":null}"#)
        else {
            panic!()
        };
        assert_eq!(env.id, None);
        assert_eq!(env.params, None);
    }

    #[test]
    fn id_string_vs_number_is_preserved() {
        let ParsedLine::Message(num) = parse_line(r#"{"jsonrpc":"2.0","id":7,"method":"ping"}"#)
        else {
            panic!()
        };
        assert_eq!(num.id, Some(json!(7)));

        let ParsedLine::Message(s) =
            parse_line(r#"{"jsonrpc":"2.0","id":"abc-123","method":"ping"}"#)
        else {
            panic!()
        };
        assert_eq!(s.id, Some(json!("abc-123")));
    }

    #[test]
    fn large_integer_id_round_trips_losslessly() {
        // u64-range id must survive parse → serialize unchanged (no f64 drift).
        let big: u64 = 9_007_199_254_740_993; // 2^53 + 1, loses precision as f64
        let line = format!(r#"{{"jsonrpc":"2.0","id":{big},"method":"ping"}}"#);
        let ParsedLine::Message(env) = parse_line(&line) else {
            panic!()
        };
        assert_eq!(env.id, Some(json!(big)));
        let out = serialize_line(&env);
        assert!(
            out.contains(&big.to_string()),
            "id lost precision on round-trip: {out}"
        );
    }

    #[test]
    fn unknown_top_level_fields_are_tolerated() {
        // `_meta` and other unknown fields must not break parsing (they are
        // preserved by raw forwarding, not by the envelope).
        let line = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"x"},"_meta":{"trace":"abc"},"extra":42}"#;
        let ParsedLine::Message(env) = parse_line(line) else {
            panic!("expected Message")
        };
        assert_eq!(env.method.as_deref(), Some("tools/call"));
        assert_eq!(env.id, Some(json!(1)));
    }

    #[test]
    fn serialize_line_never_emits_embedded_newline() {
        let env = JsonRpcEnvelope {
            jsonrpc: "2.0".into(),
            id: Some(json!(1)),
            method: None,
            params: None,
            result: Some(json!({"content":[{"type":"text","text":"line1\nline2"}],"isError":true})),
            error: None,
        };
        let out = serialize_line(&env);
        assert!(out.ends_with('\n'), "must end with a single newline");
        assert_eq!(
            out.matches('\n').count(),
            1,
            "the embedded newline in the text field must be escaped, not literal"
        );
        // Round-trips back to an equivalent envelope.
        let ParsedLine::Message(reparsed) = parse_line(out.trim_end()) else {
            panic!("synthesized line must re-parse as a Message")
        };
        assert_eq!(reparsed, env);
    }

    #[test]
    fn omitted_fields_are_not_serialized() {
        let env = JsonRpcEnvelope {
            jsonrpc: "2.0".into(),
            id: None,
            method: Some("ping".into()),
            params: None,
            result: None,
            error: None,
        };
        let out = serialize_line(&env);
        assert!(!out.contains("\"id\""), "absent id must be omitted: {out}");
        assert!(!out.contains("\"result\""));
        assert!(!out.contains("\"params\""));
    }
}
