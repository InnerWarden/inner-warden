//! JSON-RPC 2.0 envelope types and line framing for the MCP stdio proxy.
//!
//! MCP over stdio is newline-delimited JSON-RPC 2.0: exactly one JSON object
//! per line, never an array (batching was removed in spec revision 2025-06-18).
//! These types model just enough of the envelope to ROUTE and INSPECT a message
//! (`id` / `method` / `params` / `result` / `error`); unknown top-level fields
//! (e.g. `_meta`) are intentionally NOT captured, because pass-through messages
//! are forwarded as their original raw bytes and never re-serialized, that is
//! the only way to guarantee byte fidelity (no key reordering, no `1` vs `1.0`
//! number drift). [`serialize_line`] is used ONLY for messages the proxy
//! synthesizes itself (e.g. a denial), which have no unknown fields to preserve.

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
    /// A single JSON-RPC 2.0 object the proxy can inspect.
    Message(JsonRpcEnvelope),
    /// Non-empty but not a single JSON-RPC 2.0 object (e.g. a legacy batch
    /// array, or JSON the proxy chooses not to model). The transport forwards
    /// the raw bytes untouched, forward compatibility over strictness.
    Opaque(String),
}

/// Parse one line (newline already stripped) into a [`ParsedLine`].
///
/// Never panics. A line that is not a single JSON-RPC 2.0 object becomes
/// [`ParsedLine::Opaque`] so the transport forwards it verbatim rather than
/// dropping it.
pub fn parse_line(line: &str) -> ParsedLine {
    if line.trim().is_empty() {
        return ParsedLine::Empty;
    }
    match serde_json::from_str::<JsonRpcEnvelope>(line) {
        Ok(env) if env.jsonrpc == "2.0" => ParsedLine::Message(env),
        // Parsed but wrong/missing version, or not a JSON object at all
        // (array / scalar) → forward raw.
        _ => ParsedLine::Opaque(line.to_string()),
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

    #[test]
    fn top_level_array_is_opaque() {
        // Legacy batch array (batching removed from the spec): forward raw.
        let line = r#"[{"jsonrpc":"2.0","id":1,"method":"ping"}]"#;
        assert_eq!(parse_line(line), ParsedLine::Opaque(line.to_string()));
    }

    #[test]
    fn malformed_and_non_object_lines_are_opaque_not_panic() {
        for line in &["not json at all", "{ broken", "42", "\"a string\"", "true"] {
            assert_eq!(parse_line(line), ParsedLine::Opaque(line.to_string()));
        }
    }

    #[test]
    fn wrong_or_missing_version_is_opaque() {
        // Valid JSON object but not JSON-RPC 2.0 → pass through untouched.
        assert!(matches!(
            parse_line(r#"{"jsonrpc":"1.0","id":1,"method":"ping"}"#),
            ParsedLine::Opaque(_)
        ));
        assert!(matches!(
            parse_line(r#"{"id":1,"method":"ping"}"#),
            ParsedLine::Opaque(_)
        ));
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
