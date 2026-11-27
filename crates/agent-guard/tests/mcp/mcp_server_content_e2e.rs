//! End-to-end proof that the MCP proxy screens what a SERVER sends back, not
//! only what the client asks for.
//!
//! # Why this test exists
//!
//! Measured behind a deliberately vulnerable MCP lab server: most of the
//! secrets that reached the client did so in answers the proxy relayed
//! byte for byte. A `resources/read` was not screened at all, neither the
//! location it asked for nor the contents it returned, and a tool result that
//! carried an API key, a bearer token or a password was scanned for injection
//! only, then forwarded with the secret in it. The secret lives in the server's
//! own memory, so nothing on the host has a file read or a program run to
//! refuse: the message is the only place it can be stopped.
//!
//! # How it proves it
//!
//! The server is a small scripted MCP server that answers each request from a
//! table, and answers anything not in the table with what it was asked, so a
//! request that reached the server is visible in the client's output:
//!
//! * in `guard`, a secret-shaped value in any answer (a resource's contents, a
//!   tool result, a prompt, an error) is masked before the client sees it, and
//!   the rest of the answer, its id and its shape arrive as sent;
//! * in `advisory`, nothing is rewritten: the proxy stays a transparent pipe;
//! * a `resources/read` that climbs out of its root or names a secret store
//!   never reaches the server in `guard`, and the client gets an error reply
//!   keyed to its id;
//! * ordinary answers (documentation that names the word password, commit
//!   hashes, ids, an image) arrive untouched.
//!
//! The secret values are synthetic and are assembled from pieces at runtime,
//! so no provider-shaped literal lives in the source.

use std::sync::{Arc, Mutex};

use innerwarden_agent_guard::mcp_proxy::enforce::ProxyMode;
use innerwarden_agent_guard::mcp_proxy::transport::{run_proxy_with_io, ProxyConfig};
use innerwarden_agent_guard::rules::RuleEngine;
use serde_json::{json, Value};

/// The scripted server: reads one JSON-RPC request per line and answers it
/// from the table in `sys.argv[1]`, keyed by `"<method> <uri or name>"`. A
/// request with no entry is answered with the key it was asked for, which
/// proves it reached the server.
const SERVER: &str = r#"
import sys, json
table = json.loads(sys.argv[1])
for line in sys.stdin:
    try:
        msg = json.loads(line)
    except Exception:
        continue
    if not isinstance(msg, dict) or "id" not in msg or "method" not in msg:
        continue
    params = msg.get("params") or {}
    key = msg["method"] + " " + str(params.get("uri") or params.get("name") or "")
    entry = table.get(key)
    if entry is None:
        out = {"jsonrpc": "2.0", "id": msg["id"], "result": {"served": key}}
    else:
        out = dict(entry)
        out["jsonrpc"] = "2.0"
        out["id"] = msg["id"]
    sys.stdout.write(json.dumps(out) + "\n")
    sys.stdout.flush()
"#;

/// What the client saw, and every decision the proxy reported.
struct Run {
    out: String,
    events: Vec<Value>,
}

impl Run {
    /// The answer the client got for request `id`, parsed.
    fn answer(&self, id: u64) -> Value {
        self.out
            .lines()
            .filter_map(|line| serde_json::from_str::<Value>(line).ok())
            .find(|msg| msg.get("id").and_then(Value::as_u64) == Some(id))
            .unwrap_or_else(|| panic!("no answer for id {id} in:\n{}", self.out))
    }

    /// Every rule id the proxy reported, in order.
    fn rules(&self) -> Vec<String> {
        self.events
            .iter()
            .flat_map(|event| {
                event["verdict"]["alerts"]
                    .as_array()
                    .cloned()
                    .unwrap_or_default()
            })
            .filter_map(|alert| alert["rule"].as_str().map(str::to_string))
            .collect()
    }
}

/// Drive the proxy, with the rules `innerwarden proxy` loads, in front of the
/// scripted server.
fn run(table: &Value, requests: &[Value], mode: ProxyMode) -> Run {
    let input = requests
        .iter()
        .map(Value::to_string)
        .collect::<Vec<_>>()
        .join("\n")
        + "\n";
    let out = Arc::new(Mutex::new(Vec::<u8>::new()));
    let events = Arc::new(Mutex::new(Vec::<Value>::new()));
    let engine = Arc::new(RuleEngine::load_embedded());

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");
    let collected = Arc::clone(&out);
    let seen = Arc::clone(&events);
    let table = table.to_string();
    rt.block_on(async move {
        let client_in = std::io::Cursor::new(input.into_bytes());
        let writer = TestWriter(Arc::clone(&collected));
        let cfg = ProxyConfig {
            server_cmd: vec![
                "python3".to_string(),
                "-u".to_string(),
                "-c".to_string(),
                SERVER.to_string(),
                table,
            ],
            mode,
            as_protocol_error: false,
        };
        let _ = tokio::time::timeout(
            std::time::Duration::from_secs(20),
            run_proxy_with_io(client_in, writer, cfg, Some(engine), move |d| {
                seen.lock()
                    .expect("lock")
                    .push(serde_json::to_value(d).expect("decision serializes"));
            }),
        )
        .await;
    });

    let bytes = out.lock().expect("lock").clone();
    let events = events.lock().expect("lock").clone();
    Run {
        out: String::from_utf8_lossy(&bytes).to_string(),
        events,
    }
}

/// Minimal `AsyncWrite` that accumulates into a shared buffer.
struct TestWriter(Arc<Mutex<Vec<u8>>>);

impl tokio::io::AsyncWrite for TestWriter {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        self.0.lock().expect("lock").extend_from_slice(buf);
        std::task::Poll::Ready(Ok(buf.len()))
    }
    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }
    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }
}

fn request(id: u64, method: &str, params: Value) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params})
}

/// Synthetic secrets, one per class the proxy must mask, assembled at
/// runtime.
struct Secrets {
    api_key: String,
    stripe_key: String,
    github_token: String,
    aws_key_id: String,
    password: String,
    jwt: String,
    db_password: String,
    flag: String,
    private_key_body: String,
    private_key_block: String,
}

fn secrets() -> Secrets {
    let private_key_body = format!("b3BlbnNzaC1rZXktdjE{}", "AAAAlabkeymaterialonly");
    let private_key_block = format!(
        "-----BEGIN {kind} PRIVATE KEY-----\n{private_key_body}\n-----END {kind} PRIVATE KEY-----",
        kind = "OPENSSH"
    );
    Secrets {
        api_key: format!("sk-{}", "lab-reporting-key-7c41d09e2b"),
        stripe_key: format!("sk_{}_{}", "live", "51LabFakeKey0123456789"),
        github_token: format!("gh{}", "p_LabFakeToken0123456789abcdefABCDEF"),
        aws_key_id: format!("AKIA{}", "LABEXAMPLE7Q2W9Z"),
        password: format!("Lab-Pass-{}!", 4471),
        jwt: format!(
            "eyJhbGciOiJIUzI1NiJ9.{}.{}",
            "eyJzdWIiOiJsYWIifQ", "c2lnbmF0dXJlLWxhYi0wMQ"
        ),
        db_password: format!("Db-Lab-Pw-{}", 2026),
        flag: format!("LAB{{{}}}", "st0len_by_th3_read_9c2e"),
        private_key_body,
        private_key_block,
    }
}

/// The resource a vulnerable server keeps in memory: a config dump that
/// holds a credential of every class.
fn vault_text(s: &Secrets) -> String {
    format!(
        "Reporting service configuration\n\
         flag: {flag}\n\
         api_key: {api}\n\
         billing_key: {stripe}\n\
         ci_token_for_mirror {gh}\n\
         aws_key_id: {aws}\n\
         admin_password: {pw}\n\
         session: {jwt}\n\
         database_url: postgres://report:{db}@db.lab.internal:5432/sales\n\
         deploy key follows\n{pem}\n\
         Keep this page internal.",
        flag = s.flag,
        api = s.api_key,
        stripe = s.stripe_key,
        gh = s.github_token,
        aws = s.aws_key_id,
        pw = s.password,
        jwt = s.jwt,
        db = s.db_password,
        pem = s.private_key_block,
    )
}

fn assert_masked(seen: &str, s: &Secrets) {
    for (what, value) in [
        ("API key", s.api_key.as_str()),
        ("Stripe key", s.stripe_key.as_str()),
        ("GitHub token", s.github_token.as_str()),
        ("AWS key id", s.aws_key_id.as_str()),
        ("password", s.password.as_str()),
        ("JWT", s.jwt.as_str()),
        ("connection string password", s.db_password.as_str()),
        ("flag", s.flag.as_str()),
        ("private key body", s.private_key_body.as_str()),
    ] {
        assert!(
            !seen.contains(value),
            "the {what} reached the client unmasked:\n{seen}"
        );
    }
}

/// REGRESSION ANCHOR (lab case: a resource the server keeps in memory, read
/// with `resources/read`). Every secret in the contents is masked in `guard`,
/// and the rest of the answer arrives: its id, its shape, its plain text.
/// The resource was `vault://reporting` until 2026-11-20, when a read of a
/// secret store scheme (`vault://`) began to be refused in `guard` before it
/// reaches the server; the masking is proved on a location that is read.
///
/// FAILS ON REVERT: without the server-side masking the contents reach the
/// client byte for byte.
#[test]
fn guard_mode_masks_every_secret_class_in_a_resource_read() {
    let s = secrets();
    let table = json!({
        "resources/read config://reporting": {"result": {"contents": [
            {"uri": "config://reporting", "mimeType": "text/plain", "text": vault_text(&s)}
        ]}},
    });
    let seen = run(
        &table,
        &[request(
            1,
            "resources/read",
            json!({"uri": "config://reporting"}),
        )],
        ProxyMode::Guard,
    );

    assert_masked(&seen.out, &s);
    let answer = seen.answer(1);
    let text = answer["result"]["contents"][0]["text"]
        .as_str()
        .expect("the contents keep their shape");
    assert!(text.contains("Reporting service configuration"), "{text}");
    assert!(text.contains("Keep this page internal."), "{text}");
    assert!(text.contains("[REDACTED]"), "{text}");
    assert_eq!(answer["result"]["contents"][0]["uri"], "config://reporting");
    assert!(
        seen.rules().iter().any(|rule| rule == "AG-SECRET-OUT"),
        "the masking must be reported: {:?}",
        seen.rules()
    );
    // The report names the kinds, never the values.
    let events = serde_json::to_string(&seen.events).expect("json");
    assert_masked(&events, &s);
}

/// REGRESSION ANCHOR (lab case: debug output of a tool that leaks the
/// service's API key and an admin bearer token). A tool result is masked the
/// same way, and its other lines arrive.
#[test]
fn guard_mode_masks_secrets_in_a_tool_result_and_keeps_the_rest() {
    let s = secrets();
    let logs = format!(
        "System logs (debug)\n\
         [DEBUG] loaded header Authorization: Bearer {jwt}\n\
         [DEBUG] API key from env: {api}\n\
         [DEBUG] flag value {flag}\n\
         [DEBUG] scheduled task completed",
        jwt = s.jwt,
        api = s.api_key,
        flag = s.flag,
    );
    let table = json!({
        "tools/call view_logs": {"result": {"content": [{"type": "text", "text": logs}]}},
    });
    let seen = run(
        &table,
        &[request(
            2,
            "tools/call",
            json!({"name": "view_logs", "arguments": {"level": "debug"}}),
        )],
        ProxyMode::Guard,
    );

    for value in [&s.jwt, &s.api_key, &s.flag] {
        assert!(!seen.out.contains(value.as_str()), "leaked:\n{}", seen.out);
    }
    let text = seen.answer(2)["result"]["content"][0]["text"]
        .as_str()
        .expect("text block kept")
        .to_string();
    assert!(text.contains("[DEBUG] scheduled task completed"), "{text}");
    assert!(text.contains("Bearer [REDACTED]"), "{text}");
}

/// A secret in a prompt the server hands the client, in a JSON field of a
/// structured tool result, and in an error message, is masked too: every
/// server answer goes to the model the same way.
#[test]
fn guard_mode_masks_secrets_in_prompts_structured_content_and_errors() {
    let s = secrets();
    let table = json!({
        "prompts/get triage": {"result": {"messages": [
            {"role": "user", "content": {"type": "text",
             "text": format!("Use the key {} to open the ticket queue.", s.api_key)}}
        ]}},
        "tools/call db_settings": {"result": {
            "content": [{"type": "text", "text": "settings loaded"}],
            "structuredContent": {"host": "db.lab.internal", "password": s.password},
        }},
        "tools/call connect": {"error": {"code": -32000, "message":
            format!("cannot reach postgres://report:{}@db.lab.internal/sales", s.db_password)}},
    });
    let seen = run(
        &table,
        &[
            request(3, "prompts/get", json!({"name": "triage"})),
            request(
                4,
                "tools/call",
                json!({"name": "db_settings", "arguments": {}}),
            ),
            request(5, "tools/call", json!({"name": "connect", "arguments": {}})),
        ],
        ProxyMode::Guard,
    );

    for value in [&s.api_key, &s.password, &s.db_password] {
        assert!(!seen.out.contains(value.as_str()), "leaked:\n{}", seen.out);
    }
    assert_eq!(
        seen.answer(4)["result"]["structuredContent"]["host"],
        "db.lab.internal"
    );
    assert!(seen.answer(5)["error"]["message"]
        .as_str()
        .is_some_and(|message| message.starts_with("cannot reach postgres://report:")));
}

/// `advisory` is a transparent pipe: the finding is reported, the bytes are
/// not touched.
#[test]
fn advisory_mode_reports_a_secret_bearing_result_and_forwards_it_unchanged() {
    let s = secrets();
    let table = json!({
        "resources/read config://reporting": {"result": {"contents": [
            {"uri": "config://reporting", "text": vault_text(&s)}
        ]}},
    });
    let seen = run(
        &table,
        &[request(
            6,
            "resources/read",
            json!({"uri": "config://reporting"}),
        )],
        ProxyMode::Advisory,
    );

    assert!(seen.out.contains(&s.api_key), "{}", seen.out);
    assert!(seen.out.contains(&s.flag), "{}", seen.out);
    assert!(
        seen.rules().iter().any(|rule| rule == "AG-SECRET-OUT"),
        "{:?}",
        seen.rules()
    );
}

/// REGRESSION ANCHOR: a `resources/read` that climbs out of the resource
/// root, plainly or percent-encoded, names a private key store or a tool's
/// credential store (review 2C-EV-4), or carries a password in its user info
/// (review 2C-COR-1), never
/// reaches the server in `guard`; the client gets an error reply keyed to the
/// request, which is the shape a `resources/read` answer can take.
///
/// FAILS ON REVERT: unscreened, the server answers each one.
#[test]
fn guard_mode_refuses_a_resource_read_outside_its_root_or_of_a_key_store() {
    let seen = run(
        &json!({}),
        &[
            request(
                7,
                "resources/read",
                json!({"uri": "file:///srv/app/data/../../../etc/passwd"}),
            ),
            request(
                8,
                "resources/read",
                json!({"uri": "file:///srv/app/data/%2e%2e/%2E%2E/etc/hosts"}),
            ),
            request(
                9,
                "resources/read",
                json!({"uri": "file:///home/dev/.ssh/id_ed25519"}),
            ),
            request(
                40,
                "resources/read",
                json!({"uri": "file:///home/dev/.kube/config"}),
            ),
            request(
                41,
                "resources/read",
                json!({"uri": "https://admin:Pr0dLab2026x@reports.example.com/q1"}),
            ),
        ],
        ProxyMode::Guard,
    );

    assert!(
        !seen.out.contains("served"),
        "a refused read reached the server:\n{}",
        seen.out
    );
    for id in [7, 8, 9, 40, 41] {
        let answer = seen.answer(id);
        assert!(
            answer.get("error").is_some() && answer.get("result").is_none(),
            "a refused resources/read is answered with a JSON-RPC error: {answer}"
        );
    }
}

/// The other half: guard mode is not a wall. Ordinary resources and results
/// arrive byte for byte, including text that names the word password,
/// high-entropy ids that are not secrets, code, and an image.
#[test]
fn guard_mode_forwards_ordinary_resources_and_results_untouched() {
    let help = "Assistant help\n\
                To change your password: open Settings, then Security.\n\
                Passwords must be at least 12 characters long.\n\
                The token: expires after one hour of inactivity.\n\
                Set the key with export API_KEY=<your key> before you start.\n\
                Release commit 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b\n\
                sha256 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\n\
                request_id: req_7f3a9b2c trace 123e4567-e89b-12d3-a456-426614174000";
    let code = "def total():\n    result = sum(range(10))\n    max_tokens=4096\n    return result";
    let png = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg==";
    let table = json!({
        "resources/read info://help": {"result": {"contents": [
            {"uri": "info://help", "mimeType": "text/plain", "text": help}
        ]}},
        "tools/call run_snippet": {"result": {"content": [
            {"type": "text", "text": code},
            {"type": "image", "mimeType": "image/png", "data": png}
        ]}},
    });
    let seen = run(
        &table,
        &[
            request(10, "resources/read", json!({"uri": "info://help"})),
            request(11, "resources/read", json!({"uri": "docs://search_help"})),
            request(
                12,
                "resources/read",
                json!({"uri": "file:///srv/app/data/readme.txt"}),
            ),
            request(
                13,
                "tools/call",
                json!({"name": "run_snippet", "arguments": {}}),
            ),
        ],
        ProxyMode::Guard,
    );

    assert!(!seen.out.contains("[REDACTED]"), "{}", seen.out);
    assert_eq!(seen.answer(10)["result"]["contents"][0]["text"], help);
    assert_eq!(
        seen.answer(11)["result"]["served"],
        "resources/read docs://search_help"
    );
    assert_eq!(
        seen.answer(12)["result"]["served"],
        "resources/read file:///srv/app/data/readme.txt"
    );
    assert_eq!(seen.answer(13)["result"]["content"][0]["text"], code);
    assert_eq!(seen.answer(13)["result"]["content"][1]["data"], png);
    assert!(
        !seen.rules().iter().any(|rule| rule == "AG-SECRET-OUT"),
        "{:?}",
        seen.rules()
    );
}

/// REGRESSION ANCHOR (review 2C-FP-2, lab case: a login tool that issues a
/// session token the client must pass back to the next call). In `guard` the
/// token arrived as `[REDACTED]`, the client sent the marker back, and every
/// later call of the session failed as unauthenticated, with no refusal to
/// show for it.
///
/// A token the server issues under a session key, in answer to a call that
/// itself supplied a password, is the session's own: the client already holds
/// the credential it was exchanged for, so seeing the token gives it nothing it
/// could not do. It is left in place. Everything else in that answer is still
/// masked, and the same token in any other answer is masked.
///
/// FAILS ON REVERT: the login answer carried `token: [REDACTED]`.
#[test]
fn guard_mode_keeps_the_session_token_a_login_issues_and_masks_the_rest() {
    let s = secrets();
    let admin_jwt = format!(
        "eyJhbGciOiJIUzI1NiJ9.{}.{}",
        "eyJyb2xlIjoiYWRtaW4ifQ", "YWRtaW4tc2lnbmF0dXJlLTAy"
    );
    let signing_secret = format!("Lab-Signing-{}!", 7731);
    let login = format!(
        "Login successful\n  user: guest\n  token: {jwt}\n  admin_token: {admin}\n  signing_secret: {sig}\nUse this token with whoami.",
        jwt = s.jwt,
        admin = admin_jwt,
        sig = signing_secret,
    );
    let config = format!("Server config\n  token: {jwt}\n", jwt = s.jwt);
    let table = json!({
        "tools/call login": {"result": {
            "content": [{"type": "text", "text": login}],
            "structuredContent": {"session_token": s.jwt, "user": "guest"}
        }},
        "tools/call get_server_config": {"result": {"content": [{"type": "text", "text": config}]}},
    });
    let seen = run(
        &table,
        &[
            request(
                20,
                "tools/call",
                json!({"name": "login", "arguments": {"username": "guest", "password": "guest-lab-pw"}}),
            ),
            request(
                21,
                "tools/call",
                json!({"name": "get_server_config", "arguments": {}}),
            ),
        ],
        ProxyMode::Guard,
    );

    let login = seen.answer(20);
    let text = login["result"]["content"][0]["text"]
        .as_str()
        .expect("text kept");
    assert!(
        text.contains(&format!("token: {}", s.jwt)),
        "the session token the login issued must reach the client:\n{text}"
    );
    assert_eq!(login["result"]["structuredContent"]["session_token"], s.jwt);
    assert!(
        !text.contains(&admin_jwt),
        "another token in the same answer is masked:\n{text}"
    );
    assert!(
        !text.contains(&signing_secret),
        "a secret in the same answer is masked:\n{text}"
    );
    let config = seen.answer(21)["result"]["content"][0]["text"]
        .as_str()
        .expect("text kept")
        .to_string();
    assert!(
        !config.contains(&s.jwt),
        "the same token in an answer to a call that supplied no credential is masked:\n{config}"
    );
}

/// REGRESSION ANCHOR (review 2C-FP-1, lab case: a files server reading an
/// ordinary web view). Source code that names a token, a key and a password
/// arrives byte for byte, so an agent editing the file it read never writes a
/// mask back into the source.
///
/// FAILS ON REVERT: three expressions came back as `[REDACTED]`.
#[test]
fn guard_mode_forwards_source_code_that_names_secrets_unchanged() {
    let view = "from django.conf import settings\n\
                def login_view(request):\n    \
                token = request.headers.get(\"Authorization\")\n    \
                api_key = config.api_key\n    \
                password=form.cleaned_data[\"password\"]\n    \
                return token\n";
    let table = json!({
        "tools/call read_file": {"result": {"content": [{"type": "text", "text": view}]}},
    });
    let seen = run(
        &table,
        &[request(
            30,
            "tools/call",
            json!({"name": "read_file", "arguments": {"file_path": "/srv/app/views.py"}}),
        )],
        ProxyMode::Guard,
    );
    assert_eq!(seen.answer(30)["result"]["content"][0]["text"], view);
    assert!(
        !seen.rules().iter().any(|rule| rule == "AG-SECRET-OUT"),
        "{:?}",
        seen.rules()
    );
}
