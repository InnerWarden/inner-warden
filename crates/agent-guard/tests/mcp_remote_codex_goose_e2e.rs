//! End-to-end: a Codex and a Goose server reached by URL, wired through
//! the MCP proxy by connect and given back by disconnect.
//!
//! Codex names its server in TOML (`url`, the token's variable in
//! `bearer_token_env_var`, headers in `http_headers` and
//! `env_http_headers`); Goose in YAML (`type: streamable_http`, `uri`,
//! `headers` with `$VAR`). Each is wired, the proxy is run as the agent
//! would run the wrapper (its words, and the environment the agent gives
//! it), against a fake HTTP server on 127.0.0.1, and the test proves:
//!
//! * the server gets the token and every header, read from the variables
//!   the agent reads, while no token is written in the file or the wrapper;
//! * a tool call goes through and its answer comes back;
//! * disconnect gives back the file byte for byte.
//!
//! FAILS ON REVERT of the TOML or YAML wiring (the server stays as it was,
//! nothing to run), or of `--bearer-env` / `--goose-headers` in the proxy
//! (the words are refused and the session never starts, or the server sees
//! no token).

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use innerwarden_agent_guard::mcp_proxy::enforce::ProxyMode;
use innerwarden_agent_guard::mcp_proxy::transport::{run_proxy_with_io, ProxyConfig};
use innerwarden_agent_guard::{mcp_wire, mcp_wire_toml, mcp_wire_yaml};
use serde_json::{json, Value};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt};

const BIN: &str = "/usr/local/bin/innerwarden";
const TOKEN: &str = "t142-secret-token-value";

type Log = Arc<Mutex<Vec<HashMap<String, String>>>>;

/// A Streamable HTTP server that answers in JSON and keeps the headers of
/// every request.
fn server() -> (String, Log) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let url = format!("http://{}/mcp", listener.local_addr().unwrap());
    let log: Log = Arc::default();
    let seen = Arc::clone(&log);
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            let seen = Arc::clone(&seen);
            std::thread::spawn(move || serve(stream, seen));
        }
    });
    (url, log)
}

fn serve(stream: TcpStream, seen: Log) {
    let mut writer = stream.try_clone().expect("clone");
    let mut reader = BufReader::new(stream);
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line).unwrap_or(0) == 0 {
            return;
        }
        let method = line
            .split_whitespace()
            .next()
            .unwrap_or_default()
            .to_string();
        let mut headers = HashMap::new();
        loop {
            let mut header = String::new();
            if reader.read_line(&mut header).unwrap_or(0) == 0 {
                return;
            }
            let header = header.trim_end();
            if header.is_empty() {
                break;
            }
            if let Some((name, value)) = header.split_once(':') {
                headers.insert(name.trim().to_ascii_lowercase(), value.trim().to_string());
            }
        }
        let length: usize = headers
            .get("content-length")
            .and_then(|l| l.parse().ok())
            .unwrap_or(0);
        let mut body = vec![0u8; length];
        if reader.read_exact(&mut body).is_err() {
            return;
        }
        seen.lock().unwrap().push(headers);
        let request: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
        let reply = match (method.as_str(), request.get("id")) {
            ("POST", Some(id)) => {
                let result = match request["method"].as_str() {
                    Some("initialize") => json!({
                        "protocolVersion": "2025-06-18",
                        "capabilities": {"tools": {}},
                        "serverInfo": {"name": "fake-remote", "version": "1"}
                    }),
                    Some("tools/list") => json!({"tools": [
                        {"name": "read_document", "description": "Read a document.",
                         "inputSchema": {"type": "object", "properties": {"document_id": {"type": "string"}}}}
                    ]}),
                    Some("tools/call") => {
                        json!({"content": [{"type": "text", "text": "the document"}], "isError": false})
                    }
                    _ => json!({}),
                };
                Some(json!({"jsonrpc": "2.0", "id": id, "result": result}).to_string())
            }
            _ => None,
        };
        let (status, body) = match (method.as_str(), reply) {
            (_, Some(body)) => ("200 OK", body),
            ("GET", None) => ("405 Method Not Allowed", String::new()),
            _ => ("202 Accepted", String::new()),
        };
        let _ = write!(
            writer,
            "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        );
        let _ = writer.flush();
    }
}

/// Run the proxy as the agent runs the wrapper (its words after `--`), with
/// the environment already set, and make one tool call through it.
fn session(server_cmd: Vec<String>) -> Value {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");
    rt.block_on(async move {
        let (client_side, proxy_side) = tokio::io::duplex(1 << 20);
        let (proxy_in, proxy_out) = tokio::io::split(proxy_side);
        let cfg = ProxyConfig {
            server_cmd,
            mode: ProxyMode::Guard,
            as_protocol_error: false,
        };
        let proxy = tokio::spawn(run_proxy_with_io(proxy_in, proxy_out, cfg, None, |_| {}));
        let (reader, mut writer) = tokio::io::split(client_side);
        let mut lines = tokio::io::BufReader::new(reader).lines();
        let mut answer = Value::Null;
        for (id, method, params) in [
            (1, "initialize", json!({"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "t", "version": "0"}})),
            (2, "tools/list", json!({})),
            (3, "tools/call", json!({"name": "read_document", "arguments": {"document_id": "4"}})),
        ] {
            let line = format!("{}\n", json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params}));
            writer.write_all(line.as_bytes()).await.unwrap();
            writer.flush().await.unwrap();
            loop {
                let line = tokio::time::timeout(Duration::from_secs(20), lines.next_line())
                    .await
                    .expect("an answer in time")
                    .unwrap()
                    .expect("the proxy is still there");
                let message: Value = serde_json::from_str(&line).unwrap();
                if message["id"] == json!(id) {
                    answer = message;
                    break;
                }
            }
        }
        drop(writer);
        drop(lines);
        let _ = tokio::time::timeout(Duration::from_secs(15), proxy).await;
        answer
    })
}

/// The words after the wrapper's `--`.
fn server_words(args: &[String]) -> Vec<String> {
    let at = args.iter().position(|a| a == "--").expect("a wrapper");
    args[at + 1..].to_vec()
}

fn last_headers(log: &Log) -> HashMap<String, String> {
    log.lock()
        .unwrap()
        .last()
        .cloned()
        .expect("the server was reached")
}

/// Both agents in one test: the proxy reads the process environment and
/// HOME, which tests running beside it would change.
#[test]
fn codex_and_goose_remote_servers_go_through_the_proxy_and_come_back() {
    let home = tempfile::TempDir::new().unwrap();
    std::env::set_var("HOME", home.path());
    std::env::set_var("IW_T142_CODEX_TOKEN", TOKEN);
    std::env::set_var("IW_T142_ORG", "org-7");
    std::env::set_var("IW_T142_GOOSE_TOKEN", TOKEN);

    // Codex.
    let (url, log) = server();
    let original = format!(
        "# my Codex settings\nmodel = \"gpt-5\"\n\n[mcp_servers.docs]\nurl = \"{url}\"  # the docs server\nbearer_token_env_var = \"IW_T142_CODEX_TOKEN\"\nhttp_headers = {{ X-Team = \"blue\" }}\nenv_http_headers = {{ X-Org = \"IW_T142_ORG\" }}\nstartup_timeout_sec = 20\n"
    );
    let mut doc: toml_edit::DocumentMut = original.parse().unwrap();
    assert_eq!(mcp_wire_toml::wrap_toml(&mut doc, BIN, false, "codex"), 1);
    assert!(mcp_wire_toml::is_guarded_toml(&doc));
    let wired = doc.to_string();
    assert!(!wired.contains(TOKEN), "{wired}");
    let docs = doc["mcp_servers"]["docs"].as_table().unwrap();
    for key in [
        "url",
        "bearer_token_env_var",
        "http_headers",
        "env_http_headers",
    ] {
        assert!(
            docs.get(key).is_none(),
            "Codex refuses {key} on a local server: {wired}"
        );
    }
    let args: Vec<String> = docs["args"]
        .as_array()
        .unwrap()
        .iter()
        .map(|a| a.as_str().unwrap().to_string())
        .collect();
    // What Codex gives the proxy: `env` as set, `env_vars` from its own.
    let env = docs["env"].as_inline_table().unwrap();
    let header = env
        .get("INNERWARDEN_MCP_HEADER_1")
        .unwrap()
        .as_str()
        .unwrap();
    assert_eq!(header, "X-Team: blue");
    std::env::set_var("INNERWARDEN_MCP_HEADER_1", header);
    let vars: Vec<&str> = docs["env_vars"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    assert_eq!(vars, ["IW_T142_CODEX_TOKEN", "IW_T142_ORG"]);
    let answer = session(server_words(&args));
    assert_eq!(
        answer.pointer("/result/content/0/text"),
        Some(&json!("the document")),
        "{answer}"
    );
    let headers = last_headers(&log);
    assert_eq!(
        headers.get("authorization").map(String::as_str),
        Some(format!("Bearer {TOKEN}").as_str())
    );
    assert_eq!(headers.get("x-team").map(String::as_str), Some("blue"));
    assert_eq!(headers.get("x-org").map(String::as_str), Some("org-7"));
    std::env::remove_var("INNERWARDEN_MCP_HEADER_1");
    assert_eq!(mcp_wire_toml::unwrap_toml(&mut doc), 1);
    assert_eq!(doc.to_string(), original);

    // Goose.
    let (url, log) = server();
    let original = format!(
        "GOOSE_PROVIDER: anthropic\nextensions:\n  remote-tools:\n    enabled: true\n    env_keys:\n    - IW_T142_GOOSE_TOKEN\n    envs: {{}}\n    headers:\n      Authorization: Bearer ${{IW_T142_GOOSE_TOKEN}}\n      X-Team: blue\n    name: remote-tools\n    timeout: 300\n    type: streamable_http\n    uri: {url}\nGOOSE_MODE: smart_approve\n"
    );
    let path = home.path().join(".config/goose/config.yaml");
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    let mut doc = mcp_wire_yaml::YamlDoc::parse(&original).unwrap();
    let (wrapped, n) = mcp_wire::wrap(doc.view(), BIN, false, "goose");
    assert_eq!(n, 1);
    assert_eq!(doc.apply(&wrapped).unwrap(), 1);
    assert!(mcp_wire::is_guarded(&doc.view()));
    std::fs::write(&path, doc.text()).unwrap();
    assert!(!doc.text().contains(TOKEN));
    // Goose reads a stdio extension: its type, cmd and args.
    let reread: serde_yaml::Value = serde_yaml::from_str(doc.text()).unwrap();
    let extension = &reread["extensions"]["remote-tools"];
    assert_eq!(extension["type"], "stdio");
    assert_eq!(extension["cmd"], BIN);
    let args: Vec<String> = extension["args"]
        .as_sequence()
        .unwrap()
        .iter()
        .map(|a| a.as_str().unwrap().to_string())
        .collect();
    let answer = session(server_words(&args));
    assert_eq!(
        answer.pointer("/result/content/0/text"),
        Some(&json!("the document")),
        "{answer}"
    );
    let headers = last_headers(&log);
    assert_eq!(
        headers.get("authorization").map(String::as_str),
        Some(format!("Bearer {TOKEN}").as_str())
    );
    assert_eq!(headers.get("x-team").map(String::as_str), Some("blue"));
    let (restored, n) = mcp_wire::unwrap(doc.view());
    assert_eq!(n, 1);
    assert_eq!(doc.apply(&restored).unwrap(), 1);
    assert_eq!(doc.text(), original);
}
