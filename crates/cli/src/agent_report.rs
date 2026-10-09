//! Tell a local InnerWarden agent that `innerwarden proxy` refused a tool call.
//!
//! In `guard` or `kill` mode the proxy answers a dangerous `tools/call` with a
//! denial, and until 1.5.3 that refusal lived only in this CLI's own graph and
//! a stderr line. When an InnerWarden agent runs on the same host, it now also
//! hears about it: one `POST /api/agent/proxy-block` per refused call, so the
//! refusal becomes a case there.
//!
//! What is sent is what the proxy already records about the decision: the
//! proxy's label, the tool, the router's redacted and bounded summary of the
//! call, the rule ids that fired and the mode. Never the raw arguments. The
//! report says nothing about who sent it; that is for the agent to establish.
//!
//! Standalone is the normal case. With no agent, an agent that does not take
//! the route, or any other failure, the proxy says so ONCE on stderr and goes
//! on exactly as before. Reports go out from a thread of their own, so a slow
//! or absent agent never delays an MCP message, and only to this host's
//! loopback: `INNERWARDEN_AGENT_URL` may name another loopback address or
//! port (default `https://127.0.0.1:8787`), and `off` turns reporting off.

use std::sync::mpsc::{Receiver, SyncSender};
use std::time::Duration;

use innerwarden_agent_guard::mcp_proxy::enforce::{apply_mode, ProxyAction, ProxyMode};
use innerwarden_agent_guard::mcp_proxy::router::ProxyDecision;
use serde_json::{json, Value};

/// Where the agent listens when nothing says otherwise.
pub const DEFAULT_AGENT_URL: &str = "https://127.0.0.1:8787";

/// The agent's route for a refused call.
pub const PROXY_BLOCK_PATH: &str = "/api/agent/proxy-block";

/// The variable that names another loopback address, or `off`.
pub const AGENT_URL_VAR: &str = "INNERWARDEN_AGENT_URL";

/// How long one report may take, connect to answer.
const REPORT_TIMEOUT: Duration = Duration::from_secs(3);

/// How long the proxy waits, on exit, for its last reports.
pub const REPORT_DRAIN: Duration = Duration::from_secs(3);

/// Reports queued at once; past it a report is dropped.
const REPORT_QUEUE: usize = 32;

/// Longest label, tool or rule id the agent takes.
const NAME_CHARS: usize = 96;

/// Longest summary the agent takes.
const SUMMARY_CHARS: usize = 1_000;

/// A name as the agent takes it: letters, digits, `.`, `_`, `-`, `:`, `/`.
fn report_name(raw: &str) -> String {
    raw.trim()
        .chars()
        .take(NAME_CHARS)
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | ':' | '/') {
                c
            } else {
                '-'
            }
        })
        .collect()
}

/// PURE. The report for a decision the proxy REFUSED (answered with a denial,
/// never passed to the server), or `None`. Decided by `apply_mode`, the same
/// function the proxy's transport acts on.
pub fn block_report(label: &str, mode: ProxyMode, d: &ProxyDecision) -> Option<Value> {
    let refused = matches!(
        apply_mode(d, mode, false),
        ProxyAction::Block { .. } | ProxyAction::Kill { .. }
    );
    if !refused {
        return None;
    }
    let summary: String = d
        .tool_summary
        .clone()
        .or_else(|| d.tool_name.clone())
        .unwrap_or_else(|| "tools/call".to_string())
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .take(SUMMARY_CHARS)
        .collect();
    let label = Some(report_name(label))
        .filter(|l| !l.is_empty())
        .unwrap_or_else(|| "innerwarden".to_string());
    let tool = d
        .tool_name
        .as_deref()
        .map(report_name)
        .filter(|t| !t.is_empty());
    let rules: Vec<String> = d
        .verdict
        .alerts
        .iter()
        .map(|a| report_name(&a.rule))
        .filter(|r| !r.is_empty())
        .take(16)
        .collect();
    Some(json!({
        "kind": "mcp_proxy_block",
        "agent_name": label,
        "command": summary,
        "tool": tool,
        "rule_ids": rules,
        "mode": if mode == ProxyMode::Kill { "kill" } else { "guard" },
    }))
}

/// Is `url` on this host's loopback?
fn is_loopback_url(url: &str) -> bool {
    let authority = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))
        .unwrap_or("")
        .split('/')
        .next()
        .unwrap_or("");
    let host = match authority.strip_prefix('[') {
        Some(rest) => rest.split_once(']').map(|(host, _)| host).unwrap_or(rest),
        None => authority.split(':').next().unwrap_or(authority),
    };
    matches!(host, "127.0.0.1" | "localhost" | "::1")
}

/// PURE. Where reports go, from the variable's value: `None` when reporting
/// is off, with what to say about it.
pub fn report_url(var: Option<&str>) -> Result<String, String> {
    let raw = var.map(str::trim).filter(|v| !v.is_empty());
    match raw {
        None => Ok(format!("{DEFAULT_AGENT_URL}{PROXY_BLOCK_PATH}")),
        Some(v) if v.eq_ignore_ascii_case("off") => Err(String::new()),
        Some(v) if is_loopback_url(v) => {
            Ok(format!("{}{PROXY_BLOCK_PATH}", v.trim_end_matches('/')))
        }
        Some(v) => Err(format!(
            "innerwarden proxy: {AGENT_URL_VAR}={v} is not this host's loopback; \
             refused calls are not reported"
        )),
    }
}

/// POST one report; `Err` says why it was not taken.
pub fn send_report(url: &str, body: &Value) -> Result<(), String> {
    let mut config = ureq::Agent::config_builder()
        .timeout_global(Some(REPORT_TIMEOUT))
        .http_status_as_error(false);
    if is_loopback_url(url) {
        // The agent's dashboard on loopback answers with a self-signed
        // certificate. Only ever relaxed for loopback.
        config = config.tls_config(
            ureq::tls::TlsConfig::builder()
                .disable_verification(true)
                .build(),
        );
    }
    let agent: ureq::Agent = config.build().into();
    let response = agent
        .post(url)
        .send_json(body)
        .map_err(|error| error.to_string())?;
    let status = response.status().as_u16();
    if (200..300).contains(&status) {
        Ok(())
    } else {
        Err(format!("HTTP {status}"))
    }
}

/// Sends refusal reports from a thread of its own.
pub struct BlockReporter {
    tx: Option<SyncSender<Value>>,
    done: Option<Receiver<()>>,
}

impl BlockReporter {
    /// Start reporting to the URL `INNERWARDEN_AGENT_URL` names (or the
    /// default).
    pub fn from_env() -> Self {
        match report_url(std::env::var(AGENT_URL_VAR).ok().as_deref()) {
            Ok(url) => Self::start(url),
            Err(why) => {
                if !why.is_empty() {
                    eprintln!("{why}");
                }
                Self::off()
            }
        }
    }

    fn off() -> Self {
        Self {
            tx: None,
            done: None,
        }
    }

    /// Start reporting to `url` (the full route).
    pub fn start(url: String) -> Self {
        let (tx, rx) = std::sync::mpsc::sync_channel::<Value>(REPORT_QUEUE);
        let (done_tx, done) = std::sync::mpsc::channel();
        let spawned = std::thread::Builder::new()
            .name("proxy-report".to_string())
            .spawn(move || {
                let mut warned = false;
                for body in rx {
                    if let Err(why) = send_report(&url, &body) {
                        if !warned {
                            warned = true;
                            eprintln!(
                                "innerwarden proxy: no InnerWarden agent took the report at \
                                 {url} ({why}); refused calls stay in this proxy's own record"
                            );
                        }
                    }
                }
                let _ = done_tx.send(());
            });
        match spawned {
            Ok(_) => Self {
                tx: Some(tx),
                done: Some(done),
            },
            Err(_) => Self::off(),
        }
    }

    /// A handle the proxy's callback queues reports on, `None` when off.
    pub fn sender(&self) -> Option<SyncSender<Value>> {
        self.tx.clone()
    }

    /// Stop taking reports and wait, at most `wait`, for the queued ones.
    pub fn finish(mut self, wait: Duration) {
        drop(self.tx.take());
        if let Some(done) = self.done.take() {
            let _ = done.recv_timeout(wait);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use innerwarden_agent_guard::mcp_proxy::jsonrpc::{parse_line, ParsedLine};
    use innerwarden_agent_guard::mcp_proxy::router::{route_message, Direction};

    fn routed(line: &str) -> ProxyDecision {
        let ParsedLine::Message(env) = parse_line(line) else {
            panic!("message")
        };
        route_message(&env, Direction::ClientToServer, None, None, None)
    }

    /// A request read to the end its `content-length` names.
    fn whole_request(seen: &[u8]) -> bool {
        let text = String::from_utf8_lossy(seen);
        let Some((head, body)) = text.split_once("\r\n\r\n") else {
            return false;
        };
        let length = head
            .lines()
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                name.trim()
                    .eq_ignore_ascii_case("content-length")
                    .then(|| value.trim().parse::<usize>().ok())?
            })
            .unwrap_or(0);
        body.len() >= length
    }

    const CRED_CALL: &str = r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"save","arguments":{"token":"sk-ant-aaaaaaaaaaaaaaaaaaaaaaaa"}}}"#;

    /// Only a call the proxy refused is reported, and never with its raw
    /// arguments.
    ///
    /// FAILS ON REVERT: report every alert (or none) and a forwarded call is
    /// reported as refused (or a refusal is not).
    #[test]
    fn only_a_refused_call_is_reported_and_without_its_raw_arguments() {
        let cred = routed(CRED_CALL);
        assert!(!cred.verdict.allowed);
        let body = block_report("my proxy", ProxyMode::Guard, &cred).expect("refused in guard");
        assert_eq!(body["kind"], "mcp_proxy_block");
        assert_eq!(body["mode"], "guard");
        assert_eq!(body["agent_name"], "my-proxy");
        assert_eq!(body["tool"], "save");
        assert!(body["rule_ids"]
            .as_array()
            .unwrap()
            .iter()
            .any(|r| r == "AG-CRED"));
        assert!(!body.to_string().contains("sk-ant-aaaa"), "{body}");
        assert_eq!(
            block_report("l", ProxyMode::Kill, &cred).unwrap()["mode"],
            "kill"
        );
        for forwarding in [ProxyMode::Advisory, ProxyMode::Warn] {
            assert_eq!(block_report("l", forwarding, &cred), None);
        }
        let clean = routed(
            r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"list_directory","arguments":{"path":"/tmp"}}}"#,
        );
        assert_eq!(block_report("l", ProxyMode::Guard, &clean), None);
    }

    /// Reports only ever go to this host's loopback; `off` turns them off.
    #[test]
    fn reports_go_to_loopback_or_nowhere() {
        assert_eq!(
            report_url(None).unwrap(),
            "https://127.0.0.1:8787/api/agent/proxy-block"
        );
        assert_eq!(
            report_url(Some("https://127.0.0.1:443/")).unwrap(),
            "https://127.0.0.1:443/api/agent/proxy-block"
        );
        assert_eq!(
            report_url(Some("http://[::1]:9000")).unwrap(),
            "http://[::1]:9000/api/agent/proxy-block"
        );
        assert_eq!(report_url(Some("off")), Err(String::new()));
        for elsewhere in [
            "https://10.0.0.5:8787",
            "https://127.0.0.1.evil.example",
            "https://localhost.evil.example:8787",
            "ftp://127.0.0.1",
        ] {
            assert!(
                report_url(Some(elsewhere)).is_err_and(|why| !why.is_empty()),
                "{elsewhere}"
            );
        }
    }

    /// No agent on the port: the report fails and `finish` returns within
    /// its bound; the proxy never waits on an absent agent.
    #[test]
    fn a_missing_agent_never_holds_the_proxy() {
        let port = {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            listener.local_addr().unwrap().port()
        };
        let url = format!("http://127.0.0.1:{port}{PROXY_BLOCK_PATH}");
        assert!(send_report(&url, &json!({})).is_err());
        let reporter = BlockReporter::start(url);
        let tx = reporter.sender().expect("on");
        tx.try_send(json!({"kind": "mcp_proxy_block"})).unwrap();
        drop(tx);
        let started = std::time::Instant::now();
        reporter.finish(Duration::from_secs(10));
        assert!(started.elapsed() < Duration::from_secs(10));
    }

    /// The report is POSTed to the agent's route, as JSON, and a 2xx is
    /// taken.
    #[test]
    fn a_report_is_posted_to_the_agent_route() {
        use std::io::{Read, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let mut seen = Vec::new();
            let mut buf = [0u8; 4096];
            while !whole_request(&seen) {
                let n = stream.read(&mut buf).unwrap();
                if n == 0 {
                    break;
                }
                seen.extend_from_slice(&buf[..n]);
            }
            stream
                .write_all(b"HTTP/1.1 202 Accepted\r\ncontent-length: 2\r\n\r\n{}")
                .unwrap();
            String::from_utf8_lossy(&seen).into_owned()
        });
        let body = block_report("l", ProxyMode::Guard, &routed(CRED_CALL)).unwrap();
        send_report(&format!("http://127.0.0.1:{port}{PROXY_BLOCK_PATH}"), &body).unwrap();
        let request = server.join().unwrap();
        assert!(
            request.starts_with("POST /api/agent/proxy-block "),
            "{request}"
        );
        let (_, sent) = request.split_once("\r\n\r\n").expect("a body");
        let sent: Value = serde_json::from_str(sent).expect("a JSON body");
        assert_eq!(sent, body);
    }
}
