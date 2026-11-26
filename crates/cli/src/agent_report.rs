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
//! A server's message the proxy acted on in a mode that blocks is reported
//! the same way ([`server_held`]): a description or an answer carrying orders
//! for the model withheld, a tool whose definition changed held, a line it
//! cannot read refused, a secret-shaped value masked. Its body says
//! `"direction": "server->client"` and its `command` names the server's
//! message ([`server_summary`]), never a call the agent made.
//!
//! A report is never lost unsaid: one the full queue ([`REPORT_QUEUE`])
//! turns away, or one still queued when the proxy exits, is counted, and the
//! count is said in one line on stderr ([`lost_line`]).
//!
//! Standalone is the normal case. With no agent, an agent that does not take
//! the route, or any other failure, the proxy says so ONCE on stderr and goes
//! on exactly as before. Reports go out from a thread of their own, so a slow
//! or absent agent never delays an MCP message, and only to this host's
//! loopback: `INNERWARDEN_AGENT_URL` may name another loopback address or
//! port (default `https://127.0.0.1:8787`), and `off` turns reporting off.
//! `off` turns off only this report: the refusal is still written to the
//! local record, and to the guard's own record even where `IW_GRAPH_FILE`
//! moved the proxy's (`graph_io::record_mcp`), so the agent still reads its
//! `guard.blocked` line where it reads the shared record.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::{Receiver, SyncSender, TryRecvError, TrySendError};
use std::sync::Arc;
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

/// Reports queued at once; past it a report is dropped, and counted.
pub const REPORT_QUEUE: usize = 32;

/// The direction of a decision on a server's message.
pub const FROM_SERVER: &str = "server->client";

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

/// The `--mode` word for `mode`, as the person wrote it.
fn mode_word(mode: ProxyMode) -> &'static str {
    match mode {
        ProxyMode::Advisory => "advisory",
        ProxyMode::Warn => "warn",
        ProxyMode::Guard => "guard",
        ProxyMode::Kill => "kill",
        ProxyMode::Strict => "strict",
    }
}

/// PURE. Whether the proxy, in `mode`, acted on what a finding on a
/// server's message names. A mode that blocks withholds a description or an
/// answer carrying orders for the model, holds a tool whose definition
/// changed and refuses a line it cannot read (each is a finding that refuses:
/// `verdict.allowed` is false), and masks a secret-shaped value
/// (`AG-SECRET-OUT`). A mode that never blocks forwards all of it.
pub fn server_held(d: &ProxyDecision, mode: ProxyMode) -> bool {
    d.direction == FROM_SERVER
        && mode.blocks()
        && (!d.verdict.allowed
            || d.verdict
                .alerts
                .iter()
                .any(|a| a.rule == innerwarden_agent_guard::mcp_proxy::content::SECRET_OUT_RULE))
}

/// PURE. What a finding on a server's message is recorded and reported as:
/// the server's message, by its method, never a call the agent made.
pub fn server_summary(d: &ProxyDecision) -> String {
    let what = d
        .method
        .as_deref()
        .unwrap_or("a line that is not a JSON-RPC message");
    match d.tool_name.as_deref() {
        Some(tool) => format!("mcp server: {what} ({tool})"),
        None => format!("mcp server: {what}"),
    }
}

/// PURE. The report for a decision the proxy REFUSED (a call answered with a
/// denial, never passed to the server) or, on a server's message, held back
/// or masked ([`server_held`]), or `None`. A call's refusal is decided by
/// `apply_mode`, the same function the proxy's transport acts on.
pub fn block_report(
    label: &str,
    mode: ProxyMode,
    d: &ProxyDecision,
    identity: Option<&crate::hook_identity::Identity>,
) -> Option<Value> {
    let from_server = d.direction == FROM_SERVER;
    let refused = if from_server {
        server_held(d, mode)
    } else {
        matches!(
            apply_mode(d, mode, false),
            ProxyAction::Block { .. } | ProxyAction::Kill { .. }
        )
    };
    if !refused {
        return None;
    }
    let summary: String = from_server
        .then(|| server_summary(d))
        .or_else(|| d.tool_summary.clone())
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
    let mut body = json!({
        "kind": "mcp_proxy_block",
        "agent_name": label,
        "command": summary,
        "tool": tool,
        "rule_ids": rules,
        // The refusal class the agent's route takes: `guard` or `kill`, and
        // an agent refuses any other word (its `proxy_block` contract).
        "mode": if mode == ProxyMode::Kill { "kill" } else { "guard" },
    });
    // The mode the proxy runs in, where the class does not already say it.
    if body["mode"] != mode_word(mode) {
        body["proxy_mode"] = json!(mode_word(mode));
    }
    // What the server sent, not a call: an agent that does not read this
    // field files it as a refused call, with the summary naming the server.
    if from_server {
        body["direction"] = json!(FROM_SERVER);
    }
    // Labels from the proxy's own view, never proof; absent without a record.
    if let Some(identity) = identity {
        let (instance, trust) = identity.report_fields();
        if let Some(instance) = instance {
            body["instance"] = json!(instance);
        }
        body["trust"] = json!(trust);
    }
    Some(body)
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

/// PURE. The full URL of another of the local agent's routes, under the same
/// rule as [`report_url`]: the default loopback address, another loopback
/// address the variable names, or `None` when it says `off` or names a host
/// that is not this one.
// Its caller, `contain --identity`, is Linux-only; the test runs everywhere.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub fn agent_route(var: Option<&str>, path: &str) -> Option<String> {
    match var.map(str::trim).filter(|v| !v.is_empty()) {
        None => Some(format!("{DEFAULT_AGENT_URL}{path}")),
        Some(v) if v.eq_ignore_ascii_case("off") => None,
        Some(v) if is_loopback_url(v) => Some(format!("{}{path}", v.trim_end_matches('/'))),
        Some(_) => None,
    }
}

/// POST one report; `Err` says why it was not taken.
pub fn send_report(url: &str, body: &Value) -> Result<(), String> {
    // The agent's dashboard on loopback answers with a self-signed
    // certificate: only ever relaxed for loopback. Never through a proxy the
    // environment names (`crate::http_io::loopback_agent`).
    let agent = crate::http_io::loopback_agent(REPORT_TIMEOUT, false, is_loopback_url(url));
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

/// What became of the reports the proxy queued: taken by the queue, done
/// with by the thread that sends them (sent or not taken by the agent, said
/// once), and turned away by a full queue.
#[derive(Debug, Default)]
struct Tally {
    queued: AtomicUsize,
    done: AtomicUsize,
    dropped: AtomicUsize,
}

/// PURE. The line that says how many reports never reached the agent:
/// `dropped` turned away by the full queue, `unsent` still queued when the
/// proxy exited. `None` when none were lost.
pub fn lost_line(dropped: usize, unsent: usize) -> Option<String> {
    let lost = dropped + unsent;
    if lost == 0 {
        return None;
    }
    let mut why = Vec::new();
    if dropped > 0 {
        why.push(format!(
            "{dropped} turned away while its queue ({REPORT_QUEUE}) was full"
        ));
    }
    if unsent > 0 {
        why.push(format!("{unsent} still queued when the proxy exited"));
    }
    Some(format!(
        "innerwarden proxy: {lost} report(s) to the local InnerWarden agent were not sent ({}); \
         each is in this proxy's own record",
        why.join(", ")
    ))
}

/// Where the proxy's callback queues a report: never blocks the proxy, and
/// counts a report the full queue turns away.
#[derive(Clone)]
pub struct ReportSender {
    tx: SyncSender<Value>,
    tally: Arc<Tally>,
}

impl ReportSender {
    /// Queue `body`; a full queue (or a sending thread gone) counts it lost.
    pub fn send(&self, body: Value) {
        match self.tx.try_send(body) {
            Ok(()) => {
                self.tally.queued.fetch_add(1, Ordering::SeqCst);
            }
            Err(TrySendError::Full(_) | TrySendError::Disconnected(_)) => {
                self.tally.dropped.fetch_add(1, Ordering::SeqCst);
            }
        }
    }
}

/// Sends refusal reports from a thread of its own.
pub struct BlockReporter {
    tx: Option<SyncSender<Value>>,
    done: Option<Receiver<()>>,
    tally: Arc<Tally>,
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
            tally: Arc::default(),
        }
    }

    /// Start reporting to `url` (the full route).
    pub fn start(url: String) -> Self {
        let (tx, rx) = std::sync::mpsc::sync_channel::<Value>(REPORT_QUEUE);
        let (done_tx, done) = std::sync::mpsc::channel();
        let tally = Arc::new(Tally::default());
        let counts = Arc::clone(&tally);
        let spawned = std::thread::Builder::new()
            .name("proxy-report".to_string())
            .spawn(move || {
                let mut warned = false;
                let mut next = None;
                loop {
                    let body = match next.take() {
                        Some(body) => body,
                        None => {
                            // The queue is empty: what the full queue turned
                            // away since it was last said is said now, once.
                            let dropped = counts.dropped.swap(0, Ordering::SeqCst);
                            if let Some(line) = lost_line(dropped, 0) {
                                eprintln!("{line}");
                            }
                            match rx.recv() {
                                Ok(body) => body,
                                Err(_) => break,
                            }
                        }
                    };
                    if let Err(why) = send_report(&url, &body) {
                        if !warned {
                            warned = true;
                            eprintln!(
                                "innerwarden proxy: no InnerWarden agent took the report at \
                                 {url} ({why}); refused calls stay in this proxy's own record"
                            );
                        }
                    }
                    counts.done.fetch_add(1, Ordering::SeqCst);
                    match rx.try_recv() {
                        Ok(body) => next = Some(body),
                        Err(TryRecvError::Empty) => {}
                        Err(TryRecvError::Disconnected) => break,
                    }
                }
                let _ = done_tx.send(());
            });
        match spawned {
            Ok(_) => Self {
                tx: Some(tx),
                done: Some(done),
                tally,
            },
            Err(_) => Self::off(),
        }
    }

    /// A handle the proxy's callback queues reports on, `None` when off.
    pub fn sender(&self) -> Option<ReportSender> {
        self.tx.clone().map(|tx| ReportSender {
            tx,
            tally: Arc::clone(&self.tally),
        })
    }

    /// Stop taking reports and wait, at most `wait`, for the queued ones.
    /// What was lost (turned away and not said yet, or still queued) is said
    /// in one line, and returned.
    pub fn finish(mut self, wait: Duration) -> Option<String> {
        drop(self.tx.take());
        if let Some(done) = self.done.take() {
            let _ = done.recv_timeout(wait);
        }
        let dropped = self.tally.dropped.swap(0, Ordering::SeqCst);
        let unsent = self
            .tally
            .queued
            .load(Ordering::SeqCst)
            .saturating_sub(self.tally.done.load(Ordering::SeqCst));
        let line = lost_line(dropped, unsent);
        if let Some(line) = &line {
            eprintln!("{line}");
        }
        line
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

    /// The report names the instance and the level only when the proxy found a
    /// record; without one it is the body it always was.
    ///
    /// FAILS ON REVERT: add the fields unconditionally and the no-record body
    /// grows two keys.
    #[test]
    fn a_report_carries_instance_and_trust_only_with_a_record() {
        use crate::hook_identity::Identity;
        use innerwarden_agent_guard::identity::{Reason, Trust};
        let cred = routed(CRED_CALL);
        let plain = block_report("l", ProxyMode::Guard, &cred, None).unwrap();
        let mut keys: Vec<&str> = plain
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            ["agent_name", "command", "kind", "mode", "rule_ids", "tool"]
        );
        let id = Identity {
            instance_id: Some("7f3a9c1e42b84d0e9a6c5f1b2d3e4a59".into()),
            session_id: None,
            trust: Trust::Confined,
            reason: Reason::ConfinedByNamespace,
            agent_type: Some("claude-code".into()),
        };
        let labelled = block_report("l", ProxyMode::Guard, &cred, Some(&id)).unwrap();
        assert_eq!(labelled["instance"], "7f3a9c1e42b84d0e9a6c5f1b2d3e4a59");
        assert_eq!(labelled["trust"], "confined");
        // A record that named no instance still says its level, never an instance.
        let declared = Identity {
            instance_id: None,
            trust: Trust::Declared,
            reason: Reason::NamespaceMismatch,
            ..id
        };
        let body = block_report("l", ProxyMode::Guard, &cred, Some(&declared)).unwrap();
        assert!(body.get("instance").is_none());
        assert_eq!(body["trust"], "declared");
    }

    /// Only a call the proxy refused is reported, and never with its raw
    /// arguments.
    ///
    /// FAILS ON REVERT: report every alert (or none) and a forwarded call is
    /// reported as refused (or a refusal is not).
    #[test]
    fn only_a_refused_call_is_reported_and_without_its_raw_arguments() {
        let cred = routed(CRED_CALL);
        assert!(!cred.verdict.allowed);
        let body =
            block_report("my proxy", ProxyMode::Guard, &cred, None).expect("refused in guard");
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
            block_report("l", ProxyMode::Kill, &cred, None).unwrap()["mode"],
            "kill"
        );
        assert!(body.get("proxy_mode").is_none(), "{body}");
        let strict = block_report("l", ProxyMode::Strict, &cred, None).expect("refused in strict");
        assert_eq!(strict["proxy_mode"], "strict");
        // The agent's route takes only `guard` or `kill` as the class.
        assert_eq!(strict["mode"], "guard");
        assert!(block_report("l", ProxyMode::Kill, &cred, None)
            .unwrap()
            .get("proxy_mode")
            .is_none());
        for forwarding in [ProxyMode::Advisory, ProxyMode::Warn] {
            assert_eq!(block_report("l", forwarding, &cred, None), None);
        }
        let clean = routed(
            r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"list_directory","arguments":{"path":"/tmp"}}}"#,
        );
        assert_eq!(block_report("l", ProxyMode::Guard, &clean, None), None);
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

    /// Another route of the agent follows the same rule: loopback or nowhere.
    ///
    /// FAILS ON REVERT: accept any URL the variable names and a launcher
    /// sends its request off the host.
    #[test]
    fn another_agent_route_is_loopback_or_nowhere() {
        let path = "/api/agent/contain-scope";
        assert_eq!(
            agent_route(None, path).unwrap(),
            "https://127.0.0.1:8787/api/agent/contain-scope"
        );
        assert_eq!(
            agent_route(Some(" "), path).unwrap(),
            "https://127.0.0.1:8787/api/agent/contain-scope"
        );
        assert_eq!(
            agent_route(Some("https://localhost:9443/"), path).unwrap(),
            "https://localhost:9443/api/agent/contain-scope"
        );
        assert_eq!(agent_route(Some("OFF"), path), None);
        for elsewhere in [
            "https://10.0.0.5:8787",
            "https://127.0.0.1.evil.example",
            "https://localhost.evil.example:8787",
            "ftp://127.0.0.1",
        ] {
            assert_eq!(agent_route(Some(elsewhere), path), None, "{elsewhere}");
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
        tx.send(json!({"kind": "mcp_proxy_block"}));
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
        let body = block_report("l", ProxyMode::Guard, &routed(CRED_CALL), None).unwrap();
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

    /// A finding on a server's message, as the transport hands it on.
    fn from_server(method: Option<&str>, allowed: bool, rule: &str) -> ProxyDecision {
        use innerwarden_agent_guard::mcp::{Verdict, VerdictAlert};
        ProxyDecision {
            verdict: Verdict {
                allowed,
                alerts: vec![VerdictAlert {
                    rule: rule.into(),
                    detail: "found".into(),
                    block: !allowed,
                    category: None,
                    owasp: None,
                    mitre: None,
                }],
            },
            direction: FROM_SERVER,
            method: method.map(str::to_string),
            tool_name: None,
            tool_summary: None,
            request_id: Some(json!(3)),
            deciding_layer: None,
        }
    }

    /// What the proxy held back or masked of a server's message in a mode
    /// that blocks is reported as the server's, and nothing is in a mode
    /// that never blocks, or for a finding it did not act on.
    ///
    /// FAILS ON REVERT of `server_held` in `block_report` (back to
    /// `apply_mode` alone): no finding on a server's message is reported.
    #[test]
    fn a_server_finding_the_proxy_acted_on_is_reported_as_the_servers() {
        let cases = [
            (Some("tools/list"), false, "AG-DESC-POISON"),
            (Some("tools/list"), false, "AG-MCP-TOOL-CHANGED"),
            (None, false, "AG-MCP-PARSE"),
            (Some("tools/call"), true, "AG-SECRET-OUT"),
        ];
        for (method, allowed, rule) in cases {
            let d = from_server(method, allowed, rule);
            for mode in [ProxyMode::Guard, ProxyMode::Kill, ProxyMode::Strict] {
                let body = block_report("lab", mode, &d, None)
                    .unwrap_or_else(|| panic!("{rule} in {mode:?}"));
                assert_eq!(body["kind"], "mcp_proxy_block");
                assert_eq!(body["direction"], FROM_SERVER);
                assert_eq!(body["rule_ids"], json!([rule]));
                assert!(
                    body["command"]
                        .as_str()
                        .is_some_and(|c| c.starts_with("mcp server: ")),
                    "{body}"
                );
                assert!(body["tool"].is_null(), "{body}");
            }
            for mode in [ProxyMode::Advisory, ProxyMode::Warn] {
                assert_eq!(block_report("lab", mode, &d, None), None, "{rule}");
            }
        }
        // An alert the proxy did not act on (a long answer read in part, an
        // injection phrase alerted only) is not a refusal.
        let partial = from_server(Some("tools/call"), true, "AG-RESP-PARTIAL");
        assert_eq!(block_report("lab", ProxyMode::Guard, &partial, None), None);
        // A call's report is the one it always was: no direction.
        let call = block_report("l", ProxyMode::Guard, &routed(CRED_CALL), None).unwrap();
        assert!(call.get("direction").is_none(), "{call}");
        assert_eq!(
            server_summary(&from_server(None, false, "AG-MCP-PARSE")),
            "mcp server: a line that is not a JSON-RPC message"
        );
    }

    /// Reports the full queue turns away, and the ones still queued when the
    /// proxy exits, are counted and said in one line, never lost unsaid. An
    /// agent that takes the connection and never answers holds the first
    /// report for the whole of its timeout; the queue takes 32 more.
    ///
    /// The sending thread says what the queue turned away each time it finds
    /// the queue empty, so the test hands it the first report and waits for
    /// that report's connection before sending the other 39: the thread has
    /// then been through its empty-queue check and sits in the first POST
    /// (3 s) for the rest of the test. A thread that starts late is waited
    /// for, never counted in a second line (CI, ubuntu, 4d77bcbb: it started
    /// after the 40 sends and said 8 itself, `finish` said 32).
    ///
    /// FAILS ON REVERT of the counting in `ReportSender::send` and
    /// `BlockReporter::finish`: 40 reports, and no line says what became of
    /// them.
    #[test]
    fn reports_the_queue_could_not_take_are_counted_in_one_line() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let (taken_tx, taken) = std::sync::mpsc::channel();
        // Takes every connection and answers none; says when it took one.
        std::thread::spawn(move || {
            let mut held = Vec::new();
            for stream in listener.incoming().flatten() {
                held.push(stream);
                let _ = taken_tx.send(());
            }
        });
        let reporter = BlockReporter::start(format!("http://127.0.0.1:{port}{PROXY_BLOCK_PATH}"));
        let sender = reporter.sender().expect("on");
        let body = block_report("l", ProxyMode::Guard, &routed(CRED_CALL), None).unwrap();
        sender.send(body.clone());
        taken
            .recv_timeout(Duration::from_secs(30))
            .expect("the sending thread took the first report to the agent");
        for _ in 1..40 {
            sender.send(body.clone());
        }
        assert_eq!(reporter.tally.dropped.load(Ordering::SeqCst), 7);
        assert_eq!(reporter.tally.queued.load(Ordering::SeqCst), 33);
        let line = reporter
            .finish(Duration::from_millis(100))
            .expect("a line for the lost reports");
        assert_eq!(
            line,
            "innerwarden proxy: 40 report(s) to the local InnerWarden agent were not sent \
             (7 turned away while its queue (32) was full, 33 still queued when the proxy \
             exited); each is in this proxy's own record"
        );
        assert_eq!(lost_line(0, 0), None);
    }
}
