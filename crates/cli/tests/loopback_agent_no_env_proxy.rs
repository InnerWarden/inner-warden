//! What the CLI sends to a listener on this host (InnerWarden Pro's agent:
//! the MCP proxy's refusal reports, the OpenClaw guard's questions) goes
//! straight there, never through a proxy the environment names. The MCP
//! proxy and the OpenClaw guard run with the AI agent's environment, and
//! ureq takes `HTTP_PROXY`, `HTTPS_PROXY` and `ALL_PROXY` from it by
//! default: a proxy the agent named saw every report and every command sent
//! to Pro, and could drop or change Pro's answer.
//!
//! Also here: `notify --test` and `llm status` say when the environment
//! named a channel or a config a release build does not read, instead of
//! saying nothing (`IW_TEST_RELEASE_OVERRIDES=1` gives the release reading).
#![cfg(unix)]

use std::io::{Read, Write};
use std::path::Path;
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

const PROXY_VARS: [&str; 6] = [
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "ALL_PROXY",
    "http_proxy",
    "https_proxy",
    "all_proxy",
];

fn whole_request(seen: &[u8]) -> bool {
    let text = String::from_utf8_lossy(seen);
    let Some((head, body)) = text.split_once("\r\n\r\n") else {
        return false;
    };
    let length = head
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse::<usize>().ok())?
        })
        .unwrap_or(0);
    body.len() >= length
}

/// A local listener that keeps the first line of each request it is sent
/// and answers `200 {}`: the agent, a webhook, or a proxy (which sees an
/// absolute url or a CONNECT).
struct Recorder {
    port: u16,
    seen: Arc<Mutex<Vec<String>>>,
    stop: Arc<AtomicBool>,
}

impl Recorder {
    fn start() -> Self {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let port = listener.local_addr().unwrap().port();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let (kept, stopped) = (seen.clone(), stop.clone());
        std::thread::spawn(move || {
            while !stopped.load(Ordering::SeqCst) {
                let Ok((mut stream, _)) = listener.accept() else {
                    std::thread::sleep(Duration::from_millis(5));
                    continue;
                };
                stream.set_nonblocking(false).unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(10)))
                    .unwrap();
                let mut request = Vec::new();
                let mut buf = [0u8; 4096];
                while !whole_request(&request) {
                    match stream.read(&mut buf) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => request.extend_from_slice(&buf[..n]),
                    }
                }
                let text = String::from_utf8_lossy(&request);
                kept.lock()
                    .unwrap()
                    .push(text.lines().next().unwrap_or_default().to_string());
                let _ = stream.write_all(
                    b"HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: 2\r\nconnection: close\r\n\r\n{}",
                );
            }
        });
        Self { port, seen, stop }
    }

    fn url(&self) -> String {
        format!("http://127.0.0.1:{}", self.port)
    }

    fn requests(&self) -> Vec<String> {
        // A report is sent from a thread of its own and may still be on its way.
        std::thread::sleep(Duration::from_millis(300));
        self.seen.lock().unwrap().clone()
    }
}

impl Drop for Recorder {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
    }
}

/// `innerwarden` with a home of its own in `scratch`, no Pro unless a test
/// names one, nothing of the person's environment that wires a proxy, a
/// channel or a config.
fn innerwarden(scratch: &Path) -> Command {
    let home = scratch.join("home");
    let account = scratch.join("account");
    std::fs::create_dir_all(&home).unwrap();
    std::fs::create_dir_all(&account).unwrap();
    let mut command = Command::new(env!("CARGO_BIN_EXE_innerwarden"));
    command
        .env("HOME", &home)
        .env("USERPROFILE", &home)
        .env("XDG_CONFIG_HOME", home.join(".config"))
        .env("IW_TEST_ACCOUNT_HOME", &account)
        .env("IW_GRAPH_FILE", scratch.join("graph.json"))
        .env("IW_SESSION_FILE", scratch.join("sessions.json"))
        .env("IW_SUPPRESS_CONFIG", "/dev/null")
        .env("INNERWARDEN_AGENT_URL", "off")
        .env("IW_AD_CLI_DIRS", "")
        .env_remove("IW_GUARD_SESSION")
        .env_remove("NO_PROXY")
        .env_remove("no_proxy")
        .current_dir(scratch)
        .stdin(Stdio::null());
    for name in [
        "IW_WEBHOOK_URL",
        "IW_SLACK_WEBHOOK",
        "IW_DISCORD_WEBHOOK",
        "IW_TELEGRAM_TOKEN",
        "IW_TELEGRAM_CHAT",
        "IW_NOTIFY_REVIEW",
        "IW_LLM_CONFIG",
        "IW_NOTIFY_CONFIG",
        "IW_TEST_RELEASE_OVERRIDES",
    ] {
        command.env_remove(name);
    }
    for name in PROXY_VARS {
        command.env_remove(name);
    }
    command
}

/// Every proxy variable pointed at `proxy`.
fn through(command: &mut Command, proxy: &Recorder) {
    for name in PROXY_VARS {
        command.env(name, proxy.url());
    }
}

fn said(out: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

/// The MCP proxy reports a refused call to the agent on this host's
/// loopback. With every proxy variable set, the report reaches the agent and
/// the proxy hears nothing.
///
/// FAILS ON REVERT of `.proxy(None)` in `agent_report::send_report`: the
/// report goes to the proxy and the agent hears nothing.
#[test]
fn a_refusal_report_goes_to_the_agent_and_not_to_the_environments_proxy() {
    let agent = Recorder::start();
    let proxy = Recorder::start();
    let scratch = tempfile::tempdir().unwrap();
    let secret = format!("sk-ant{}", "-FAKEfake1111fake2222fake3333value789");
    let denied = serde_json::json!({
        "jsonrpc": "2.0", "id": 2, "method": "tools/call",
        "params": {"name": "save", "arguments": {"token": secret}}
    });
    let mut command = innerwarden(scratch.path());
    command
        .args(["proxy", "--mode", "guard", "--label", "e2e", "--", "cat"])
        .env("INNERWARDEN_AGENT_URL", agent.url())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    through(&mut command, &proxy);
    let mut child = command.spawn().expect("spawn MCP proxy");
    writeln!(child.stdin.as_mut().unwrap(), "{denied}").unwrap();
    drop(child.stdin.take());
    let out = child.wait_with_output().expect("wait for MCP proxy");
    assert!(out.status.success(), "{}", said(&out));
    let heard = proxy.requests();
    assert!(
        heard.is_empty(),
        "the proxy heard: {heard:?}\n{}",
        said(&out)
    );
    let reports = agent.requests();
    assert!(
        reports
            .iter()
            .any(|line| line.starts_with("POST /api/agent/proxy-block ")),
        "the agent heard: {reports:?}\n{}",
        said(&out)
    );
}

/// `openclaw status` asks Pro on this host's loopback for its status. With
/// every proxy variable set, the question reaches Pro and the proxy hears
/// nothing.
///
/// FAILS ON REVERT of `.proxy(None)` in `openclaw_guard_io::loopback_agent`.
#[test]
fn the_openclaw_guard_asks_pro_straight_and_not_through_the_environments_proxy() {
    let agent = Recorder::start();
    let proxy = Recorder::start();
    let scratch = tempfile::tempdir().unwrap();
    // Pro counts as installed when its CLI is where it is looked for.
    let pro_bin = scratch.path().join("pro-bin");
    std::fs::create_dir_all(&pro_bin).unwrap();
    std::fs::write(pro_bin.join("innerwarden-ctl"), "#!/bin/sh\nexit 0\n").unwrap();
    let home = scratch.path().join("home");
    std::fs::create_dir_all(home.join(".openclaw")).unwrap();
    std::fs::write(
        home.join(".openclaw/openclaw.json"),
        serde_json::json!({"mcp": {"servers": {}}, "plugins": {"allow": []}}).to_string(),
    )
    .unwrap();
    let mut command = innerwarden(scratch.path());
    command
        .args(["openclaw", "status"])
        .env("INNERWARDEN_AGENT_URL", agent.url())
        .env("IW_AD_CLI_DIRS", &pro_bin);
    through(&mut command, &proxy);
    let out = command.output().expect("run openclaw status");
    let heard = proxy.requests();
    assert!(
        heard.is_empty(),
        "the proxy heard: {heard:?}\n{}",
        said(&out)
    );
    let asked = agent.requests();
    assert!(
        asked
            .iter()
            .any(|line| line.starts_with("GET /api/agent/protection-status")),
        "Pro heard: {asked:?}\n{}",
        said(&out)
    );
}

/// `notify --test` with channels only in the environment: a release build
/// does not read them, and it used to print nothing and exit 0, which reads
/// as a test that passed. It now says nothing was sent, names the variables
/// it did not read and why, and exits 1. The webhook hears nothing.
#[test]
fn notify_test_with_channels_only_in_the_environment_says_they_were_not_read() {
    let webhook = Recorder::start();
    let scratch = tempfile::tempdir().unwrap();
    let out = innerwarden(scratch.path())
        .args(["notify", "--test"])
        .env("IW_TEST_RELEASE_OVERRIDES", "1")
        .env("IW_WEBHOOK_URL", format!("{}/hook", webhook.url()))
        .env("IW_SLACK_WEBHOOK", format!("{}/slack", webhook.url()))
        .output()
        .expect("run notify --test");
    let text = said(&out);
    assert_eq!(out.status.code(), Some(1), "{text}");
    assert!(text.contains("--test sent nothing"), "{text}");
    assert!(
        text.contains("not read: IW_SLACK_WEBHOOK, IW_WEBHOOK_URL"),
        "{text}"
    );
    assert!(text.contains("AI agent's environment"), "{text}");
    assert!(webhook.requests().is_empty());

    // Control: the debug reading (the tests') does read them and sends.
    let out = innerwarden(scratch.path())
        .args(["notify", "--test"])
        .env("IW_WEBHOOK_URL", format!("{}/hook", webhook.url()))
        .output()
        .expect("run notify --test");
    assert_eq!(out.status.code(), Some(0), "{}", said(&out));
    assert!(!said(&out).contains("sent nothing"), "{}", said(&out));
    assert_eq!(webhook.requests().len(), 1);
}

/// `llm status` says when `IW_LLM_CONFIG` was not read (a release build,
/// any value but /dev/null), and says nothing of it otherwise.
#[test]
fn llm_status_says_when_iw_llm_config_was_not_read() {
    let scratch = tempfile::tempdir().unwrap();
    let named = scratch.path().join("agents-llm.toml");
    std::fs::write(&named, "url = \"http://127.0.0.1:9/v1\"\nmodel = \"m\"\n").unwrap();
    let status = |value: Option<&Path>, release: bool| {
        let mut command = innerwarden(scratch.path());
        command.args(["llm", "status"]);
        if let Some(value) = value {
            command.env("IW_LLM_CONFIG", value);
        }
        if release {
            command.env("IW_TEST_RELEASE_OVERRIDES", "1");
        }
        let out = command.output().expect("run llm status");
        assert!(out.status.success(), "{}", said(&out));
        said(&out)
    };
    let ignored = status(Some(&named), true);
    assert!(ignored.contains("not read: IW_LLM_CONFIG"), "{ignored}");
    assert!(ignored.contains("only as /dev/null"), "{ignored}");
    for (value, release) in [
        (Some(Path::new("/dev/null")), true),
        (Some(named.as_path()), false),
        (None, true),
    ] {
        let text = status(value, release);
        assert!(
            !text.contains("not read: IW_LLM_CONFIG"),
            "{value:?} {release}: {text}"
        );
    }
}
