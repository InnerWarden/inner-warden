//! The second opinion of a model, through the hook the way an agent runs it:
//! every line of a call that needs one gets it, when the model answers
//! quickly.
//!
//! The model is a local listener that answers in the shape of an
//! OpenAI-compatible endpoint. HOME, the record and the session store point
//! into a scratch directory.

use std::io::{Read, Write};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

/// Whether `seen` holds a whole HTTP request: headers and the body their
/// `content-length` names.
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

/// A model that answers `deny` for a command naming `deny_for` and not
/// `unless`, and `review` for any other, counting the requests it was sent.
struct Model {
    port: u16,
    asked: Arc<AtomicUsize>,
    stop: Arc<AtomicBool>,
}

impl Model {
    fn start(deny_for: &'static str, unless: &'static str) -> Self {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let port = listener.local_addr().unwrap().port();
        let asked = Arc::new(AtomicUsize::new(0));
        let stop = Arc::new(AtomicBool::new(false));
        let (count, stopped) = (asked.clone(), stop.clone());
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
                let mut seen = Vec::new();
                let mut buf = [0u8; 4096];
                while !whole_request(&seen) {
                    match stream.read(&mut buf) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => seen.extend_from_slice(&buf[..n]),
                    }
                }
                count.fetch_add(1, Ordering::SeqCst);
                let request = String::from_utf8_lossy(&seen);
                let verdict = if request.contains(deny_for) && !request.contains(unless) {
                    "deny"
                } else {
                    "review"
                };
                let content = format!("{{\"verdict\":\"{verdict}\",\"why\":\"test model\"}}");
                let body = serde_json::json!({
                    "choices": [{"message": {"content": content}}]
                })
                .to_string();
                let _ = write!(
                    stream,
                    "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                    body.len()
                );
            }
        });
        Self { port, asked, stop }
    }
}

impl Drop for Model {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
    }
}

/// Review of #414, item 1: a call of two lines that each need a second
/// opinion, and the model refuses the second. Each wait is charged what it
/// waited, so the second line is asked too and the call is refused (exit 2
/// in enforce). Charged at its whole bound, the first wait took the run's
/// allowance: the second line kept its review, Claude Code asked the person
/// and the call could run, where the main branch refused it.
///
/// FAILS ON REVERT of charging a wait by what it waited (`waited`).
#[test]
fn every_line_gets_the_model_when_it_answers_quickly() {
    let model = Model::start("./logs", "./data");
    let dir = tempfile::tempdir().expect("scratch dir");
    let home = dir.path().join("home");
    let project = home.join("proj");
    std::fs::create_dir_all(&project).unwrap();
    let config = dir.path().join("llm.toml");
    std::fs::write(
        &config,
        format!(
            "url = \"http://127.0.0.1:{}/v1/chat/completions\"\nmodel = \"test-model\"\n",
            model.port
        ),
    )
    .unwrap();
    let payload = serde_json::json!({
        "session_id": "s-second-opinion",
        "hook_event_name": "PreToolUse",
        "cwd": project,
        "tool_name": "Bash",
        "tool_input": { "commands": ["chmod 777 ./data", "chmod 777 ./logs"] },
    })
    .to_string();
    let mut command = Command::new(env!("CARGO_BIN_EXE_innerwarden"));
    command
        .arg("hook")
        .env("HOME", &home)
        .env("USERPROFILE", &home)
        .env("IW_GRAPH_FILE", dir.path().join("graph.json"))
        .env("IW_SESSION_FILE", dir.path().join("sessions.json"))
        .env("IW_LLM_CONFIG", &config)
        .env("INNERWARDEN_AGENT_URL", "off")
        .env_remove("IW_GUARD_SESSION")
        .env_remove("IW_TEST_HOOK_DEADLINE_MS")
        .env_remove("INNERWARDEN_HOOK_DEADLINE_MS")
        .current_dir(&project)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for proxy in [
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "http_proxy",
        "https_proxy",
        "all_proxy",
    ] {
        command.env_remove(proxy);
    }
    let mut child = command.spawn().expect("run innerwarden hook");
    child
        .stdin
        .take()
        .unwrap()
        .write_all(payload.as_bytes())
        .unwrap();
    let out = child.wait_with_output().unwrap();
    let said = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    // The call carries each line, and the two together (the shapes of a
    // shell call are read apart and as one): every one is asked.
    assert!(model.asked.load(Ordering::SeqCst) >= 2, "{said}");
    assert_eq!(out.status.code(), Some(2), "{said}");
    // Refused by the model's answer, not by the deadline (which exits 2 too).
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("second opinion: deny"),
        "{said}"
    );
}
