//! The second opinion and the notifications take their config, and the
//! model's key, only from the account's own home (from the account database,
//! never the `HOME` the caller hands down) or from the override a test or the
//! jail names. A home the caller names is never read, a key file outside the
//! config's folder is never read, and an override never names an environment
//! variable to send.
//!
//! The model and the webhook are a local listener that keeps every request it
//! is sent.
#![cfg(unix)]

use std::io::{Read, Write};
use std::path::Path;
use std::process::{Command, Output};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

const KEY_IN_FILE: &str = "FAKE-PRIVATE-KEY-CONTENT-123";
const KEY_IN_ENV: &str = "FAKE-ENV-SECRET-456";
const ENV_NAME: &str = "IW_TEST_SECOND_OPINION_SECRET";
/// A line the rules leave at `review`, so a second opinion is asked and a
/// notification sent when one is wired.
const REVIEW_LINE: &str = "chmod 777 ./data";

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

/// A listener that answers `review` in the shape of an OpenAI-compatible
/// endpoint and keeps each request it was sent.
struct Listener {
    port: u16,
    seen: Arc<Mutex<Vec<String>>>,
    stop: Arc<AtomicBool>,
}

impl Listener {
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
                kept.lock()
                    .unwrap()
                    .push(String::from_utf8_lossy(&request).to_string());
                let content = "{\"verdict\":\"review\",\"why\":\"test model\"}";
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
        Self { port, seen, stop }
    }

    fn url(&self) -> String {
        format!("http://127.0.0.1:{}/v1/chat/completions", self.port)
    }

    fn requests(&self) -> Vec<String> {
        // A notification may still be on its way as the run ends.
        std::thread::sleep(Duration::from_millis(300));
        self.seen.lock().unwrap().clone()
    }
}

impl Drop for Listener {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
    }
}

/// `innerwarden check` on [`REVIEW_LINE`] with `HOME` at `home`, nothing of
/// the person's environment that wires a channel, and `env` on top.
fn check(scratch: &Path, home: &Path, env: &[(&str, &Path)], secret_env: bool) -> Output {
    let project = scratch.join("project");
    std::fs::create_dir_all(&project).unwrap();
    let mut command = Command::new(env!("CARGO_BIN_EXE_innerwarden"));
    command
        .args(["check", REVIEW_LINE])
        .env("HOME", home)
        .env("USERPROFILE", home)
        .env("XDG_CONFIG_HOME", home.join(".config"))
        .env("IW_GRAPH_FILE", scratch.join("graph.json"))
        .env("IW_SESSION_FILE", scratch.join("sessions.json"))
        .env("IW_SUPPRESS_CONFIG", scratch.join("absent-suppress.toml"))
        .env("INNERWARDEN_AGENT_URL", "off")
        .env_remove("IW_LLM_CONFIG")
        .env_remove("IW_NOTIFY_CONFIG")
        .env_remove("IW_GUARD_SESSION")
        .current_dir(&project);
    for name in [
        "IW_WEBHOOK_URL",
        "IW_SLACK_WEBHOOK",
        "IW_DISCORD_WEBHOOK",
        "IW_TELEGRAM_TOKEN",
        "IW_TELEGRAM_CHAT",
        "IW_NOTIFY_REVIEW",
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "http_proxy",
        "https_proxy",
        "all_proxy",
    ] {
        command.env_remove(name);
    }
    if secret_env {
        command.env(ENV_NAME, KEY_IN_ENV);
    } else {
        command.env_remove(ENV_NAME);
    }
    for (name, value) in env {
        command.env(name, value);
    }
    command.output().expect("run innerwarden check")
}

fn said(out: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

fn write_secret(path: &Path, value: &str) {
    std::fs::write(path, format!("{value}\n")).unwrap();
}

/// The finding: with `HOME` at a folder of the caller's, `check` read the
/// `llm.toml` there and sent the file its `api_key_file` named as
/// `Authorization: Bearer` to the url it named, and the `notify.toml` there
/// sent the line to its webhook. Neither file is read now: nothing reaches the
/// listener.
///
/// FAILS ON REVERT of reading the config from the account's home.
#[test]
fn a_home_the_caller_names_is_never_where_the_config_comes_from() {
    let listener = Listener::start();
    let scratch = tempfile::tempdir().unwrap();
    let home = scratch.path().join("home");
    let config = home.join(".config/innerwarden");
    std::fs::create_dir_all(&config).unwrap();
    let secret = scratch.path().join("private.key");
    write_secret(&secret, KEY_IN_FILE);
    std::fs::write(
        config.join("llm.toml"),
        format!(
            "url = \"{}\"\nmodel = \"m\"\nmin_risk = 0\napi_key_file = \"{}\"\napi_key_env = \"{ENV_NAME}\"\n",
            listener.url(),
            secret.display()
        ),
    )
    .unwrap();
    std::fs::write(
        config.join("notify.toml"),
        format!(
            "webhook_url = \"http://127.0.0.1:{}/hook\"\nnotify_review = true\n",
            listener.port
        ),
    )
    .unwrap();

    let out = check(scratch.path(), &home, &[], true);
    let requests = listener.requests();
    assert!(requests.is_empty(), "sent: {requests:?}\n{}", said(&out));
}

/// A config the override names (`IW_LLM_CONFIG`, how the tests and the jail
/// point the reader) still reaches its url, but the key it names is read only
/// from inside its own folder, and an environment variable it names is never
/// sent.
///
/// FAILS ON REVERT of the folder check and of refusing `api_key_env` there.
#[test]
fn an_override_never_sends_a_key_from_outside_its_folder_or_the_environment() {
    let listener = Listener::start();
    let scratch = tempfile::tempdir().unwrap();
    let home = scratch.path().join("home");
    std::fs::create_dir_all(&home).unwrap();
    let folder = scratch.path().join("cfg");
    std::fs::create_dir_all(&folder).unwrap();
    let secret = scratch.path().join("private.key");
    write_secret(&secret, KEY_IN_FILE);

    let outside = folder.join("outside.toml");
    std::fs::write(
        &outside,
        format!(
            "url = \"{}\"\nmodel = \"m\"\nmin_risk = 0\napi_key_file = \"{}\"\n",
            listener.url(),
            secret.display()
        ),
    )
    .unwrap();
    let from_env = folder.join("env.toml");
    std::fs::write(
        &from_env,
        format!(
            "url = \"{}\"\nmodel = \"m\"\nmin_risk = 0\napi_key_env = \"{ENV_NAME}\"\n",
            listener.url()
        ),
    )
    .unwrap();
    let absent_notify = scratch.path().join("absent-notify.toml");

    let mut said_all = String::new();
    for config in [&outside, &from_env] {
        let out = check(
            scratch.path(),
            &home,
            &[
                ("IW_LLM_CONFIG", config.as_path()),
                ("IW_NOTIFY_CONFIG", absent_notify.as_path()),
            ],
            true,
        );
        said_all.push_str(&said(&out));
    }
    let requests = listener.requests();
    assert_eq!(requests.len(), 2, "both runs ask the model: {said_all}");
    for request in &requests {
        assert!(
            !request.contains(KEY_IN_FILE) && !request.contains(KEY_IN_ENV),
            "a secret was sent: {request}"
        );
        assert!(
            !request.to_ascii_lowercase().contains("authorization:"),
            "{request}"
        );
    }
}

/// A key file inside the folder that is a hard link or a symbolic link to a
/// file elsewhere is not the key the person stored there: neither is sent.
///
/// FAILS ON REVERT of refusing a linked key file.
#[test]
fn a_key_file_linked_into_the_folder_is_never_sent() {
    let listener = Listener::start();
    let scratch = tempfile::tempdir().unwrap();
    let home = scratch.path().join("home");
    std::fs::create_dir_all(&home).unwrap();
    let folder = scratch.path().join("cfg");
    std::fs::create_dir_all(&folder).unwrap();
    let secret = scratch.path().join("private.key");
    write_secret(&secret, KEY_IN_FILE);
    std::fs::hard_link(&secret, folder.join("hard-key")).unwrap();
    std::os::unix::fs::symlink(&secret, folder.join("soft-key")).unwrap();
    let absent_notify = scratch.path().join("absent-notify.toml");

    for name in ["hard-key", "soft-key"] {
        let config = folder.join(format!("{name}.toml"));
        std::fs::write(
            &config,
            format!(
                "url = \"{}\"\nmodel = \"m\"\nmin_risk = 0\napi_key_file = \"{}\"\n",
                listener.url(),
                folder.join(name).display()
            ),
        )
        .unwrap();
        check(
            scratch.path(),
            &home,
            &[
                ("IW_LLM_CONFIG", config.as_path()),
                ("IW_NOTIFY_CONFIG", absent_notify.as_path()),
            ],
            false,
        );
    }
    let requests = listener.requests();
    assert_eq!(requests.len(), 2, "both runs ask the model");
    for request in &requests {
        assert!(
            !request.contains(KEY_IN_FILE),
            "a secret was sent: {request}"
        );
    }
}

/// The control: a key file of its own in the config's folder, as `llm
/// set-key` writes it, is still sent. The checks above refuse what is not the
/// person's key, not every key.
#[test]
fn a_key_stored_in_the_folder_is_still_sent() {
    let listener = Listener::start();
    let scratch = tempfile::tempdir().unwrap();
    let home = scratch.path().join("home");
    std::fs::create_dir_all(&home).unwrap();
    let folder = scratch.path().join("cfg");
    std::fs::create_dir_all(&folder).unwrap();
    let key = folder.join("llm-key");
    write_secret(&key, "OWN-STORED-KEY-789");
    let config = folder.join("llm.toml");
    std::fs::write(
        &config,
        format!(
            "url = \"{}\"\nmodel = \"m\"\nmin_risk = 0\napi_key_file = \"{}\"\n",
            listener.url(),
            key.display()
        ),
    )
    .unwrap();
    let absent_notify = scratch.path().join("absent-notify.toml");
    let out = check(
        scratch.path(),
        &home,
        &[
            ("IW_LLM_CONFIG", config.as_path()),
            ("IW_NOTIFY_CONFIG", absent_notify.as_path()),
        ],
        false,
    );
    let requests = listener.requests();
    assert_eq!(requests.len(), 1, "{}", said(&out));
    assert!(
        requests[0].contains("Bearer OWN-STORED-KEY-789"),
        "{}",
        requests[0]
    );
}
