//! The second opinion and the notifications take their config, and the
//! model's key, only from the account's own home (from the account database,
//! never the `HOME` the caller hands down) or from the override a test or the
//! jail names. A home the caller names is never read, a config the override
//! names never carries a key, the account's key is read only from its own
//! config folder, through the handle its `llm.toml` was read through, and a
//! url moved elsewhere by `llm set` loses the key. The suppressions too come
//! only from the account's home.
//!
//! The model and the webhook are a local listener that keeps every request it
//! is sent. The account's home is a scratch folder each test names with
//! `IW_TEST_ACCOUNT_HOME`, which only a debug build reads.
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

/// `innerwarden` with `HOME` at `home`, the account's home at an empty
/// scratch folder, nothing of the person's environment that wires a channel,
/// run in `scratch/project`.
fn innerwarden(scratch: &Path, home: &Path) -> Command {
    let project = scratch.join("project");
    std::fs::create_dir_all(&project).unwrap();
    let account = scratch.join("empty-account");
    std::fs::create_dir_all(&account).unwrap();
    let mut command = Command::new(env!("CARGO_BIN_EXE_innerwarden"));
    command
        .env("IW_TEST_ACCOUNT_HOME", &account)
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
        .current_dir(&project)
        .stdin(std::process::Stdio::null());
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
    command
}

/// `innerwarden check` on [`REVIEW_LINE`] ([`innerwarden`]), with `env` on
/// top.
fn check(scratch: &Path, home: &Path, env: &[(&str, &Path)], secret_env: bool) -> Output {
    let mut command = innerwarden(scratch, home);
    command.args(["check", REVIEW_LINE]);
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

/// The account's own config folder in a scratch account home `account`:
/// `llm.toml` pointing at `url` with `key_line` (an `api_key_file` line, or
/// none), and the key `llm set-key` would have stored.
fn account_config(account: &Path, url: &str, key_line: &str) -> std::path::PathBuf {
    let folder = account.join(".config/innerwarden");
    std::fs::create_dir_all(&folder).unwrap();
    write_secret(&folder.join("llm-key"), ACCOUNT_KEY);
    std::fs::write(
        folder.join("llm.toml"),
        format!("url = \"{url}\"\nmodel = \"m\"\nmin_risk = 0\n{key_line}"),
    )
    .unwrap();
    folder
}

/// The key the person stored with `llm set-key` in the account's folder.
const ACCOUNT_KEY: &str = "ACCOUNT-REAL-KEY-001";

fn no_key_in(requests: &[String], secrets: &[&str]) {
    for request in requests {
        for secret in secrets {
            assert!(!request.contains(secret), "a secret was sent: {request}");
        }
        assert!(
            !request.to_ascii_lowercase().contains("authorization:"),
            "{request}"
        );
    }
}

/// A config the override names (`IW_LLM_CONFIG`, how the tests and the jail
/// point the reader) never carries a key: not a file outside its folder, not
/// an environment variable.
///
/// That the request still reaches the url such a config names is a LIMIT,
/// not what is wanted: the command line (secrets redacted) goes to an address
/// whoever starts the process chose. It is the open item on agent-chosen
/// destinations for the second opinion and notify; this test pins only that
/// no key goes with it.
///
/// FAILS ON REVERT of the override carrying no key.
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
    assert_eq!(
        requests.len(),
        2,
        "the limit: both runs ask the model: {said_all}"
    );
    no_key_in(&requests, &[KEY_IN_FILE, KEY_IN_ENV]);
}

/// The finding of the review: an override naming the account's own stored
/// key (relative to the home, with `~/`, by absolute path), another secret
/// in the home, or a project's `.env`, sent it as the bearer key. An
/// override carries no key at all now, and `check` says so on stderr.
///
/// FAILS ON REVERT of the override carrying no key.
#[test]
fn an_override_never_sends_the_accounts_key_or_another_secret_in_its_home() {
    let listener = Listener::start();
    let scratch = tempfile::tempdir().unwrap();
    let account = scratch.path().join("account");
    let folder = account_config(
        &account,
        "http://127.0.0.1:9/unused",
        "api_key_file = \"llm-key\"\n",
    );
    write_secret(&account.join(".vault-token"), "VAULT-TOKEN-002");
    let project = scratch.path().join("project");
    std::fs::create_dir_all(&project).unwrap();
    write_secret(&project.join(".env"), "PROJECT-ENV-SECRET-003");
    let absent_notify = scratch.path().join("absent-notify.toml");

    let named = [
        ".config/innerwarden/llm-key".to_string(),
        "~/.config/innerwarden/llm-key".to_string(),
        folder.join("llm-key").display().to_string(),
        "~/.vault-token".to_string(),
        ".vault-token".to_string(),
        ".env".to_string(),
        "llm-key".to_string(),
    ];
    let mut said_all = String::new();
    for (n, key_file) in named.iter().enumerate() {
        // In the home the agent works in (`~/iw.toml`), and in the project.
        for place in [&account, &project] {
            let config = place.join(format!("iw-{n}.toml"));
            std::fs::write(
                &config,
                format!(
                    "url = \"{}\"\nmodel = \"m\"\nmin_risk = 0\napi_key_file = \"{key_file}\"\n",
                    listener.url()
                ),
            )
            .unwrap();
            let out = check(
                scratch.path(),
                &account,
                &[
                    ("IW_TEST_ACCOUNT_HOME", account.as_path()),
                    ("IW_LLM_CONFIG", config.as_path()),
                    ("IW_NOTIFY_CONFIG", absent_notify.as_path()),
                ],
                false,
            );
            let stderr = String::from_utf8_lossy(&out.stderr).to_string();
            assert!(
                stderr.contains("API key was not read"),
                "the refusal is said: {stderr}"
            );
            said_all.push_str(&said(&out));
        }
    }
    let requests = listener.requests();
    assert_eq!(requests.len(), named.len() * 2, "{said_all}");
    no_key_in(
        &requests,
        &[ACCOUNT_KEY, "VAULT-TOKEN-002", "PROJECT-ENV-SECRET-003"],
    );
}

/// A key file in the account's folder that is a hard link or a symbolic link
/// to a file elsewhere is not the key the person stored there, and a key
/// named in another folder is not read: none is sent.
///
/// FAILS ON REVERT of refusing a linked key file: of `O_NOFOLLOW` alone,
/// and of the one-name check alone.
#[test]
fn a_key_file_linked_into_the_folder_is_never_sent() {
    let listener = Listener::start();
    let scratch = tempfile::tempdir().unwrap();
    let account = scratch.path().join("account");
    let secret = scratch.path().join("private.key");
    write_secret(&secret, KEY_IN_FILE);
    // The symbolic link names a file of one name, so its refusal is its own
    // and not the hard link's (a target with two names is refused anyway).
    let linked = scratch.path().join("linked.key");
    write_secret(&linked, KEY_IN_FILE);
    let absent_notify = scratch.path().join("absent-notify.toml");

    let other = scratch.path().join("other");
    std::fs::create_dir_all(&other).unwrap();
    write_secret(&other.join("llm-key"), KEY_IN_FILE);
    for key_file in [
        "hard-key".to_string(),
        "soft-key".to_string(),
        other.join("llm-key").display().to_string(),
        "../../../other/llm-key".to_string(),
    ] {
        let folder = account_config(
            &account,
            &listener.url(),
            &format!("api_key_file = \"{key_file}\"\n"),
        );
        if !folder.join("hard-key").exists() {
            std::fs::hard_link(&secret, folder.join("hard-key")).unwrap();
            std::os::unix::fs::symlink(&linked, folder.join("soft-key")).unwrap();
        }
        check(
            scratch.path(),
            &account,
            &[
                ("IW_TEST_ACCOUNT_HOME", account.as_path()),
                ("IW_NOTIFY_CONFIG", absent_notify.as_path()),
            ],
            false,
        );
    }
    let requests = listener.requests();
    assert_eq!(requests.len(), 4, "every run asks the model");
    no_key_in(&requests, &[KEY_IN_FILE]);
}

/// The control: the key `llm set-key` stored in the account's folder is
/// still sent, named as it stores it (the full path), by plain name, and with
/// `~/`. The checks above refuse what is not the person's key, not every
/// key.
#[test]
fn a_key_stored_in_the_folder_is_still_sent() {
    let listener = Listener::start();
    let scratch = tempfile::tempdir().unwrap();
    let account = scratch.path().join("account");
    let stored = account.join(".config/innerwarden/llm-key");
    let absent_notify = scratch.path().join("absent-notify.toml");
    let mut said_all = String::new();
    for key_file in [
        stored.display().to_string(),
        "llm-key".to_string(),
        "~/.config/innerwarden/llm-key".to_string(),
    ] {
        account_config(
            &account,
            &listener.url(),
            &format!("api_key_file = \"{key_file}\"\n"),
        );
        let out = check(
            scratch.path(),
            &account,
            &[
                ("IW_TEST_ACCOUNT_HOME", account.as_path()),
                ("IW_NOTIFY_CONFIG", absent_notify.as_path()),
            ],
            false,
        );
        said_all.push_str(&said(&out));
    }
    let requests = listener.requests();
    assert_eq!(requests.len(), 3, "{said_all}");
    for request in &requests {
        assert!(
            request.contains(&format!("Bearer {ACCOUNT_KEY}")),
            "{request}"
        );
    }
}

/// The finding of the review: with the account's config folder a link that
/// is swapped between a folder of the agent's and a folder holding another
/// secret, the key was read from the folder the link pointed at when the key
/// was read, not when `llm.toml` was: 22 of 60 runs sent the other secret.
/// Both are read through one handle on the folder now, so a run reads the
/// config and the key from the same folder, or nothing. A folder that is a
/// link still works (dotfiles kept with stow).
///
/// FAILS ON REVERT of reading both through one folder handle (a race: most
/// runs of the old reader send the other secret at least once).
#[test]
fn a_config_folder_swapped_between_the_two_reads_never_sends_another_folders_key() {
    let listener = Listener::start();
    let scratch = tempfile::tempdir().unwrap();
    let account = scratch.path().join("account");
    std::fs::create_dir_all(account.join(".config")).unwrap();
    let agents = scratch.path().join("agents");
    std::fs::create_dir_all(&agents).unwrap();
    write_secret(&agents.join("llm-key"), "AGENTS-OWN-KEY-004");
    std::fs::write(
        agents.join("llm.toml"),
        format!(
            "url = \"{}\"\nmodel = \"m\"\nmin_risk = 0\napi_key_file = \"llm-key\"\n",
            listener.url()
        ),
    )
    .unwrap();
    let secret = scratch.path().join("secret423");
    std::fs::create_dir_all(&secret).unwrap();
    write_secret(&secret.join("llm-key"), "ROOT-DIR-SECRET-005");
    let link = account.join(".config/innerwarden");
    std::os::unix::fs::symlink(&agents, &link).unwrap();

    let stop = Arc::new(AtomicBool::new(false));
    let swapper = {
        let (stop, link, agents, secret) =
            (stop.clone(), link.clone(), agents.clone(), secret.clone());
        let next = link.with_file_name("innerwarden.next");
        std::thread::spawn(move || {
            let mut flip = false;
            while !stop.load(Ordering::SeqCst) {
                let _ = std::fs::remove_file(&next);
                let target = if flip { &agents } else { &secret };
                std::os::unix::fs::symlink(target, &next).unwrap();
                std::fs::rename(&next, &link).unwrap();
                flip = !flip;
            }
        })
    };
    let absent_notify = scratch.path().join("absent-notify.toml");
    for _ in 0..40 {
        check(
            scratch.path(),
            &account,
            &[
                ("IW_TEST_ACCOUNT_HOME", account.as_path()),
                ("IW_NOTIFY_CONFIG", absent_notify.as_path()),
            ],
            false,
        );
    }
    stop.store(true, Ordering::SeqCst);
    swapper.join().unwrap();
    let requests = listener.requests();
    for request in &requests {
        assert!(
            !request.contains("ROOT-DIR-SECRET-005"),
            "another folder's key was sent: {request}"
        );
    }
    assert!(
        requests
            .iter()
            .any(|r| r.contains("Bearer AGENTS-OWN-KEY-004")),
        "a run reads the linked folder's own key: {} requests",
        requests.len()
    );
}

/// The finding of the review: `llm set --url <another> --model m` kept the
/// stored key, and the next `check` sent it to the new address. A url moved
/// to another origin drops the key settings unless the same call gives them
/// again; a new path on the same origin keeps them.
///
/// FAILS ON REVERT of dropping the key when the origin moves.
#[test]
fn llm_set_to_another_address_drops_the_stored_key() {
    let good = Listener::start();
    let moved = Listener::start();
    let scratch = tempfile::tempdir().unwrap();
    let account = scratch.path().join("account");
    let folder = account_config(&account, &good.url(), "api_key_file = \"llm-key\"\n");
    let absent_notify = scratch.path().join("absent-notify.toml");
    let env: [(&str, &Path); 2] = [
        ("IW_TEST_ACCOUNT_HOME", account.as_path()),
        ("IW_NOTIFY_CONFIG", absent_notify.as_path()),
    ];
    let set = |url: &str| {
        let out = innerwarden(scratch.path(), &account)
            .env("IW_TEST_ACCOUNT_HOME", &account)
            .args(["llm", "set", "--url", url, "--model", "m"])
            .output()
            .unwrap();
        assert!(out.status.success(), "{}", said(&out));
        said(&out)
    };

    // The same origin, another path: the key stays.
    let same = format!("http://127.0.0.1:{}/v2/chat/completions", good.port);
    let kept = set(&same);
    assert!(!kept.contains("set-key"), "{kept}");
    check(scratch.path(), &account, &env, false);
    let to_good = good.requests();
    assert_eq!(to_good.len(), 1);
    assert!(
        to_good[0].contains(&format!("Bearer {ACCOUNT_KEY}")),
        "{}",
        to_good[0]
    );

    // Another origin: the key settings go, and the person is told.
    let told = set(&moved.url());
    assert!(told.contains("innerwarden llm set-key"), "{told}");
    let config = std::fs::read_to_string(folder.join("llm.toml")).unwrap();
    assert!(!config.contains("api_key"), "{config}");
    check(scratch.path(), &account, &env, false);
    let to_moved = moved.requests();
    assert_eq!(to_moved.len(), 1);
    no_key_in(&to_moved, &[ACCOUNT_KEY]);
}

/// A FIFO planted as the key never holds `check`: the key is opened without
/// blocking and refused as not a regular file.
///
/// FAILS ON REVERT of opening without blocking (the run hangs until killed).
#[test]
fn a_fifo_as_the_key_never_holds_check() {
    let listener = Listener::start();
    let scratch = tempfile::tempdir().unwrap();
    let account = scratch.path().join("account");
    let folder = account_config(&account, &listener.url(), "api_key_file = \"fifo-key\"\n");
    let made = Command::new("mkfifo")
        .arg(folder.join("fifo-key"))
        .status()
        .unwrap();
    assert!(made.success());
    let absent_notify = scratch.path().join("absent-notify.toml");
    for args in [&["check", REVIEW_LINE][..], &["llm", "status"]] {
        let mut child = innerwarden(scratch.path(), &account)
            .env("IW_TEST_ACCOUNT_HOME", &account)
            .env("IW_NOTIFY_CONFIG", &absent_notify)
            .args(args)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        let started = std::time::Instant::now();
        loop {
            if child.try_wait().unwrap().is_some() {
                break;
            }
            if started.elapsed() > Duration::from_secs(30) {
                let _ = child.kill();
                panic!("{args:?} held by a FIFO key");
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        let out = child.wait_with_output().unwrap();
        assert!(
            said(&out).contains("not a regular file"),
            "{args:?}: {}",
            said(&out)
        );
    }
}

/// A service account whose home does not exist: `llm status` and `llm set`
/// say so and name `IW_LLM_CONFIG`, instead of a bare "not configured" or a
/// failed write.
#[test]
fn an_account_without_a_home_is_told_about_the_override() {
    let scratch = tempfile::tempdir().unwrap();
    let missing = scratch.path().join("nonexistent");
    for args in [
        &["llm", "status"][..],
        &[
            "llm",
            "set",
            "--url",
            "http://127.0.0.1:9/v1",
            "--model",
            "m",
        ],
    ] {
        let out = innerwarden(scratch.path(), scratch.path())
            .env("IW_TEST_ACCOUNT_HOME", &missing)
            .args(args)
            .output()
            .unwrap();
        let text = said(&out);
        assert!(
            text.contains("does not exist") && text.contains("IW_LLM_CONFIG"),
            "{args:?}: {text}"
        );
    }
}

/// The verdict `check` prints for [`REVIEW_LINE`] with `HOME` at `home`, the
/// account's home at `account`, and no `IW_SUPPRESS_CONFIG`.
fn verdict_with_suppressions(scratch: &Path, home: &Path, account: &Path) -> String {
    let out = innerwarden(scratch, home)
        .env("IW_TEST_ACCOUNT_HOME", account)
        .env("IW_LLM_CONFIG", "/dev/null")
        .env("IW_NOTIFY_CONFIG", "/dev/null")
        .env_remove("IW_SUPPRESS_CONFIG")
        .args(["check", REVIEW_LINE])
        .output()
        .unwrap();
    format!(
        "exit {:?}\n{}",
        out.status.code(),
        String::from_utf8_lossy(&out.stdout)
    )
}

/// The finding of the review: the suppressions came from `HOME`, so a
/// `suppress.toml` planted in a home the caller names lowered the verdict on
/// the command it lists. They come from the account's home now: the planted
/// one changes nothing, and the same file in the account's home does (the
/// file is a working suppression, so the first comparison means something).
///
/// FAILS ON REVERT of reading the suppressions from the account's home.
#[test]
fn a_suppression_planted_in_a_home_the_caller_names_changes_no_verdict() {
    let scratch = tempfile::tempdir().unwrap();
    let suppress = format!("allow = [\"{REVIEW_LINE}\"]\n");
    let planted = scratch.path().join("planted");
    std::fs::create_dir_all(planted.join(".config/innerwarden")).unwrap();
    std::fs::write(planted.join(".config/innerwarden/suppress.toml"), &suppress).unwrap();
    let clean = scratch.path().join("clean");
    std::fs::create_dir_all(&clean).unwrap();

    let before = verdict_with_suppressions(scratch.path(), &clean, &clean);
    let with_planted = verdict_with_suppressions(scratch.path(), &planted, &clean);
    assert_eq!(
        with_planted, before,
        "a planted suppression changed the verdict"
    );
    let account_owns = verdict_with_suppressions(scratch.path(), &clean, &planted);
    assert_ne!(
        account_owns, before,
        "the account's own suppression applies"
    );
}
