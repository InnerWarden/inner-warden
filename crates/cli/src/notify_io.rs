//! The thin I/O adapter for `innerwarden notify` and the verdict-notification fire.
//!
//! All the DECISION logic (config precedence, merge-on-set, the `--test` fan-out,
//! the status line) lives in the pure, fully-tested `notify` module. This file is
//! only the un-unit-testable boundary: read/write the config file, resolve its
//! path, and POST with `ureq`. It is excluded from the coverage floor for the same
//! reason `main.rs` and `ctl/commands/notify.rs` are - a thin CLI/network adapter
//! over tested logic. It is still exercised end-to-end by `tests/cli.rs`.

use innerwarden_notify::Request;
use serde_json::Value;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use innerwarden_notify::cli::{compute, plan, Action};

/// The shared notify config path (env `IW_NOTIFY_CONFIG`, else
/// `~/.config/innerwarden/notify.toml`) - resolved by the shared crate so the
/// Active Defence host agent reads the exact SAME file.
fn config_path() -> Option<PathBuf> {
    innerwarden_notify::config_path(|k| std::env::var(k).ok())
}

/// Read the shared notify config file's contents, or `None` if unset/unreadable.
fn config_file() -> Option<String> {
    read_config_file(&config_path()?).ok().flatten()
}

fn config_parent(path: &Path, create: bool) -> Result<PathBuf, String> {
    let parent = path
        .parent()
        .ok_or_else(|| format!("{} has no parent directory", path.display()))?;
    if create {
        std::fs::create_dir_all(parent)
            .map_err(|error| format!("creating {}: {error}", parent.display()))?;
    }
    let metadata = match std::fs::symlink_metadata(parent) {
        Ok(metadata) => metadata,
        Err(error) if !create && error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(parent.to_path_buf())
        }
        Err(error) => return Err(format!("inspecting {}: {error}", parent.display())),
    };
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(format!(
            "notification config parent {} is not a trusted directory",
            parent.display()
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if metadata.uid() != unsafe { libc::geteuid() } {
            return Err(format!(
                "notification config parent {} is not owned by the current user",
                parent.display()
            ));
        }
        if create {
            std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700)).map_err(
                |error| {
                    format!(
                        "setting private permissions on {}: {error}",
                        parent.display()
                    )
                },
            )?;
        }
    }
    Ok(parent.to_path_buf())
}

fn read_config_file(path: &Path) -> Result<Option<String>, String> {
    let parent = config_parent(path, false)?;
    if !parent.exists() {
        return Ok(None);
    }
    let bytes = innerwarden_agent_guard::file_update::read_config_no_symlinks(&parent, path)?;
    bytes
        .map(|bytes| {
            String::from_utf8(bytes).map_err(|_| format!("{} is not valid UTF-8", path.display()))
        })
        .transpose()
}

fn clamp_private_file(path: &Path) -> Result<(), String> {
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(format!("inspecting {}: {error}", path.display())),
    };
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(format!(
            "notification config {} is not a regular file",
            path.display()
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if metadata.uid() != unsafe { libc::geteuid() } {
            return Err(format!(
                "notification config {} is not owned by the current user",
                path.display()
            ));
        }
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).map_err(
            |error| format!("setting private permissions on {}: {error}", path.display()),
        )?;
    }
    Ok(())
}

fn write_config_file(path: &Path, content: &str) -> Result<(), String> {
    let parent = config_parent(path, true)?;
    clamp_private_file(path)?;
    let expected = innerwarden_agent_guard::file_update::read_config_no_symlinks(&parent, path)?;
    innerwarden_agent_guard::file_update::replace_if_unchanged_no_symlinks(
        &parent,
        path,
        expected.as_deref(),
        content.as_bytes(),
    )?;
    clamp_private_file(path)
}

/// Whether at least one notification channel is already configured (used by the
/// setup wizard to pre-check the box on a re-run).
pub fn is_configured() -> bool {
    match compute(&[], config_file().as_deref(), |k| std::env::var(k).ok()) {
        Action::Status(s) => {
            s.contains("telegram")
                || s.contains("slack")
                || s.contains("discord")
                || s.contains("webhook")
        }
        _ => false,
    }
}

/// `innerwarden notify [flags]` - show status (no args) or set channels into the
/// shared config file (merging, so setting one channel keeps the others), with an
/// optional `--test` alert. Thin I/O over the pure `compute`.
pub fn cmd(rest: &[String]) -> std::process::ExitCode {
    match compute(rest, config_file().as_deref(), |k| std::env::var(k).ok()) {
        Action::Status(status) => {
            println!("innerwarden notify - {status}");
            println!("  set: innerwarden notify --telegram-token <T> --telegram-chat <C> [--slack-webhook <URL>] [--notify-review] [--test]");
            println!(
                "  config: {}",
                config_path()
                    .map(|p| p.display().to_string())
                    .unwrap_or_else(|| "(no HOME)".into())
            );
            std::process::ExitCode::SUCCESS
        }
        Action::Error(e) => {
            eprintln!("innerwarden notify: {e}");
            std::process::ExitCode::from(2)
        }
        Action::Apply { write, tests } => {
            if let Some(content) = write {
                let Some(path) = config_path() else {
                    eprintln!("innerwarden notify: cannot resolve a config path (set IW_NOTIFY_CONFIG or HOME)");
                    return std::process::ExitCode::from(2);
                };
                if let Err(e) = write_config_file(&path, &content) {
                    eprintln!(
                        "innerwarden notify: failed to write {}: {e}",
                        path.display()
                    );
                    return std::process::ExitCode::from(1);
                }
                println!("innerwarden notify - saved to {}", path.display());
            }
            let attempted = tests.len();
            let delivered = tests
                .iter()
                .filter(|request| send(request) == DeliveryStatus::Delivered)
                .count();
            if attempted > 0 && delivered == attempted {
                println!(
                    "innerwarden notify - test alert delivered to {delivered} configured channel(s)."
                );
            } else if attempted > 0 {
                eprintln!(
                    "innerwarden notify - delivery confirmed for {delivered}/{attempted} configured channel(s); failed attempts were ignored."
                );
            }
            std::process::ExitCode::SUCCESS
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DeliveryStatus {
    Delivered,
    Failed,
}

/// POST one request, best-effort. `Delivered` means the adapter received a
/// successful HTTP response; merely constructing or attempting a request never
/// counts as delivery. Callers still swallow failures so notification transport
/// cannot change a guardrail verdict or exit code.
fn delivery_failure_message(_req: &Request, http_status: Option<u16>) -> String {
    match http_status {
        Some(status) => format!("notification delivery returned HTTP {status} (ignored)"),
        None => "notification delivery failed with a transport error (ignored)".into(),
    }
}

fn send_with_timeout(req: &Request, timeout: Duration) -> DeliveryStatus {
    let resp = crate::http_io::agent_with_timeout(timeout)
        .post(&req.url)
        .header("Content-Type", "application/json")
        .send(&req.body);
    match resp {
        Ok(response) if (200..300).contains(&response.status().as_u16()) => {
            DeliveryStatus::Delivered
        }
        Ok(response) => {
            eprintln!(
                "innerwarden: {}",
                delivery_failure_message(req, Some(response.status().as_u16()))
            );
            DeliveryStatus::Failed
        }
        // ureq 3 turns 4xx/5xx into StatusCode; everything else is a transport
        // failure. `status_of` keeps this from becoming a variant list that goes
        // stale the next time ureq adds one.
        Err(e) => {
            eprintln!(
                "innerwarden: {}",
                delivery_failure_message(req, crate::http_io::status_of(&e))
            );
            DeliveryStatus::Failed
        }
    }
}

fn send(req: &Request) -> DeliveryStatus {
    send_with_timeout(req, Duration::from_secs(5))
}

const ENFORCEMENT_DELIVERY_BUDGET: Duration = Duration::from_millis(150);

fn deliver_with_total_budget(requests: Vec<Request>, budget: Duration) -> usize {
    if requests.is_empty() {
        return 0;
    }
    let deadline = Instant::now() + budget;
    let mut delivered = 0;
    let total = requests.len();
    for (index, request) in requests.into_iter().enumerate() {
        let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
            break;
        };
        // Divide the one enforcement budget among channels that remain. This is
        // deterministic and leaves no worker thread holding hook stdio open after
        // the blocking verdict has been decided.
        let slots = u32::try_from(total - index).unwrap_or(1).max(1);
        let timeout = remaining / slots;
        delivered += usize::from(send_with_timeout(&request, timeout) == DeliveryStatus::Delivered);
    }
    delivered
}

/// Fire notifications for a deny verdict (and optionally review), best-effort.
/// No-op when nothing is configured or the verdict does not warrant one.
pub fn fire(command: &str, verdict: &Value) {
    let reqs = plan(
        |k| std::env::var(k).ok(),
        config_file().as_deref(),
        command,
        verdict,
    );
    let _ = deliver_with_total_budget(reqs, ENFORCEMENT_DELIVERY_BUDGET);
}

/// Fire a plain health message on every configured channel, best-effort.
///
/// Separate from [`fire`] because this is not a verdict: it carries no command
/// and is not filtered by the deny/review preference. An operator who wired a
/// channel to hear about blocks also wants to hear that the record stopped
/// recording them. Callers must send this at most once per outage episode.
pub fn fire_text(text: &str) {
    let config = innerwarden_notify::resolved(|k| std::env::var(k).ok(), config_file().as_deref());
    let requests = innerwarden_notify::text_requests(&config, text);
    let _ = deliver_with_total_budget(requests, ENFORCEMENT_DELIVERY_BUDGET);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};

    #[test]
    fn adapter_reports_delivered_only_after_a_successful_http_response() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(std::time::Duration::from_secs(2)))
                .unwrap();
            let mut request = Vec::new();
            let mut buffer = [0_u8; 1024];
            loop {
                match stream.read(&mut buffer) {
                    Ok(0) => break,
                    Ok(read) => {
                        request.extend_from_slice(&buffer[..read]);
                        let body = b"{\"kind\":\"deny\"}";
                        if request.windows(body.len()).any(|window| window == body) {
                            break;
                        }
                    }
                    Err(error)
                        if matches!(
                            error.kind(),
                            std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                        ) =>
                    {
                        break;
                    }
                    Err(error) => panic!("reading notification request: {error}"),
                }
            }
            stream
                .write_all(b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n")
                .unwrap();
            String::from_utf8(request).unwrap()
        });

        let request = Request {
            url: format!("http://{address}/notify"),
            body: r#"{"kind":"deny"}"#.into(),
            json: true,
        };
        assert_eq!(send(&request), DeliveryStatus::Delivered);
        let received = server.join().unwrap();
        assert!(received.starts_with("POST /notify HTTP/1.1"));
        // Case-insensitive because HTTP header NAMES are, and this assertion is
        // about the request declaring JSON, not about which casing the client
        // happens to emit. ureq 2 sent `Content-Type`; ureq 3 normalises through
        // the `http` crate and sends `content-type`, and pinning the old spelling
        // turned a working request into a red test.
        assert!(
            received
                .to_lowercase()
                .contains("content-type: application/json"),
            "the request must declare JSON: {received}"
        );
        assert!(received.ends_with(r#"{"kind":"deny"}"#));
    }

    #[test]
    fn refused_connection_is_failed_not_delivered() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        drop(listener);
        let request = Request {
            url: format!("http://{address}/notify"),
            body: "{}".into(),
            json: true,
        };
        assert_eq!(send(&request), DeliveryStatus::Failed);
    }

    #[test]
    fn http_500_is_failed_not_delivered() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        // Same class of hang as the fan-out test above: a bare `accept()` with a
        // joined thread turns "the client never connected" into a test binary
        // that never exits. Bounded, so that case FAILS and says so.
        let server = std::thread::spawn(move || {
            listener
                .set_nonblocking(true)
                .expect("nonblocking listener");
            let deadline = Instant::now() + Duration::from_secs(5);
            let mut stream = loop {
                match listener.accept() {
                    Ok((stream, _)) => break stream,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        assert!(
                            Instant::now() < deadline,
                            "the client never connected to the 500 server"
                        );
                        std::thread::sleep(Duration::from_millis(5));
                    }
                    Err(error) => panic!("accepting the 500 request: {error}"),
                }
            };
            stream.set_nonblocking(false).expect("blocking stream");
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .expect("read timeout");
            let mut buffer = [0_u8; 1024];
            let _ = stream.read(&mut buffer);
            stream
                .write_all(
                    b"HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                )
                .unwrap();
        });
        let request = Request {
            url: format!("http://{address}/notify"),
            body: "{}".into(),
            json: true,
        };

        assert_eq!(send(&request), DeliveryStatus::Failed);
        server.join().unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn config_write_clamps_new_and_existing_permissions() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        let root = tempfile::Builder::new()
            .prefix("iw-notify-config-")
            .tempdir_in(std::env::current_dir().unwrap())
            .unwrap();
        let directory = root.path().join("innerwarden");
        std::fs::create_dir(&directory).unwrap();
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o755)).unwrap();
        let path = directory.join("notify.toml");

        write_config_file(&path, "slack_webhook = \"https://first\"\n").unwrap();
        assert_eq!(std::fs::metadata(&directory).unwrap().mode() & 0o777, 0o700);
        assert_eq!(std::fs::metadata(&path).unwrap().mode() & 0o777, 0o600);
        assert_eq!(std::fs::metadata(&path).unwrap().uid(), unsafe {
            libc::geteuid()
        });

        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o777)).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666)).unwrap();
        write_config_file(&path, "slack_webhook = \"https://second\"\n").unwrap();
        assert_eq!(std::fs::metadata(&directory).unwrap().mode() & 0o777, 0o700);
        assert_eq!(std::fs::metadata(&path).unwrap().mode() & 0o777, 0o600);
        assert_eq!(
            read_config_file(&path).unwrap().unwrap(),
            "slack_webhook = \"https://second\"\n"
        );
    }

    #[cfg(unix)]
    #[test]
    fn config_write_rejects_a_symlink_without_touching_its_target() {
        use std::os::unix::fs::symlink;

        let root = tempfile::Builder::new()
            .prefix("iw-notify-link-")
            .tempdir_in(std::env::current_dir().unwrap())
            .unwrap();
        let directory = root.path().join("innerwarden");
        std::fs::create_dir(&directory).unwrap();
        let target = root.path().join("victim");
        std::fs::write(&target, "unchanged").unwrap();
        let path = directory.join("notify.toml");
        symlink(&target, &path).unwrap();

        assert!(write_config_file(&path, "stolen").is_err());
        assert_eq!(std::fs::read_to_string(target).unwrap(), "unchanged");
    }

    #[test]
    fn delivery_errors_never_include_url_credentials_or_query_values() {
        let request = Request {
            url: "https://user:super-secret@example.test/hook?token=query-secret".into(),
            body: "{}".into(),
            json: true,
        };
        for message in [
            delivery_failure_message(&request, Some(503)),
            delivery_failure_message(&request, None),
        ] {
            assert!(!message.contains("super-secret"));
            assert!(!message.contains("query-secret"));
            assert!(!message.contains("user:"));
            assert!(!message.contains("example.test"));
        }
    }

    #[test]
    fn enforcement_fanout_has_one_strict_total_budget() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        // Accept whatever arrives, until a deadline. NOT `for _ in 0..4`.
        //
        // This test starves the client on purpose: 100 ms of total budget across
        // four channels is 25 ms each. On Linux and macOS a loopback connect is
        // sub-millisecond so all four land, and demanding exactly four accepts
        // looked safe. On Windows a 25 ms connect budget is not comfortably met,
        // so fewer connections arrive, `accept()` blocks forever waiting for the
        // fourth, and `server.join()` below never returns. The test binary then
        // never exits and `cargo test --workspace` hangs with no output - which
        // is exactly what happened the first time the suite ran on Windows: 35
        // minutes, no output, two independent runners.
        //
        // The client is what this test asserts on. The server exists only to be
        // slow, so it must never be able to hold the suite hostage.
        let server = std::thread::spawn(move || {
            listener
                .set_nonblocking(true)
                .expect("nonblocking listener");
            let deadline = Instant::now() + Duration::from_secs(2);
            let mut held = Vec::new();
            while held.len() < 4 && Instant::now() < deadline {
                match listener.accept() {
                    // Hold them open: an accepted-then-closed socket would be a
                    // fast failure, and slowness is the condition under test.
                    Ok((stream, _)) => held.push(stream),
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(5));
                    }
                    Err(error) => panic!("accepting fan-out connection: {error}"),
                }
            }
        });
        let requests = (0..4)
            .map(|_| Request {
                url: format!("http://{address}/slow"),
                body: "{}".into(),
                json: true,
            })
            .collect();

        let started = Instant::now();
        assert_eq!(
            deliver_with_total_budget(requests, Duration::from_millis(100)),
            0
        );
        assert!(
            started.elapsed() < Duration::from_millis(350),
            "fan-out multiplied the per-channel timeout: {:?}",
            started.elapsed()
        );
        server.join().unwrap();
    }
}
