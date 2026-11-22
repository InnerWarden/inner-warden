//! The MCP proxy in front of a server reached by URL (Streamable HTTP, and
//! the older HTTP with SSE).
//!
//! `innerwarden agents connect` rewrites a remote server entry
//! (`{"url": "https://..."}`) into the same wrapper a local server gets:
//! `innerwarden proxy --mode guard -- https://...`. The client starts the
//! proxy as a local stdio server, and the proxy, seeing an address where a
//! program would be, talks to the real server over HTTP(S) instead of
//! spawning one. Every line still goes through the stdio proxy's loop
//! ([`super::transport`]), so a remote server gets exactly the checks a
//! local one gets: pinned tool definitions, effect and provenance, secrets
//! in answers, the posture. The proxy opens no port and serves no TLS of its
//! own: the client reaches it through a pipe, and it reaches the server as
//! the configuration said, with the system's certificates.
//!
//! The bridge here only moves messages: lines the loop forwards are sent to
//! the server, and every message the server answers with (a JSON body, each
//! event of an SSE stream, the server's own stream) comes back as one line
//! the loop reads as the server's output. A request the server cannot
//! answer (unreachable, an HTTP error) gets a JSON-RPC error with its id, so
//! the client is never left waiting.
//!
//! * **Streamable HTTP** (2025-03-26 and later): each message is a POST; the
//!   session id the server gives is sent back on every request, with the
//!   protocol version the server chose; after `notifications/initialized`
//!   the server's own stream is opened with a GET when it has one; the
//!   session is ended with a DELETE when the client leaves.
//! * **HTTP with SSE** (2024-11-05): a GET opens the server's stream, whose
//!   first `endpoint` event says where to POST; answers arrive on the
//!   stream. Used when the entry says `"type": "sse"`, or when the server
//!   answers the first POST with 400, 404 or 405 (the fallback the
//!   specification describes). An endpoint on another origin is refused.
//!
//! Headers the entry carried (a token) reach the proxy through its
//! environment, one `INNERWARDEN_MCP_HEADER_<n>` per header, written as
//! `Name: value`: the client gives a stdio server its `env`, and a value in
//! the environment is not shown to every user of the machine as an argument
//! is. Redirects are not followed, so a header never goes anywhere the entry
//! did not name.
//!
//! What it cannot do: sign in for the client. A server that asks the client
//! to sign in (HTTP 401) gets an error that says so; a token in the entry's
//! headers works, an OAuth sign-in done by the client does not.

use std::collections::VecDeque;
use std::io::{BufRead, Read};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::{json, Value};
use tokio::io::{AsyncWriteExt, BufReader, DuplexStream};
use tokio::sync::mpsc::{
    channel, unbounded_channel, Receiver, Sender, UnboundedReceiver, UnboundedSender,
};

/// The environment variables a wrapper carries its server's headers in:
/// `INNERWARDEN_MCP_HEADER_1`, `_2`, ... each `Name: value`.
pub const HEADER_ENV_PREFIX: &str = "INNERWARDEN_MCP_HEADER_";

/// Most headers read from the environment.
pub(crate) const MAX_HEADERS: usize = 64;

/// Longest message the bridge relays: the loop's own cap on a line.
const MAX_MESSAGE_BYTES: usize = 4 * 1024 * 1024;

/// How long a connection to the server may take to open.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);

/// Bytes buffered in each pipe between the loop and the bridge.
const PIPE_BYTES: usize = 256 * 1024;

/// Server messages waiting for the bridge. A full queue holds the threads
/// that read the server: a server that streams without end, in front of a
/// client that reads slowly, waits instead of filling memory. The client's
/// side is not bounded, so neither side can hold the other up in a cycle.
const SERVER_QUEUE: usize = 256;

/// Whether a server command's first word is an address the proxy reaches
/// over HTTP rather than a program it spawns.
pub fn is_remote_url(word: &str) -> bool {
    let lower = word.get(..8).unwrap_or(word).to_ascii_lowercase();
    let rest = if lower.starts_with("https://") {
        &word[8..]
    } else if lower.starts_with("http://") {
        &word[7..]
    } else {
        return false;
    };
    !rest.is_empty()
        && !rest.starts_with('/')
        && !word.chars().any(|c| c.is_whitespace() || c.is_control())
}

/// Whether `url` names a server on this host: no `scheme://host` (a
/// file, a word that is no address), a unix socket, or one whose host is this host's loopback or
/// unspecified address (`localhost`, a name under `.localhost`,
/// `127.0.0.0/8` in any of the forms a URL parser reads, `0.0.0.0`,
/// `::1`, `::` and their IPv4-mapped forms). A path handed to such a
/// server names a file here, so its calls keep the path rules, and a
/// connect carries it through the proxy whatever signs in to it. A name
/// that only resolves to the loopback (a DNS record) is not seen.
pub fn is_local_url(url: &str) -> bool {
    let url = url.trim();
    let Some(at) = url.find("://") else {
        return true;
    };
    if url[..at].to_ascii_lowercase().contains("unix") {
        return true;
    }
    let after = &url[at + 3..];
    let authority = &after[..after.find(['/', '?', '#', '\\']).unwrap_or(after.len())];
    let host = authority.rsplit('@').next().unwrap_or(authority);
    let host = percent_decoded(host).to_ascii_lowercase();
    if let Some(inside) = host.strip_prefix('[') {
        let inside = inside.split(']').next().unwrap_or(inside);
        let inside = inside.split('%').next().unwrap_or(inside);
        return inside.parse::<std::net::Ipv6Addr>().is_ok_and(|ip| {
            ip.is_loopback()
                || ip.is_unspecified()
                || ip
                    .to_ipv4_mapped()
                    .is_some_and(|v4| v4.is_loopback() || v4.is_unspecified())
        });
    }
    let host = host.rsplit_once(':').map_or(host.as_str(), |(name, _)| name);
    let host = host.trim_end_matches('.');
    if host.is_empty() || host == "localhost" || host.ends_with(".localhost") {
        return true;
    }
    url_ipv4(host).is_some_and(|ip| ip.is_loopback() || ip.is_unspecified())
}

/// `text` with each `%XX` read as its byte (a URL's host may be written so).
fn percent_decoded(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            if let Some(byte) = text
                .get(i + 1..i + 3)
                .and_then(|hex| u8::from_str_radix(hex, 16).ok())
            {
                out.push(byte);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// An IPv4 host as a URL parser reads it (the WHATWG rules): one to four
/// numbers split by `.`, each decimal, `0x` hex or `0` octal, the last
/// filling the bytes left (`127.1`, `2130706433`, `0x7f.0.0.1`).
fn url_ipv4(host: &str) -> Option<std::net::Ipv4Addr> {
    let host = host.strip_suffix('.').unwrap_or(host);
    let parts: Vec<&str> = host.split('.').collect();
    if parts.len() > 4 {
        return None;
    }
    let mut numbers = Vec::with_capacity(parts.len());
    for part in &parts {
        let (digits, radix) = if let Some(hex) = part
            .strip_prefix("0x")
            .or_else(|| part.strip_prefix("0X"))
        {
            (hex, 16)
        } else if part.len() > 1 && part.starts_with('0') {
            (&part[1..], 8)
        } else if part.is_empty() {
            return None;
        } else {
            (*part, 10)
        };
        let number = if digits.is_empty() {
            0
        } else {
            u64::from_str_radix(digits, radix).ok()?
        };
        numbers.push(number);
    }
    let last = numbers.pop()?;
    let mut address: u64 = 0;
    for (i, number) in numbers.iter().enumerate() {
        if *number > 255 {
            return None;
        }
        address |= number << (8 * (3 - i));
    }
    if last >= 1u64 << (8 * (4 - numbers.len())) {
        return None;
    }
    address |= last;
    u32::try_from(address).ok().map(std::net::Ipv4Addr::from)
}

/// One remote server, as its wrapper names it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteSpec {
    /// The server's address.
    pub url: String,
    /// The older HTTP with SSE transport from the start.
    pub legacy_sse: bool,
    /// Headers sent with every request.
    pub headers: Vec<(String, String)>,
}

/// Where Goose keeps its configuration, under `$HOME`: the file
/// `agents connect` wires (`agents::KNOWN`, `mcp_yaml`), read again by a
/// Goose remote server's proxy for the headers the extension names
/// (`--goose-headers`).
pub const GOOSE_CONFIG: &str = ".config/goose/config.yaml";

/// A header name as HTTP takes it (a token).
pub(crate) fn is_header_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_|~".contains(&b))
}

/// An environment variable name as a configuration may give one.
pub(crate) fn is_env_name(name: &str) -> bool {
    !name.is_empty()
        && !name.starts_with(|c: char| c.is_ascii_digit())
        && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

/// Goose's `$VAR` and `${VAR}` in a header value, filled from `env` the
/// way Goose fills them (`substitute_env_vars` in its extension config): a
/// name with no value stays written as it was, and a value put in is not
/// read again.
fn fill_goose_vars(value: &str, env: &impl Fn(&str) -> Option<String>) -> String {
    let mut out = String::with_capacity(value.len());
    let mut rest = value;
    while let Some(at) = rest.find('$') {
        out.push_str(&rest[..at]);
        let after = &rest[at + 1..];
        let (name, used) = if let Some(inner) = after.strip_prefix('{') {
            match inner.find('}') {
                Some(close)
                    if !inner[..close].trim().is_empty()
                        && !inner[..close].trim().contains(char::is_whitespace)
                        && !inner[..close].contains('{') =>
                {
                    (inner[..close].trim(), close + 2)
                }
                _ => ("", 0),
            }
        } else {
            let len = after
                .char_indices()
                .take_while(|(i, c)| {
                    c.is_ascii_alphabetic() || *c == '_' || (*i > 0 && c.is_ascii_digit())
                })
                .count();
            (&after[..len], len)
        };
        match (name.is_empty(), env(name)) {
            (false, Some(filled)) => out.push_str(&filled),
            _ if used > 0 => out.push_str(&rest[at..at + 1 + used]),
            _ => out.push('$'),
        }
        rest = &after[used..];
    }
    out.push_str(rest);
    out
}

/// The headers Goose's extension `name` gives its remote server, read from
/// Goose's configuration text and filled from `env` ([`fill_goose_vars`]).
/// An extension with no `headers` has none; one Goose would not read is an
/// error naming the extension, never a value.
fn goose_headers(
    config: &str,
    name: &str,
    env: &impl Fn(&str) -> Option<String>,
) -> Result<Vec<(String, String)>, String> {
    let doc: serde_yaml::Value = serde_yaml::from_str(config)
        .map_err(|_| "Goose's configuration could not be read".to_string())?;
    let extension = doc
        .get("extensions")
        .and_then(|extensions| extensions.get(name))
        .ok_or_else(|| format!("Goose's configuration has no extension `{name}`"))?;
    let Some(headers) = extension.get("headers") else {
        return Ok(Vec::new());
    };
    if headers.is_null() {
        return Ok(Vec::new());
    }
    let map = headers
        .as_mapping()
        .ok_or_else(|| format!("the headers of extension `{name}` are not a mapping"))?;
    let mut out = Vec::new();
    for (key, value) in map {
        let (Some(key), Some(value)) = (key.as_str(), value.as_str()) else {
            return Err(format!(
                "a header of extension `{name}` is not written as text"
            ));
        };
        if !is_header_name(key.trim()) {
            return Err(format!(
                "extension `{name}` names a header HTTP does not take"
            ));
        }
        out.push((key.trim().to_string(), fill_goose_vars(value, env)));
    }
    Ok(out)
}

impl RemoteSpec {
    /// The remote server a wrapper's command names, with its headers read
    /// through `env`. `None` when the command is a program; an error for an
    /// address followed by words the proxy does not take, or a header it
    /// cannot send.
    ///
    /// After the address the wrapper may carry `--key <name>` (the key the
    /// address was under, for disconnect) and `--type <type>` (the entry's
    /// type; `sse` selects the older transport). A Codex server adds where
    /// its token and headers come from: `--bearer-env <VAR>` (sent as
    /// `Authorization: Bearer`, the variable must be set) and
    /// `--header-env <Name> <VAR>` (sent when the variable is set). A Goose
    /// server adds `--goose-headers <extension>`: the headers that
    /// extension has in Goose's configuration (the file `--goose-config
    /// <path>` names, else `$HOME/.config/goose/config.yaml`), `$VAR` filled
    /// from the environment Goose gives its servers. A value is only ever read where
    /// the agent itself would read it; none is written in the wrapper.
    pub fn from_cmd(
        cmd: &[String],
        env: impl Fn(&str) -> Option<String>,
    ) -> Option<Result<Self, String>> {
        Self::from_cmd_reading(cmd, env, |path| std::fs::read_to_string(path).ok())
    }

    /// [`Self::from_cmd`] with the read of Goose's configuration given.
    pub fn from_cmd_reading(
        cmd: &[String],
        env: impl Fn(&str) -> Option<String>,
        read: impl Fn(&std::path::Path) -> Option<String>,
    ) -> Option<Result<Self, String>> {
        let url = cmd.first()?;
        if !is_remote_url(url) {
            return None;
        }
        Some(Self::parse(url, &cmd[1..], env, read))
    }

    fn parse(
        url: &str,
        rest: &[String],
        env: impl Fn(&str) -> Option<String>,
        read: impl Fn(&std::path::Path) -> Option<String>,
    ) -> Result<Self, String> {
        let mut legacy_sse = false;
        let mut headers = Vec::new();
        let mut from_vars: Vec<(String, String)> = Vec::new();
        let mut goose_config: Option<String> = None;
        let mut goose_extension: Option<String> = None;
        let mut words = rest.iter();
        let value_of = |word: &str, words: &mut std::slice::Iter<'_, String>| {
            words
                .next()
                .cloned()
                .ok_or_else(|| format!("{word} after the remote server's address needs a value"))
        };
        while let Some(word) = words.next() {
            match word.as_str() {
                // What the entry had, for disconnect; nothing to the proxy.
                "--headers" | "--env" | "--env-headers" => {}
                "--key" | "--type" => {
                    let value = value_of(word, &mut words)?;
                    if word == "--type" && value.eq_ignore_ascii_case("sse") {
                        legacy_sse = true;
                    }
                }
                "--bearer-env" => {
                    let var = value_of(word, &mut words)?;
                    if !is_env_name(&var) {
                        return Err("--bearer-env does not name a variable".to_string());
                    }
                    match env(&var).filter(|token| !token.is_empty()) {
                        Some(token) => from_vars.push((
                            "Authorization".to_string(),
                            format!("Bearer {}", token.trim()),
                        )),
                        None => {
                            return Err(format!(
                            "the variable {var}, which holds the remote server's token, is not set"
                        ))
                        }
                    }
                }
                "--header-env" => {
                    let name = value_of(word, &mut words)?;
                    let var = value_of(word, &mut words)?;
                    if !is_header_name(&name) || !is_env_name(&var) {
                        return Err("--header-env needs a header name and a variable".to_string());
                    }
                    if let Some(value) = env(&var).filter(|value| !value.is_empty()) {
                        from_vars.push((name, value.trim().to_string()));
                    }
                }
                "--goose-config" => goose_config = Some(value_of(word, &mut words)?),
                "--goose-headers" => goose_extension = Some(value_of(word, &mut words)?),
                other => {
                    return Err(format!(
                        "unexpected word `{other}` after the remote server's address"
                    ))
                }
            }
        }
        if let Some(extension) = goose_extension {
            // The file the wrapper names (`--goose-config`, written by
            // connect), else Goose's own place under `HOME` (a wrapper
            // written before the file was named).
            let path = match goose_config {
                Some(path) => std::path::PathBuf::from(path),
                None => {
                    let home = env("HOME").filter(|home| !home.is_empty()).ok_or(
                        "HOME is not set, so Goose's configuration cannot be found".to_string(),
                    )?;
                    std::path::Path::new(&home).join(GOOSE_CONFIG)
                }
            };
            let config =
                read(&path).ok_or("Goose's configuration could not be read".to_string())?;
            from_vars.extend(goose_headers(&config, &extension, &env)?);
        }
        for n in 1..=MAX_HEADERS {
            let name = format!("{HEADER_ENV_PREFIX}{n}");
            let Some(line) = env(&name) else {
                break;
            };
            let Some((key, value)) = line.split_once(':') else {
                return Err(format!("{name} is not written as `Name: value`"));
            };
            let key = key.trim();
            if !is_header_name(key) {
                return Err(format!("{name} does not name a header"));
            }
            if value.contains(['\r', '\n', '\0']) {
                return Err(format!("{name} holds a line break"));
            }
            headers.push((key.to_string(), value.trim().to_string()));
        }
        for (key, value) in from_vars {
            // The name only: the value may be the token.
            if value.contains(['\r', '\n', '\0']) {
                return Err(format!("the value for header {key} holds a line break"));
            }
            headers.push((key, value));
        }
        if headers.len() > MAX_HEADERS {
            return Err(format!("more than {MAX_HEADERS} headers"));
        }
        Ok(Self {
            url: url.to_string(),
            legacy_sse,
            headers,
        })
    }
}

/// The two ends the proxy loop uses, and the bridge behind them, stopped
/// when this is dropped.
pub(super) struct Remote {
    /// What the loop writes: lines for the server.
    pub(super) input: Option<DuplexStream>,
    /// What the loop reads: the server's messages, one per line.
    pub(super) output: Option<DuplexStream>,
    tasks: Vec<tokio::task::JoinHandle<()>>,
}

impl Remote {
    /// Start the bridge to `spec`. Needs a Tokio runtime.
    pub(super) fn start(spec: RemoteSpec) -> Self {
        let (input, bridge_in) = tokio::io::duplex(PIPE_BYTES);
        let (bridge_out, output) = tokio::io::duplex(PIPE_BYTES);
        let (in_tx, in_rx) = unbounded_channel();
        let (tx, rx) = channel(SERVER_QUEUE);
        // The loop's lines are read by a task of their own and handed over
        // as messages, so no read is ever cut in the middle of a line.
        let reader = tokio::spawn(read_input(bridge_in, in_tx));
        let bridge = tokio::spawn(bridge(spec, bridge_out, tx, rx, in_rx));
        Self {
            input: Some(input),
            output: Some(output),
            tasks: vec![reader, bridge],
        }
    }

    /// Stop the bridge. A request already on its way finishes on its own
    /// thread; nothing it answers reaches the client.
    pub(super) fn stop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
    }
}

impl Drop for Remote {
    fn drop(&mut self) {
        self.stop();
    }
}

/// What the loop hands the bridge.
enum Input {
    /// A line the loop forwarded to the server.
    Line(String),
    /// The loop closed its end: the client left.
    Closed,
}

/// What reaches the bridge from the threads that talk to the server.
enum Up {
    /// A message from the server, as one line.
    Line(String),
    /// A request finished (answered, failed, or none was due).
    Done,
    /// The older transport's stream said where to POST.
    Endpoint(String),
    /// The older transport's stream ended, or never opened.
    StreamEnded,
    /// The server does not take Streamable HTTP: this line goes again over
    /// the older transport.
    Fallback(String),
}

async fn read_input(input: DuplexStream, tx: UnboundedSender<Input>) {
    let mut lines = super::transport::CappedLines::new(BufReader::new(input), MAX_MESSAGE_BYTES);
    while let Ok(Some(line)) = lines.next_line().await {
        if !line.trim().is_empty() && tx.send(Input::Line(line)).is_err() {
            return;
        }
    }
    let _ = tx.send(Input::Closed);
}

/// The server's address as `scheme://host`, the only part of it a message
/// names: a path, a query or a user part (`user:token@`) may carry a token.
fn host_of(url: &str) -> String {
    let Some((origin, _)) = split_origin(url) else {
        return "the remote MCP server".to_string();
    };
    let Some(at) = origin.find("://") else {
        return "the remote MCP server".to_string();
    };
    let authority = &origin[at + 3..];
    let host = authority.rsplit('@').next().unwrap_or(authority);
    format!("{}{host}", &origin[..at + 3])
}

/// An error's text with every address in it cut to its host, for the same
/// reason as [`host_of`].
fn scrub(text: &str) -> String {
    text.split(' ')
        .map(|word| {
            let Some(at) = word.find("://") else {
                return word.to_string();
            };
            let after = &word[at + 3..];
            let end = after
                .find(['/', '?', '#', '"', '\'', ')', ']', ','])
                .unwrap_or(after.len());
            let authority = &after[..end];
            let host = authority.rsplit('@').next().unwrap_or(authority);
            format!("{}{host}", &word[..at + 3])
        })
        .collect::<Vec<_>>()
        .join(" ")
}

fn unreachable(shared: &Shared, error: &ureq::Error) -> String {
    format!(
        "{} could not be reached: {}",
        host_of(&shared.url),
        scrub(&error.to_string())
    )
}

/// What every request to the server shares.
struct Shared {
    agent: ureq::Agent,
    url: String,
    headers: Vec<(String, String)>,
    session: Mutex<Option<String>>,
    protocol: Mutex<Option<String>>,
    listening: AtomicBool,
}

impl Shared {
    fn new(spec: &RemoteSpec) -> Self {
        let agent = ureq::Agent::config_builder()
            .http_status_as_error(false)
            .max_redirects(0)
            .max_redirects_will_error(false)
            .timeout_connect(Some(CONNECT_TIMEOUT))
            // Never through a proxy from the environment: with an http://
            // address the entry's token would cross it in clear.
            .proxy(None)
            .build()
            .new_agent();
        Self {
            agent,
            url: spec.url.clone(),
            headers: spec.headers.clone(),
            session: Mutex::new(None),
            protocol: Mutex::new(None),
            listening: AtomicBool::new(false),
        }
    }

    fn session(&self) -> Option<String> {
        self.session.lock().ok().and_then(|s| s.clone())
    }

    fn decorate<B>(&self, mut request: ureq::RequestBuilder<B>) -> ureq::RequestBuilder<B> {
        for (key, value) in &self.headers {
            request = request.header(key.as_str(), value.as_str());
        }
        if let Some(session) = self.session() {
            request = request.header("Mcp-Session-Id", session);
        }
        if let Some(version) = self.protocol.lock().ok().and_then(|p| p.clone()) {
            request = request.header("MCP-Protocol-Version", version);
        }
        request
    }

    fn post(&self, url: &str, line: &str) -> Result<ureq::http::Response<ureq::Body>, ureq::Error> {
        self.decorate(self.agent.post(url))
            .header("Content-Type", "application/json")
            .header("Accept", "application/json, text/event-stream")
            .send(line.as_bytes())
    }

    fn open_stream(&self) -> Result<ureq::http::Response<ureq::Body>, ureq::Error> {
        self.decorate(self.agent.get(&self.url))
            .header("Accept", "text/event-stream")
            .call()
    }
}

/// The method of a line the client sent, and the id of every request in it
/// (one, or each of a batch).
struct Sent {
    method: Option<String>,
    ids: Vec<Value>,
}

impl Sent {
    fn of(line: &str) -> Self {
        let value: Value = serde_json::from_str(line).unwrap_or(Value::Null);
        let request_id = |message: &Value| {
            message
                .get("method")
                .and_then(Value::as_str)
                .and(message.get("id"))
                .filter(|id| !id.is_null())
                .cloned()
        };
        let ids = match &value {
            Value::Array(items) => items.iter().filter_map(request_id).collect(),
            other => request_id(other).into_iter().collect(),
        };
        Self {
            method: value
                .get("method")
                .and_then(Value::as_str)
                .map(str::to_string),
            ids,
        }
    }

    /// Answer every request the server could not answer, so the client is
    /// not left waiting. A notification gets nothing.
    fn fail(&self, tx: &Sender<Up>, why: &str) {
        for line in self.error_lines(why) {
            let _ = tx.blocking_send(Up::Line(line));
        }
    }

    fn error_lines(&self, why: &str) -> Vec<String> {
        self.ids
            .iter()
            .map(|id| {
                json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "error": {"code": -32603, "message": format!("innerwarden proxy: {why}")}
                })
                .to_string()
            })
            .collect()
    }
}

fn status_failure(status: u16) -> String {
    match status {
        401 | 403 => format!(
            "the remote MCP server refused the request (HTTP {status}): it asks for a sign-in \
             the proxy cannot do for the client; put its token in the server entry's headers"
        ),
        300..=399 => format!(
            "the remote MCP server answered with a redirect (HTTP {status}); the proxy does not \
             follow redirects, so its headers reach only the address the entry names"
        ),
        _ => format!("the remote MCP server answered HTTP {status}"),
    }
}

/// A message as one line: a raw line break in JSON is always whitespace
/// between tokens (inside a string it must be escaped), so it is made a
/// space and every other byte is kept as the server sent it.
fn one_line(message: &str) -> String {
    message.trim().replace(['\r', '\n'], " ")
}

fn header(response: &ureq::http::Response<ureq::Body>, name: &str) -> Option<String> {
    response
        .headers()
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(str::to_string)
}

fn is_event_stream(response: &ureq::http::Response<ureq::Body>) -> bool {
    header(response, "content-type").is_some_and(|kind| {
        kind.trim()
            .to_ascii_lowercase()
            .starts_with("text/event-stream")
    })
}

/// Lines of an event stream, ended by `\r\n`, `\n` or `\r` alone (all
/// three are valid there), each at most [`MAX_MESSAGE_BYTES`].
struct EventLines<R> {
    reader: std::io::BufReader<R>,
    /// The last line ended with `\r`: a `\n` right after it is part of
    /// that end, even when it comes in the next read.
    after_cr: bool,
}

impl<R: Read> EventLines<R> {
    /// The next line into `line`: `Ok(false)` at the end of the stream.
    fn next(&mut self, line: &mut Vec<u8>) -> std::io::Result<bool> {
        line.clear();
        loop {
            let available = self.reader.fill_buf()?;
            if available.is_empty() {
                return Ok(!line.is_empty());
            }
            let start = usize::from(std::mem::take(&mut self.after_cr) && available[0] == b'\n');
            match available[start..]
                .iter()
                .position(|&b| b == b'\n' || b == b'\r')
            {
                Some(at) => {
                    line.extend_from_slice(&available[start..start + at]);
                    self.after_cr = available[start + at] == b'\r';
                    self.reader.consume(start + at + 1);
                    return Ok(true);
                }
                None => {
                    let used = available.len();
                    line.extend_from_slice(&available[start..]);
                    self.reader.consume(used);
                    if line.len() > MAX_MESSAGE_BYTES {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            "event line over the size limit",
                        ));
                    }
                }
            }
        }
    }
}

/// Read a server-sent event stream, handing each event's type and data to
/// `on_event` until it returns false, the stream ends, or an event is
/// longer than [`MAX_MESSAGE_BYTES`].
fn read_events(reader: impl Read, mut on_event: impl FnMut(&str, &str) -> bool) {
    let mut lines = EventLines {
        reader: std::io::BufReader::new(reader),
        after_cr: false,
    };
    let mut event = String::new();
    let mut data = String::new();
    let mut has_data = false;
    let mut line = Vec::new();
    loop {
        match lines.next(&mut line) {
            Ok(true) => {}
            Ok(false) => return,
            Err(_) => {
                eprintln!(
                    "innerwarden proxy: the remote MCP server sent an event over the size limit"
                );
                return;
            }
        }
        let text = String::from_utf8_lossy(&line);
        if text.is_empty() {
            if has_data && !on_event(&event, &data) {
                return;
            }
            event.clear();
            data.clear();
            has_data = false;
            continue;
        }
        if text.starts_with(':') {
            continue;
        }
        let (field, value) = match text.split_once(':') {
            Some((field, value)) => (field, value.strip_prefix(' ').unwrap_or(value)),
            None => (&*text, ""),
        };
        match field {
            "event" => event = value.to_string(),
            "data" => {
                if has_data {
                    data.push('\n');
                }
                data.push_str(value);
                has_data = true;
                if data.len() > MAX_MESSAGE_BYTES {
                    eprintln!(
                        "innerwarden proxy: the remote MCP server sent an event over the size limit"
                    );
                    return;
                }
            }
            _ => {}
        }
    }
}

/// `scheme://authority` and the rest of an address.
fn split_origin(url: &str) -> Option<(&str, &str)> {
    let start = url.find("://")? + 3;
    let end = url[start..]
        .find(['/', '?', '#'])
        .map_or(url.len(), |at| start + at);
    Some((&url[..end], &url[end..]))
}

/// Where the older transport's `endpoint` event says to POST, read against
/// the stream's address. An endpoint on another origin is refused: the
/// entry's headers go to the server it names and nowhere else.
fn resolve_endpoint(base: &str, endpoint: &str) -> Option<String> {
    let endpoint = endpoint.trim();
    let (origin, path) = split_origin(base)?;
    if is_remote_url(endpoint) {
        let (other, _) = split_origin(endpoint)?;
        return other
            .eq_ignore_ascii_case(origin)
            .then(|| endpoint.to_string());
    }
    if endpoint.is_empty() || endpoint.starts_with("//") || endpoint.contains("://") {
        return None;
    }
    if endpoint.starts_with('/') {
        return Some(format!("{origin}{endpoint}"));
    }
    let path = path.split(['?', '#']).next().unwrap_or("");
    let dir = path.rsplit_once('/').map_or("", |(dir, _)| dir);
    Some(format!("{origin}{dir}/{endpoint}"))
}

async fn write_line(output: &mut DuplexStream, line: &str) -> std::io::Result<()> {
    output.write_all(line.as_bytes()).await?;
    output.write_all(b"\n").await?;
    output.flush().await
}

async fn bridge(
    spec: RemoteSpec,
    mut output: DuplexStream,
    tx: Sender<Up>,
    mut rx: Receiver<Up>,
    mut input: UnboundedReceiver<Input>,
) {
    let shared = Arc::new(Shared::new(&spec));
    let mut legacy = spec.legacy_sse;
    let mut endpoint: Option<String> = None;
    let mut queued: VecDeque<String> = VecDeque::new();
    let mut input_open = true;
    let mut in_flight = 0usize;
    if legacy {
        open_legacy_stream(Arc::clone(&shared), tx.clone());
    }
    loop {
        tokio::select! {
            got = input.recv(), if input_open => match got {
                Some(Input::Line(line)) => match (legacy, &endpoint) {
                    (false, _) => {
                        in_flight += 1;
                        post_streamable(Arc::clone(&shared), line, tx.clone());
                    }
                    (true, Some(at)) => {
                        in_flight += 1;
                        post_legacy(Arc::clone(&shared), at.clone(), line, tx.clone());
                    }
                    (true, None) => queued.push_back(line),
                },
                Some(Input::Closed) | None => input_open = false,
            },
            got = rx.recv() => {
                let Some(up) = got else { break };
                match up {
                    Up::Line(line) => {
                        if write_line(&mut output, &line).await.is_err() {
                            break;
                        }
                    }
                    Up::Done => in_flight = in_flight.saturating_sub(1),
                    Up::Fallback(line) => {
                        if !legacy {
                            legacy = true;
                            open_legacy_stream(Arc::clone(&shared), tx.clone());
                        }
                        queued.push_back(line);
                    }
                    Up::Endpoint(at) => {
                        while let Some(line) = queued.pop_front() {
                            in_flight += 1;
                            post_legacy(Arc::clone(&shared), at.clone(), line, tx.clone());
                        }
                        endpoint = Some(at);
                    }
                    Up::StreamEnded => {
                        if legacy {
                            for line in queued.drain(..) {
                                let why = "the remote MCP server's stream closed";
                                for reply in Sent::of(&line).error_lines(why) {
                                    let _ = write_line(&mut output, &reply).await;
                                }
                            }
                            break;
                        }
                    }
                }
            }
        }
        if !input_open && in_flight == 0 && queued.is_empty() {
            break;
        }
    }
    if !legacy {
        end_session(&shared);
    }
}

/// Send one line as a Streamable HTTP POST, on a thread of its own: an
/// answer that streams for a long time holds no other request back.
fn post_streamable(shared: Arc<Shared>, line: String, tx: Sender<Up>) {
    std::thread::spawn(move || {
        let sent = Sent::of(&line);
        match shared.post(&shared.url, &line) {
            Err(error) => sent.fail(&tx, &unreachable(&shared, &error)),
            Ok(response) => {
                let status = response.status().as_u16();
                if let Some(session) = header(&response, "mcp-session-id") {
                    if let Ok(mut slot) = shared.session.lock() {
                        *slot = Some(session);
                    }
                }
                if matches!(status, 400 | 404 | 405)
                    && sent.method.as_deref() == Some("initialize")
                    && shared.session().is_none()
                {
                    let _ = tx.blocking_send(Up::Fallback(line));
                    let _ = tx.blocking_send(Up::Done);
                    return;
                }
                if (200..300).contains(&status) {
                    let initialize = sent.method.as_deref() == Some("initialize");
                    let forward = |message: &str| {
                        let line = one_line(message);
                        if line.is_empty() {
                            return true;
                        }
                        if initialize {
                            record_protocol(&shared, &line);
                        }
                        tx.blocking_send(Up::Line(line)).is_ok()
                    };
                    let streams = is_event_stream(&response);
                    let body = response.into_body();
                    if streams {
                        read_events(body.into_reader(), |event, data| {
                            !matches!(event, "" | "message") || forward(data)
                        });
                    } else if status != 202 && status != 204 {
                        let mut text = String::new();
                        let read = body
                            .into_reader()
                            .take(MAX_MESSAGE_BYTES as u64 + 1)
                            .read_to_string(&mut text);
                        if read.is_err() || text.len() > MAX_MESSAGE_BYTES {
                            sent.fail(
                                &tx,
                                "the remote MCP server's answer could not be read whole",
                            );
                        } else {
                            forward(&text);
                        }
                    }
                    if sent.method.as_deref() == Some("notifications/initialized") {
                        listen(Arc::clone(&shared), tx.clone());
                    }
                } else {
                    sent.fail(&tx, &status_failure(status));
                }
            }
        }
        let _ = tx.blocking_send(Up::Done);
    });
}

/// Keep the protocol version the server chose, to send it back.
fn record_protocol(shared: &Shared, line: &str) {
    let version = serde_json::from_str::<Value>(line).ok().and_then(|value| {
        value
            .pointer("/result/protocolVersion")
            .and_then(Value::as_str)
            .map(str::to_string)
    });
    if let (Some(version), Ok(mut slot)) = (version, shared.protocol.lock()) {
        *slot = Some(version);
    }
}

/// Open the server's own stream (Streamable HTTP), once: what the server
/// sends there (a notification, a request of its own) comes back through
/// the loop like any answer. A server with none (405) is fine.
fn listen(shared: Arc<Shared>, tx: Sender<Up>) {
    if shared.listening.swap(true, Ordering::SeqCst) {
        return;
    }
    std::thread::spawn(move || {
        let Ok(response) = shared.open_stream() else {
            return;
        };
        if response.status().as_u16() != 200 || !is_event_stream(&response) {
            return;
        }
        read_events(response.into_body().into_reader(), |event, data| {
            if !matches!(event, "" | "message") {
                return true;
            }
            let line = one_line(data);
            line.is_empty() || tx.blocking_send(Up::Line(line)).is_ok()
        });
    });
}

/// Open the older transport's stream: its `endpoint` event, then every
/// message the server sends.
fn open_legacy_stream(shared: Arc<Shared>, tx: Sender<Up>) {
    std::thread::spawn(move || {
        match shared.open_stream() {
            Err(error) => {
                eprintln!("innerwarden proxy: {}", unreachable(&shared, &error))
            }
            Ok(response) => {
                let status = response.status().as_u16();
                if status != 200 || !is_event_stream(&response) {
                    eprintln!(
                        "innerwarden proxy: the remote MCP server did not open an event stream \
                         (HTTP {status})"
                    );
                } else {
                    read_events(
                        response.into_body().into_reader(),
                        |event, data| match event {
                            "endpoint" => match resolve_endpoint(&shared.url, data) {
                                Some(at) => tx.blocking_send(Up::Endpoint(at)).is_ok(),
                                None => {
                                    eprintln!(
                                    "innerwarden proxy: the remote MCP server named an endpoint \
                                     on another origin; refused"
                                );
                                    false
                                }
                            },
                            "" | "message" => {
                                let line = one_line(data);
                                line.is_empty() || tx.blocking_send(Up::Line(line)).is_ok()
                            }
                            _ => true,
                        },
                    );
                }
            }
        }
        let _ = tx.blocking_send(Up::StreamEnded);
    });
}

/// POST one line to the older transport's endpoint; its answer comes on the
/// stream.
fn post_legacy(shared: Arc<Shared>, at: String, line: String, tx: Sender<Up>) {
    std::thread::spawn(move || {
        let sent = Sent::of(&line);
        match shared.post(&at, &line) {
            Err(error) => sent.fail(&tx, &unreachable(&shared, &error)),
            Ok(response) => {
                let status = response.status().as_u16();
                if !(200..300).contains(&status) {
                    sent.fail(&tx, &status_failure(status));
                }
            }
        }
        let _ = tx.blocking_send(Up::Done);
    });
}

/// End a Streamable HTTP session the server gave an id for, without
/// waiting for its answer.
fn end_session(shared: &Arc<Shared>) {
    if shared.session().is_none() {
        return;
    }
    let shared = Arc::clone(shared);
    std::thread::spawn(move || {
        let _ = shared.decorate(shared.agent.delete(&shared.url)).call();
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A server on this host is told by its address in every form a URL
    /// parser reads as the loopback; another host is not.
    #[test]
    fn a_loopback_address_is_local_in_every_form() {
        for url in [
            "http://127.0.0.1:8931/mcp",
            "http://LOCALHOST/mcp",
            "https://api.localhost./mcp",
            "http://127.1/mcp",
            "http://2130706433/mcp",
            "http://0x7f.0.0.1/mcp",
            "http://0177.0.0.1/mcp",
            "http://127.200.3.4:80",
            "http://0.0.0.0:9000/",
            "http://0/",
            "http://[::1]:8080/mcp",
            "http://[::]/mcp",
            "http://[::ffff:127.0.0.1]/mcp",
            "http://user:pw@127.0.0.1/mcp",
            "http://%31%32%37.0.0.1/mcp",
            "unix:///run/mcp.sock",
            "http+unix://%2Frun%2Fmcp.sock/mcp",
            "ws://127.0.0.1:9/",
            "file:///tmp/x",
        ] {
            assert!(is_local_url(url), "{url}");
        }
        for url in [
            "https://mcp.linear.app/mcp",
            "https://128.0.0.1/mcp",
            "http://10.0.0.5:8080/mcp",
            "https://localhost.example.com/mcp",
            "http://[2001:db8::1]/mcp",
            "https://127.0.0.1.nip.io.example/mcp",
            "https://example.com/?next=http://127.0.0.1/",
            "wss://x.example/mcp",
        ] {
            assert!(!is_local_url(url), "{url}");
        }
    }

    /// Goose's `$VAR` and `${VAR}` are filled as Goose fills them: a name
    /// with no value stays written, a value is not read again (Goose's own
    /// cases, `substitute_env_vars`).
    #[test]
    fn goose_variables_are_filled_as_goose_fills_them() {
        let env = |name: &str| match name {
            "TOKEN" => Some("abc$KEY".to_string()),
            "KEY" => Some("no".to_string()),
            _ => None,
        };
        for (input, want) in [
            ("${TOKEN}", "abc$KEY"),
            ("$TOKEN", "abc$KEY"),
            ("Bearer ${ TOKEN }!", "Bearer abc$KEY!"),
            ("$MISSING and ${MISSING}", "$MISSING and ${MISSING}"),
            ("cost: $5", "cost: $5"),
            ("$", "$"),
        ] {
            assert_eq!(fill_goose_vars(input, &env), want, "{input}");
        }
    }

    /// A Codex token's variable that is not set stops the proxy with a
    /// message naming the variable; a header's variable that is not set
    /// sends no header. A token value is never in a message. FAILS ON
    /// REVERT of `--bearer-env` (the word is refused as unexpected).
    #[test]
    fn a_codex_token_comes_from_its_variable_and_is_never_named() {
        let words = |rest: &[&str]| -> Vec<String> {
            std::iter::once("https://x.example/mcp")
                .chain(rest.iter().copied())
                .map(str::to_string)
                .collect()
        };
        let spec = RemoteSpec::from_cmd(
            &words(&[
                "--bearer-env",
                "TOK",
                "--env-headers",
                "--header-env",
                "X-Org",
                "ORG",
            ]),
            |name| (name == "TOK").then(|| "s3cret".to_string()),
        )
        .unwrap()
        .unwrap();
        assert_eq!(
            spec.headers,
            [("Authorization".to_string(), "Bearer s3cret".to_string())]
        );
        let error = RemoteSpec::from_cmd(&words(&["--bearer-env", "TOK"]), |_| None)
            .unwrap()
            .unwrap_err();
        assert!(
            error.contains("TOK") && error.contains("not set"),
            "{error}"
        );
        let error = RemoteSpec::from_cmd(&words(&["--bearer-env", "TOK"]), |_| {
            Some("s3cret\nX: y".to_string())
        })
        .unwrap()
        .unwrap_err();
        assert!(!error.contains("s3cret"), "{error}");
    }

    /// Goose's headers are read from Goose's configuration under HOME, for
    /// the extension the wrapper names, filled from the environment.
    #[test]
    fn goose_headers_are_read_where_goose_keeps_them() {
        let config = "extensions:\n  r:\n    type: stdio\n    headers:\n      Authorization: Bearer ${T}\n      X-Team: blue\n  bare:\n    type: stdio\n";
        let words: Vec<String> = ["https://x.example/mcp", "--goose-headers", "r"]
            .map(str::to_string)
            .to_vec();
        let env = |name: &str| match name {
            "HOME" => Some("/home/u".to_string()),
            "T" => Some("tok".to_string()),
            _ => None,
        };
        let read = |path: &std::path::Path| {
            (path == std::path::Path::new("/home/u/.config/goose/config.yaml"))
                .then(|| config.to_string())
        };
        let spec = RemoteSpec::from_cmd_reading(&words, env, read)
            .unwrap()
            .unwrap();
        assert_eq!(
            spec.headers,
            [
                ("Authorization".to_string(), "Bearer tok".to_string()),
                ("X-Team".to_string(), "blue".to_string())
            ]
        );
        let none = ["https://x.example/mcp", "--goose-headers", "bare"].map(str::to_string);
        let spec = RemoteSpec::from_cmd_reading(&none, env, read)
            .unwrap()
            .unwrap();
        assert!(spec.headers.is_empty());
        let gone = ["https://x.example/mcp", "--goose-headers", "gone"].map(str::to_string);
        assert!(RemoteSpec::from_cmd_reading(&gone, env, read)
            .unwrap()
            .is_err());
    }

    /// The path the proxy reads is the one connect wires.
    #[test]
    fn the_goose_config_is_the_one_connect_wires() {
        let goose = crate::agents::KNOWN
            .iter()
            .find(|k| k.name == "goose")
            .unwrap();
        assert_eq!(goose.mcp_yaml, Some(GOOSE_CONFIG));
    }

    fn cmd(words: &[&str]) -> Vec<String> {
        words.iter().map(|w| w.to_string()).collect()
    }

    #[test]
    fn an_address_is_remote_and_a_program_is_not() {
        assert!(is_remote_url("https://mcp.example.com/mcp"));
        assert!(is_remote_url("HTTP://127.0.0.1:8080/sse"));
        for word in [
            "npx",
            "/usr/bin/node",
            "https://",
            "https:///x",
            "https://a b",
            "ftp://x",
        ] {
            assert!(!is_remote_url(word), "{word}");
        }
        assert_eq!(
            RemoteSpec::from_cmd(&cmd(&["node", "server.js"]), |_| None),
            None
        );
    }

    #[test]
    fn the_wrapper_words_and_headers_are_read() {
        let env = |name: &str| match name {
            "INNERWARDEN_MCP_HEADER_1" => Some("Authorization: Bearer abc".to_string()),
            "INNERWARDEN_MCP_HEADER_2" => Some("X-Team:  blue ".to_string()),
            _ => None,
        };
        let spec = RemoteSpec::from_cmd(
            &cmd(&[
                "https://x.example/sse",
                "--key",
                "serverUrl",
                "--type",
                "sse",
            ]),
            env,
        )
        .unwrap()
        .unwrap();
        assert!(spec.legacy_sse);
        assert_eq!(
            spec.headers,
            vec![
                ("Authorization".to_string(), "Bearer abc".to_string()),
                ("X-Team".to_string(), "blue".to_string())
            ]
        );
        let plain =
            RemoteSpec::from_cmd(&cmd(&["https://x.example/mcp", "--type", "http"]), |_| None)
                .unwrap()
                .unwrap();
        assert!(!plain.legacy_sse);
        assert!(plain.headers.is_empty());
        assert!(
            RemoteSpec::from_cmd(&cmd(&["https://x.example/mcp", "--verbose"]), |_| None)
                .unwrap()
                .is_err()
        );
        assert!(
            RemoteSpec::from_cmd(&cmd(&["https://x.example/mcp", "--key"]), |_| None)
                .unwrap()
                .is_err()
        );
        let bad = |name: &str| (name == "INNERWARDEN_MCP_HEADER_1").then(|| "no colon".to_string());
        assert!(RemoteSpec::from_cmd(&cmd(&["https://x.example/mcp"]), bad)
            .unwrap()
            .is_err());
    }

    /// The entry's headers go with every request, and a redirect is not
    /// followed: the client gets an error that says so.
    #[test]
    fn headers_are_sent_and_a_redirect_is_not_followed() {
        use std::io::Write;
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}/mcp", listener.local_addr().unwrap());
        let seen = Arc::new(Mutex::new(Vec::<String>::new()));
        let log = Arc::clone(&seen);
        std::thread::spawn(move || {
            for (n, stream) in listener.incoming().flatten().enumerate() {
                let mut writer = stream.try_clone().unwrap();
                let mut reader = std::io::BufReader::new(stream);
                let mut head = String::new();
                loop {
                    let mut line = String::new();
                    if reader.read_line(&mut line).unwrap_or(0) == 0 || line == "\r\n" {
                        break;
                    }
                    head.push_str(&line);
                }
                log.lock().unwrap().push(head);
                let answer = if n == 0 {
                    "HTTP/1.1 307 Temporary Redirect\r\nLocation: http://evil.invalid/\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_string()
                } else {
                    let body = r#"{"jsonrpc":"2.0","id":2,"result":{}}"#;
                    format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len())
                };
                let _ = writer.write_all(answer.as_bytes());
            }
        });
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async move {
            let mut remote = Remote::start(RemoteSpec {
                url,
                legacy_sse: false,
                headers: vec![("Authorization".into(), "Bearer t0k".into())],
            });
            let mut input = remote.input.take().unwrap();
            let mut lines = tokio::io::BufReader::new(remote.output.take().unwrap()).lines();
            input
                .write_all(b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\"}\n")
                .await
                .unwrap();
            let first = lines.next_line().await.unwrap().unwrap();
            assert!(
                first.contains("\"id\":1") && first.contains("redirect"),
                "{first}"
            );
            input
                .write_all(b"{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/list\"}\n")
                .await
                .unwrap();
            let second = lines.next_line().await.unwrap().unwrap();
            assert_eq!(second, r#"{"jsonrpc":"2.0","id":2,"result":{}}"#);
        });
        let seen = seen.lock().unwrap();
        assert_eq!(seen.len(), 2, "the redirect was not followed");
        for head in seen.iter() {
            assert!(
                head.to_ascii_lowercase()
                    .contains("authorization: bearer t0k"),
                "{head}"
            );
        }
    }

    /// A server that streams without end, in front of a client that does not
    /// read, is held back: what the bridge keeps is bounded (the queue of
    /// [`SERVER_QUEUE`] messages and the pipe), so the server's writes stall
    /// long before it has sent everything. With an unbounded queue all 40 MB
    /// were taken in at once.
    #[test]
    fn a_server_that_streams_without_end_is_held_back() {
        use std::io::{BufRead, Read, Write};
        use std::sync::atomic::AtomicUsize;
        use tokio::io::AsyncWriteExt;
        const EVENTS: usize = 10_000;
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}/mcp", listener.local_addr().unwrap());
        let sent = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&sent);
        std::thread::spawn(move || {
            let Ok((stream, _)) = listener.accept() else {
                return;
            };
            let mut writer = stream.try_clone().unwrap();
            let mut reader = std::io::BufReader::new(stream);
            let mut length = 0usize;
            loop {
                let mut line = String::new();
                if reader.read_line(&mut line).unwrap_or(0) == 0 || line == "\r\n" {
                    break;
                }
                if let Some(value) = line.to_ascii_lowercase().strip_prefix("content-length:") {
                    length = value.trim().parse().unwrap_or(0);
                }
            }
            let mut body = vec![0u8; length];
            let _ = reader.read_exact(&mut body);
            let _ = writer.write_all(
                b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nConnection: close\r\n\r\n",
            );
            let text = "x".repeat(4000);
            let event = format!(
                "data: {{\"jsonrpc\":\"2.0\",\"method\":\"notifications/message\",\"params\":{{\"t\":\"{text}\"}}}}\n\n"
            );
            for _ in 0..EVENTS {
                if writer.write_all(event.as_bytes()).is_err() {
                    return;
                }
                counter.fetch_add(event.len(), Ordering::SeqCst);
            }
        });
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async move {
            let mut remote = Remote::start(RemoteSpec {
                url,
                legacy_sse: false,
                headers: Vec::new(),
            });
            let mut input = remote.input.take().unwrap();
            let _output = remote.output.take().unwrap();
            input
                .write_all(
                    b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{}}\n",
                )
                .await
                .unwrap();
            tokio::time::sleep(Duration::from_secs(3)).await;
        });
        // Each event is a little over 4000 bytes.
        let total = EVENTS * 4000;
        let taken = sent.load(Ordering::SeqCst);
        assert!(
            taken < total / 2,
            "the server sent {taken} of {total} bytes to a client that reads nothing"
        );
    }

    /// An address in an error is cut to its host: its path and query may
    /// carry a token, and so may a user part.
    #[test]
    fn an_error_names_only_the_host() {
        assert_eq!(
            scrub("bad uri: https://u:p@mcp.example.com/v1/sse?token=abc failed"),
            "bad uri: https://mcp.example.com failed"
        );
        assert_eq!(scrub("Uri(\"http://h:9/x?k=1\")"), "Uri(\"http://h:9");
        assert_eq!(
            host_of("https://mcp.example.com/mcp?key=s"),
            "https://mcp.example.com"
        );
    }

    /// Every request of a batch the server could not answer gets its error;
    /// notifications get none.
    #[test]
    fn each_request_of_a_failed_batch_is_answered() {
        let batch = r#"[{"jsonrpc":"2.0","id":1,"method":"tools/list"},{"jsonrpc":"2.0","method":"notifications/x"},{"jsonrpc":"2.0","id":"b","method":"ping"}]"#;
        let lines = Sent::of(batch).error_lines("down");
        assert_eq!(lines.len(), 2);
        assert!(lines[0].contains("\"id\":1") && lines[1].contains("\"id\":\"b\""));
        assert!(
            Sent::of(r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#)
                .error_lines("down")
                .is_empty()
        );
        // A response the client sends (no method) is not a request.
        assert!(Sent::of(r#"{"jsonrpc":"2.0","id":3,"result":{}}"#)
            .error_lines("down")
            .is_empty());
    }

    /// A user part (`user:token@`) never reaches a message: not stderr, not
    /// the error the client gets.
    #[test]
    fn a_user_part_of_the_address_is_never_named() {
        assert_eq!(
            host_of("https://user:tok@mcp.example.com:8443/mcp"),
            "https://mcp.example.com:8443"
        );
        assert_eq!(host_of("http://a@b@h/x"), "http://h");
        let sent = Sent::of(r#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#);
        let why = format!(
            "{} could not be reached: refused",
            host_of("https://user:tok@h.example/mcp")
        );
        let lines = sent.error_lines(&why);
        assert!(
            lines[0].contains("https://h.example") && !lines[0].contains("tok"),
            "{}",
            lines[0]
        );
    }

    #[test]
    fn an_endpoint_stays_on_the_server_it_came_from() {
        let base = "https://mcp.example.com/v1/sse?x=1";
        assert_eq!(
            resolve_endpoint(base, "/messages?session=1").as_deref(),
            Some("https://mcp.example.com/messages?session=1")
        );
        assert_eq!(
            resolve_endpoint(base, "messages?s=2").as_deref(),
            Some("https://mcp.example.com/v1/messages?s=2")
        );
        assert_eq!(
            resolve_endpoint(base, "https://MCP.example.com/m").as_deref(),
            Some("https://MCP.example.com/m")
        );
        for other in [
            "https://evil.example/m",
            "//evil.example/m",
            "http://mcp.example.com/m",
            "",
        ] {
            assert_eq!(resolve_endpoint(base, other), None, "{other}");
        }
    }

    #[test]
    fn events_are_read_as_the_stream_sends_them() {
        let stream = b": ping\r\n\r\nevent: endpoint\ndata: /m\n\ndata: {\"a\":\ndata: 1}\n\nevent: other\ndata: x\n\ndata: cut";
        let mut seen = Vec::new();
        read_events(&stream[..], |event, data| {
            seen.push((event.to_string(), data.to_string()));
            true
        });
        assert_eq!(
            seen,
            vec![
                ("endpoint".to_string(), "/m".to_string()),
                (String::new(), "{\"a\":\n1}".to_string()),
                ("other".to_string(), "x".to_string()),
            ]
        );
        assert_eq!(one_line("{\"a\":\r\n 1}\n"), "{\"a\":   1}");
        // A stream whose lines end with \r alone, or \r\n cut between reads.
        let mut seen = Vec::new();
        read_events(
            &b"event: endpoint\rdata: /m\r\rdata: x\r\r"[..],
            |event, data| {
                seen.push((event.to_string(), data.to_string()));
                true
            },
        );
        read_events(
            std::io::Read::chain(&b"data: a\r"[..], &b"\n\r\n"[..]),
            |event, data| {
                seen.push((event.to_string(), data.to_string()));
                true
            },
        );
        assert_eq!(
            seen,
            vec![
                ("endpoint".to_string(), "/m".to_string()),
                (String::new(), "x".to_string()),
                (String::new(), "a".to_string()),
            ]
        );
    }
}
