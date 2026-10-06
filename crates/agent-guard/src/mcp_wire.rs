//! Guard a reviewed JSON MCP configuration (currently Cursor and Gemini) by
//! rewriting its stdio server entries so they run THROUGH `innerwarden proxy`
//! instead of directly. The proxy pumps the real server's
//! stdio transparently and screens tool calls with the same engine as `check`;
//! monitor mode records findings, while enforcement can block a dangerous call
//! before it reaches the server. Fully reversible (`unwrap`) and idempotent.
//!
//! This is the honest cross-agent mechanism: Claude Code gets a native pre-exec
//! hook (its shell), while supported JSON MCP clients are guarded here. A
//! remote (`url`) MCP server has no local command to wrap, so it is left alone.
//!
//! Two schema keys are handled: `mcpServers` (Cursor/Gemini and compatible
//! clients) and `servers` (VS Code style). All logic here is pure/tested.
//!
//! Every wrapper names the agent whose configuration it is in
//! (`--label <agent> --agent <agent>`), so the decisions its proxy records say
//! which agent asked instead of all landing in one `mcp:innerwarden` session
//! that names nobody. See [`naming`].

use serde_json::{json, Value};

use crate::hook::is_agent_id;

/// The basename of a command path, cross-platform (`/` and `\`), lowercased,
/// without a Windows `.exe`.
fn basename(cmd: &str) -> String {
    let name = cmd
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or(cmd)
        .to_ascii_lowercase();
    match name.strip_suffix(".exe") {
        Some(stem) => stem.to_string(),
        None => name,
    }
}

/// Effective enforcement of MCP servers wired through the local proxy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WiringMode {
    Monitor,
    Enforce,
    Mixed,
}

/// The names the guard's binary is installed under: the binary itself and
/// the installer's `iw` and `iw-guard` shortcuts.
const GUARD_COMMAND_NAMES: &[&str] = &["innerwarden", "iw", "iw-guard"];

/// Whether a wrapper's command names the guard's binary: its file name is one
/// of [`GUARD_COMMAND_NAMES`], in any directory, with or without `.exe`.
///
/// Exactly those names. Any program whose name merely began with
/// `innerwarden` used to count, so a script the agent's own account wrote as
/// `innerwarden-shim`, given `proxy --mode guard -- <server>`, was listed as
/// the guard in enforce mode while it ran the server unscreened. A command
/// under another name is a server like any other: listed as not guarded, and
/// wrapped by the real proxy when the agent is connected.
///
/// The configuration is read, the binary is not run: a program written under
/// one of these names is still taken for the guard.
pub(crate) fn is_guard_command(command: &str) -> bool {
    GUARD_COMMAND_NAMES.contains(&basename(command).as_str())
}

fn has_proxy_prefix(server: &Value) -> bool {
    let is_guard = server
        .get("command")
        .and_then(|c| c.as_str())
        .is_some_and(is_guard_command);
    if !is_guard {
        return false;
    }
    server
        .get("args")
        .and_then(Value::as_array)
        .and_then(|args| args.first())
        .and_then(Value::as_str)
        == Some("proxy")
}

/// Locate the proxy's `--` separator when this is one of our wrappers. Supports
/// both the legacy `proxy --` layout and the explicit `proxy --mode M --` layout.
fn wrapper_separator(server: &Value) -> Option<usize> {
    if !has_proxy_prefix(server) {
        return None;
    }
    let args = server.get("args")?.as_array()?;
    args.iter().position(|v| v.as_str() == Some("--"))
}

/// The mode this server's proxy runs in, read from its own wrapper the way
/// `innerwarden proxy` reads it ([`wrapper_blocks`]); `None` for a server that
/// is not a complete wrapper.
fn server_mode(server: &Value) -> Option<WiringMode> {
    let separator = wrapper_separator(server)?;
    let args = server.get("args")?.as_array()?;
    if args
        .get(separator + 1)
        .and_then(Value::as_str)
        .is_none_or(|command| command.trim().is_empty())
    {
        return None;
    }
    let options: Vec<Option<&str>> = args[1..separator].iter().map(Value::as_str).collect();
    Some(if wrapper_blocks(&options)? {
        WiringMode::Enforce
    } else {
        WiringMode::Monitor
    })
}

/// Whether `innerwarden proxy`, started with these options (the words between
/// `proxy` and the wrapper's `--`), refuses what the guard denies:
/// `Some(true)` for `guard` and `kill`, `Some(false)` for `advisory` and
/// `warn`, which only record.
///
/// No `--mode` at all is `Some(true)`: legacy Community wrappers were written
/// as `proxy -- <child>`, and the proxy's default is `guard`.
///
/// The options are read as the proxy reads them ([`OptionWalk`]), never by
/// looking for a word: `--label --mode=guard` is a label, and the proxy runs
/// the mode given before it.
///
/// `None` when the proxy does not run these options as they look:
/// * a word that is not a string, or a `--mode` value the proxy refuses;
/// * a word the proxy does not take as an option (`--verbose`, an empty
///   word): it exits on it, so the server never starts and nothing is
///   screened;
/// * a flag that takes a value standing last, so the proxy takes the `--` for
///   that value and reads the words after it as more options. In
///   `--mode guard --label -- --mode advisory -- <child>` the proxy runs
///   `advisory`, while the words in front of the first `--` say `guard`.
pub(crate) fn wrapper_blocks(options: &[Option<&str>]) -> Option<bool> {
    if options.iter().any(Option::is_none) {
        return None;
    }
    let walk = walk_options(options);
    if walk.takes_the_separator || walk.refused_word {
        return None;
    }
    match walk.mode {
        None | Some(Some("guard" | "kill")) => Some(true),
        Some(Some("advisory" | "warn")) => Some(false),
        Some(_) => None,
    }
}

/// True when a server entry is already routed through the guard proxy: its
/// command is the guard binary and its args contain the proxy command separator.
fn is_wrapped_server(server: &Value) -> bool {
    server_mode(server).is_some()
}

fn proxy_prefix_without_mode(args: &[Value], separator: usize) -> Vec<Value> {
    let mut prefix = Vec::with_capacity(separator + 2);
    prefix.push(json!("proxy"));
    let mut i = 1usize;
    while i < separator {
        let is_mode = args[i].as_str() == Some("--mode");
        let is_inline_mode = args[i]
            .as_str()
            .is_some_and(|arg| arg.starts_with("--mode="));
        if is_mode {
            i = (i + 2).min(separator);
        } else if is_inline_mode {
            i += 1;
        } else {
            prefix.push(args[i].clone());
            i += 1;
        }
    }
    prefix
}

/// A name wiring writes into a wrapper: a plain agent id ([`is_agent_id`])
/// that does not start with `-`. A generic MCP client is named after its
/// configuration directory, and a directory called `--mode` would otherwise
/// put a word on the proxy's command line that this module's own readers take
/// for a flag.
pub(crate) fn is_wrapper_name(agent: &str) -> bool {
    is_agent_id(agent) && !agent.starts_with('-')
}

/// What wiring changes in a wrapper's proxy options so that they name `agent`.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct Naming {
    /// Positions (in the options) of every `--agent` word and its value, to
    /// drop because they are replaced by `add`.
    pub(crate) drop: Vec<usize>,
    /// Words to append to the options.
    pub(crate) add: Vec<String>,
}

/// A wrapper's proxy options (the words between `proxy` and its `--`), read
/// the way `innerwarden proxy` reads them: `--mode`, `--label` and `--agent`
/// each take the next word as their value, an inline `--flag=value` takes
/// none, and the last `--mode` and the last `--agent` win.
struct OptionWalk<'a> {
    labelled: bool,
    /// The value of the last `--agent`, `Some(None)` for one with no value.
    agent: Option<Option<&'a str>>,
    agent_flags: usize,
    /// Positions of every `--agent` word and its value.
    agent_words: Vec<usize>,
    /// The value of the last `--mode`, `Some(None)` for one with no value.
    mode: Option<Option<&'a str>>,
    /// The last option is a flag that takes a value, so the proxy takes the
    /// wrapper's `--` as that value.
    takes_the_separator: bool,
    /// A word the proxy does not take as an option. It exits on it.
    refused_word: bool,
}

fn walk_options<'a>(options: &[Option<&'a str>]) -> OptionWalk<'a> {
    let mut walk = OptionWalk {
        labelled: false,
        agent: None,
        agent_flags: 0,
        agent_words: Vec::new(),
        mode: None,
        takes_the_separator: false,
        refused_word: false,
    };
    let mut i = 0usize;
    while i < options.len() {
        let last = i + 1 == options.len();
        match options[i] {
            Some("--label") => {
                walk.labelled = true;
                walk.takes_the_separator |= last;
                i += 2;
            }
            Some("--mode") => {
                walk.mode = Some(options.get(i + 1).copied().flatten());
                walk.takes_the_separator |= last;
                i += 2;
            }
            Some("--agent") => {
                walk.agent = Some(options.get(i + 1).copied().flatten());
                walk.agent_flags += 1;
                walk.agent_words.push(i);
                if i + 1 < options.len() {
                    walk.agent_words.push(i + 1);
                }
                walk.takes_the_separator |= last;
                i += 2;
            }
            Some(word) if word.starts_with("--mode=") => {
                walk.mode = Some(Some(&word["--mode=".len()..]));
                i += 1;
            }
            Some(word) if word.starts_with("--label=") => {
                walk.labelled = true;
                i += 1;
            }
            Some(word) if word.starts_with("--agent=") => {
                walk.agent = Some(Some(&word["--agent=".len()..]));
                walk.agent_flags += 1;
                walk.agent_words.push(i);
                i += 1;
            }
            Some("--error-response") => i += 1,
            _ => {
                walk.refused_word = true;
                i += 1;
            }
        }
    }
    walk
}

/// The agent `innerwarden proxy` records for a wrapper with these options:
/// the last `--agent`, and none when its value is not a plain agent id.
pub(crate) fn proxy_agent<'a>(options: &[Option<&'a str>]) -> Option<&'a str> {
    walk_options(options)
        .agent
        .flatten()
        .filter(|agent| is_agent_id(agent))
}

/// How a wrapper's proxy options (the words between `proxy` and its `--`)
/// change to name `agent`, the agent whose configuration the wrapper is in.
/// The options are read as the proxy reads them (see [`OptionWalk`]).
///
/// * `--label <agent>` is added only when no label is set. The label names the
///   proxy's session (`mcp:<label>`); a label an operator chose is theirs and
///   is kept.
/// * `--agent <agent>` is added unless the options already name exactly this
///   agent. Every other `--agent` is dropped for it: one without a value or
///   with a value that is not a plain agent id is ignored by the proxy, and
///   another agent's name in this agent's configuration would attribute this
///   agent's calls to that one. Connecting an agent is the statement of whose
///   servers these are.
/// * Nothing changes when `agent` is not a name [`is_wrapper_name`] accepts:
///   such a name is left out, never quoted in.
///
/// The name is DECLARED, not proven: the configuration is a file the agent's
/// own account can edit, so a reader of the record must not treat it as more.
pub(crate) fn naming(options: &[Option<&str>], agent: Option<&str>) -> Naming {
    let Some(agent) = agent.filter(|agent| is_wrapper_name(agent)) else {
        return Naming::default();
    };
    let walk = walk_options(options);
    let mut out = Naming::default();
    if !walk.labelled {
        out.add.extend(["--label".to_string(), agent.to_string()]);
    }
    if walk.agent != Some(Some(agent)) || walk.agent_flags > 1 {
        out.drop = walk.agent_words;
        out.add.extend(["--agent".to_string(), agent.to_string()]);
    }
    out
}

/// A stdio server is one we can wrap: it has a local `command` (not a remote
/// `url`-only server).
fn is_stdio_server(server: &Value) -> bool {
    server
        .get("command")
        .and_then(|c| c.as_str())
        .map(|c| !c.trim().is_empty())
        .unwrap_or(false)
}

fn wrap_server(server: &mut Value, guard_bin: &str, monitor: bool, agent: Option<&str>) -> bool {
    if !is_stdio_server(server) {
        return false;
    }
    let current_command = server
        .get("command")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    let current_args = server
        .get("args")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let separator = wrapper_separator(server);
    if separator.is_none() && has_proxy_prefix(server) {
        // An InnerWarden proxy without `-- <child>` is irrecoverably incomplete.
        // Never wrap that broken proxy as though it were the original server.
        return false;
    }
    let (orig_cmd, orig_args, proxy_prefix) = if let Some(separator) = separator {
        if current_args.len() <= separator + 1 {
            return false;
        }
        (
            current_args[separator + 1]
                .as_str()
                .unwrap_or_default()
                .to_string(),
            current_args[separator + 2..].to_vec(),
            proxy_prefix_without_mode(&current_args, separator),
        )
    } else {
        (
            current_command.clone(),
            current_args.clone(),
            vec![json!("proxy")],
        )
    };
    if orig_cmd.is_empty() {
        return false;
    }
    // `proxy_prefix[0]` is `proxy`; the options follow it.
    let options: Vec<Option<&str>> = proxy_prefix[1..].iter().map(Value::as_str).collect();
    let naming = naming(&options, agent);
    let mut new_args: Vec<Value> = proxy_prefix
        .iter()
        .enumerate()
        .filter(|(i, _)| *i == 0 || !naming.drop.contains(&(i - 1)))
        .map(|(_, arg)| arg.clone())
        .collect();
    new_args.extend(naming.add.into_iter().map(Value::String));
    let mode = if monitor { "advisory" } else { "guard" };
    new_args.extend([json!("--mode"), json!(mode), json!("--"), json!(orig_cmd)]);
    new_args.extend(orig_args);
    if current_command == guard_bin && current_args == new_args {
        return false;
    }
    let Some(obj) = server.as_object_mut() else {
        return false;
    };
    obj.insert("command".into(), json!(guard_bin));
    obj.insert("args".into(), json!(new_args));
    true
}

fn unwrap_server(server: &mut Value) -> bool {
    let Some(separator) = wrapper_separator(server) else {
        return false;
    };
    let Some(obj) = server.as_object_mut() else {
        return false;
    };
    let args = obj
        .get("args")
        .and_then(|a| a.as_array())
        .cloned()
        .unwrap_or_default();
    if args.len() <= separator + 1 {
        return false;
    }
    let orig_cmd = args[separator + 1].as_str().unwrap_or_default().to_string();
    let orig_args: Vec<Value> = args[separator + 2..].to_vec();
    obj.insert("command".into(), json!(orig_cmd));
    obj.insert("args".into(), json!(orig_args));
    true
}

/// Where a server table can live, as a path from the config root.
///
/// It used to be two top-level keys. OpenClaw nests its table under
/// `mcp.servers`, so the locator is a PATH rather than a key: the wiring logic
/// is identical once the table is found, and hardcoding depth-1 was the only
/// thing keeping a whole agent unguardable.
const SERVER_TABLE_PATHS: &[&[&str]] = &[&["mcpServers"], &["servers"], &["mcp", "servers"]];

/// Resolve a path to a server table, read-only.
fn table_at<'a>(root: &'a Value, path: &[&str]) -> Option<&'a serde_json::Map<String, Value>> {
    let mut node = root;
    for key in path {
        node = node.get(key)?;
    }
    node.as_object()
}

/// Resolve a path to a server table for mutation. Never CREATES intermediate
/// nodes: wiring must only ever touch a table the user already has.
fn table_at_mut<'a>(
    root: &'a mut Value,
    path: &[&str],
) -> Option<&'a mut serde_json::Map<String, Value>> {
    let mut node = root;
    for key in path {
        node = node.get_mut(key)?;
    }
    node.as_object_mut()
}

/// Apply `f` to every server object under either schema key. Returns how many
/// times `f` returned true.
fn for_each_server(root: &mut Value, mut f: impl FnMut(&mut Value) -> bool) -> usize {
    let mut n = 0;
    for path in SERVER_TABLE_PATHS {
        if let Some(map) = table_at_mut(root, path) {
            for (_name, server) in map.iter_mut() {
                if f(server) {
                    n += 1;
                }
            }
        }
    }
    n
}

/// Count (stdio servers, of those already wrapped) across both schema keys.
fn counts(root: &Value) -> (usize, usize) {
    let mut stdio = 0;
    let mut wrapped = 0;
    for path in SERVER_TABLE_PATHS {
        if let Some(map) = table_at(root, path) {
            for (_name, server) in map {
                if is_stdio_server(server) {
                    stdio += 1;
                    if is_wrapped_server(server) {
                        wrapped += 1;
                    }
                }
            }
        }
    }
    (stdio, wrapped)
}

/// Route every stdio MCP server through `guard_bin proxy` in explicit advisory
/// (`monitor=true`) or guard mode, each wrapper naming `agent`, the agent whose
/// configuration this is (see [`naming`]). Existing wrappers are safely
/// reconfigured, so switching modes is idempotent and never nests proxies, and
/// a wrapper written before wrappers named their agent gains the name. Returns
/// the new config and how many server entries changed. Pure.
pub fn wrap(root: Value, guard_bin: &str, monitor: bool, agent: &str) -> (Value, usize) {
    wrap_naming(root, guard_bin, monitor, Some(agent))
}

fn wrap_naming(
    mut root: Value,
    guard_bin: &str,
    monitor: bool,
    agent: Option<&str>,
) -> (Value, usize) {
    let n = for_each_server(&mut root, |s| wrap_server(s, guard_bin, monitor, agent));
    (root, n)
}

/// For wiring whose proxies do not all record `agent`: the mode flag
/// `agents connect <agent>` needs to add the name in the mode the wiring
/// already has (` --monitor`, or nothing for enforce). Run by hand with
/// `guard_bin`, that reconnect then changes the name and nothing else.
///
/// Offered only when some wrapper's proxy records no agent, or another one
/// ([`proxy_agent`]): a wrapper that already records `agent` and only lacks
/// a `--label` has cases that name it, and nothing to tell a person about.
///
/// `None` as well whenever the reconnect would change more than the name: a
/// config not fully guarded (finishing it is a different step), wrappers in
/// different modes (a reconnect would pick one), or a wrapper that runs
/// another program than `guard_bin` or is laid out differently (the reconnect
/// would rewrite that too, and a wrapper pointed at a copy of the CLI that
/// someone else manages must not be moved off it by a step offered as "only
/// adds the name"). Also `None` for an `agent` that [`is_wrapper_name`]
/// refuses, since no name would be written. Pure.
pub fn unnamed_reconnect_flag(root: &Value, guard_bin: &str, agent: &str) -> Option<&'static str> {
    if !is_wrapper_name(agent) || !is_guarded(root) {
        return None;
    }
    let monitor = match guarded_mode(root)? {
        WiringMode::Monitor => true,
        WiringMode::Enforce => false,
        WiringMode::Mixed => return None,
    };
    let unnamed = SERVER_TABLE_PATHS
        .iter()
        .filter_map(|path| table_at(root, path))
        .flat_map(|map| map.values())
        .filter_map(wrapper_options)
        .any(|options| proxy_agent(&options) != Some(agent));
    let (_, beyond_the_name) = wrap_naming(root.clone(), guard_bin, monitor, None);
    (unnamed && beyond_the_name == 0).then_some(if monitor { " --monitor" } else { "" })
}

/// The proxy options of a wrapper (the words between `proxy` and its `--`),
/// or `None` for a server that is not one.
fn wrapper_options(server: &Value) -> Option<Vec<Option<&str>>> {
    let separator = wrapper_separator(server)?;
    let args = server.get("args")?.as_array()?;
    Some(args[1..separator].iter().map(Value::as_str).collect())
}

/// Undo `wrap`: restore each server's original command/args. Returns the config
/// and how many were unwrapped. Pure.
pub fn unwrap(mut root: Value) -> (Value, usize) {
    let n = for_each_server(&mut root, unwrap_server);
    (root, n)
}

/// Is there at least one stdio server that is NOT yet routed through the proxy?
///
/// # Why this is not `!is_guarded` and not `!has_guard_wiring`
///
/// Automatic setup used to be offered only when a config had NO wiring at all
/// (`!has_guard_wiring`). That conflated two different questions: "have we
/// touched this file" and "is there work left to do". A config with three stdio
/// servers where only one is wrapped answers YES to the first, so it was skipped
/// forever, and the other two stayed unguarded with nothing offering to fix it.
///
/// Observed on a real machine (2026-08-05): a Codex config with `icm` wrapped
/// and `node_repl` and `computer-use` open. The dashboard correctly reported
/// `partial`, and eligibility said there was nothing to do. Not protected, and
/// not offered: the worst of both.
///
/// Wrapping is idempotent and never nests proxies, so re-running over a
/// partially wired config only touches what is still open.
pub fn has_unguarded_stdio_server(root: &Value) -> bool {
    let (stdio, wrapped) = counts(root);
    stdio > wrapped
}

/// Whether this config is guarded: it has at least one stdio server and EVERY
/// stdio server is routed through the proxy. (A config with only remote `url`
/// servers, or no servers, is `false`, there is nothing local to guard.) Pure.
pub fn is_guarded(root: &Value) -> bool {
    let (stdio, wrapped) = counts(root);
    stdio > 0 && stdio == wrapped
}

/// Whether at least one server still points at an InnerWarden proxy wrapper,
/// including a legacy or malformed wrapper. Used to repair partial/broken wiring
/// without pretending the entire config is protected.
pub fn has_guard_wiring(root: &Value) -> bool {
    SERVER_TABLE_PATHS
        .iter()
        .any(|path| table_at(root, path).is_some_and(|map| map.values().any(has_proxy_prefix)))
}

/// Effective mode across every guarded stdio server. `None` means there is no
/// fully guarded local server; differing modes are reported as `Mixed`.
pub fn guarded_mode(root: &Value) -> Option<WiringMode> {
    let mut found: Option<WiringMode> = None;
    for path in SERVER_TABLE_PATHS {
        if let Some(map) = table_at(root, path) {
            for server in map
                .values()
                .filter(|server| wrapper_separator(server).is_some())
            {
                let mode = server_mode(server)?;
                found = Some(match found {
                    None => mode,
                    Some(existing) if existing == mode => existing,
                    Some(_) => WiringMode::Mixed,
                });
            }
        }
    }
    found
}

/// Whether this config has anything the guard can wrap (any stdio server). Pure.
pub fn is_guardable(root: &Value) -> bool {
    counts(root).0 > 0
}

/// Strict shape required by background setup. Manual connect remains able to
/// repair permissive legacy configs, but automatic wrapping never normalizes a
/// malformed server entry or drops a non-array/non-string `args` value.
pub fn is_automatic_wrap_safe(root: &Value) -> bool {
    if !root.is_object() {
        return false;
    }
    for path in SERVER_TABLE_PATHS {
        // A missing table is fine; a table that is not an object is not
        // something to rewrite blind.
        let mut node = root;
        let mut missing = false;
        for key in *path {
            match node.get(key) {
                Some(next) => node = next,
                None => {
                    missing = true;
                    break;
                }
            }
        }
        if missing {
            continue;
        }
        let Some(servers) = node.as_object() else {
            return false;
        };
        for server in servers.values() {
            if !server.is_object() {
                return false;
            }
            if is_stdio_server(server)
                && server.get("args").is_some_and(|args| {
                    !args
                        .as_array()
                        .is_some_and(|args| args.iter().all(Value::is_string))
                })
            {
                return false;
            }
        }
    }
    is_guardable(root)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> Value {
        json!({
            "mcpServers": {
                "fs":   { "command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"] },
                "git":  { "command": "uvx", "args": ["mcp-server-git"] },
                "remote": { "url": "https://example.com/sse" }
            }
        })
    }

    #[test]
    fn wrap_routes_stdio_servers_through_the_proxy_and_leaves_remote_alone() {
        let (out, n) = wrap(cfg(), "/abs/innerwarden", false, "cursor");
        assert_eq!(n, 2, "two stdio servers wrapped, the url server skipped");
        let fs = &out["mcpServers"]["fs"];
        assert_eq!(fs["command"], "/abs/innerwarden");
        assert_eq!(
            fs["args"],
            json!([
                "proxy",
                "--label",
                "cursor",
                "--agent",
                "cursor",
                "--mode",
                "guard",
                "--",
                "npx",
                "-y",
                "@modelcontextprotocol/server-filesystem",
                "/tmp"
            ])
        );
        // remote untouched
        assert_eq!(
            out["mcpServers"]["remote"]["url"],
            "https://example.com/sse"
        );
        assert!(is_guarded(&out));
        assert_eq!(guarded_mode(&out), Some(WiringMode::Enforce));
    }

    #[test]
    fn automatic_wrap_rejects_shapes_that_permissive_manual_repair_would_drop() {
        assert!(is_automatic_wrap_safe(&cfg()));
        assert!(is_automatic_wrap_safe(&json!({
            "mcpServers": {"local": {"command": "npx"}}
        })));
        assert!(!is_automatic_wrap_safe(&json!({
            "mcpServers": {"local": {"command": "npx", "args": "--foo"}}
        })));
        assert!(!is_automatic_wrap_safe(&json!({
            "mcpServers": {"local": {"command": "npx", "args": ["ok", 1]}}
        })));
        assert!(!is_automatic_wrap_safe(&json!({"mcpServers": []})));
    }

    #[test]
    fn wrap_is_idempotent() {
        let (once, n1) = wrap(cfg(), "/abs/innerwarden", false, "cursor");
        let (twice, n2) = wrap(once.clone(), "/abs/innerwarden", false, "cursor");
        assert_eq!(n1, 2);
        assert_eq!(n2, 0, "already wrapped: nothing to do");
        assert_eq!(once, twice);
    }

    #[test]
    fn unwrap_restores_the_original() {
        let original = cfg();
        let (wrapped, _) = wrap(original.clone(), "/abs/innerwarden", false, "cursor");
        let (restored, n) = unwrap(wrapped);
        assert_eq!(n, 2);
        assert_eq!(restored, original);
        assert!(!is_guarded(&restored));
    }

    #[test]
    fn servers_schema_key_is_handled_too() {
        let c = json!({ "servers": { "sh": { "command": "bash", "args": ["-c", "mcp"] } } });
        let (out, n) = wrap(c, "iw", false, "cursor");
        assert_eq!(n, 1);
        assert_eq!(out["servers"]["sh"]["command"], "iw");
        assert!(is_guarded(&out));
    }

    #[test]
    fn only_remote_or_empty_is_not_guardable() {
        assert!(!is_guardable(
            &json!({ "mcpServers": { "r": { "url": "https://x" } } })
        ));
        assert!(!is_guardable(&json!({ "mcpServers": {} })));
        assert!(!is_guardable(&json!({})));
        assert!(!is_guarded(&json!({ "mcpServers": {} })));
    }

    #[test]
    fn partial_wrap_is_not_fully_guarded() {
        // one wrapped, one fresh -> guardable but not guarded
        let mut c = cfg();
        c["mcpServers"]["new"] = json!({ "command": "node", "args": ["srv.js"] });
        let (partial, _) = wrap(c, "iw", false, "cursor");
        // now add another unwrapped server after wrapping
        let mut partial = partial;
        partial["mcpServers"]["late"] = json!({ "command": "python", "args": ["late.py"] });
        assert!(is_guardable(&partial));
        assert!(has_guard_wiring(&partial));
        assert!(
            !is_guarded(&partial),
            "a later unwrapped server means not fully guarded"
        );
        assert_eq!(guarded_mode(&partial), Some(WiringMode::Enforce));
        // re-wrap closes the gap
        let (rewrapped, n) = wrap(partial, "iw", false, "cursor");
        assert_eq!(n, 1);
        assert!(is_guarded(&rewrapped));
    }

    #[test]
    fn recognizes_iw_and_iw_guard_aliases_as_wrapped() {
        for bin in [
            "/x/iw",
            "/x/iw-guard",
            "/x/innerwarden",
            "innerwarden",
            "C:\\x\\innerwarden.exe",
            "C:\\x\\IW-GUARD.EXE",
        ] {
            let (out, _) = wrap(
                json!({"mcpServers":{"s":{"command":"npx","args":[]}}}),
                bin,
                false,
                "cursor",
            );
            assert!(
                is_guarded(&out),
                "wrapped with {bin} should read as guarded"
            );
        }
    }

    /// Only the guard's own names are the guard. A command that merely
    /// begins with `innerwarden` is another program: a script the agent's
    /// account wrote, or Active Defence's `innerwarden-ctl`, whose proxy is
    /// `agent proxy`, so `innerwarden-ctl proxy` never starts. Such a wrapper
    /// is a server like any other: not guarded, and connecting the agent
    /// wraps it in the real proxy.
    ///
    /// FAILS ON REVERT: accept any `innerwarden*` command again and the shim
    /// reads guarded, `Enforce`.
    #[test]
    fn a_command_that_only_begins_with_the_guards_name_is_not_the_guard() {
        for bin in [
            "/home/u/.local/bin/innerwarden-shim",
            "/opt/innerwarden-ctl",
            "innerwardenx",
            "/x/iwx",
        ] {
            let config = json!({"mcpServers":{"s":{"command": bin, "args":["proxy","--mode","guard","--","npx","fs"]}}});
            assert!(!is_guarded(&config), "{bin}");
            assert_eq!(guarded_mode(&config), None, "{bin}");
            assert!(has_unguarded_stdio_server(&config), "{bin}");
            let (wrapped, n) = wrap(config, "/abs/innerwarden", false, "cursor");
            assert_eq!(n, 1, "{bin}: the real proxy wraps it");
            let server = &wrapped["mcpServers"]["s"];
            assert_eq!(server["command"], "/abs/innerwarden");
            let args = server["args"].as_array().unwrap();
            let separator = args.iter().position(|a| a == "--").unwrap();
            assert_eq!(args[separator + 1], bin, "{bin}");
            assert_eq!(guarded_mode(&wrapped), Some(WiringMode::Enforce));
        }
    }

    /// A word the proxy does not take before `--` makes it exit with a usage
    /// error, so the server never starts and nothing is screened: no mode is
    /// reported for it. The options it does take still read.
    ///
    /// FAILS ON REVERT: step over unknown words again and the first case
    /// reads `Some(true)`.
    #[test]
    fn a_word_the_proxy_refuses_leaves_no_mode_to_report() {
        for options in [
            &["--mode", "guard", "--verbose"][..],
            &["--verbose"][..],
            &["--mode", "guard", ""][..],
            &["guard"][..],
        ] {
            let words: Vec<Option<&str>> = options.iter().map(|w| Some(*w)).collect();
            assert_eq!(wrapper_blocks(&words), None, "{options:?}");
        }
        let words: Vec<Option<&str>> = ["--mode", "advisory", "--error-response", "--label=x"]
            .iter()
            .map(|w| Some(*w))
            .collect();
        assert_eq!(wrapper_blocks(&words), Some(false));
    }

    #[test]
    fn switching_monitor_and_enforce_rewrites_one_proxy_without_nesting() {
        let original = cfg();
        let (monitor, n) = wrap(original.clone(), "innerwarden", true, "cursor");
        assert_eq!(n, 2);
        assert_eq!(guarded_mode(&monitor), Some(WiringMode::Monitor));
        assert_eq!(
            monitor["mcpServers"]["fs"]["args"],
            json!([
                "proxy",
                "--label",
                "cursor",
                "--agent",
                "cursor",
                "--mode",
                "advisory",
                "--",
                "npx",
                "-y",
                "@modelcontextprotocol/server-filesystem",
                "/tmp"
            ])
        );

        let (enforce, changed) = wrap(monitor, "innerwarden", false, "cursor");
        assert_eq!(changed, 2);
        assert_eq!(guarded_mode(&enforce), Some(WiringMode::Enforce));
        assert_eq!(
            enforce["mcpServers"]["fs"]["args"],
            json!([
                "proxy",
                "--label",
                "cursor",
                "--agent",
                "cursor",
                "--mode",
                "guard",
                "--",
                "npx",
                "-y",
                "@modelcontextprotocol/server-filesystem",
                "/tmp"
            ])
        );
        let (restored, n) = unwrap(enforce);
        assert_eq!(n, 2);
        assert_eq!(restored, original);
    }

    #[test]
    fn legacy_proxy_layout_stays_detectable_and_reversible() {
        let legacy = json!({
            "mcpServers": {
                "s": { "command": "innerwarden", "args": ["proxy", "--", "npx", "srv"] }
            }
        });
        assert!(is_guarded(&legacy));
        assert_eq!(guarded_mode(&legacy), Some(WiringMode::Enforce));
        let (restored, n) = unwrap(legacy);
        assert_eq!(n, 1);
        assert_eq!(restored["mcpServers"]["s"]["command"], "npx");
        assert_eq!(restored["mcpServers"]["s"]["args"], json!(["srv"]));
    }

    #[test]
    fn mode_switch_preserves_existing_proxy_options() {
        let configured = json!({"mcpServers":{"s":{
            "command":"innerwarden",
            "args":["proxy","--label","codex-main","--error-response","--mode","guard","--","npx","srv"]
        }}});
        let (monitor, changed) = wrap(configured, "innerwarden", true, "codex");
        assert_eq!(changed, 1);
        assert_eq!(
            monitor["mcpServers"]["s"]["args"],
            json!([
                "proxy",
                "--label",
                "codex-main",
                "--error-response",
                "--agent",
                "codex",
                "--mode",
                "advisory",
                "--",
                "npx",
                "srv"
            ])
        );
        let (enforce, changed) = wrap(monitor, "innerwarden", false, "codex");
        assert_eq!(changed, 1);
        assert_eq!(
            enforce["mcpServers"]["s"]["args"],
            json!([
                "proxy",
                "--label",
                "codex-main",
                "--error-response",
                "--agent",
                "codex",
                "--mode",
                "guard",
                "--",
                "npx",
                "srv"
            ])
        );
    }

    #[test]
    fn invalid_or_incomplete_proxy_mode_is_not_reported_as_enforcing() {
        for args in [
            json!(["proxy", "--mode", "bogus", "--", "npx"]),
            json!(["proxy", "--mode", "guard", "--"]),
            json!(["proxy", "--mode", "guard", "npx"]),
        ] {
            let cfg = json!({"mcpServers":{"s":{"command":"innerwarden","args":args}}});
            assert!(has_guard_wiring(&cfg));
            assert!(!is_guarded(&cfg));
            assert_eq!(guarded_mode(&cfg), None);
        }

        let broken = json!({"mcpServers":{"s":{
            "command":"innerwarden", "args":["proxy","--mode","guard","npx"]
        }}});
        let (unchanged, changed) = wrap(broken.clone(), "innerwarden", true, "cursor");
        assert_eq!(changed, 0);
        assert_eq!(
            unchanged, broken,
            "a broken proxy must never be wrapped again"
        );
    }
}

#[cfg(test)]
mod nested_table_tests {
    use super::*;
    use serde_json::json;

    /// REGRESSION ANCHOR. The table locator was two top-level keys, so an agent
    /// that nests its servers was unguardable no matter what: `agents connect`
    /// found no table and silently wired nothing. OpenClaw nests under
    /// `mcp.servers`, and it is the agent this product's own description names
    /// first.
    ///
    /// FAILS ON REVERT: drop `["mcp","servers"]` from the paths and nothing is
    /// wrapped.
    #[test]
    fn a_nested_server_table_is_wired_like_a_flat_one() {
        let cfg = json!({
            "meta": {"version": 1},
            "mcp": {"servers": {"fs": {"command": "npx", "args": ["-y", "fs-server"]}}}
        });
        let (out, n) = wrap(cfg, "/usr/bin/innerwarden", false, "openclaw");
        assert_eq!(n, 1, "the nested stdio server must be wrapped");
        let server = &out["mcp"]["servers"]["fs"];
        assert_eq!(server["command"], "/usr/bin/innerwarden");
        assert!(
            server["args"]
                .as_array()
                .unwrap()
                .iter()
                .any(|a| a == "npx"),
            "the real server must still be invoked: {server}"
        );
        assert!(is_guarded(&out), "and the config must report as guarded");
    }

    /// Wiring must be reversible for a nested table too, byte for byte.
    #[test]
    fn a_nested_table_round_trips() {
        let original = json!({
            "mcp": {"servers": {"fs": {"command": "npx", "args": ["-y", "fs-server"]}}}
        });
        let (wrapped, _) = wrap(original.clone(), "/usr/bin/innerwarden", false, "openclaw");
        let (restored, n) = unwrap(wrapped);
        assert_eq!(n, 1);
        assert_eq!(
            restored, original,
            "unwrap must restore the original exactly"
        );
    }

    /// Unrelated keys must survive untouched. OpenClaw's file carries auth,
    /// channels and gateway config beside the servers, and mangling any of it
    /// would be worse than not guarding at all.
    #[test]
    fn everything_outside_the_table_is_preserved() {
        let cfg = json!({
            "meta": {"version": 1},
            "auth": {"token": "secret"},
            "channels": [{"id": "main"}],
            "mcp": {"allowed": ["fs"], "servers": {"fs": {"command": "npx", "args": []}}}
        });
        let (out, _) = wrap(cfg.clone(), "/usr/bin/innerwarden", false, "openclaw");
        assert_eq!(out["meta"], cfg["meta"]);
        assert_eq!(out["auth"], cfg["auth"]);
        assert_eq!(out["channels"], cfg["channels"]);
        assert_eq!(
            out["mcp"]["allowed"], cfg["mcp"]["allowed"],
            "a sibling of `servers` must not be disturbed"
        );
    }

    /// A config with no table must not gain one. Creating `mcp.servers` where
    /// the user had none would be inventing configuration.
    #[test]
    fn a_missing_table_is_never_created() {
        let cfg = json!({"meta": {"version": 1}, "tools": {"profile": "coding"}});
        let (out, n) = wrap(cfg.clone(), "/usr/bin/innerwarden", false, "openclaw");
        assert_eq!(n, 0);
        assert_eq!(out, cfg, "an untouched config must be returned unchanged");
        assert!(out.get("mcp").is_none(), "no table may be conjured");
    }

    /// A nested table whose entries are malformed must not be auto-wrapped.
    #[test]
    fn a_malformed_nested_entry_blocks_automatic_wiring() {
        let cfg = json!({"mcp": {"servers": {"broken": "not-an-object"}}});
        assert!(
            !is_automatic_wrap_safe(&cfg),
            "automatic wiring must refuse a config it cannot rewrite safely"
        );
    }
}

#[cfg(test)]
mod partial_wiring_tests {
    use super::*;
    use serde_json::json;

    /// REGRESSION ANCHOR. Found on a real machine: a config with one server
    /// wrapped and two open. "Has any wiring" was used to mean "nothing to do",
    /// so the two open servers stayed open forever and nothing offered to fix
    /// them. Not protected, and not offered.
    ///
    /// FAILS ON REVERT: express this as `!has_guard_wiring` and it returns false
    /// for the partial config.
    #[test]
    fn a_partially_wired_config_still_has_work_to_do() {
        let cfg = json!({"mcpServers": {
            "icm":         {"command": "/home/u/.local/bin/iw", "args": ["proxy", "--mode", "guard", "--", "icm"]},
            "node_repl":   {"command": "/apps/node_repl", "args": []},
            "computer-use":{"command": "/apps/SkyComputerUseClient", "args": []}
        }});
        assert!(
            has_guard_wiring(&cfg),
            "the file HAS been touched, which is a different question"
        );
        assert!(
            !is_guarded(&cfg),
            "and it is not fully guarded, which the dashboard already said"
        );
        assert!(
            has_unguarded_stdio_server(&cfg),
            "so there IS still work to do, and that is what eligibility must ask"
        );
    }

    /// A fully wired config has nothing left, so it must not be offered again.
    #[test]
    fn a_fully_wired_config_has_nothing_left() {
        let cfg = json!({"mcpServers": {
            "a": {"command": "/home/u/.local/bin/iw", "args": ["proxy", "--mode", "guard", "--", "a"]}
        }});
        assert!(is_guarded(&cfg));
        assert!(!has_unguarded_stdio_server(&cfg));
    }

    /// An untouched config is the ordinary case and must still be offered.
    #[test]
    fn an_untouched_config_has_work_to_do() {
        let cfg = json!({"mcpServers": {"a": {"command": "npx", "args": ["-y", "a"]}}});
        assert!(!has_guard_wiring(&cfg));
        assert!(has_unguarded_stdio_server(&cfg));
    }

    /// A remote-only config has no local command to wrap, so there is nothing to
    /// do and offering it would be noise.
    #[test]
    fn a_remote_only_config_has_nothing_to_wrap() {
        let cfg = json!({"mcpServers": {"remote": {"url": "https://example.com/mcp"}}});
        assert!(!has_unguarded_stdio_server(&cfg));
    }

    /// Wrapping a partially wired config must close the gap without nesting a
    /// proxy inside the one already wrapped.
    #[test]
    fn wrapping_a_partial_config_closes_the_gap_without_nesting() {
        let cfg = json!({"mcpServers": {
            "wrapped": {"command": "/home/u/.local/bin/iw", "args": ["proxy", "--mode", "guard", "--", "npx", "a"]},
            "open":    {"command": "npx", "args": ["-y", "b"]}
        }});
        let (out, _) = wrap(cfg, "/home/u/.local/bin/iw", false, "codex");
        assert!(is_guarded(&out), "every stdio server must now be wrapped");
        assert!(!has_unguarded_stdio_server(&out));
        let args = out["mcpServers"]["wrapped"]["args"].as_array().unwrap();
        assert_eq!(
            args.iter().filter(|a| *a == "proxy").count(),
            1,
            "the already-wrapped server must not gain a second proxy: {args:?}"
        );
    }
}

#[cfg(test)]
mod agent_naming_tests {
    use super::*;
    use serde_json::json;

    const BIN: &str = "/home/u/.local/bin/innerwarden";

    fn args_of(root: &Value, path: &[&str], name: &str) -> Vec<String> {
        let mut node = root;
        for key in path {
            node = &node[*key];
        }
        node[name]["args"]
            .as_array()
            .unwrap()
            .iter()
            .map(|arg| arg.as_str().unwrap().to_string())
            .collect()
    }

    fn openclaw(server_args: Value) -> Value {
        json!({
            "gateway": {"port": 18789},
            "mcp": {"servers": {"fs": {"command": BIN, "args": server_args}}}
        })
    }

    /// REGRESSION ANCHOR. `agents connect openclaw` wrote `proxy --mode M --
    /// <server>` and nothing else, so the proxy recorded every OpenClaw tool
    /// call in the session `mcp:innerwarden` with no agent: the cases said
    /// "An agent asked, through an MCP connection", and the Agents page could
    /// never say OpenClaw had been screened while another MCP agent was
    /// connected beside it.
    ///
    /// FAILS ON REVERT: drop the naming from `wrap_server` and the args read
    /// `proxy --mode advisory -- npx ...`.
    #[test]
    fn wrap_names_the_agent_on_the_proxy() {
        let cfg =
            json!({"mcp": {"servers": {"fs": {"command": "npx", "args": ["-y", "fs-server"]}}}});
        let (out, n) = wrap(cfg, BIN, true, "openclaw");
        assert_eq!(n, 1);
        assert_eq!(
            args_of(&out, &["mcp", "servers"], "fs"),
            [
                "proxy",
                "--label",
                "openclaw",
                "--agent",
                "openclaw",
                "--mode",
                "advisory",
                "--",
                "npx",
                "-y",
                "fs-server"
            ]
        );
        assert_eq!(
            guarded_mode(&out),
            Some(WiringMode::Monitor),
            "the mode is read through the label and the agent"
        );
    }

    /// The label is the proxy's session name. One an operator chose is theirs:
    /// only the agent is added beside it, and no second `--label` appears.
    #[test]
    fn an_operator_label_is_kept() {
        for (label, expected) in [
            (
                json!(["--label", "prod-fs"]),
                vec![
                    "proxy", "--label", "prod-fs", "--agent", "openclaw", "--mode", "guard", "--",
                    "npx",
                ],
            ),
            (
                json!(["--label=prod-fs"]),
                vec![
                    "proxy",
                    "--label=prod-fs",
                    "--agent",
                    "openclaw",
                    "--mode",
                    "guard",
                    "--",
                    "npx",
                ],
            ),
        ] {
            let mut options: Vec<Value> = vec![json!("proxy")];
            options.extend(label.as_array().unwrap().iter().cloned());
            options.extend([json!("--mode"), json!("guard"), json!("--"), json!("npx")]);
            let (out, n) = wrap(openclaw(json!(options)), BIN, false, "openclaw");
            assert_eq!(n, 1, "{label}");
            assert_eq!(
                args_of(&out, &["mcp", "servers"], "fs"),
                expected,
                "{label}"
            );
        }
    }

    /// A wrapper an earlier release wrote names no agent. A connect gains the
    /// name and changes nothing else: same program, same mode, the same
    /// options it already had, the server's own command line byte for byte,
    /// and every key outside the wrapper. Unwrapping it still gives back the
    /// original server exactly.
    #[test]
    fn a_wrapper_written_before_wrappers_named_their_agent_gains_the_name_and_nothing_else() {
        let before = openclaw(json!([
            "proxy",
            "--error-response",
            "--mode",
            "advisory",
            "--",
            "npx",
            "-y",
            "fs-server",
            "--root",
            "/srv/a b"
        ]));
        let (after, n) = wrap(before.clone(), BIN, true, "openclaw");
        assert_eq!(n, 1);
        assert_eq!(
            args_of(&after, &["mcp", "servers"], "fs"),
            [
                "proxy",
                "--error-response",
                "--label",
                "openclaw",
                "--agent",
                "openclaw",
                "--mode",
                "advisory",
                "--",
                "npx",
                "-y",
                "fs-server",
                "--root",
                "/srv/a b"
            ]
        );
        assert_eq!(after["mcp"]["servers"]["fs"]["command"], BIN);
        assert_eq!(after["gateway"], before["gateway"]);
        assert_eq!(guarded_mode(&after), guarded_mode(&before));
        assert_eq!(
            unwrap(after.clone()).0,
            unwrap(before).0,
            "the server under the wrapper is the same server"
        );
        assert_eq!(
            unwrap(after.clone()).0["mcp"]["servers"]["fs"],
            json!({"command": "npx", "args": ["-y", "fs-server", "--root", "/srv/a b"]})
        );
        assert_eq!(
            wrap(after, BIN, true, "openclaw").1,
            0,
            "named once, then left alone"
        );
    }

    /// Both spellings the proxy accepts are read, and the flags with values
    /// are walked the way the proxy walks them.
    #[test]
    fn server_mode_reads_through_label_and_agent() {
        for (args, mode) in [
            (
                json!([
                    "proxy", "--label", "openclaw", "--agent", "openclaw", "--mode", "advisory",
                    "--", "npx"
                ]),
                WiringMode::Monitor,
            ),
            (
                json!([
                    "proxy",
                    "--agent=openclaw",
                    "--label=x",
                    "--mode=guard",
                    "--",
                    "npx"
                ]),
                WiringMode::Enforce,
            ),
            (
                json!(["proxy", "--label", "openclaw", "--agent", "openclaw", "--", "npx"]),
                WiringMode::Enforce,
            ),
        ] {
            let cfg = openclaw(args.clone());
            assert!(is_guarded(&cfg), "{args}");
            assert_eq!(guarded_mode(&cfg), Some(mode), "{args}");
        }
    }

    /// A flag's value is never read as the mode. `innerwarden proxy` takes the
    /// word after `--label` or `--agent` as that flag's value whatever it says,
    /// so `--label --mode=guard` is a label and the proxy runs the mode given
    /// before it. The reader stepped one word at a time and took any
    /// `--mode` it met, so a configuration anyone with the agent's account can
    /// edit could keep a recording proxy listed as enforce.
    ///
    /// FAILS ON REVERT: step over every option one word at a time in
    /// `server_mode` again; the first case reads `Some(Enforce)`.
    #[test]
    fn a_flag_value_is_never_read_as_the_mode() {
        for (args, mode) in [
            (
                json!([
                    "proxy",
                    "--mode",
                    "advisory",
                    "--label",
                    "--mode=guard",
                    "--",
                    "npx"
                ]),
                WiringMode::Monitor,
            ),
            (
                json!([
                    "proxy",
                    "--mode",
                    "advisory",
                    "--agent",
                    "--mode=kill",
                    "--",
                    "npx"
                ]),
                WiringMode::Monitor,
            ),
            // The label is `--mode`; no mode is given, so the proxy's default
            // (`guard`) applies.
            (
                json!(["proxy", "--label", "--mode", "--", "npx"]),
                WiringMode::Enforce,
            ),
        ] {
            let cfg = openclaw(args.clone());
            assert!(is_guarded(&cfg), "{args}");
            assert_eq!(guarded_mode(&cfg), Some(mode), "{args}");
        }
    }

    /// A flag that takes a value, standing just before the first `--`, takes
    /// that `--` as its value: the proxy reads on, and runs the mode written
    /// AFTER it. The words in front of the first `--` are not what runs, so
    /// such a wrapper has no mode to report and is not guarded.
    ///
    /// FAILS ON REVERT: drop the `takes_the_separator` check from
    /// `wrapper_blocks`; the first case reads guarded, `Some(Enforce)`, while
    /// its proxy records only.
    #[test]
    fn a_flag_that_takes_the_separator_leaves_no_mode_to_report() {
        for args in [
            json!(["proxy", "--mode", "guard", "--label", "--", "--mode", "advisory", "--", "npx"]),
            json!(["proxy", "--mode", "guard", "--agent", "--", "--mode", "advisory", "--", "npx"]),
            json!(["proxy", "--mode", "--", "npx"]),
        ] {
            let cfg = openclaw(args.clone());
            assert!(!is_guarded(&cfg), "{args}");
            assert!(has_unguarded_stdio_server(&cfg), "{args}");
            assert_eq!(guarded_mode(&cfg), None, "{args}");
        }
    }

    /// A name that is not a plain agent id is left out, never quoted in: the
    /// wrapper is then exactly what it was before wrappers named their agent.
    #[test]
    fn a_name_that_is_not_a_plain_id_is_never_written() {
        for agent in ["", "Open Claw", "my.app", "x; rm -rf /", "--mode"] {
            let cfg = json!({"mcpServers": {"s": {"command": "npx", "args": ["srv"]}}});
            let (out, _) = wrap(cfg, BIN, false, agent);
            assert_eq!(
                args_of(&out, &["mcpServers"], "s"),
                ["proxy", "--mode", "guard", "--", "npx", "srv"],
                "{agent:?}"
            );
        }
    }

    /// Connecting an agent says whose servers these are. An `--agent` the
    /// proxy ignores (no value, or not a plain id), another agent's name, or
    /// the name written twice all become the one name of this agent. The
    /// label, an operator's, is never touched.
    #[test]
    fn any_other_agent_flag_becomes_this_agents_name() {
        for options in [
            json!(["--agent", "Open Claw"]),
            json!(["--agent", "cursor"]),
            json!(["--agent=cursor"]),
            json!(["--agent"]),
            json!(["--agent=openclaw", "--agent", "openclaw"]),
            json!(["--agent", "openclaw", "--agent", "cursor"]),
        ] {
            let mut args: Vec<Value> = vec![json!("proxy"), json!("--label"), json!("mine")];
            args.extend(options.as_array().unwrap().iter().cloned());
            args.extend([json!("--mode"), json!("guard"), json!("--"), json!("npx")]);
            let (out, n) = wrap(openclaw(json!(args)), BIN, false, "openclaw");
            assert_eq!(n, 1, "{options}");
            assert_eq!(
                args_of(&out, &["mcp", "servers"], "fs"),
                [
                    "proxy", "--label", "mine", "--agent", "openclaw", "--mode", "guard", "--",
                    "npx"
                ],
                "{options}"
            );
        }
        // Already named, in either spelling: nothing to do.
        for options in [json!(["--agent", "openclaw"]), json!(["--agent=openclaw"])] {
            let mut args: Vec<Value> = vec![json!("proxy"), json!("--label"), json!("mine")];
            args.extend(options.as_array().unwrap().iter().cloned());
            args.extend([json!("--mode"), json!("guard"), json!("--"), json!("npx")]);
            assert_eq!(
                wrap(openclaw(json!(args)), BIN, false, "openclaw").1,
                0,
                "{options}"
            );
        }
    }

    /// The step a person is offered for wiring that does not name its agent:
    /// the reconnect in the mode the wiring already has.
    #[test]
    fn an_unnamed_wiring_is_offered_the_reconnect_that_names_it_in_its_own_mode() {
        let monitor = openclaw(json!(["proxy", "--mode", "advisory", "--", "npx"]));
        assert_eq!(
            unnamed_reconnect_flag(&monitor, BIN, "openclaw"),
            Some(" --monitor")
        );
        let enforce = openclaw(json!(["proxy", "--mode", "guard", "--", "npx"]));
        assert_eq!(unnamed_reconnect_flag(&enforce, BIN, "openclaw"), Some(""));

        // A server copied in from another agent's configuration records that
        // agent: its cases do not say this one asked either.
        let borrowed = openclaw(json!([
            "proxy", "--label", "cursor", "--agent", "cursor", "--mode", "advisory", "--", "npx"
        ]));
        assert_eq!(
            unnamed_reconnect_flag(&borrowed, BIN, "openclaw"),
            Some(" --monitor")
        );
        // One named server beside one that is not: the second still needs it.
        let half = json!({"mcpServers": {
            "a": {"command": BIN, "args": ["proxy", "--label", "cursor", "--agent", "cursor", "--mode", "guard", "--", "npx"]},
            "b": {"command": BIN, "args": ["proxy", "--mode", "guard", "--", "uvx"]}
        }});
        assert_eq!(unnamed_reconnect_flag(&half, BIN, "cursor"), Some(""));

        // And that reconnect only names it: run it, and nothing is left to
        // offer, the mode is the same and the server under it is the same.
        for (cfg, monitor) in [(monitor, true), (enforce, false), (borrowed, true)] {
            let (named, n) = wrap(cfg.clone(), BIN, monitor, "openclaw");
            assert_eq!(n, 1);
            assert_eq!(unnamed_reconnect_flag(&named, BIN, "openclaw"), None);
            assert_eq!(guarded_mode(&named), guarded_mode(&cfg));
            assert_eq!(unwrap(named).0, unwrap(cfg).0);
        }
    }

    /// Nothing is offered where the reconnect would change more than the name,
    /// or where there is no name to add.
    #[test]
    fn no_reconnect_is_offered_where_it_would_change_more_than_the_name() {
        let named = openclaw(json!([
            "proxy", "--label", "openclaw", "--agent", "openclaw", "--mode", "advisory", "--",
            "npx"
        ]));
        assert_eq!(
            unnamed_reconnect_flag(&named, BIN, "openclaw"),
            None,
            "already named"
        );
        // Its proxy records the agent already, in either spelling, the last
        // `--agent` winning: its cases name it, so there is nothing to tell
        // anyone. A connect would still tidy these (add the session label,
        // drop the overridden flag), which is not worth a step on the page.
        for args in [
            json!(["proxy", "--agent", "openclaw", "--mode", "advisory", "--", "npx"]),
            json!([
                "proxy",
                "--agent=openclaw",
                "--mode",
                "advisory",
                "--",
                "npx"
            ]),
            json!([
                "proxy", "--label", "p", "--agent", "cursor", "--agent", "openclaw", "--mode",
                "advisory", "--", "npx"
            ]),
        ] {
            let cfg = openclaw(args.clone());
            assert!(wrap(cfg.clone(), BIN, true, "openclaw").1 > 0, "{args}");
            assert_eq!(
                unnamed_reconnect_flag(&cfg, BIN, "openclaw"),
                None,
                "{args}"
            );
        }
        let operator_label = openclaw(json!([
            "proxy", "--label", "prod", "--agent", "openclaw", "--mode", "advisory", "--", "npx"
        ]));
        assert_eq!(
            unnamed_reconnect_flag(&operator_label, BIN, "openclaw"),
            None
        );

        // A wrapper that runs another copy of the CLI, one root installed for
        // the wrapper to run for instance: the reconnect would move it to this
        // binary. That is not "only adds the name".
        let elsewhere = json!({"mcp": {"servers": {"fs": {
            "command": "/opt/pinned/innerwarden", "args": ["proxy", "--mode", "advisory", "--", "npx"]
        }}}});
        assert_eq!(unnamed_reconnect_flag(&elsewhere, BIN, "openclaw"), None);

        // Two modes: a reconnect picks one.
        let mixed = json!({"mcpServers": {
            "a": {"command": BIN, "args": ["proxy", "--mode", "advisory", "--", "npx"]},
            "b": {"command": BIN, "args": ["proxy", "--mode", "guard", "--", "uvx"]}
        }});
        assert_eq!(guarded_mode(&mixed), Some(WiringMode::Mixed));
        assert_eq!(unnamed_reconnect_flag(&mixed, BIN, "cursor"), None);

        // Partly wired: finishing it is a different step.
        let partial = json!({"mcpServers": {
            "a": {"command": BIN, "args": ["proxy", "--mode", "advisory", "--", "npx"]},
            "b": {"command": "uvx", "args": ["srv"]}
        }});
        assert_eq!(unnamed_reconnect_flag(&partial, BIN, "cursor"), None);

        // The oldest layout has no `--mode`: a reconnect would write one.
        let legacy = json!({"mcpServers": {"a": {"command": BIN, "args": ["proxy", "--", "npx"]}}});
        assert_eq!(unnamed_reconnect_flag(&legacy, BIN, "cursor"), None);

        // No plain id, no name to add.
        let unnamed = openclaw(json!(["proxy", "--mode", "advisory", "--", "npx"]));
        assert_eq!(unnamed_reconnect_flag(&unnamed, BIN, "my.app"), None);

        // Nothing wired at all.
        let bare = json!({"mcpServers": {"a": {"command": "npx"}}});
        assert_eq!(unnamed_reconnect_flag(&bare, BIN, "cursor"), None);
    }
}
