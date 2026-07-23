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

use serde_json::{json, Value};

/// The basename of a command path, cross-platform (`/` and `\`), lowercased.
fn basename(cmd: &str) -> String {
    cmd.rsplit(['/', '\\'])
        .next()
        .unwrap_or(cmd)
        .trim_end_matches(".exe")
        .to_ascii_lowercase()
}

/// Effective enforcement of MCP servers wired through the local proxy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WiringMode {
    Monitor,
    Enforce,
    Mixed,
}

fn has_proxy_prefix(server: &Value) -> bool {
    let is_guard = server
        .get("command")
        .and_then(|c| c.as_str())
        .map(|c| {
            let b = basename(c);
            b.starts_with("innerwarden") || b == "iw" || b == "innerwarden"
        })
        .unwrap_or(false);
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
    let mut mode: Option<&str> = None;
    let mut i = 1usize;
    while i < separator {
        let arg = args[i].as_str()?;
        if arg == "--mode" {
            mode = Some(args.get(i + 1)?.as_str()?);
            i += 2;
        } else if let Some(value) = arg.strip_prefix("--mode=") {
            mode = Some(value);
            i += 1;
        } else {
            i += 1;
        }
    }
    match mode {
        // Legacy Community wrappers were written as `proxy -- <child>`; the
        // Community CLI's historical default is guard, so they enforce.
        None | Some("guard" | "kill") => Some(WiringMode::Enforce),
        Some("advisory" | "warn") => Some(WiringMode::Monitor),
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

/// A stdio server is one we can wrap: it has a local `command` (not a remote
/// `url`-only server).
fn is_stdio_server(server: &Value) -> bool {
    server
        .get("command")
        .and_then(|c| c.as_str())
        .map(|c| !c.trim().is_empty())
        .unwrap_or(false)
}

fn wrap_server(server: &mut Value, guard_bin: &str, monitor: bool) -> bool {
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
    let (orig_cmd, orig_args, mut proxy_prefix) = if let Some(separator) = separator {
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
    let mode = if monitor { "advisory" } else { "guard" };
    proxy_prefix.extend([json!("--mode"), json!(mode), json!("--"), json!(orig_cmd)]);
    let mut new_args = proxy_prefix;
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

/// Apply `f` to every server object under either schema key. Returns how many
/// times `f` returned true.
fn for_each_server(root: &mut Value, mut f: impl FnMut(&mut Value) -> bool) -> usize {
    let mut n = 0;
    for key in ["mcpServers", "servers"] {
        if let Some(map) = root.get_mut(key).and_then(|m| m.as_object_mut()) {
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
    for key in ["mcpServers", "servers"] {
        if let Some(map) = root.get(key).and_then(|m| m.as_object()) {
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
/// (`monitor=true`) or guard mode. Existing wrappers are safely reconfigured, so
/// switching modes is idempotent and never nests proxies. Returns the new config
/// and how many server entries changed. Pure.
pub fn wrap(mut root: Value, guard_bin: &str, monitor: bool) -> (Value, usize) {
    let n = for_each_server(&mut root, |s| wrap_server(s, guard_bin, monitor));
    (root, n)
}

/// Undo `wrap`: restore each server's original command/args. Returns the config
/// and how many were unwrapped. Pure.
pub fn unwrap(mut root: Value) -> (Value, usize) {
    let n = for_each_server(&mut root, unwrap_server);
    (root, n)
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
    ["mcpServers", "servers"].iter().any(|key| {
        root.get(key)
            .and_then(Value::as_object)
            .is_some_and(|map| map.values().any(has_proxy_prefix))
    })
}

/// Effective mode across every guarded stdio server. `None` means there is no
/// fully guarded local server; differing modes are reported as `Mixed`.
pub fn guarded_mode(root: &Value) -> Option<WiringMode> {
    let mut found: Option<WiringMode> = None;
    for key in ["mcpServers", "servers"] {
        if let Some(map) = root.get(key).and_then(Value::as_object) {
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
    for key in ["mcpServers", "servers"] {
        let Some(servers) = root.get(key) else {
            continue;
        };
        let Some(servers) = servers.as_object() else {
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
        let (out, n) = wrap(cfg(), "/abs/innerwarden", false);
        assert_eq!(n, 2, "two stdio servers wrapped, the url server skipped");
        let fs = &out["mcpServers"]["fs"];
        assert_eq!(fs["command"], "/abs/innerwarden");
        assert_eq!(
            fs["args"],
            json!([
                "proxy",
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
        let (once, n1) = wrap(cfg(), "/abs/innerwarden", false);
        let (twice, n2) = wrap(once.clone(), "/abs/innerwarden", false);
        assert_eq!(n1, 2);
        assert_eq!(n2, 0, "already wrapped: nothing to do");
        assert_eq!(once, twice);
    }

    #[test]
    fn unwrap_restores_the_original() {
        let original = cfg();
        let (wrapped, _) = wrap(original.clone(), "/abs/innerwarden", false);
        let (restored, n) = unwrap(wrapped);
        assert_eq!(n, 2);
        assert_eq!(restored, original);
        assert!(!is_guarded(&restored));
    }

    #[test]
    fn servers_schema_key_is_handled_too() {
        let c = json!({ "servers": { "sh": { "command": "bash", "args": ["-c", "mcp"] } } });
        let (out, n) = wrap(c, "iw", false);
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
        let (partial, _) = wrap(c, "iw", false);
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
        let (rewrapped, n) = wrap(partial, "iw", false);
        assert_eq!(n, 1);
        assert!(is_guarded(&rewrapped));
    }

    #[test]
    fn recognizes_iw_and_iw_guard_aliases_as_wrapped() {
        for bin in [
            "/x/iw",
            "/x/innerwarden",
            "innerwarden",
            "/opt/innerwarden-ctl", // Active Defence dev binary / install-name variant
            "C:\\x\\innerwarden.exe",
        ] {
            let (out, _) = wrap(
                json!({"mcpServers":{"s":{"command":"npx","args":[]}}}),
                bin,
                false,
            );
            assert!(
                is_guarded(&out),
                "wrapped with {bin} should read as guarded"
            );
        }
    }

    #[test]
    fn switching_monitor_and_enforce_rewrites_one_proxy_without_nesting() {
        let original = cfg();
        let (monitor, n) = wrap(original.clone(), "innerwarden", true);
        assert_eq!(n, 2);
        assert_eq!(guarded_mode(&monitor), Some(WiringMode::Monitor));
        assert_eq!(
            monitor["mcpServers"]["fs"]["args"],
            json!([
                "proxy",
                "--mode",
                "advisory",
                "--",
                "npx",
                "-y",
                "@modelcontextprotocol/server-filesystem",
                "/tmp"
            ])
        );

        let (enforce, changed) = wrap(monitor, "innerwarden", false);
        assert_eq!(changed, 2);
        assert_eq!(guarded_mode(&enforce), Some(WiringMode::Enforce));
        assert_eq!(
            enforce["mcpServers"]["fs"]["args"],
            json!([
                "proxy",
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
        let (monitor, changed) = wrap(configured, "innerwarden", true);
        assert_eq!(changed, 1);
        assert_eq!(
            monitor["mcpServers"]["s"]["args"],
            json!([
                "proxy",
                "--label",
                "codex-main",
                "--error-response",
                "--mode",
                "advisory",
                "--",
                "npx",
                "srv"
            ])
        );
        let (enforce, changed) = wrap(monitor, "innerwarden", false);
        assert_eq!(changed, 1);
        assert_eq!(
            enforce["mcpServers"]["s"]["args"],
            json!([
                "proxy",
                "--label",
                "codex-main",
                "--error-response",
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
        let (unchanged, changed) = wrap(broken.clone(), "innerwarden", true);
        assert_eq!(changed, 0);
        assert_eq!(
            unchanged, broken,
            "a broken proxy must never be wrapped again"
        );
    }
}
